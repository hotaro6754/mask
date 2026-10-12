"""Insider-threat detection over each user's stream of queries.

Masking stops a single query from returning raw values. An insider can still try many queries: guessing an email
over and over, binary-searching a balance, paging through a whole table, or poking at the statement firewall.
The threat engine watches a sliding window of each user's recent queries and scores it two ways:

  * rules  - explainable detectors for known patterns (enumeration, probing masked columns, firewall bursts,
             bulk paging); each yields a risk 0-100 and a reason
  * ML     - an IsolationForest fitted on windows from simulated *normal* sessions only; its anomaly score is turned
             into a risk by comparing it with the scores of normal windows (risk 90 = more unusual than ~99% of them)

Risk = max(rules, ML). Policy decides the response: alert at `alert`, block the user for `block_minutes` at `block`.
State is in memory per gateway process (use a shared store such as Redis for several processes).
"""
import math, os, threading, time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

WINDOW_QUERIES, WINDOW_SECONDS = 40, 300          # short window: bursts
LONG_QUERIES, LONG_SECONDS = 400, 24 * 3600         # long window: patient attackers
FEATURES = ["q_per_min", "reject_frac", "top_shape_frac", "top_shape_literal_variety", "pred_masked_frac",
            "order_masked_frac", "empty_frac", "narrow_frac", "log_rows", "small_limit_frac", "offset_frac",
            "distinct_shape_ratio", "aggregate_frac", "star_frac", "offhours",
            "long_log_probes", "long_log_top_shape_repeats", "long_log_rejects", "long_log_offsets"]
TRAIN_PATH = os.path.join(os.path.dirname(__file__), "ml", "threat_benign_windows.npz")


@dataclass
class Event:
    ts: float
    decision: str            # allow | reject | blocked
    fingerprint: str         # literal-stripped SQL
    rows: int = 0
    shape: dict = field(default_factory=dict)


@dataclass
class Assessment:
    risk: int
    action: str              # none | alert | block
    reasons: list
    rule_risk: int = 0
    ml_risk: int = 0
    features: dict = field(default_factory=dict)


def _long_counts(long_events):
    shapes = Counter(e.fingerprint for e in long_events if e.shape.get("pred_masked") or e.shape.get("order_masked"))
    return {"probes": sum(bool(e.shape.get("pred_masked") or e.shape.get("order_masked")) for e in long_events),
            "top_repeats": shapes.most_common(1)[0][1] if shapes else 0,
            "rejects": sum(e.decision == "reject" for e in long_events),
            "offsets": sum(bool(e.shape.get("offset")) for e in long_events)}


def window_features(events, long_events=None):
    if not events:
        return np.zeros(len(FEATURES), dtype=np.float32)
    lc = _long_counts(long_events if long_events is not None else events)
    n = len(events)
    span_min = max((events[-1].ts - events[0].ts) / 60.0, 0.5)
    shapes = Counter(e.fingerprint for e in events)
    top_fp, top_n = shapes.most_common(1)[0]
    top_lits = {e.shape.get("literal_hash") for e in events if e.fingerprint == top_fp}
    allowed = [e for e in events if e.decision == "allow"]
    na = len(allowed) or 1
    hour = time.localtime(events[-1].ts).tm_hour
    f = {
        "q_per_min": n / span_min,
        "reject_frac": sum(e.decision != "allow" for e in events) / n,
        "top_shape_frac": top_n / n,
        "top_shape_literal_variety": len(top_lits) / top_n,
        "pred_masked_frac": sum(bool(e.shape.get("pred_masked")) for e in events) / n,
        "order_masked_frac": sum(bool(e.shape.get("order_masked")) for e in events) / n,
        "empty_frac": sum(e.rows == 0 for e in allowed) / na,
        "narrow_frac": sum(e.rows <= 1 for e in allowed) / na,
        "log_rows": math.log1p(sum(e.rows for e in allowed)),
        "small_limit_frac": sum(bool(e.shape.get("small_limit")) for e in events) / n,
        "offset_frac": sum(bool(e.shape.get("offset")) for e in events) / n,
        "distinct_shape_ratio": len(shapes) / n,
        "aggregate_frac": sum(bool(e.shape.get("aggregate")) for e in events) / n,
        "star_frac": sum(bool(e.shape.get("star")) for e in events) / n,
        "offhours": float(hour < 7 or hour >= 21),
        "long_log_probes": math.log1p(lc["probes"]),
        "long_log_top_shape_repeats": math.log1p(lc["top_repeats"]),
        "long_log_rejects": math.log1p(lc["rejects"]),
        "long_log_offsets": math.log1p(lc["offsets"]),
    }
    return np.asarray([f[k] for k in FEATURES], dtype=np.float32)


def rule_risk(events, long_events=None):
    """Explainable detectors over the short window (bursts) and the 24 h window (patient attackers)."""
    if not events:
        return 0, []
    reasons, risk = [], 0
    shapes = Counter(e.fingerprint for e in events)
    top_fp, top_n = shapes.most_common(1)[0]
    top = [e for e in events if e.fingerprint == top_fp]
    variety = len({e.shape.get("literal_hash") for e in top}) / max(top_n, 1)
    probes = sum(bool(e.shape.get("pred_masked") or e.shape.get("order_masked")) for e in events)
    rejects = sum(e.decision == "reject" for e in events)
    paging = sum(bool(e.shape.get("offset")) for e in events)
    if top_n >= 12 and variety >= 0.8 and any(e.shape.get("pred_masked") or e.shape.get("order_masked") for e in top):
        risk = max(risk, min(100, 60 + 3 * (top_n - 12)))
        reasons.append(f"enumeration: same query shape {top_n}x with different values on a masked column")
    if probes >= 10:
        risk = max(risk, min(100, 50 + 3 * (probes - 10)))
        reasons.append(f"probing: {probes} queries filter or sort on columns masked for this role")
    if rejects >= 3:
        risk = max(risk, min(100, 55 + 10 * (rejects - 3)))
        reasons.append(f"firewall: {rejects} unsafe statements rejected")
    if paging >= 8:
        risk = max(risk, min(100, 50 + 5 * (paging - 8)))
        reasons.append(f"bulk paging: {paging} OFFSET queries")
    if long_events is not None:
        lc = _long_counts(long_events)
        if lc["top_repeats"] >= 15:
            risk = max(risk, min(100, 60 + 2 * (lc["top_repeats"] - 15)))
            reasons.append(f"slow enumeration: one probe shape repeated {lc['top_repeats']}x in 24 h")
        if lc["probes"] >= 25:
            risk = max(risk, min(100, 55 + 2 * (lc["probes"] - 25)))
            reasons.append(f"sustained probing: {lc['probes']} masked-column probes in 24 h")
        if lc["rejects"] >= 6:
            risk = max(risk, min(100, 60 + 5 * (lc["rejects"] - 6)))
            reasons.append(f"repeated firewall hits: {lc['rejects']} rejected statements in 24 h")
    return risk, reasons


def iter_windows(events, min_queries=8):
    """Feature vectors as the engine would compute them after each event (for training/evaluation)."""
    short, long_ = deque(maxlen=WINDOW_QUERIES), deque(maxlen=LONG_QUERIES)
    for e in events:
        short.append(e); long_.append(e)
        while short and e.ts - short[0].ts > WINDOW_SECONDS:
            short.popleft()
        while long_ and e.ts - long_[0].ts > LONG_SECONDS:
            long_.popleft()
        if len(long_) >= min_queries:
            yield window_features(list(short), list(long_)), list(short), list(long_)


class AnomalyModel:
    """IsolationForest over window features; trained only on normal behaviour."""

    def __init__(self, X_benign, seed=0):
        from sklearn.ensemble import IsolationForest
        self.forest = IsolationForest(n_estimators=200, contamination="auto", random_state=seed).fit(X_benign)
        self.benign_scores = np.sort(-self.forest.score_samples(X_benign))  # higher = more anomalous

    @classmethod
    def load(cls, path=TRAIN_PATH):
        return cls(np.load(path)["X"])

    def risk(self, x):
        """Calibrated on normal windows only: 70 = beyond their 99.9th percentile, 90 = beyond the most unusual one.
        (A session spans ~20 windows, so per-window thresholds must be strict to keep per-session false alarms low.)"""
        s = float(-self.forest.score_samples(x[None, :])[0])
        b = self.benign_scores
        pct = np.searchsorted(b, s) / len(b)
        p99, p999, top = b[int(0.99 * (len(b) - 1))], b[int(0.999 * (len(b) - 1))], b[-1]
        if s <= p99:
            return int(40 * pct / 0.99)
        if s <= p999:
            return int(40 + 30 * (s - p99) / max(p999 - p99, 1e-9))
        if s <= top:
            return int(70 + 19 * (s - p999) / max(top - p999, 1e-9))
        return int(min(100, 90 + 10 * (s - top) / max(top - p999, 1e-9)))


class ThreatEngine:
    def __init__(self, cfg=None, model=None, use_rules=True):
        cfg = cfg or {}
        self.use_rules = use_rules
        self.alert, self.block = cfg.get("alert", 70), cfg.get("block", 90)
        self.block_seconds = 60 * cfg.get("block_minutes", 15)
        self.min_queries = cfg.get("min_queries", 8)
        self.ml_can_block = cfg.get("ml_can_block", False)  # default: ML alerts, only rule evidence blocks
        self.model = model
        self.windows = defaultdict(lambda: deque(maxlen=WINDOW_QUERIES))
        self.long_windows = defaultdict(lambda: deque(maxlen=LONG_QUERIES))
        self.blocked_until, self.latest, self.lock = {}, {}, threading.Lock()

    @classmethod
    def from_policy(cls, policy):
        cfg = policy.get("threat") or {}
        if cfg.get("enabled") is False:
            return None
        model = None
        if cfg.get("ml", True) and os.path.exists(TRAIN_PATH):
            try:
                model = AnomalyModel.load()
            except Exception:
                model = None
        return cls(cfg, model)

    def is_blocked(self, user, now=None):
        until = self.blocked_until.get(user)
        return bool(until and (now or time.time()) < until)

    def observe(self, user, event):
        with self.lock:
            w, lw = self.windows[user], self.long_windows[user]
            w.append(event); lw.append(event)
            while w and event.ts - w[0].ts > WINDOW_SECONDS:
                w.popleft()
            while lw and event.ts - lw[0].ts > LONG_SECONDS:
                lw.popleft()
            events, long_events = list(w), list(lw)
        r_risk, reasons = rule_risk(events, long_events) if self.use_rules else (0, [])
        m_risk, feats = 0, window_features(events, long_events)
        if self.model is not None and len(long_events) >= self.min_queries:
            m_risk = self.model.risk(feats)
            if m_risk >= 90:
                reasons = reasons + ["anomaly: more unusual than any normal session seen in training"]
            elif m_risk >= self.alert:
                reasons = reasons + ["anomaly: beyond the 99.9th percentile of normal sessions"]
        if not self.ml_can_block and r_risk < self.alert:
            m_risk = min(m_risk, self.block - 1)
        risk = max(r_risk, m_risk)
        action = "block" if risk >= self.block else "alert" if risk >= self.alert else "none"
        if action == "block":
            self.blocked_until[user] = event.ts + self.block_seconds
        a = Assessment(risk, action, reasons, r_risk, m_risk, dict(zip(FEATURES, map(float, feats))))
        self.latest[user] = (event.ts, a)
        return a

    def unblock(self, user):
        self.blocked_until.pop(user, None)
        self.windows.pop(user, None)
        self.long_windows.pop(user, None)

    def snapshot(self):
        return {u: {"risk": a.risk, "action": a.action, "reasons": a.reasons, "blocked": self.is_blocked(u),
                    "rule_risk": a.rule_risk, "ml_risk": a.ml_risk, "at": ts}
                for u, (ts, a) in self.latest.items()}
