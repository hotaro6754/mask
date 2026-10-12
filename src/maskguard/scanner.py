"""PII discovery: hybrid LightGBM column classifier + checksum rules (see maskguard.ml.model.decide).

classify_column() is the scanner used everywhere. classify_column_rules() is the v1 rules-only scanner, kept as a
fallback when LightGBM is unavailable and as a baseline for bench/eval_scanner.py.
"""
import logging, re, threading, time
import yaml
from stdnum import iban as _iban, luhn as _luhn
from stdnum.in_ import aadhaar as _aadhaar, pan as _pan

log = logging.getLogger("maskguard.scanner")

KIND_TAG = {
    # direct identifiers
    "aadhaar": "PII_HIGH", "pan": "PII_HIGH", "passport": "PII_HIGH", "voter_id": "PII_HIGH", "ssn": "PII_HIGH",
    "phone": "PII_HIGH", "email": "PII_HIGH", "upi": "PII_HIGH",
    # financial
    "card": "FINANCIAL_CONFIDENTIAL", "iban": "FINANCIAL_CONFIDENTIAL", "bank_account": "FINANCIAL_CONFIDENTIAL",
    "amount": "FINANCIAL_CONFIDENTIAL", "balance": "FINANCIAL_CONFIDENTIAL", "gstin": "FINANCIAL_CONFIDENTIAL",
    # quasi-identifiers
    "name": "PII_MEDIUM", "address": "PII_MEDIUM", "dob": "PII_MEDIUM", "pincode": "PII_MEDIUM",
    "vehicle_reg": "PII_MEDIUM", "ifsc": "PII_MEDIUM",
}
HEADER_WORDS = {"email": "email", "mail": "email", "phone": "phone", "mobile": "phone", "msisdn": "phone",
                "ssn": "ssn", "aadhaar": "aadhaar", "aadhar": "aadhaar", "pan": "pan", "card": "card", "cc": "card",
                "iban": "iban", "balance": "balance", "name": "name", "address": "address", "dob": "dob", "birth": "dob"}


def _digits(v):
    return re.sub(r"[\s-]", "", str(v))


def _is_card(v):
    d = _digits(v)
    return d.isdigit() and 13 <= len(d) <= 19 and _luhn.is_valid(d)


VALIDATORS = {
    "card": _is_card,
    "aadhaar": lambda v: _aadhaar.is_valid(_digits(v)),
    "pan": lambda v: _pan.is_valid(str(v).strip().upper()),
    "iban": lambda v: _iban.is_valid(str(v).replace(" ", "")),
    "email": lambda v: re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(v)) is not None,
    "phone": lambda v: re.fullmatch(r"(?:\+?91)?[6-9]\d{9}", _digits(v)) is not None,
    "ssn": lambda v: re.fullmatch(r"\d{3}-?\d{2}-?\d{4}", str(v)) is not None,
}


def header_kind(column):
    tokens = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", column).lower())
    return next((HEADER_WORDS[t] for t in tokens if t in HEADER_WORDS), None)


def _safe(fn, v):
    try:
        return bool(fn(v))
    except Exception:
        return False


def _out(kind, conf, evidence, **extra):
    return {"kind": kind, "tag": KIND_TAG[kind], "confidence": conf, "evidence": evidence, **extra}


def classify_column_rules(column, values, hi=0.8, lo=0.3):
    """v1 scanner: validators + header keywords."""
    sample = [v for v in values if v is not None][:200]
    hk = header_kind(column)
    best_kind, best_ratio = None, 0.0
    for kind, fn in VALIDATORS.items():
        if not sample:
            break
        ratio = sum(1 for v in sample if _safe(fn, v)) / len(sample)
        if ratio > best_ratio:
            best_kind, best_ratio = kind, ratio
    if best_kind and best_ratio >= hi:
        return _out(best_kind, "high", f"{best_ratio:.0%} pass {best_kind} validator; header={hk}", source="rules")
    if best_kind and best_ratio >= lo:
        return _out(best_kind, "review", f"only {best_ratio:.0%} pass {best_kind} validator; header={hk}", source="rules")
    if hk:  # header-only evidence: tag anyway (fail closed)
        return _out(hk, "medium", f"header token matched {hk}; no validator match", source="rules")
    return None


_ML = {"ok": None}


def ml_available():
    if _ML["ok"] is None:
        try:
            from .ml.model import Classifier
            Classifier.get()
            _ML["ok"] = True
        except Exception as e:  # missing lightgbm or model file -> rules only
            log.warning("ML scanner unavailable (%s); using rules only", e)
            _ML["ok"] = False
    return _ML["ok"]


def classify_column(column, values):
    """Hybrid scanner. Returns {kind, tag, confidence, evidence, source, probs} or None for non-PII columns."""
    if not ml_available():
        return classify_column_rules(column, values)
    from .ml.model import decide
    sample = [v for v in values if v is not None][:200]
    d = decide(column, sample)
    kind = d["kind"]
    if kind in KIND_TAG:
        return _out(kind, d["confidence"], d["evidence"], source=d["source"], probs=d["probs"])
    if kind == "free_text":
        return {"kind": "free_text", "confidence": d["confidence"], "evidence": d["evidence"], "source": d["source"],
                "probs": d["probs"]}
    hk = header_kind(column)  # ML says not PII; a PII header with a non-confident model still masks (fail closed)
    if hk and d["confidence"] != "high":
        return _out(hk, "review", f"header says {hk}; {d['evidence']}", source="header", probs=d["probs"])
    return None


def scan_table(backend, table, sample_size=200):
    from .backends import is_numeric
    entry = {}
    for name, sql_type in backend.columns(table):
        vals = backend.sample(table, name, sample_size)
        entry[name] = {"type": "num" if is_numeric(sql_type) else "text", "sql_type": sql_type,
                       **(classify_column(name, vals) or {})}
    return entry


def scan(backend, tables=None, overrides=None, sample_size=200):
    """Scan every table (or the given ones) and return {table: {column: meta}}. Overrides win over the scanner."""
    registry = {t: scan_table(backend, t, sample_size) for t in (tables or backend.tables())}
    for table, cols in (overrides or {}).items():
        for col, meta in (cols or {}).items():
            if table in registry and col in registry[table]:
                registry[table][col].update(meta, confidence="override", evidence="manual override")
    return registry


def save_registry(registry, path):
    with open(path, "w") as f:
        yaml.safe_dump(registry, f, sort_keys=True)


def load_registry(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}


def summary(registry):
    """Flat list of tagged columns for display."""
    return [{"table": t, "column": c, "tag": m.get("tag"), "kind": m.get("kind"), "source": m.get("source"),
             "confidence": m.get("confidence"), "evidence": m.get("evidence")}
            for t, cols in registry.items() for c, m in cols.items() if m.get("tag")]


class ScanWorker(threading.Thread):
    """Background worker: rescans on an interval and hands the new registry to on_update (e.g. the gateway).
    New tables become queryable only after they've been scanned, so unscanned data stays rejected (fail closed)."""

    def __init__(self, backend, on_update, interval=300, overrides=None):
        super().__init__(daemon=True, name="maskguard-scanner")
        self.backend, self.on_update, self.interval, self.overrides = backend, on_update, interval, overrides
        self.stop_event = threading.Event()
        self.last_run, self.last_error = None, None

    def run_once(self):
        try:
            self.on_update(scan(self.backend, overrides=self.overrides))
            self.last_run, self.last_error = time.time(), None
        except Exception as e:  # keep the old registry; a failed scan must not unmask anything
            self.last_error = repr(e)

    def run(self):
        while not self.stop_event.wait(self.interval):  # the caller already ran the first scan
            self.run_once()

    def stop(self):
        self.stop_event.set()
