import threading, time
from dataclasses import dataclass, field

from .audit import AuditLog, fingerprint
from .rewriter import Rejected, rewrite
from .threat import Event, ThreatEngine
from .dp import BudgetExceeded, PrivacyLedger, apply_noise


@dataclass
class QueryResult:
    columns: list
    rows: list
    rewritten_sql: str
    masked: list = field(default_factory=list)
    ms: float = 0.0
    risk: int = 0
    dp: dict = None  # {"epsilon": spent, "remaining": budget left today} when noise was added


class Gateway:
    """The only path to the data: authenticate -> rewrite -> execute read-only -> audit."""

    def __init__(self, backend, registry, policy, auth, audit_path):
        self.backend, self.policy, self.auth = backend, policy, auth
        self.audit = AuditLog(audit_path)
        self._registry, self._lock = registry, threading.Lock()
        self.threat = ThreatEngine.from_policy(policy)
        self.dp_ledger = PrivacyLedger.from_policy(policy)

    @property
    def registry(self):
        return self._registry

    def update_registry(self, registry):  # called by the background scanner
        with self._lock:
            self._registry = registry

    def _assess(self, session, decision, fp, rows=0, shape=None, now=None, observe=True):
        if self.threat is None or not observe:
            return None
        return self.threat.observe(session.user, Event(now or time.time(), decision, fp, rows, shape or {}))

    def query(self, session, sql, now=None, observe=True):
        t0 = time.perf_counter()
        if not self.auth.valid(session):
            raise PermissionError("not authenticated")
        dialect = self.backend.dialect
        fp = fingerprint(sql, dialect)
        base = dict(user=session.user, role=session.role, sql=fp, backend=dialect)
        if observe and self.threat is not None and self.threat.is_blocked(session.user, now):
            self.audit.append(**base, decision="blocked", reason="session blocked by threat engine")
            raise Rejected("session blocked by the threat engine; ask an admin to review the alert")
        try:
            res = rewrite(sql, session.role, self.registry, self.policy, dialect, self.backend.default_schema)
        except Rejected as e:
            a = self._assess(session, "reject", fp, now=now, observe=observe)
            self.audit.append(**base, decision="reject", reason=str(e)[:160], **self._risk_fields(a))
            raise
        dp_info = None
        if res.dp:
            try:  # charge the budget before touching the data
                remaining = self.dp_ledger.spend(session.user, res.dp["cost"], now)
            except BudgetExceeded as e:
                self.audit.append(**base, decision="reject", reason=str(e)[:160])
                raise Rejected(str(e)) from None
            dp_info = {"epsilon": res.dp["cost"], "remaining": remaining, "columns": res.dp["columns"]}
        try:
            cols, rows = self.backend.execute(res.sql)
            if res.dp:
                cols, rows = apply_noise(cols, rows, res.dp)
        except Exception as e:
            a = self._assess(session, "reject", fp, shape=res.shape, now=now, observe=observe)
            self.audit.append(**base, decision="error", reason=type(e).__name__, **self._risk_fields(a))
            raise
        a = self._assess(session, "allow", fp, len(rows), res.shape, now=now, observe=observe)
        ms = (time.perf_counter() - t0) * 1000
        self.audit.append(**base, rewritten=fingerprint(res.sql, dialect), masked=res.masked, decision="allow",
                          rows=len(rows), ms=round(ms, 2), **self._risk_fields(a),
                          **({"dp_epsilon": dp_info["epsilon"], "dp_remaining": dp_info["remaining"]} if dp_info else {}))
        if a is not None and a.action == "block":  # withhold this result too: the session is now blocked
            raise Rejected("session blocked by the threat engine: " + "; ".join(a.reasons)[:200])
        return QueryResult(cols, rows, res.sql, res.masked, ms, a.risk if a else 0, dp_info)

    @staticmethod
    def _risk_fields(a):
        return {} if a is None else {"risk": a.risk, "threat_action": a.action, "threat_reasons": a.reasons}

    def execute(self, session, sql, now=None, observe=True):  # (columns, rows) convenience
        r = self.query(session, sql, now, observe)
        return r.columns, r.rows
