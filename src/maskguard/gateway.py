import threading, time
from dataclasses import dataclass, field

from .audit import AuditLog, fingerprint
from .rewriter import Rejected, rewrite


@dataclass
class QueryResult:
    columns: list
    rows: list
    rewritten_sql: str
    masked: list = field(default_factory=list)
    ms: float = 0.0


class Gateway:
    """The only path to the data: authenticate -> rewrite -> execute read-only -> audit."""

    def __init__(self, backend, registry, policy, auth, audit_path):
        self.backend, self.policy, self.auth = backend, policy, auth
        self.audit = AuditLog(audit_path)
        self._registry, self._lock = registry, threading.Lock()

    @property
    def registry(self):
        return self._registry

    def update_registry(self, registry):  # called by the background scanner
        with self._lock:
            self._registry = registry

    def query(self, session, sql):
        t0 = time.perf_counter()
        if not self.auth.valid(session):
            raise PermissionError("not authenticated")
        dialect = self.backend.dialect
        fp = fingerprint(sql, dialect)
        base = dict(user=session.user, role=session.role, sql=fp, backend=dialect)
        try:
            res = rewrite(sql, session.role, self.registry, self.policy, dialect)
        except Rejected as e:
            self.audit.append(**base, decision="reject", reason=str(e)[:160])
            raise
        try:
            cols, rows = self.backend.execute(res.sql)
        except Exception as e:
            self.audit.append(**base, decision="error", reason=type(e).__name__)
            raise
        ms = (time.perf_counter() - t0) * 1000
        self.audit.append(**base, rewritten=fingerprint(res.sql, dialect), masked=res.masked, decision="allow",
                          rows=len(rows), ms=round(ms, 2))
        return QueryResult(cols, rows, res.sql, res.masked, ms)

    def execute(self, session, sql):  # (columns, rows) convenience
        r = self.query(session, sql)
        return r.columns, r.rows
