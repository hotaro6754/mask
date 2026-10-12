import hmac as _hmac
from dataclasses import dataclass
from .audit import AuditLog, fingerprint
from .rewriter import Rejected, rewrite

@dataclass(frozen=True)
class Session:
    user: str
    role: str
    _minted_by: object = None

class Authenticator:
    """Demo auth. Swap in real login/JWT verification; the point is the role never comes from the SQL."""
    def __init__(self, users):  # {"sam": ("pw", "support")}
        self._users, self._token = users, object()

    def login(self, user, password):
        rec = self._users.get(user)
        if not rec or not _hmac.compare_digest(rec[0], password):
            raise PermissionError("bad credentials")
        return Session(user, rec[1], self._token)

    def valid(self, s):
        return isinstance(s, Session) and s._minted_by is self._token

class Gateway:
    def __init__(self, conn, registry, policy, auth, audit_path, dialect="sqlite"):
        self.conn, self.registry, self.policy, self.auth, self.dialect = conn, registry, policy, auth, dialect
        self.audit = AuditLog(audit_path)

    def execute(self, session, sql):
        if not self.auth.valid(session):
            raise PermissionError("not authenticated")
        fp = fingerprint(sql, self.dialect)
        try:
            res = rewrite(sql, session.role, self.registry, self.policy, self.dialect)
        except Rejected as e:
            self.audit.append(user=session.user, role=session.role, sql=fp, decision="reject", reason=str(e)[:120])
            raise
        cur = self.conn.execute(res.sql)
        rows, cols = cur.fetchall(), [d[0] for d in cur.description]
        self.audit.append(user=session.user, role=session.role, sql=fp, rewritten=fingerprint(res.sql, self.dialect),
                          masked=res.masked, decision="allow", rows=len(rows))
        return cols, rows
