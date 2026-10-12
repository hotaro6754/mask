"""Python SDK for the MaskGuard REST API (standard library only).

    from maskguard.client import MaskGuardClient
    mg = MaskGuardClient("http://localhost:8000", "support.sam", "support123")
    rows = mg.query("SELECT name, ssn FROM users LIMIT 5")          # list of dicts, already masked for the role
    df = mg.query_df("SELECT status, avg(balance) FROM accounts GROUP BY status")   # pandas, if installed
"""
import json
import urllib.error
import urllib.request


class MaskGuardError(Exception):
    def __init__(self, status, detail):
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class MaskGuardClient:
    def __init__(self, base_url, username, password, timeout=30):
        self.base_url, self.timeout = base_url.rstrip("/"), timeout
        r = self._call("POST", "/auth/login", {"username": username, "password": password}, auth=False)
        self.token, self.role = r["token"], r["role"]

    def _call(self, method, path, body=None, auth=True):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        if auth:
            req.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                detail = json.loads(e.read()).get("detail")
            except Exception:
                detail = e.reason
            raise MaskGuardError(e.code, detail) from None

    def query_raw(self, sql):
        """Full response: columns, rows, masked columns, rewritten SQL, timing, privacy budget."""
        return self._call("POST", "/query", {"sql": sql})

    def query(self, sql):
        r = self.query_raw(sql)
        return [dict(zip(r["columns"], row)) for row in r["rows"]]

    def query_df(self, sql):
        import pandas as pd
        r = self.query_raw(sql)
        return pd.DataFrame(r["rows"], columns=r["columns"])

    def me(self):
        return self._call("GET", "/me")

    def attacks(self):
        return self._call("GET", "/attacks")

    # admin
    def registry(self):
        return self._call("GET", "/registry")["tagged"]

    def rescan(self):
        return self._call("POST", "/scan")["tagged"]

    def integrity(self):
        return self._call("GET", "/integrity")

    def audit(self, n=20):
        return self._call("GET", f"/audit?n={int(n)}")

    def threats(self):
        return self._call("GET", "/threats")["users"]

    def pia(self, days=30):
        return self._call("GET", f"/pia?days={int(days)}")

    def unblock(self, user):
        return self._call("POST", f"/threats/{user}/unblock")
