"""Append-only, hash-chained audit log (JSON lines). Literals are stripped so PII never reaches the log."""
import hashlib, json, os, threading, time
import sqlglot
from sqlglot import exp

GENESIS = "0" * 64


def fingerprint(sql, dialect=None):
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
        return tree.transform(lambda n: exp.Placeholder() if isinstance(n, exp.Literal) else n).sql(dialect=dialect)
    except Exception:
        return "<unparseable>"


def _digest(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path):
        self.path, self.prev, self.lock = path, GENESIS, threading.Lock()
        if os.path.exists(path):  # continue the existing chain after a restart
            for line in open(path):
                if line.strip():
                    self.prev = json.loads(line)["hash"]

    def append(self, **entry):
        with self.lock:
            entry.update(ts=time.time(), prev=self.prev)
            entry["hash"] = _digest(entry)
            self.prev = entry["hash"]
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")

    def verify(self):
        """True if no entry was edited, removed or reordered."""
        if not os.path.exists(self.path):
            return True
        prev = GENESIS
        for line in open(self.path):
            if not line.strip():
                continue
            e = json.loads(line)
            h = e.pop("hash")
            if e.get("prev") != prev or _digest(e) != h:
                return False
            prev = h
        return True

    def tail(self, n=20):
        if not os.path.exists(self.path):
            return []
        lines = [l for l in open(self.path) if l.strip()]
        return [json.loads(l) for l in lines[-n:]]
