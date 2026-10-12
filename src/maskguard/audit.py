import hashlib, json, time
import sqlglot
from sqlglot import exp

def fingerprint(sql, dialect=None):  # strip literals so PII never reaches the log
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
        return tree.transform(lambda n: exp.Placeholder() if isinstance(n, exp.Literal) else n).sql(dialect=dialect)
    except Exception:
        return "<unparseable>"

class AuditLog:
    def __init__(self, path):
        self.path, self.prev = path, "0" * 64

    def append(self, **entry):
        entry.update(ts=time.time(), prev=self.prev)
        entry["hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()
        self.prev = entry["hash"]
        with open(self.path, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

    def verify(self):
        prev = "0" * 64
        for line in open(self.path):
            e = json.loads(line)
            h = e.pop("hash")
            if e["prev"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest() != h:
                return False
            prev = h
        return True
