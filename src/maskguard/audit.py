"""Append-only, hash-chained audit log (JSON lines). Literals and comments are stripped so PII never reaches the log."""
import collections, hashlib, json, os, threading, time
import sqlglot
from sqlglot import exp

GENESIS = "0" * 64


def fingerprint(sql, dialect=None):
    try:
        tree = sqlglot.parse_one(sql, dialect=dialect)
        for hint in list(tree.find_all(exp.Hint)):  # MySQL /*+ ... */ is parsed as a hint, not a comment
            hint.pop()
        tree = tree.transform(lambda n: exp.Placeholder() if isinstance(n, exp.Literal) else n)
        return tree.sql(dialect=dialect, comments=False)  # a comment can carry anything, e.g. an email address
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

    def entries(self):
        if not os.path.exists(self.path):
            return []
        return [json.loads(l) for l in open(self.path) if l.strip()]

    def search(self, user=None, role=None, decision=None, text=None, request_id=None, since=None, limit=100):
        """Newest first. text matches the literal-free SQL fingerprint, reason or table names."""
        out = []
        for e in reversed(self.entries()):
            if since and e.get("ts", 0) < since:
                break
            if (user and e.get("user") != user) or (role and e.get("role") != role) \
                    or (decision and e.get("decision") != decision) or (request_id and e.get("request_id") != request_id):
                continue
            if text and text.lower() not in " ".join(str(e.get(k, "")) for k in ("sql", "reason", "masked", "target")).lower():
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def stats(self, hours=24, now=None):
        """Real activity from the log: per-hour decisions, totals, busiest users, threat alerts."""
        now = now or time.time()
        start = now - hours * 3600
        buckets = [collections.Counter() for _ in range(hours)]
        totals, users, roles, alerts = collections.Counter(), collections.Counter(), collections.Counter(), 0
        ms = []
        for e in self.entries():
            ts = e.get("ts", 0)
            if ts < start:
                continue
            d = e.get("decision", "?")
            buckets[min(hours - 1, int((ts - start) // 3600))][d] += 1
            totals[d] += 1
            users[e.get("user")] += 1
            roles[e.get("role")] += 1
            alerts += e.get("threat_action") in ("alert", "block")
            if e.get("ms") is not None:
                ms.append(e["ms"])
        ms.sort()
        return {"hours": hours, "since": start, "totals": dict(totals),
                "series": [{"hour_start": start + i * 3600, **dict(b)} for i, b in enumerate(buckets)],
                "top_users": users.most_common(5), "by_role": dict(roles), "threat_alerts": alerts,
                "p50_ms": ms[len(ms) // 2] if ms else None}
