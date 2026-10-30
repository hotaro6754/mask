"""Append-only, hash-chained audit log (JSON lines). Literals and comments are stripped so PII never reaches the log."""

import collections
import hashlib
import json
import os
import threading
import time

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
    except Exception:  # noqa: BLE001 (a fingerprint must never fail the audit write; unparseable SQL is logged as such)
        return "<unparseable>"


def _owner_only(path):
    try:
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o600)
    except OSError:  # not ours to change (e.g. a read-only mount): keep going, the chain still verifies
        pass


def _digest(entry):
    return hashlib.sha256(json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest()


def read_entries(path):
    """Every entry of an audit log file, oldest first."""
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class AuditLog:
    """The chain shows edits, deletions and reordering. Someone who can rewrite the whole file can also recompute every
    hash, so copy head() somewhere they can't write (a ticket, another server) and check it later with verify(anchor)."""

    def __init__(self, path):
        self.path, self.prev, self.count, self.lock = path, GENESIS, 0, threading.Lock()
        if os.path.exists(path):  # continue the existing chain after a restart
            _owner_only(path)
            existing = read_entries(path)
            self.count = len(existing)
            self.prev = existing[-1]["hash"] if existing else GENESIS

    def append(self, **entry):
        with self.lock:
            entry.update(ts=time.time(), prev=self.prev)
            entry["hash"] = _digest(entry)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)  # owner-only from the first line
            with os.fdopen(fd, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
            # only a written entry moves the chain: after a failed write (disk full) the next entry links to the
            # last one on disk, so verify() still passes; the caller's error withholds the query's result
            self.prev, self.count = entry["hash"], self.count + 1

    def head(self):
        """{entries, head}: the hash of the newest entry. Record it outside this machine to anchor the chain."""
        with self.lock:
            return {"entries": self.count, "head": self.prev}

    def verify(self, anchor=None):
        """True if no entry was edited, removed or reordered, and (given an anchor recorded earlier) that entry is
        still in the chain: a rewritten file has different hashes, even if they were all recomputed."""
        if not os.path.exists(self.path):
            return anchor in (None, GENESIS)
        prev, seen = GENESIS, anchor in (None, GENESIS)
        for e in read_entries(self.path):
            h = e.pop("hash")
            if e.get("prev") != prev or _digest(e) != h:
                return False
            prev, seen = h, seen or h == anchor
        return seen

    def tail(self, n=20):
        if not os.path.exists(self.path):
            return []
        return read_entries(self.path)[-n:]

    def entries(self):
        if not os.path.exists(self.path):
            return []
        return read_entries(self.path)

    def search(self, user=None, role=None, decision=None, text=None, request_id=None, since=None, limit=100):
        """Newest first. text matches the literal-free SQL fingerprint, reason or table names."""
        out = []
        for e in reversed(self.entries()):
            if since and e.get("ts", 0) < since:
                break
            if (
                (user and e.get("user") != user)
                or (role and e.get("role") != role)
                or (decision and e.get("decision") != decision)
                or (request_id and e.get("request_id") != request_id)
            ):
                continue
            if (
                text
                and text.lower()
                not in " ".join(str(e.get(k, "")) for k in ("sql", "reason", "masked", "target")).lower()
            ):
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
        return {
            "hours": hours,
            "since": start,
            "totals": dict(totals),
            "series": [{"hour_start": start + i * 3600, **dict(b)} for i, b in enumerate(buckets)],
            "top_users": users.most_common(5),
            "by_role": dict(roles),
            "threat_alerts": alerts,
            "p50_ms": ms[len(ms) // 2] if ms else None,
        }
