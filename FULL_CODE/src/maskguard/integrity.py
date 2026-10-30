"""Source-data integrity: prove that masking never changes the stored records.

snapshot() reads every table through the privileged (non-gateway) connection and records, per table:
  * schema fingerprint  - SHA-256 over the ordered (column, type) list
  * row count
  * content digest      - SHA-256 over the sorted canonical-JSON encoding of every row (row order independent)
verify() recomputes these and compares them with a stored baseline.

What it covers: values, row counts and schemas of the source tables. What it does not cover: MaskGuard's own files
(audit log, policy history, registry), which change by design and have their own checks (the audit hash chain,
policy versions). A digest change means the data changed, not necessarily that someone tampered with it:
legitimate application writes between baseline and verification also change it. Take the baseline when the data is
known to be quiet (e.g. right after seeding), or treat a mismatch as "investigate", not "attack". Each check reads
whole tables, so it is meant for demos and audits, not for every query on large databases.
"""

import datetime
import decimal
import hashlib
import json
import os
import time
from pathlib import Path

from .audit import read_entries
from .rewriter import Rejected


def _canon(v):
    if v is None or isinstance(v, (bool, int, str)):
        return v
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, decimal.Decimal):
        return format(v.normalize(), "f")
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    return str(v)


def table_state(backend, table):
    cols = backend.columns(table)
    schema = hashlib.sha256(json.dumps(cols).encode()).hexdigest()
    _names, rows = backend.admin_query(f"SELECT * FROM {backend._qualified(table)}")  # noqa: S608 (identifiers via quote_ident)
    lines = sorted(json.dumps([_canon(v) for v in r], ensure_ascii=False, separators=(",", ":")) for r in rows)
    h = hashlib.sha256()
    for line in lines:
        h.update(line.encode())
        h.update(b"\n")
    return {"rows": len(rows), "columns": len(cols), "schema_sha256": schema, "content_sha256": h.hexdigest()}


def snapshot(backend):
    tables = {t: table_state(backend, t) for t in backend.tables()}
    combined = hashlib.sha256(json.dumps(tables, sort_keys=True).encode()).hexdigest()
    return {
        "taken_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "ts": time.time(),
        "backend": backend.dialect,
        "tables": tables,
        "combined_sha256": combined,
    }


def compare(baseline, current):
    """MATCH if every baselined table is unchanged; otherwise CHANGED with the reason per table."""
    rows, changed = [], False
    for t in sorted(set(baseline["tables"]) | set(current["tables"])):
        b, c = baseline["tables"].get(t), current["tables"].get(t)
        if b is None:
            rows.append({"table": t, "status": "ADDED", "rows_before": None, "rows_after": c["rows"]})
            changed = True
            continue
        if c is None:
            rows.append({"table": t, "status": "REMOVED", "rows_before": b["rows"], "rows_after": None})
            changed = True
            continue
        why = [
            k
            for k, label in (("schema_sha256", "schema"), ("rows", "row count"), ("content_sha256", "content"))
            if b[k] != c[k]
        ]
        status = "MATCH" if not why else "CHANGED"
        changed |= bool(why)
        rows.append(
            {
                "table": t,
                "status": status,
                "rows_before": b["rows"],
                "rows_after": c["rows"],
                "schema_changed": b["schema_sha256"] != c["schema_sha256"],
                "content_changed": b["content_sha256"] != c["content_sha256"],
                "digest_before": b["content_sha256"],
                "digest_after": c["content_sha256"],
            }
        )
    return {
        "status": "CHANGED" if changed else "MATCH",
        "tables": rows,
        "baseline_taken_at": baseline["taken_at"],
        "verified_at": current["taken_at"],
        "combined_before": baseline["combined_sha256"],
        "combined_after": current["combined_sha256"],
    }


def _db_id(url):
    """Identify the database without storing credentials: scheme + host/path, hashed."""
    safe = url.split("@")[-1] if "@" in url else url
    return hashlib.sha256(safe.encode()).hexdigest()[:16]


class IntegrityStore:
    """Baseline file + verification history (JSON lines). A baseline belongs to one database (db_id)."""

    def __init__(self, backend, db_url, baseline_path, history_path):
        self.backend, self.db_id = backend, _db_id(db_url)
        self.baseline_path, self.history_path = baseline_path, history_path

    def baseline(self):
        if not self.baseline_path or not os.path.exists(self.baseline_path):
            return None
        b = json.loads(Path(self.baseline_path).read_text(encoding="utf-8"))
        return b if b.get("db_id") == self.db_id else None

    def record_baseline(self, actor="system", reason=""):
        snap = snapshot(self.backend)
        snap.update(db_id=self.db_id, recorded_by=actor, reason=reason)
        if self.baseline_path:
            os.makedirs(os.path.dirname(self.baseline_path) or ".", exist_ok=True)
            Path(self.baseline_path).write_text(json.dumps(snap, indent=2), encoding="utf-8")
        return snap

    def ensure_baseline(self):
        return self.baseline() or self.record_baseline("system", "initial baseline at startup")

    def verify(self, actor="system"):
        base = self.baseline()
        if base is None:
            return {"status": "NO_BASELINE", "tables": [], "message": "record a baseline first"}
        result = compare(base, snapshot(self.backend))
        self._history(
            {
                "ts": time.time(),
                "actor": actor,
                "status": result["status"],
                "verified_at": result["verified_at"],
                "combined_after": result["combined_after"],
                "changed": [t["table"] for t in result["tables"] if t["status"] != "MATCH"],
            }
        )
        return result

    def history(self, n=20):
        if not self.history_path or not os.path.exists(self.history_path):
            return []
        return read_entries(self.history_path)[-n:]

    def _history(self, entry):
        if self.history_path:
            os.makedirs(os.path.dirname(self.history_path) or ".", exist_ok=True)
            with open(self.history_path, "a") as f:
                f.write(json.dumps(entry) + "\n")


UNAUTHORIZED = [
    ("UPDATE through the gateway", "UPDATE users SET name = 'x'"),
    ("DELETE through the gateway", "DELETE FROM accounts"),
    ("DROP TABLE", "DROP TABLE support_tickets"),
    ("Stacked write after a SELECT", "SELECT 1; UPDATE accounts SET balance = 0"),
    ("INSERT ... SELECT", "INSERT INTO users (id) SELECT 999999"),
    ("SELECT INTO a new table", "SELECT * INTO stolen FROM users"),
]


def proof(app, sql="SELECT * FROM users ORDER BY id LIMIT 5", sessions=None, actor="system"):
    """Reproducible immutability proof: digest -> same query as every role -> write attempts -> digest again.

    sessions: {role: Session}; defaults to the demo identities (only when demo mode is on)."""
    from . import config

    before = snapshot(app.backend)
    if sessions is None:
        sessions = {r: app.auth.login(u, p) for r, (u, p) in config.demo_accounts().items()}
    queries = []
    for role, s in sessions.items():
        try:
            r = app.gateway.query(s, sql, observe=False)
            queries.append(
                {
                    "role": role,
                    "status": "ALLOWED",
                    "rows": len(r.rows),
                    "masked": len(r.masked),
                    "request_id": r.request_id,
                }
            )
        except Rejected as e:
            queries.append({"role": role, "status": "REJECTED", "reason": str(e)[:120]})
    attempts = []
    probe = next(iter(sessions.values()), None)
    for name, bad in UNAUTHORIZED if probe else []:
        try:
            app.gateway.query(probe, bad, observe=False)
            attempts.append({"attempt": name, "status": "EXECUTED"})  # would be a defect: the proof then fails
        except Rejected as e:
            attempts.append({"attempt": name, "status": "REJECTED", "reason": str(e)[:120]})
        except Exception as e:  # noqa: BLE001 (any failed write attempt is a result of the integrity proof, reported by type)
            attempts.append({"attempt": name, "status": "FAILED", "reason": type(e).__name__})
    after = snapshot(app.backend)
    cmp = compare(before, after)
    ok = cmp["status"] == "MATCH" and all(a["status"] != "EXECUTED" for a in attempts)
    return {
        "status": "PASS" if ok else "FAIL",
        "sql": sql,
        "queries": queries,
        "unauthorized_attempts": attempts,
        "before": before["combined_sha256"],
        "after": after["combined_sha256"],
        "tables": cmp["tables"],
        "actor": actor,
        "at": after["taken_at"],
    }
