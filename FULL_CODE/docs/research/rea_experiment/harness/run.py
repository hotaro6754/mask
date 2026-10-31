"""Run every scenario on both systems and write evidence JSON. Usage: uv run python -I run.py <out.json>"""

import datetime
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
EXP = os.path.dirname(HERE)
STATE = os.path.join(EXP, "mg-state")
os.makedirs(STATE, exist_ok=True)

os.environ.update(
    {
        "MASKGUARD_DB": "postgresql://postgres@127.0.0.1:5433/rea_fixture",
        "MASKGUARD_POLICY": "/home/user/mask/policies/default.yaml",
        "MASKGUARD_USERS": "/home/user/mask/policies/users.demo.yaml",
        "MASKGUARD_OVERRIDES": os.path.join(EXP, "fixture", "maskguard_overrides.yaml"),
        "MASKGUARD_REGISTRY": os.path.join(STATE, "registry.yaml"),
        "MASKGUARD_AUDIT": os.path.join(STATE, "audit.jsonl"),
        "MASKGUARD_STATE_DIR": STATE,
        "MASKGUARD_SEED_IF_EMPTY": "0",
        "MASKGUARD_DEMO": "1",
        "MASKGUARD_HMAC_KEY": "rea-experiment-local-hmac-key",
        "MASKGUARD_JWT_SECRET": "rea-experiment-local-jwt-secret-0123456789",
    }
)

import psycopg  # noqa: E402
from scenarios import S  # noqa: E402

from maskguard import config  # noqa: E402
from maskguard.gateway import Rejected, safe_error  # noqa: E402

ANON = "host=127.0.0.1 port=5441 dbname=rea user={u} password=rea-local-only"
MGDB = "host=127.0.0.1 port=5433 dbname=rea_fixture user=postgres"
DIGEST = (
    "SELECT (SELECT md5(string_agg(t::text, '|' ORDER BY id)) FROM customers t), "
    "(SELECT md5(string_agg(t::text, '|' ORDER BY id)) FROM accounts t), "
    "(SELECT count(*) FROM accounts)"
)


def jsonable(v):
    return v if isinstance(v, (int, str, type(None), bool)) else str(v)


def digest(dsn):
    with psycopg.connect(dsn) as c:
        return list(c.execute(DIGEST).fetchone())


def run_anon(sc):
    stmts = sc["anon_sql"] if isinstance(sc["anon_sql"], list) else [sc["anon_sql"]]
    notices, rows, cols, err = [], None, None, None
    with psycopg.connect(ANON.format(u="support_m"), autocommit=True) as c:
        c.add_notice_handler(lambda d: notices.append(d.message_primary))
        try:
            for q in stmts:
                if q.startswith("COPY"):
                    with c.cursor() as cur, cur.copy(q) as cp:
                        rows = [[bytes(b).decode()] for b in cp]
                    continue
                cur = c.execute(q)
                if cur.description:
                    cols = [d.name for d in cur.description]
                    rows = [[jsonable(v) for v in r] for r in cur.fetchall()]
        except Exception as e:
            err = f"{type(e).__name__}: {str(e).strip().splitlines()[0][:300]}"
    return {"columns": cols, "rows": rows, "error": err, "notices": notices}


def run_mg(app, session, sc):
    try:
        r = app.gateway.query(session, sc["sql"], observe=False, channel="engine")
        return {
            "columns": r.columns,
            "rows": [[jsonable(v) for v in row] for row in r.rows],
            "error": None,
            "notices": [],
            "masked": r.masked,
            "rewritten_sql": r.rewritten_sql,
        }
    except Rejected as e:
        return {"columns": None, "rows": None, "error": f"Rejected: {e}", "notices": []}
    except Exception as e:
        return {"columns": None, "rows": None, "error": f"{type(e).__name__}: {safe_error(e)}", "notices": []}


def main(out):
    app = config.build()
    session = app.auth.login(*config.demo_accounts()["support"])
    before = {"target": digest(ANON.format(u="postgres")), "maskguard": digest(MGDB)}
    results = []
    for sc in S:
        rec = {k: sc[k] for k in ("id", "cat", "title", "sql", "expect")}
        if sc["anon_sql"] != sc["sql"]:
            rec["anon_sql"] = sc["anon_sql"]
        for name, fn in (("target", lambda sc=sc: run_anon(sc)), ("maskguard", lambda sc=sc: run_mg(app, session, sc))):
            t0 = time.perf_counter()
            r = fn()
            r["ms"] = round((time.perf_counter() - t0) * 1000, 1)
            r["leak"] = bool(sc["leak"](r["rows"], r["error"], r["notices"]))
            rec[name] = r
        results.append(rec)
        print(
            f"{sc['id']} target={'LEAK' if rec['target']['leak'] else 'ok  '} "
            f"maskguard={'LEAK' if rec['maskguard']['leak'] else 'ok  '}  {sc['title']}"
        )
    after = {"target": digest(ANON.format(u="postgres")), "maskguard": digest(MGDB)}
    doc = {
        "run_at": datetime.datetime.now(datetime.UTC).isoformat(timespec="seconds"),
        "target": "PostgreSQL Anonymizer 3.2.3 on PostgreSQL 16.15, role support_m (MASKED + RLS)",
        "maskguard": "MaskGuard (branch claude/zealous-bell-me62fn) on PostgreSQL 16, role support, "
        f"policy {app.gateway.query(session, 'SELECT 1 AS one', observe=False).policy_version}; "
        "threat engine not consulted (observe=False) so masking is measured alone",
        "digest_before": before,
        "digest_after": after,
        "data_unchanged": before == after,
        "results": results,
    }
    with open(out, "w") as f:
        json.dump(doc, f, indent=1)
    print("data unchanged:", before == after, before, after)


if __name__ == "__main__":
    main(sys.argv[1])
