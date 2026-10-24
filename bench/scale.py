"""Direct vs gateway latency by table size and query shape (p50/p95), after the method of Fotache et al. (IEEE Access,
2023): the same queries with and without masking, several sizes and shapes, environment recorded. Not comparable to
their Oracle/TPC-H numbers; small synthetic tables on one machine.

    MASKGUARD_DB=postgresql://... uv run python bench/scale.py --rows 300,10000,100000 --out docs/eval/perf_pg.json

Each shape returns the same rows directly and through the gateway (explicit LIMITs below every role's row cap).
Two gateway modes: core (rewrite + masking functions + audit write) and full (core + insider-threat scoring).
The seeded tables are dropped and recreated: never point this at a database you care about.
"""
import argparse, json, os, platform, statistics, sys, tempfile, time

os.environ.setdefault("MASKGUARD_HMAC_KEY", "bench-key")
from maskguard import config
from maskguard.dp import PrivacyLedger
from maskguard.seed import make_db

SHAPES = {
    "projection": "SELECT id, email, phone, pan FROM users WHERE id > 10 ORDER BY id LIMIT 100",
    "filter":     "SELECT * FROM users WHERE city = 'Pune' LIMIT 50",
    "join":       "SELECT a.credit_card, u.email FROM accounts a JOIN users u ON u.id = a.user_id ORDER BY a.id LIMIT 50",
    "cte":        "WITH c AS (SELECT id, email, ssn FROM users) SELECT * FROM c ORDER BY id LIMIT 50",
    "aggregate":  "SELECT status, count(*) FROM accounts GROUP BY status",
    "point":      "SELECT name, email FROM users WHERE id = 42",
}


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def timed(fn, n):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1000)
    return out


def run(db, rows, n, roles, tmp):
    app = config.build(config.Settings(db=db, audit=f"{tmp}/audit-{rows}.jsonl", registry_out=f"{tmp}/reg.yaml",
                                       seed_if_empty=False))
    t0 = time.perf_counter()
    make_db(app.backend, n=rows)
    seed_s = time.perf_counter() - t0
    from maskguard.scanner import scan
    t0 = time.perf_counter()
    app.gateway.update_registry(scan(app.backend, overrides=config.load_overrides(app.settings)))
    scan_s = time.perf_counter() - t0
    gw = app.gateway
    gw.dp_ledger = PrivacyLedger(1e12)
    threat = gw.threat
    res = {"rows_per_table": rows, "seed_seconds": round(seed_s, 1), "scan_seconds": round(scan_s, 2), "shapes": {}}
    for name, sql in SHAPES.items():
        app.backend.execute(sql)  # warm the cache once; every number below is a warm run
        direct = timed(lambda: app.backend.execute(sql), n)
        entry = {"direct": {"p50": round(statistics.median(direct), 2), "p95": round(pct(direct, .95), 2)}}
        for role in roles:
            s = app.auth.login(*config.DEMO_ACCOUNTS[role])
            for mode in ("core", "full"):
                gw.threat = threat if mode == "full" else None
                if threat:
                    threat.alert = threat.block = 1000  # score every query, never block the benchmark loop
                gw.query(s, sql, observe=mode == "full")
                g = timed(lambda: gw.query(s, sql, observe=mode == "full"), n)
                entry[f"{role}_{mode}"] = {"p50": round(statistics.median(g), 2), "p95": round(pct(g, .95), 2),
                                           "overhead_p50": round(statistics.median(g) - statistics.median(direct), 2)}
        res["shapes"][name] = entry
        print(f"{rows:>7} {name:10} direct p50 {entry['direct']['p50']:7.2f}  " + "  ".join(
            f"{k} {v['p50']:7.2f}/{v['p95']:7.2f}" for k, v in entry.items() if k != "direct"), flush=True)
    gw.threat = threat
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", default="300,10000")
    ap.add_argument("-n", type=int, default=50, help="timed runs per shape and mode")
    ap.add_argument("--roles", default="analyst,support")
    ap.add_argument("--out")
    args = ap.parse_args()
    tmp = tempfile.mkdtemp()
    db = os.environ.get("MASKGUARD_DB", f"sqlite:///{tmp}/scale.db")
    report = {"environment": {"backend": db.split(":")[0], "machine": platform.machine(), "os": platform.system(),
                              "python": platform.python_version(), "cpus": os.cpu_count(),
                              "timed_runs_per_cell": args.n, "cache": "warm", "units": "ms"},
              "shapes": SHAPES, "results": []}
    for rows in [int(x) for x in args.rows.split(",")]:
        report["results"].append(run(db, rows, args.n, args.roles.split(","), tmp))
    if args.out:
        json.dump(report, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    sys.exit(main())
