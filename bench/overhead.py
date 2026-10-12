"""Gateway overhead vs. running the same SQL directly.  Run: make bench   (uses MASKGUARD_DB, default SQLite)"""
import os, platform, statistics, sys, tempfile, time

os.environ.setdefault("MASKGUARD_HMAC_KEY", "bench-key")
from maskguard import config

QUERIES = ["SELECT * FROM users WHERE city = 'Pune'",
           "SELECT a.credit_card, u.email FROM accounts a JOIN users u ON u.id = a.user_id LIMIT 50",
           "WITH c AS (SELECT email, ssn FROM users) SELECT * FROM c LIMIT 50",
           "SELECT status, count(*), avg(balance) FROM accounts GROUP BY status"]


def pct(xs, p):
    return sorted(xs)[min(len(xs) - 1, int(len(xs) * p))]


def main(n=200):
    tmp = tempfile.mkdtemp()
    db = os.environ.get("MASKGUARD_DB", f"sqlite:///{tmp}/bench.db")
    app = config.build(config.Settings(db=db, audit=f"{tmp}/audit.jsonl", registry_out=f"{tmp}/reg.yaml"))
    s = app.auth.login(*config.DEMO_ACCOUNTS["analyst"])
    direct, gated = [], []
    for _ in range(n):
        for q in QUERIES:
            t = time.perf_counter(); app.backend.execute(q); direct.append(time.perf_counter() - t)
            t = time.perf_counter(); app.gateway.query(s, q); gated.append(time.perf_counter() - t)
    ms = lambda x: f"{x * 1000:.2f} ms"
    print(f"backend: {app.backend.dialect} · machine: {platform.machine()} {platform.system()} · Python "
          f"{platform.python_version()} · {os.cpu_count()} CPUs")
    print(f"queries: {len(gated)} ({len(QUERIES)} shapes x {n}), role=analyst, 300 rows per table")
    print(f"direct   p50 {ms(statistics.median(direct))}  p95 {ms(pct(direct, .95))}")
    print(f"gateway  p50 {ms(statistics.median(gated))}  p95 {ms(pct(gated, .95))}")
    print(f"overhead p50 {ms(statistics.median(gated) - statistics.median(direct))} "
          "(parse + rewrite + masking functions + audit write)")


if __name__ == "__main__":
    sys.exit(main())
