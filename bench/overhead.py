"""Median/p95 gateway overhead vs. running the same SQL directly. Run: uv run python bench/overhead.py"""
import os, pathlib, platform, sqlite3, statistics, sys, tempfile, time
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
os.environ.setdefault("MASKGUARD_HMAC_KEY", "bench-key")
from maskguard import masks
from maskguard.gateway import Authenticator, Gateway
from maskguard.scanner import scan_sqlite
from seed.make_data import make_db

QUERIES = ["SELECT * FROM users WHERE city = 'Pune'",
           "SELECT a.credit_card, u.email FROM accounts a JOIN users u ON u.id = a.user_id LIMIT 50",
           "WITH c AS (SELECT email, ssn FROM users) SELECT * FROM c LIMIT 50",
           "SELECT status, count(*), avg(balance) FROM accounts GROUP BY status"]

def pct(xs, p):
    return sorted(xs)[min(len(xs) - 1, int(len(xs) * p))]

def main(n=200):
    conn = sqlite3.connect(":memory:")
    masks.register_sqlite(conn)
    make_db(conn)
    registry = {t: scan_sqlite(conn, t) for t in ("users", "accounts")}
    policy = yaml.safe_load((ROOT / "policies" / "default.yaml").read_text())
    auth = Authenticator({"ali": ("pw", "analyst")})
    gw = Gateway(conn, registry, policy, auth, os.path.join(tempfile.mkdtemp(), "audit.jsonl"))
    s = auth.login("ali", "pw")
    direct, gated = [], []
    for _ in range(n):
        for q in QUERIES:
            t = time.perf_counter(); conn.execute(q).fetchall(); direct.append(time.perf_counter() - t)
            t = time.perf_counter(); gw.execute(s, q); gated.append(time.perf_counter() - t)
    ms = lambda x: f"{x * 1000:.2f} ms"
    print(f"machine: {platform.processor() or platform.machine()} / {platform.system()} / Python {platform.python_version()}")
    print(f"queries: {len(gated)} ({len(QUERIES)} shapes x {n}), role=analyst, 300 users + 300 accounts")
    print(f"direct  p50 {ms(statistics.median(direct))}  p95 {ms(pct(direct, .95))}")
    print(f"gateway p50 {ms(statistics.median(gated))}  p95 {ms(pct(gated, .95))}")
    print(f"overhead p50 {ms(statistics.median(gated) - statistics.median(direct))}")

if __name__ == "__main__":
    main()
