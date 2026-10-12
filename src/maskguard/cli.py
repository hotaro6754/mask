"""maskguard CLI.

  maskguard seed                         create demo tables (users, accounts, support_tickets)
  maskguard scan [--watch SECONDS]       tag PII columns; --watch keeps rescanning in the background
  maskguard query -u USER "SQL"          run SQL through the gateway (password prompted or -p)
  maskguard roles "SQL"                  same query as every demo role, side by side
  maskguard attack -u USER               attack suite: naive masking vs MaskGuard
  maskguard integrity                    SHA-256 per table, to show the data is untouched
  maskguard audit [--verify]             tail / verify the hash-chained audit log
  maskguard serve [--port 8000]          REST API
  maskguard dashboard [--port 8501]      Streamlit dashboard
  maskguard hash-password                hash a password for the users file
  maskguard train-scanner                retrain the LightGBM PII column classifier (synthetic data only)
  maskguard classify COLUMN V1 V2 ...    classify one column from sample values
Settings come from MASKGUARD_* environment variables (see README).
"""
import argparse, getpass, sys, time

from . import config
from .attacks import run_suite, score
from .auth import hash_password
from .rewriter import Rejected
from .scanner import save_registry, scan, summary
from .seed import make_db

def _table(cols, rows, limit=15):
    rows = [[("NULL" if v is None else str(v)) for v in r] for r in rows[:limit]]
    widths = [min(32, max([len(c)] + [len(r[i]) for r in rows])) for i, c in enumerate(cols)]
    line = lambda vals: " | ".join(v[:w].ljust(w) for v, w in zip(vals, widths))
    out = [line(cols), "-+-".join("-" * w for w in widths)] + [line(r) for r in rows]
    return "\n".join(out)


def _login(app, user, password):
    return app.auth.login(user, password if password is not None else getpass.getpass(f"password for {user}: "))


def main(argv=None):
    p = argparse.ArgumentParser(prog="maskguard", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed")
    sc = sub.add_parser("scan"); sc.add_argument("--watch", type=int, default=0)
    q = sub.add_parser("query"); q.add_argument("-u", "--user", required=True); q.add_argument("-p", "--password")
    q.add_argument("sql")
    r = sub.add_parser("roles"); r.add_argument("sql")
    a = sub.add_parser("attack"); a.add_argument("-u", "--user", required=True); a.add_argument("-p", "--password")
    sub.add_parser("integrity")
    au = sub.add_parser("audit"); au.add_argument("--verify", action="store_true"); au.add_argument("-n", type=int, default=10)
    s = sub.add_parser("serve"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000)
    sub.add_parser("hash-password")
    d = sub.add_parser("dashboard"); d.add_argument("--port", type=int, default=8501)
    tr = sub.add_parser("train-scanner"); tr.add_argument("--per-kind", type=int, default=300)
    tr.add_argument("--seed", type=int, default=7)
    cl = sub.add_parser("classify"); cl.add_argument("column"); cl.add_argument("values", nargs="+")
    args = p.parse_args(argv)

    if args.cmd == "hash-password":
        pw = getpass.getpass("password: ")
        print(hash_password(pw))
        return 0
    if args.cmd == "serve":
        import uvicorn
        uvicorn.run("maskguard.api:app", host=args.host, port=args.port)
        return 0

    if args.cmd == "train-scanner":
        from .ml.model import train
        train(n_per_kind=args.per_kind, seed=args.seed)
        return 0
    if args.cmd == "classify":
        from .scanner import classify_column
        print(classify_column(args.column, args.values))
        return 0
    if args.cmd == "dashboard":
        import os, subprocess
        path = os.path.join(os.path.dirname(__file__), "dashboard.py")
        return subprocess.call([sys.executable, "-m", "streamlit", "run", path, "--server.port", str(args.port),
                                "--server.headless", "true", "--client.toolbarMode", "minimal"])

    app = config.build()
    if args.cmd == "seed":
        make_db(app.backend)
        print("seeded users, accounts, support_tickets")
    elif args.cmd == "scan":
        overrides = config._load_yaml(app.settings.overrides)
        while True:
            reg = scan(app.backend, overrides=overrides)
            save_registry(reg, app.settings.registry_out)
            rows = summary(reg)
            print(_table(["table", "column", "tag", "kind", "confidence", "evidence"],
                         [[r[k] for k in ("table", "column", "tag", "kind", "confidence", "evidence")] for r in rows], 100))
            print(f"\n{len(rows)} tagged columns -> {app.settings.registry_out}")
            if not args.watch:
                break
            time.sleep(args.watch)
    elif args.cmd == "query":
        try:
            r = app.gateway.query(_login(app, args.user, args.password), args.sql)
        except Rejected as e:
            print(f"REJECTED: {e}"); return 2
        print(_table(r.columns, r.rows))
        print(f"\n{len(r.rows)} rows · {r.ms:.1f} ms · masked: {', '.join(r.masked) or 'nothing'}")
    elif args.cmd == "roles":
        for role, (user, pw) in config.DEMO_ACCOUNTS.items():
            print(f"\n=== {role.upper()} ({user}) ===")
            try:
                r = app.gateway.query(app.auth.login(user, pw), args.sql)
                print(_table(r.columns, r.rows, 5))
            except Rejected as e:
                print(f"REJECTED: {e}")
    elif args.cmd == "attack":
        results = run_suite(app.gateway, _login(app, args.user, args.password))
        print(_table(["attack", "category", "naive", "maskguard"],
                     [[x["attack"], x["category"], x["naive"]["status"], x["maskguard"]["status"]] for x in results], 100))
        sc_ = score(results)
        print(f"\nPII leaks: naive {sc_['naive_leaks']}/{sc_['pii_attacks']} · MaskGuard "
              f"{sc_['maskguard_leaks']}/{sc_['pii_attacks']} · firewall rejected "
              f"{sc_['firewall_rejected']}/{sc_['firewall_attacks']}")
        return 1 if sc_["maskguard_leaks"] else 0
    elif args.cmd == "integrity":
        for t in app.backend.tables():
            print(f"{t:20} {app.backend.checksum(t)}")
    elif args.cmd == "audit":
        if args.verify:
            ok = app.gateway.audit.verify()
            print("audit chain OK" if ok else "audit chain BROKEN"); return 0 if ok else 1
        for e in app.gateway.audit.tail(args.n):
            print(f"{e['decision']:7} {e['role']:8} {e['user']:12} {e.get('sql', '')[:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
