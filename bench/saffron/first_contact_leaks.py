"""Did the sensitive columns the scanner missed on first contact leak? Loads a saved first-contact registry exactly as
it was (no rescan) and queries every missed column as a Support and an Analyst user, twice: with nobody approving
anything, and after a reviewer blindly accepts every "suggested PUBLIC". Prints counts only, never values.
Usage: first_contact_leaks.py REGISTRY.yaml DB_URL WORKDIR USERS.yaml PASSWORDS.yaml OUT.json"""
import json, os, sys, yaml
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from truth import TRUTH
from maskguard import config
from maskguard.rewriter import Rejected

reg_file, url, work, users_file, pw_file, out = sys.argv[1:7]
os.makedirs(work, exist_ok=True)
overrides = os.path.join(work, "overrides.yaml")
open(overrides, "w").write("{}\n")
st = config.Settings(db=url, audit=os.path.join(work, "audit.jsonl"), registry_out=os.path.join(work, "registry.yaml"),
                     users=users_file, overrides=overrides, seed_if_empty=False)
app = config.build(st)
gw = app.gateway
first = yaml.safe_load(open(reg_file))
missed = [(t, c) for t, cols in first.items() for c, m in cols.items()
          if TRUTH[t][c] == "S" and m.get("tag") in (None, "UNREVIEWED", "PUBLIC")]
pw = yaml.safe_load(open(pw_file))
users = {"admin": "admin_anita", "support": "support_ravi", "analyst": "analyst_kavya"}
login = {u: app.auth.login(u, pw[u]) for u in users.values()}
q = (lambda c: f"`{c}`") if app.backend.dialect == "mysql" else (lambda c: f'"{c}"')


def values(user, sql):
    try:
        return [r[0] for r in gw.query(login[user], sql, observe=False).rows]
    except Rejected:
        return None


def sweep(reg, n=50):
    gw.update_registry(reg)
    per, total, leaked = {}, 0, 0
    for t, c in missed:
        sql = f"SELECT {q(c)} FROM {t} WHERE {q(c)} IS NOT NULL LIMIT {n}"
        raw = values(users["admin"], sql)
        row = {"suggest": reg[t][c].get("suggest"), "tag": reg[t][c].get("tag") or "UNREVIEWED"}
        for role in ("support", "analyst"):
            got = values(users[role], sql)
            k = 0 if got is None else sum(1 for a, v in zip(raw, got) if v is not None and str(v) == str(a))
            row[role] = {"raw_values_returned": k, "checked": len(raw)}
            total += len(raw)
            leaked += k
        per[f"{t}.{c}"] = row
    return {"values_checked": total, "raw_values_returned": leaked, "columns": per}


as_scanned = sweep({t: dict(cols) for t, cols in first.items()})
blind = {t: {c: ({**m, "tag": "PUBLIC"} if not m.get("tag") and m.get("suggest") == "PUBLIC" else m)
             for c, m in cols.items()} for t, cols in first.items()}
blindly_approved = sweep(blind)
report = {"backend": app.backend.dialect, "missed_sensitive_columns": len(missed),
          "as_scanned_nobody_approved": as_scanned, "reviewer_blindly_approves_suggestions": blindly_approved}
json.dump(report, open(out, "w"), indent=1)
for name in ("as_scanned_nobody_approved", "reviewer_blindly_approves_suggestions"):
    r = report[name]
    exposed = [k for k, v in r["columns"].items() if v["support"]["raw_values_returned"] or v["analyst"]["raw_values_returned"]]
    print(f"{name}: {r['raw_values_returned']} of {r['values_checked']} raw values returned; exposed columns: {exposed or 'none'}")
