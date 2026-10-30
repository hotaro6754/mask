"""MaskGuard on the organisers' Saffron Bank pack, as the organisers' users, on one backend.
Usage: eval_saffron_masking.py BACKEND_URL WORKDIR USERS.yaml PASSWORDS.yaml DSTOOLS_DIR OUT.json"""

import json
import os
import re
import sys
from pathlib import Path

import yaml

url, work, users_file, pw_file, tools, out = sys.argv[1:7]
os.makedirs(work, exist_ok=True)
sys.path.insert(0, tools)
from truth import TRUTH

from maskguard import config, textpii
from maskguard.rewriter import Rejected, action_for
from maskguard.scanner import scan

overrides = os.path.join(work, "overrides.yaml")
Path(overrides).write_text("{}\n", encoding="utf-8")
st = config.Settings(
    db=url,
    audit=os.path.join(work, "audit.jsonl"),
    registry_out=os.path.join(work, "registry.yaml"),
    users=users_file,
    overrides=overrides,
    seed_if_empty=False,
)
app = config.build(st)
gw, b = app.gateway, app.backend
dialect = b.dialect
reg = scan(b)
# --- the review step: what a bank reviewer approves. Suggested keys/lists first, then the remaining non-personal
# columns (ids, dates, codes) and the bank's own branch contact data. Personal attributes (Q) stay UNREVIEWED.
approved_suggested, approved_by_reviewer = [], []
for t, cols in reg.items():
    for c, m in cols.items():
        if m.get("tag"):
            if TRUTH[t][c] == "N":  # scanner tagged the bank's own data: the reviewer approves it
                approved_by_reviewer.append(f"{t}.{c}")
            continue
        if m.get("suggest") == "PUBLIC" and TRUTH[t][c] == "N":
            approved_suggested.append(f"{t}.{c}")
        elif TRUTH[t][c] == "N":
            approved_by_reviewer.append(f"{t}.{c}")
for item in approved_suggested + approved_by_reviewer:
    t, c = item.split(".")
    reg[t][c] = {**reg[t][c], "tag": "PUBLIC", "kind": None, "confidence": "override", "source": "approval"}
gw.update_registry(reg)
pw = yaml.safe_load(Path(pw_file).read_text(encoding="utf-8"))
login = {u: app.auth.login(u, pw[u]) for u in pw}
who = {"admin": "admin_anita", "support": "support_ravi", "analyst": "analyst_kavya"}
q = (lambda c: f'"{c}"') if dialect != "mysql" else (lambda c: f"`{c}`")
report = {
    "backend": dialect,
    "tables": len(reg),
    "columns": sum(len(c) for c in reg.values()),
    "approved_suggested": len(approved_suggested),
    "approved_by_reviewer": len(approved_by_reviewer),
    "views": {},
}


def run(user, sql):
    try:
        r = gw.query(login[user], sql, observe=False)
        return {"columns": r.columns, "rows": [[None if v is None else str(v) for v in row] for row in r.rows]}
    except Rejected as e:
        return {"refused": str(e)[:120]}


checksums_before = {t: b.checksum(t) for t in b.tables()}
Q1 = (
    "SELECT c.cust_nm, c.mob_no, k.pan_no, k.aadhaar_no, a.account_no, a.curr_bal FROM customers c "
    "JOIN kyc_records k ON k.customer_id = c.customer_id JOIN accounts a ON a.customer_id = c.customer_id "
    "WHERE k.pan_no IS NOT NULL ORDER BY a.account_no LIMIT 2"
)
QC = f"SELECT {q('CARD_NO')}, {q('NAME_ON_CARD')}, {q('CREDIT_LIMIT')} FROM cards ORDER BY {q('CARD_REF')} LIMIT 3"
QT = "SELECT ticket_text, notes FROM support_tickets WHERE notes LIKE '%Called%' ORDER BY ticket_id LIMIT 2"
QS = "SELECT ssn, us_phone FROM international_customers ORDER BY customer_id LIMIT 2"
for name, sql in (("customer_360", Q1), ("cards", QC), ("tickets", QT), ("nri_ssn", QS)):
    report["views"][name] = {role: run(u, sql) for role, u in who.items()}
# guessing a value: filters run on what the role can see
real_pan = b.admin_query("SELECT pan_no FROM kyc_records WHERE pan_no IS NOT NULL ORDER BY kyc_id LIMIT 1")[1][0][0]
guess = f"SELECT kyc_id FROM kyc_records WHERE pan_no = '{real_pan}'"
report["guess"] = {role: len(run(u, guess).get("rows", [])) for role, u in who.items()}
report["writes"] = {
    role: [
        ("refused" in run(u, s))
        for s in (
            "UPDATE customers SET mob_no = '0'",
            "DELETE FROM transactions",
            "DROP TABLE cards",
            "INSERT INTO branches (branch_code) VALUES ('x')",
        )
    ]
    for role, u in who.items()
}
# leak sweep: every table, every role, 200 rows; a raw admin value in a column the role's policy masks is a leak
leaks, cells = {}, 0
pol = gw.policy
for t in b.tables():
    pk = next(iter(reg[t]))
    sql = f"SELECT * FROM {t} ORDER BY {q(pk)} LIMIT 200"
    admin = run("admin_anita", sql)
    for role in ("support", "analyst"):
        got = run(who[role], sql)
        if "refused" in got:
            leaks[f"{role}:{t}"] = "refused"
            continue
        for j, col in enumerate(admin["columns"]):
            act = action_for(reg[t][col], role, pol)
            if act == "allow":
                continue
            for ra, rb in zip(admin["rows"], got["rows"], strict=False):
                cells += 1
                a, v = ra[j], rb[j]
                if a is None or v is None or v != a or len(a) < 4:
                    continue
                if act == "partial" and reg[t][col].get("type") == "num":
                    if float(a) % pol.get("bucket_size", 10000) == 0:
                        continue  # already a round number: rounding down returns it unchanged
                elif act == "partial" and re.search(r"[Xx*]{3}", a):
                    continue  # stored already masked at source (XXXX XXXX 7738)
                elif act == "redact_text" and textpii.redact(v) == v:
                    continue  # text with no identifier left in it: only identifiers are replaced
                leaks.setdefault(f"{role}:{t}.{col}:{act}", 0)
                leaks[f"{role}:{t}.{col}:{act}"] += 1
report["leak_sweep"] = {"masked_cells_checked": cells, "raw_values_returned": leaks}
report["integrity_unchanged"] = checksums_before == {t: b.checksum(t) for t in b.tables()}
report["audit_chain"] = gw.audit.verify()
report["organiser_users_logged_in"] = len(login)
Path(out).write_text(json.dumps(report, indent=1, ensure_ascii=False), encoding="utf-8")
print(json.dumps({k: v for k, v in report.items() if k != "views"}, ensure_ascii=False)[:1500])
