"""Cell-by-cell comparison of the Saffron Bank tables across SQLite, PostgreSQL and MySQL (display differences
normalised: money precision, timestamp separator, JSON key order; rows sorted in Python)."""

import datetime
import decimal
import hashlib
import json
import os
import sqlite3
import sys

import psycopg
import pymysql

TABLES = [
    "branches",
    "customers",
    "kyc_records",
    "international_customers",
    "accounts",
    "cards",
    "transactions",
    "support_tickets",
    "loan_applications",
]


def norm(v):
    if v is None:
        return None
    if isinstance(v, (int, float, decimal.Decimal)) and not isinstance(v, bool):
        return format(decimal.Decimal(str(v)).normalize(), "f")
    if isinstance(v, (datetime.datetime, datetime.date)):
        return v.isoformat()
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    s = str(v)
    if s[:1] in "{[":
        try:
            return json.dumps(json.loads(s), sort_keys=True, ensure_ascii=False)
        except ValueError:
            pass
    return s


def digest(rows):
    rows = sorted(tuple(norm(v) for v in r) for r in rows)
    return len(rows), hashlib.sha256(repr(rows).encode()).hexdigest()[:12]


lite = sqlite3.connect(sys.argv[1])
pg = psycopg.connect("postgresql://postgres@127.0.0.1:5433/saffron_bank")
my = pymysql.connect(
    host="127.0.0.1",
    port=3307,
    user="root",
    password=os.environ["MYSQL_PW"],
    database="saffron_bank",
    charset="utf8mb4",
)
ok = 0
for t in TABLES:
    a = digest(lite.execute(f'SELECT * FROM "{t}"').fetchall())
    c = pg.cursor()
    c.execute(f'SELECT * FROM "{t}"')
    b = digest(c.fetchall())
    c = my.cursor()
    c.execute(f"SELECT * FROM `{t}`")
    m = digest(c.fetchall())
    same = a == b == m
    ok += same
    print(
        f"{t:26} sqlite {a[0]:7} {a[1]}  postgres {b[0]:7} {b[1]}  mysql {m[0]:7} {m[1]}  {'IDENTICAL' if same else 'DIFFERENT'}"
    )
print(f"{ok}/{len(TABLES)} tables identical across the three databases")
