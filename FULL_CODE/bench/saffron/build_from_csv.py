"""Build the Saffron Bank database from the pack's CSVs, with the schema taken from the pack README's column tables.
Usage: build_saffron.py PACK_DIR sqlite OUT.db | postgres URL | mysql URL"""

import csv
import re
import sys
from pathlib import Path

ORDER = [
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


def schema(readme):
    tables, cur = {}, None
    for line in readme.splitlines():
        m = re.match(r"### `(\w+)`", line)
        if m:
            cur = tables.setdefault(m.group(1), [])
            continue
        m = re.match(r"\| `(\w+)` \| ([^|]+) \| ([^|]+) \| ([^|]+) \| (yes|no) \| ([^|]*) \|", line)
        if cur is not None and m:
            name, lite, pg, my, null, key = (x.strip() for x in m.groups())
            cur.append({"name": name, "sqlite": lite, "postgres": pg, "mysql": my, "null": null == "yes", "key": key})
    return tables


def q(dialect, ident):
    return f"`{ident}`" if dialect == "mysql" else f'"{ident}"'


def ddl(dialect, table, cols):
    parts = []
    for c in cols:
        s = f"{q(dialect, c['name'])} {c[dialect]}" + ("" if c["null"] else " NOT NULL")
        if "PK" in c["key"]:
            s += " PRIMARY KEY"
        if "UNIQUE" in c["key"]:
            s += " UNIQUE"
        parts.append(s)
    for c in cols:
        m = re.search(r"FK → `(\w+)\.(\w+)`", c["key"])
        if m:
            parts.append(
                f"FOREIGN KEY ({q(dialect, c['name'])}) REFERENCES {q(dialect, m.group(1))}({q(dialect, m.group(2))})"
            )
    return f"CREATE TABLE {q(dialect, table)} (\n  " + ",\n  ".join(parts) + "\n)"


def main():
    pack, dialect, target = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    tables = schema((pack / "README.md").read_text(encoding="utf-8"))
    assert sorted(tables) == sorted(ORDER), sorted(tables)
    if dialect == "sqlite":
        import sqlite3

        Path(target).unlink(missing_ok=True)
        conn, ph = sqlite3.connect(target), "?"
    elif dialect == "postgres":
        import psycopg

        conn, ph = psycopg.connect(target), "%s"
    else:
        from urllib.parse import urlparse

        import pymysql

        u = urlparse(target)
        conn = pymysql.connect(
            host=u.hostname,
            port=u.port,
            user=u.username,
            password=u.password,
            database=u.path.lstrip("/"),
            charset="utf8mb4",
            autocommit=False,
        )
        ph = "%s"
    cur = conn.cursor()
    for t in reversed(ORDER):
        cur.execute(f"DROP TABLE IF EXISTS {q(dialect, t)}" + (" CASCADE" if dialect == "postgres" else ""))
    for t in ORDER:
        cur.execute(ddl(dialect, t, tables[t]))
        with open(pack / "data" / "csv" / f"{t}.csv", encoding="utf-8", newline="") as f:
            r = csv.reader(f)
            header = next(r)
            assert header == [c["name"] for c in tables[t]], (t, header)
            rows = [[None if v == "" else v for v in row] for row in r]
        cols = ", ".join(q(dialect, h) for h in header)
        sql = f"INSERT INTO {q(dialect, t)} ({cols}) VALUES ({', '.join([ph] * len(header))})"
        for i in range(0, len(rows), 5000):
            cur.executemany(sql, rows[i : i + 5000])
        conn.commit()
        cur.execute(f"SELECT COUNT(*) FROM {q(dialect, t)}")
        print(f"  {t:26}{(cur.fetchone()[0]):>9,}", flush=True)
    conn.close()


if __name__ == "__main__":
    main()
