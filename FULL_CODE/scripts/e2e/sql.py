"""Run SQL statements (autocommit) and print the first column of the last result, if any: sql.py URL STATEMENT…"""

import sys

import psycopg

with psycopg.connect(sys.argv[1], autocommit=True) as conn:
    cur = None
    for stmt in sys.argv[2:]:
        cur = conn.execute(stmt)
    if cur is not None and cur.description:
        for row in cur.fetchall():
            print(row[0])
