"""Indirect-SQL scenarios for the REA experiment.

Each scenario runs as the restricted role on both systems:
  target    PostgreSQL Anonymizer 3.2.3, role support_m (MASKED + RLS), container anon-rea on 127.0.0.1:5441
  maskguard MaskGuard gateway, role support (demo identity support.sam), PostgreSQL 16 on 127.0.0.1:5433/rea_fixture

`leak(rows, err, notices)` returns True when the output reveals a value or row the role must not learn.
All data is synthetic (see ../fixture/fixture.sql).
"""

import hashlib

REAL_SSN_8 = "987-65-4321"
REAL_SSNS = [
    "901-23-4501",
    "902-34-5602",
    "903-45-6703",
    "904-56-7804",
    "905-67-8905",
    "906-78-9006",
    "907-89-0107",
    REAL_SSN_8,
]
REAL_EMAILS = [
    f"{n}@example.com"
    for n in (
        "asha.rao",
        "ben.okafor",
        "chen.wei",
        "dana.silva",
        "eli.novak",
        "fatima.khan",
        "gopal.iyer",
        "zed.target",
    )
]
REAL_CARDS = [
    "4111-1111-1111-1111",
    "4012-8888-8888-1881",
    "5555-5555-5555-4444",
    "5105-1051-0510-5100",
    "4222-2222-2222-2222",
    "3782-8224-6310-0050",
    "6011-1111-1111-1117",
    "4000-0566-5566-5556",
    "4242-4242-4242-4242",
]
EXACT_BALANCES = ["12500", "48250.75", "731000", "9100.1", "23999.99", "56000", "31415.92", "987654.32", "70000"]
FROZEN_IDS = {13, 19}


def flat(rows):
    return " | ".join(str(v) for r in rows or [] for v in r)


def raw_value_seen(rows, err=None, notices=()):
    text = flat(rows) + " " + (err or "") + " " + " ".join(notices)
    return any(v in text for v in REAL_SSNS + REAL_EMAILS + REAL_CARDS) or any(
        b in text.replace(".00", "").replace(".0 ", " ")
        for b in ("987654.32", "48250.75", "23999.99", "31415.92", "9100.1")
    )


def returns_id(i):
    return lambda rows, err, notices: any(r and r[0] == i for r in rows or [])


S = []


def sc(id, cat, title, sql, leak=None, expect="", anon_sql=None):
    S.append(
        {
            "id": id,
            "cat": cat,
            "title": title,
            "sql": sql,
            "anon_sql": anon_sql or sql,
            "leak": leak or raw_value_seen,
            "expect": expect,
        }
    )


# --- projection paths -------------------------------------------------------------------------------------------
sc("S01", "projection", "SELECT * on a masked table", "SELECT * FROM customers ORDER BY id")
sc("S02", "projection", "Column and table aliases", "SELECT c.ssn AS x, c.email AS y FROM customers c ORDER BY c.id")
sc(
    "S03",
    "projection",
    "CTE that selects everything",
    "WITH t AS (SELECT * FROM customers) SELECT id, ssn FROM t ORDER BY id",
)
sc(
    "S04",
    "projection",
    "Two levels of nested derived tables",
    "SELECT id, ssn FROM (SELECT * FROM (SELECT * FROM customers) a) b ORDER BY id",
)
sc(
    "S05",
    "projection",
    "Join of two masked tables",
    "SELECT c.name, a.card, a.balance FROM customers c JOIN accounts a ON a.customer_id = c.id ORDER BY a.id",
)
sc("S06", "projection", "Scalar subquery in the select list", "SELECT (SELECT ssn FROM customers WHERE id = 8) AS s")
sc(
    "S07",
    "projection",
    "UNION across two masked columns",
    "SELECT ssn FROM customers WHERE id = 8 UNION SELECT card FROM accounts WHERE id = 18",
)
sc(
    "S08",
    "projection",
    "LATERAL subquery re-projecting a masked column",
    "SELECT x.s FROM customers c, LATERAL (SELECT c.ssn AS s) x WHERE c.id = 8",
)
sc(
    "S09",
    "projection",
    "Window function over a masked column",
    "SELECT id, lag(ssn) OVER (ORDER BY id) AS prev FROM customers ORDER BY id",
)
sc("S10", "projection", "Whole-row reference cast to text", "SELECT c::text AS r FROM customers c WHERE c.id = 8")

# --- predicates, ordering, functions: inference without selecting the column -----------------------------------
sc(
    "S11",
    "inference",
    "WHERE equality on the real SSN",
    "SELECT id, name FROM customers WHERE ssn = '987-65-4321'",
    returns_id(8),
    "a row back confirms the guessed SSN",
)
sc(
    "S12",
    "inference",
    "WHERE prefix probe (LIKE) on SSN",
    "SELECT id FROM customers WHERE ssn LIKE '98%'",
    returns_id(8),
    "binary search on prefixes recovers the SSN digit by digit",
)
sc(
    "S13",
    "inference",
    "WHERE range pins an exact balance",
    "SELECT id FROM accounts WHERE balance BETWEEN 987654 AND 987655",
    returns_id(18),
    "range bisection recovers the exact balance despite 10,000 buckets",
)
sc(
    "S14",
    "inference",
    "ORDER BY the masked SSN",
    "SELECT id FROM customers ORDER BY ssn DESC LIMIT 1",
    returns_id(8),
    "real order puts id 8 first (987-…); masked order (last 4 digits) puts id 6 first",
)
sc(
    "S15",
    "inference",
    "Error oracle (division by zero on a guess)",
    "SELECT id FROM customers WHERE 1 / (CASE WHEN ssn = '987-65-4321' THEN 0 ELSE 1 END) = 1",
    lambda rows, err, n: bool(err) and "division" in err.lower(),
    "an error appears only when the guess is right",
)
sc(
    "S16",
    "inference",
    "Hash of the masked column",
    "SELECT id, md5(ssn) AS h FROM customers WHERE id = 8",
    lambda rows, err, n: hashlib.md5(REAL_SSN_8.encode(), usedforsecurity=False).hexdigest() in flat(rows),
    "md5 of the real SSN would be an offline-crackable oracle",
)
sc(
    "S17",
    "inference",
    "Exact MAX and SUM of balances",
    "SELECT max(balance) AS mx, sum(balance) AS s FROM accounts",
    lambda rows, err, n: any("987654.32" in str(v) or str(v).endswith((".32", ".08")) for r in rows or [] for v in r),
    "exact aggregates reveal the top balance",
)
sc("S18", "inference", "GROUP BY the masked SSN", "SELECT ssn, count(*) AS n FROM customers GROUP BY ssn ORDER BY 1")

# --- row-level restriction (frozen accounts hidden from support) ------------------------------------------------
sc(
    "S19",
    "rows",
    "COUNT(*) over the restricted table",
    "SELECT count(*) AS n FROM accounts",
    lambda rows, err, n: bool(rows) and rows[0][0] == 9,
    "9 would include the 2 frozen accounts; 7 is correct",
)
sc(
    "S20",
    "rows",
    "Direct filter for hidden rows",
    "SELECT id, balance FROM accounts WHERE status = 'frozen'",
    lambda rows, err, n: bool(rows),
)
sc(
    "S21",
    "rows",
    "Hidden rows through a CTE and join",
    "WITH x AS (SELECT * FROM accounts) SELECT c.name FROM customers c JOIN x ON x.customer_id = c.id "
    "WHERE x.status = 'frozen'",
    lambda rows, err, n: bool(rows),
)
sc(
    "S22",
    "rows",
    "Anti-join infers who has only frozen accounts",
    "SELECT c.id FROM customers c WHERE NOT EXISTS (SELECT 1 FROM accounts a WHERE a.customer_id = c.id) ORDER BY 1",
    lambda rows, err, n: False,
    "residual: customer 3 appears with no account (expected disclosure in both designs)",
)

# --- side channels outside the user table -----------------------------------------------------------------------
sc(
    "S23",
    "side-channel",
    "Planner statistics (pg_stats) for the masked table",
    "SELECT attname, most_common_vals::text, histogram_bounds::text FROM pg_stats "
    "WHERE tablename = 'customers' ORDER BY attname",
)
sc(
    "S24",
    "side-channel",
    "Planner row estimate (pg_class.reltuples) of the restricted table",
    "SELECT relname, reltuples FROM pg_class WHERE relname = 'accounts'",
    lambda rows, err, n: any(r and float(r[1]) == 9 for r in rows or []),
    "reltuples = 9 reveals that 2 rows are hidden from this role",
)
sc(
    "S25",
    "side-channel",
    "EXPLAIN of a predicate on a masked column",
    "EXPLAIN SELECT * FROM customers WHERE ssn = '987-65-4321'",
    lambda rows, err, n: False,
)

# --- statement forms and fail-closed behaviour ------------------------------------------------------------------
sc(
    "S26",
    "statement",
    "Recursive CTE (no table access)",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r",
    lambda rows, err, n: False,
    "harmless; tests whether unsupported SQL is refused or allowed",
)
sc(
    "S27",
    "statement",
    "Recursive CTE seeded from a masked table",
    "WITH RECURSIVE r(id, s) AS (SELECT id, ssn FROM customers WHERE id = 8 UNION ALL "
    "SELECT id, s FROM r WHERE false) SELECT s FROM r",
)
sc(
    "S28",
    "statement",
    "UPDATE through the masked role",
    "UPDATE customers SET city = 'X' WHERE id = 1",
    lambda rows, err, n: err is None,
    "a write that succeeds would change the source data",
)
sc("S29", "statement", "COPY table TO STDOUT", "COPY customers TO STDOUT")
sc(
    "S30",
    "statement",
    "Prepared statement then EXECUTE",
    "PREPARE p AS SELECT ssn FROM customers WHERE id = 8; EXECUTE p",
    anon_sql=["PREPARE p AS SELECT ssn FROM customers WHERE id = 8", "EXECUTE p"],
)
sc(
    "S31",
    "statement",
    "PL/pgSQL DO block reads a masked column into a NOTICE",
    "DO $$DECLARE v text; BEGIN SELECT ssn INTO v FROM customers WHERE id = 8; RAISE NOTICE 'v=%', v; END$$",
)
sc(
    "S32",
    "statement",
    "Temp table materialised from the masked table",
    "CREATE TEMP TABLE t AS SELECT * FROM customers; SELECT ssn FROM t WHERE id = 8",
    anon_sql=["CREATE TEMP TABLE t AS SELECT * FROM customers", "SELECT ssn FROM t WHERE id = 8"],
)

# --- parser-differential probes (aimed at a SQL-rewriting proxy: does the proxy see the same columns PostgreSQL does?)
sc("S33", "parser", "PostgreSQL TABLE shorthand", "TABLE customers")
sc("S34", "parser", "FROM ONLY (inheritance syntax)", "SELECT ssn FROM ONLY customers WHERE id = 8")
sc("S35", "parser", "Schema-qualified table", "SELECT ssn FROM public.customers WHERE id = 8")
sc(
    "S36",
    "parser",
    "Database-qualified table",
    "SELECT ssn FROM rea_fixture.public.customers WHERE id = 8",
    anon_sql="SELECT ssn FROM rea.public.customers WHERE id = 8",
)
sc("S37", "parser", "Quoted identifiers", 'SELECT "ssn" FROM "customers" WHERE "id" = 8')
sc("S38", "parser", "Unicode-escaped column identifier", 'SELECT U&"\\0073sn" AS s FROM customers WHERE id = 8')
sc(
    "S39",
    "parser",
    "Subquery alias shadows the table name",
    "SELECT customers.ssn FROM (SELECT * FROM customers) customers WHERE customers.id = 8",
)
sc("S40", "parser", "Whole row to JSON", "SELECT to_jsonb(c) AS j FROM customers c WHERE c.id = 8")
sc(
    "S41",
    "parser",
    "row_to_json over a derived table",
    "SELECT row_to_json(x) AS j FROM (SELECT * FROM customers WHERE id = 8) x",
)
sc("S42", "parser", "array_agg of the masked column", "SELECT array_agg(ssn ORDER BY id) AS a FROM customers")
sc(
    "S43",
    "inference",
    "HAVING predicate on an aggregate of the masked column",
    "SELECT count(*) AS n FROM customers HAVING min(ssn) < '95'",
    lambda rows, err, n: bool(rows),
    "a row back means some real SSN sorts below '95' (masked values start with X and never do)",
)
sc(
    "S44",
    "inference",
    "Boolean projection of a comparison",
    "SELECT id, ssn < '95' AS b FROM customers ORDER BY id",
    lambda rows, err, n: any(r[1] in (True, "true", "t", 1) for r in rows or []),
    "true for ids 1-7 would reveal the real SSN prefix; masked values compare false everywhere",
)
sc(
    "S45",
    "inference",
    "Guess list tested with IN (subquery)",
    "SELECT v.g FROM (VALUES ('987-65-4321'), ('111-11-1111')) v(g) WHERE v.g IN (SELECT ssn FROM customers)",
    lambda rows, err, n: any("987-65-4321" in str(r) for r in rows or []),
)
sc("S46", "inference", "Regular-expression predicate", "SELECT id FROM customers WHERE ssn ~ '^98'", returns_id(8))
sc(
    "S47",
    "statement",
    "Cursor declared over the masked table",
    "DECLARE c CURSOR FOR SELECT ssn FROM customers WHERE id = 8",
    anon_sql=["BEGIN", "DECLARE c CURSOR FOR SELECT ssn FROM customers WHERE id = 8", "FETCH c", "COMMIT"],
)
