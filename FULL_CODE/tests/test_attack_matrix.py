"""Attack matrix: database x role x attack family, plus a seeded fuzzer that composes the same tricks at random.

Pass means one of two things for every query: the gateway refused it, or nothing in the result contains a raw protected
value (whole, or the first 10 characters of a long one). Oracle queries filter on a real value; they must return the
rows an admin gets back only for the admin. This is evidence for these shapes, not a proof for every query.
"""

import random

import pytest

from maskguard import config
from maskguard.dp import PrivacyLedger
from maskguard.rewriter import Rejected
from tests.conftest import BACKENDS, Env, make_settings

ROLES = ["support", "analyst", "auditor"]
PROTECTED = [
    ("users", "email"),
    ("users", "phone"),
    ("users", "aadhaar"),
    ("users", "pan"),
    ("users", "ssn"),
    ("accounts", "credit_card"),
    ("accounts", "iban"),
    ("support_tickets", "contact"),
    ("support_tickets", "payment_ref"),
]


class Matrix(Env):
    def __init__(self, app):
        super().__init__(app)
        self.gw.threat = None  # many queries in a row would trip the insider-threat engine; it is tested elsewhere
        self.gw.dp_ledger = PrivacyLedger(1e9)  # likewise the daily privacy budget for analysts' aggregates
        self.first = {
            (t, c): str(self.backend.admin_query(f"SELECT {c} FROM {t} ORDER BY id LIMIT 1")[1][0][0])
            for t, c in PROTECTED
        }
        self.frozen = {
            str(r[0]) for r in self.backend.admin_query("SELECT id FROM accounts WHERE status = 'frozen'")[1]
        }
        self._secrets = {}

    def secrets(self, role):
        if role not in self._secrets:
            vals = self.raw | (set() if role == "support" else self.names)  # support may see names by policy
            self._secrets[role] = ({v for v in vals if len(v) >= 6}, {v[:10] for v in vals if len(v) >= 12})
        return self._secrets[role]

    def leaks(self, role, rows):
        whole, prefixes = self.secrets(role)
        lengths = sorted({len(v) for v in whole})
        found = set()
        for r in rows:
            for cell in r:
                s = "" if cell is None else str(cell)
                for n in lengths:
                    if n > len(s):
                        break
                    found |= {s[i : i + n] for i in range(len(s) - n + 1)} & whole
                found |= {s[i : i + 10] for i in range(len(s) - 9)} & prefixes
        return found

    def attempt(self, role, sql):
        """(rows, refused). A database error counts as a refusal: nothing was returned."""
        try:
            return self.run(role, sql)[1], False
        except Rejected:
            return [], True
        except Exception:  # noqa: BLE001 (the DB rejected the rewritten query (e.g. a shape that dialect doesn't support))
            return [], True


@pytest.fixture(scope="module", params=BACKENDS)
def mx(request, tmp_path_factory):
    from maskguard.scanner import scan
    from maskguard.seed import make_db

    app = config.build(make_settings(tmp_path_factory.mktemp(request.param), request.param))
    make_db(app.backend)
    app.gateway.update_registry(scan(app.backend, overrides=config.load_overrides(app.settings)))
    return Matrix(app)


def _q(mx, ident):  # quoted identifier in the backend's own syntax
    return f"`{ident}`" if mx.backend.dialect == "mysql" else f'"{ident}"'


FAMILIES = {
    "alias": [
        "SELECT ssn AS city FROM users",
        "SELECT u.email AS name FROM users AS u",
        "SELECT pan AS mg_hmac FROM users",
        'SELECT aadhaar AS "id" FROM users',
    ],
    "quoted": ["SELECT {q_email} FROM {q_users}", "SELECT {q_users}.{q_ssn} FROM {q_users}"],
    "qualified": ["SELECT email FROM {schema}.users", "SELECT x.pan FROM {schema}.users x"],
    "wildcard": ["SELECT u.* FROM users u", "SELECT *, ssn FROM users", "SELECT a.*, u.* FROM accounts a, users u"],
    "expression": [
        "SELECT upper(email), lower(pan) FROM users",
        "SELECT CONCAT(email, phone) FROM users",
        "SELECT substr(ssn, 1, 7), substr(aadhaar, 1, 8) FROM users",
        "SELECT trim(credit_card) FROM accounts",
        "SELECT coalesce(NULL, iban) FROM accounts",
        "SELECT replace(phone, '9', '9') FROM users",
        "SELECT CASE WHEN id > 0 THEN pan ELSE ssn END FROM users",
    ],
    "cte": [
        "WITH a AS (SELECT * FROM users), b AS (SELECT email AS e FROM a) SELECT e FROM b",
        "WITH accounts AS (SELECT ssn AS iban FROM users) SELECT iban FROM accounts",
        "WITH x AS (SELECT pan FROM users) SELECT * FROM (SELECT pan AS y FROM x) z",
    ],
    "subquery": [
        "SELECT (SELECT max(u2.ssn) FROM users u2 WHERE u2.id = u.id) FROM users u",
        "SELECT x FROM (SELECT y AS x FROM (SELECT pan AS y FROM users) a) b",
        "SELECT email FROM users WHERE id IN (SELECT user_id FROM accounts)",
    ],
    "join": [
        "SELECT email, iban FROM users JOIN accounts USING (id)",
        "SELECT u.ssn, t.contact FROM users u LEFT JOIN support_tickets t ON t.user_id = u.id",
        "SELECT u.pan, a.credit_card FROM users u, accounts a WHERE a.user_id = u.id",
    ],
    "window": [
        "SELECT email, row_number() OVER (ORDER BY ssn) FROM users",
        "SELECT first_value(ssn) OVER (PARTITION BY city ORDER BY id) FROM users",
        "SELECT max(aadhaar) OVER () FROM users",
        "SELECT lag(phone) OVER (ORDER BY id) FROM users",
    ],
    "setop": [
        "SELECT email FROM users UNION ALL SELECT contact FROM support_tickets",
        "SELECT email FROM users INTERSECT SELECT email FROM users",
        "SELECT pan FROM users EXCEPT SELECT pan FROM users WHERE id > 10",
    ],
    "aggregate": [
        "SELECT city, max(ssn), min(email) FROM users GROUP BY city",
        "SELECT ssn, count(*) FROM users GROUP BY ssn",
        "SELECT count(DISTINCT pan) FROM users",
    ],
    "comments": [
        "SELECT /*+ INDEX(users) */ ssn FROM users",
        "SELECT ssn -- the real one\nFROM users",
        "SELECT/**/email/**/FROM/**/users",
    ],
}
CASES = [(f, i) for f, sqls in FAMILIES.items() for i in range(len(sqls))]


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("family,i", CASES, ids=[f"{f}{i}" for f, i in CASES])
def test_no_raw_value_comes_back(mx, role, family, i):
    sql = FAMILIES[family][i].format(
        schema=mx.backend.default_schema, q_users=_q(mx, "users"), q_email=_q(mx, "email"), q_ssn=_q(mx, "ssn")
    )
    rows, _ = mx.attempt(role, sql)
    assert not mx.leaks(role, rows), sql


ORACLES = [  # true for the first user's real value; must find nothing through a masked view
    "SELECT id FROM {t} WHERE {c} = '{v}'",
    "SELECT id FROM {t} WHERE {c} LIKE '{p}%'",
    "SELECT id FROM {t} WHERE {c} BETWEEN '{v}' AND '{v}'",
    "SELECT id FROM {t} WHERE {c} IN ('{v}', 'nobody')",
    "SELECT id FROM {t} WHERE upper({c}) = upper('{v}')",
    "SELECT count(*) FROM {t} GROUP BY status HAVING max(CASE WHEN {c} = '{v}' THEN 1 ELSE 0 END) = 1",
    "SELECT id FROM {t} x WHERE EXISTS (SELECT 1 FROM {t} y WHERE y.id = x.id AND y.{c} = '{v}')",
    "WITH m AS (SELECT * FROM {t} WHERE {c} = '{v}') SELECT id FROM m",
    "SELECT id FROM {t} WHERE (SELECT count(*) FROM {t} z WHERE z.{c} = '{v}') > 0",
    "SELECT id FROM {t} WHERE id = 1 AND CASE WHEN {c} = '{v}' THEN 1 ELSE 0 END = 1",
]


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("oracle", range(len(ORACLES)))
@pytest.mark.parametrize(
    "target", [("users", "ssn"), ("accounts", "credit_card"), ("support_tickets", "contact")], ids=lambda t: ".".join(t)
)
def test_predicates_on_real_values_find_nothing(mx, role, oracle, target):
    t, c = target
    if "status" in ORACLES[oracle] and t == "users":
        t, c = "accounts", "iban"  # users has no status column to group by
    v = mx.first[(t, c)]
    sql = ORACLES[oracle].format(t=t, c=c, v=v, p=v[:6])
    admin_rows, _ = mx.attempt("admin", sql)
    assert admin_rows, f"the oracle should work for admin: {sql}"
    rows, _ = mx.attempt(role, sql)
    hits = [r for r in rows if r and r[0] not in (None, 0, "0")]
    assert not hits, sql


ROW_FILTER_SHAPES = [
    "SELECT id FROM accounts",
    "SELECT a.id FROM users u JOIN accounts a ON a.user_id = u.id",
    "WITH x AS (SELECT * FROM accounts) SELECT id FROM x",
    "SELECT id FROM accounts UNION SELECT id FROM accounts",
    "SELECT id FROM (SELECT * FROM accounts) s WHERE status = 'frozen' OR 1 = 1",
    "SELECT id FROM accounts WHERE status = 'frozen'",
    "SELECT max(id) FROM accounts WHERE status = 'frozen'",
]


@pytest.mark.parametrize("sql", ROW_FILTER_SHAPES)
def test_support_never_sees_frozen_accounts(mx, sql):
    assert mx.frozen  # the seed has some
    rows, _ = mx.attempt("support", sql)
    assert not {str(r[0]) for r in rows if r} & mx.frozen, sql


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT mg_partial(ssn, 0, 4) FROM users",
        "SELECT mg_token(pan, '', 32) FROM users",
        "SELECT mg_redact_text(notes) FROM support_tickets",
    ],
)
def test_mask_functions_cannot_be_called_by_users(mx, sql):
    with pytest.raises(Rejected):
        mx.run("analyst", sql)


# --- seeded fuzzer --------------------------------------------------------------------------------------------------
FUNCS = [
    "upper({})",
    "lower({})",
    "trim({})",
    "coalesce({}, 'x')",
    "substr({}, 1, 12)",
    "CASE WHEN id > 0 THEN {} END",
    "replace({}, '-', '')",
    "CONCAT({}, '')",
]
ALIASES = ["v", "city", "name", "status", "id_x"]


def fuzz_queries(mx, seed, n):
    rng = random.Random(seed)
    for _ in range(n):
        t, c = rng.choice(PROTECTED)
        expr = c
        for _ in range(rng.randint(0, 2)):
            expr = rng.choice(FUNCS).format(expr)
        sql = f"SELECT id, {expr} AS {rng.choice([*ALIASES, c])} FROM {t}"
        oracle = rng.random() < 0.35
        if oracle:
            sql += f" WHERE {c} = '{mx.first[(t, c)]}'"
        for _ in range(rng.randint(0, 2)):
            w = rng.choice(["cte", "derived", "union"])
            if w == "cte":
                sql = f"WITH q AS ({sql}) SELECT * FROM q"
            elif w == "derived":
                sql = f"SELECT * FROM ({sql}) d"
            else:
                sql = f"SELECT * FROM ({sql}) a UNION ALL SELECT * FROM ({sql}) b"
        yield sql, oracle


@pytest.mark.parametrize("role", ROLES)
def test_seeded_fuzz(mx, role):
    ran = refused = 0
    for sql, oracle in fuzz_queries(mx, seed=20261024, n=120):
        rows, was_refused = mx.attempt(role, sql)
        refused += was_refused
        ran += not was_refused
        assert not mx.leaks(role, rows), sql
        if oracle:
            assert rows == [], sql
    assert ran >= 100, f"only {ran} of 120 fuzz queries ran ({refused} refused): the fuzzer is not exercising much"


def test_a_column_added_after_the_scan_stays_hidden(env):
    """Schema drift: a new column holding copies of emails is not in the registry yet, so it must not come back raw.
    The masked view lists only scanned columns, so naming the new one fails and `*` leaves it out until a rescan."""
    env.backend.admin_script("ALTER TABLE users ADD COLUMN backup_email VARCHAR(80)")
    env.backend.admin_script("UPDATE users SET backup_email = email")
    for role in ROLES:
        for sql in ("SELECT backup_email FROM users", "SELECT * FROM users", "SELECT u.* FROM users u"):
            try:
                cols, rows = env.run(role, sql)
            except Exception:  # noqa: BLE001 (Rejected, or the database: no such column in the masked view)
                continue
            assert "backup_email" not in cols and not {str(c) for r in rows for c in r} & env.raw, (role, sql)
