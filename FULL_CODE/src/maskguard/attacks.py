"""Attack suite: each attack runs against MaskGuard and against the naive output-masking baseline.

Leak checks:
  value  - a raw sensitive value (one the role may not see) appears in, or inside, any output cell
  oracle - the same probe with a true guess and a false guess gives different answers (inference)
  order  - ordering by a protected column reproduces the true order of rows
  reject - statement firewall; MaskGuard must reject it (not counted as a PII leak)
"""

import logging
from dataclasses import dataclass

from .backends import quote_ident
from .config import environment
from .naive import naive_query
from .rewriter import Rejected, action_for

# Same text on every channel: it names no SQL, table, column, error or result.
SELF_TEST_REFUSAL = "self-tests are disabled in production"


class SelfTestDisabled(Exception):
    """A self-test was refused before it touched the database."""


def self_test_allowed(gateway):
    """Self-tests run crafted SQL straight against the database (the naive baseline, the benchmark) and read protected
    columns in full, so they run only where the environment is positively development: now, and when the gateway was
    built. An environment that can't be determined counts as production."""
    try:
        return environment() == "development" and getattr(gateway, "allow_self_test", False) is True
    except Exception:  # noqa: BLE001 (any doubt about the environment counts as production: self-tests stay off)
        return False


def require_self_test(gateway, session=None, channel="engine", what="attack suite"):
    """Refuse, and audit who asked through which channel (never SQL, schema or results), unless self_test_allowed."""
    if self_test_allowed(gateway):
        return
    try:
        gateway.audit.append(
            user=getattr(session, "user", None),
            role=getattr(session, "role", None),
            channel=channel,
            decision="reject",
            reason=f"{what}: {SELF_TEST_REFUSAL}",
        )
    except Exception as e:  # noqa: BLE001 (an audit failure must not turn a refusal into a run)
        logging.getLogger("maskguard").warning("self-test refused; audit write failed (%s)", type(e).__name__)
    raise SelfTestDisabled(SELF_TEST_REFUSAL)


@dataclass
class Attack:
    name: str
    category: str
    sql: str
    check: str = "value"
    sql_false: str = None  # oracle: the same probe with a wrong guess
    probes: str = None  # oracle/order: "table.column" being probed; only a leak if the role may not see it


def catalogue(dialect):
    catalog_read = (
        "SELECT name, sql FROM sqlite_master"
        if dialect == "sqlite"
        else "SELECT table_name, column_name FROM information_schema.columns"
    )
    file_read = "SELECT load_extension('evil')" if dialect == "sqlite" else "SELECT pg_read_file('/etc/passwd')"
    return [
        Attack("Direct projection", "projection", "SELECT email, ssn FROM users"),
        Attack("SELECT *", "projection", "SELECT * FROM users"),
        Attack("Alias rename", "projection", "SELECT email AS mail, ssn AS x FROM users"),
        Attack("Expression laundering", "projection", "SELECT lower(email) AS e, ssn || '' AS s FROM users"),
        Attack("Concatenation", "projection", "SELECT 'id:' || pan AS p FROM users"),
        Attack("CTE rename", "nesting", "WITH c AS (SELECT email AS mail FROM users) SELECT * FROM c"),
        Attack(
            "CTE shadows table name", "nesting", "WITH users AS (SELECT * FROM users) SELECT aadhaar AS a FROM users"
        ),
        Attack("Derived table", "nesting", "SELECT t.x FROM (SELECT ssn AS x FROM users) t"),
        Attack("UNION", "nesting", "SELECT pan AS v FROM users UNION SELECT aadhaar FROM users"),
        Attack(
            "Correlated subquery", "nesting", "SELECT (SELECT ssn FROM users u2 WHERE u2.id = u.id) AS s FROM users u"
        ),
        Attack(
            "Join", "nesting", "SELECT a.credit_card AS c, u.pan AS p FROM accounts a JOIN users u ON u.id = a.user_id"
        ),
        Attack("Aggregate MAX", "aggregate", "SELECT max(balance) AS top FROM accounts"),
        Attack("Single-row aggregate", "aggregate", "SELECT avg(balance) AS b FROM accounts WHERE id = 1"),
        Attack(
            "Equality oracle",
            "inference",
            "SELECT count(*) AS n FROM users WHERE email = '{email}'",
            "oracle",
            "SELECT count(*) AS n FROM users WHERE email = 'nobody@invalid.test'",
            "users.email",
        ),
        Attack(
            "Prefix (LIKE) oracle",
            "inference",
            "SELECT count(*) AS n FROM users WHERE ssn LIKE '{ssn5}%'",
            "oracle",
            "SELECT count(*) AS n FROM users WHERE ssn LIKE '000-0%'",
            "users.ssn",
        ),
        Attack(
            "Range (BETWEEN) oracle",
            "inference",
            "SELECT count(*) AS n FROM accounts WHERE balance BETWEEN {bal_lo} AND {bal_hi}",
            "oracle",
            "SELECT count(*) AS n FROM accounts WHERE balance BETWEEN -2 AND -1",
            "accounts.balance",
        ),
        Attack(
            "ORDER BY oracle",
            "inference",
            "SELECT id FROM users ORDER BY ssn, id LIMIT 20",
            "order",
            probes="users.ssn",
        ),
        Attack("Stacked statement", "firewall", "SELECT 1; DROP TABLE users", "reject"),
        Attack("Write statement", "firewall", "UPDATE users SET ssn = '0'", "reject"),
        Attack("Catalog read", "firewall", catalog_read, "reject"),
        Attack("Dangerous function", "firewall", file_read, "reject"),
    ]


def _facts(backend):
    def q(sql):
        return backend.admin_query(sql)[1]

    email, ssn = q("SELECT email, ssn FROM users ORDER BY id LIMIT 1")[0]
    bal = float(q("SELECT balance FROM accounts ORDER BY id LIMIT 1")[0][0])
    order = [r[0] for r in q("SELECT id FROM users ORDER BY ssn, id LIMIT 20")]
    return {"email": email, "ssn5": ssn[:5], "bal_lo": round(bal - 0.5, 2), "bal_hi": round(bal + 0.5, 2)}, order


def _secrets(backend, registry, role, policy):
    """Raw values of every column this role may not see in full."""
    out = set()
    for table, cols in registry.items():
        for col, meta in cols.items():
            action = action_for(meta, role, policy)
            if action == "allow":
                continue
            values = [
                str(r[0])
                for r in backend.admin_query(f"SELECT {quote_ident(col)} FROM {quote_ident(table)}")[1]  # noqa: S608 (identifiers via quote_ident)
                if r[0] is not None
            ]
            if action == "redact_text":  # the secret is the identifiers inside the text, not the whole sentence
                from .textpii import find

                out |= {span[3] for v in values for span in find(v)}
            else:
                out |= set(values)
    return out


def _leaks(rows, secrets):
    lengths = sorted({len(s) for s in secrets if len(s) >= 6})
    found = set()
    for r in rows:
        for cell in r:
            s = str(cell)
            if s in secrets:
                found.add(s)
                continue
            for n in lengths:  # substring search: catches 'id:' || pan and similar wrapping
                for i in range(len(s) - n + 1):
                    if s[i : i + n] in secrets:
                        found.add(s[i : i + n])
    return found


def _outcome(run, attack, facts, order, secrets, allowed=False):
    try:
        _cols, rows = run(attack.sql.format(**facts))
    except Rejected as e:
        return {"status": "rejected", "leak": False, "detail": str(e)[:100]}
    except Exception as e:  # noqa: BLE001 (any database failure is an attack outcome, reported by type only)
        return {"status": "db error", "leak": False, "detail": type(e).__name__}
    if attack.check == "reject":
        return {"status": "executed", "leak": False, "detail": f"{len(rows)} rows"}
    if attack.check == "value":
        found = _leaks(rows, secrets)
        return {
            "status": "LEAK" if found else "masked",
            "leak": bool(found),
            "detail": f"{len(found)} raw values in {len(rows)} rows",
        }
    if attack.check == "oracle":
        _, rows_false = run(attack.sql_false)
        signal = [tuple(map(str, r)) for r in rows] != [tuple(map(str, r)) for r in rows_false]
        leak = signal and not allowed
        return {
            "status": "allowed" if signal and allowed else "LEAK" if leak else "no signal",
            "leak": leak,
            "detail": f"true guess -> {rows[:1]}, false guess -> {rows_false[:1]}",
        }
    if attack.check == "order":
        signal = [r[0] for r in rows] == order
        leak = signal and not allowed
        return {
            "status": "allowed" if signal and allowed else "LEAK" if leak else "no signal",
            "leak": leak,
            "detail": "row order matches real values" if leak else "row order is not the real order",
        }
    raise ValueError(attack.check)


def run_suite(gateway, session, attacks=None, channel="engine"):
    """Returns one dict per attack with the naive and MaskGuard outcomes for this session's role. Development only."""
    require_self_test(gateway, session, channel)  # before the first read: the naive half bypasses the gateway
    backend, registry, policy, role = gateway.backend, gateway.registry, gateway.policy, session.role
    facts, order = _facts(backend)
    secrets = _secrets(backend, registry, role, policy)
    results = []
    for a in attacks or catalogue(backend.dialect):
        allowed = False
        if a.probes:  # the role may legitimately learn about a column it is allowed to see
            t, c = a.probes.split(".")
            allowed = action_for(registry.get(t, {}).get(c, {}), role, policy) == "allow"
        naive = _outcome(
            lambda sql: naive_query(backend, sql, role, registry, policy), a, facts, order, secrets, allowed
        )
        # self-test: masking is what is being measured here, so don't let it trip the threat engine for this user
        guard = _outcome(lambda sql: gateway.execute(session, sql, observe=False), a, facts, order, secrets, allowed)
        results.append({"attack": a.name, "category": a.category, "check": a.check, "naive": naive, "maskguard": guard})
    return results


def score(results):
    pii = [r for r in results if r["check"] != "reject"]
    fw = [r for r in results if r["check"] == "reject"]
    return {
        "pii_attacks": len(pii),
        "naive_leaks": sum(r["naive"]["leak"] for r in pii),
        "maskguard_leaks": sum(r["maskguard"]["leak"] for r in pii),
        "firewall_attacks": len(fw),
        "firewall_rejected": sum(r["maskguard"]["status"] == "rejected" for r in fw),
    }
