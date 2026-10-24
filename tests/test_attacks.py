import pytest
from maskguard.attacks import run_suite, score
from maskguard.auth import Session
from maskguard.rewriter import Rejected

ROLES = ["support", "analyst"]


def leaked(env, rows, role):
    secrets = env.raw | (env.names if role == "analyst" else set())  # Support may see names by policy
    return {str(c) for r in rows for c in r} & secrets


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("sql", [
    "SELECT email FROM users",
    "SELECT email AS contact FROM users",
    "SELECT * FROM users",
    "SeLeCt /* x */ ssn FROM USERS",
    "WITH c AS (SELECT email AS mail FROM users) SELECT * FROM c",
    "WITH users AS (SELECT * FROM users) SELECT aadhaar FROM users",
    "SELECT * FROM (SELECT ssn FROM users) t",
    "SELECT pan FROM users UNION SELECT aadhaar FROM users",
    "SELECT (SELECT ssn FROM users u2 WHERE u2.id = u.id) FROM users u",
    "SELECT a.credit_card, u.pan FROM accounts a JOIN users u ON u.id = a.user_id",
    "SELECT ssn FROM users ORDER BY ssn",
    "SELECT min(ssn), max(ssn), min(balance) FROM users, accounts",
    "SELECT contact, payment_ref FROM support_tickets",
    "SELECT CASE WHEN id > 0 THEN ssn END FROM users",
])
def test_no_raw_value_in_output(env, role, sql):
    _, rows = env.run(role, sql)
    assert rows and not leaked(env, rows, role)


@pytest.mark.parametrize("role", ROLES)
def test_predicates_on_masked_columns_learn_nothing(env, role):
    ssn = env.real("ssn")
    assert env.run(role, f"SELECT id FROM users WHERE email = '{env.real('email')}'")[1] == []
    assert env.run(role, f"SELECT id FROM users WHERE ssn LIKE '{ssn[:3]}%'")[1] == []


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("sql", [
    "DROP TABLE users", "SELECT 1; DROP TABLE users", "UPDATE users SET ssn='0'", "DELETE FROM users",
    "INSERT INTO users (id) VALUES (999)", "SELECT load_extension('x')", "SELECT pg_read_file('/etc/passwd')",
    "SELECT * FROM sqlite_master", "SELECT * FROM pg_catalog.pg_user", "SELECT * FROM information_schema.tables",
    "SELECT ssn INTO t FROM users", "SELECT * FROM other.users", "SELECT * FROM users FOR UPDATE",
    "SELECT current_setting('maskguard.hmac_key')", "SELECT mg_hmac(email) FROM users", "not sql at all ((",
])
def test_unsafe_statements_are_rejected(env, role, sql):
    with pytest.raises(Rejected):
        env.run(role, sql)


def test_role_comes_from_authenticated_session_only(env):
    with pytest.raises(PermissionError):
        env.gw.execute(Session("mallory", "admin"), "SELECT ssn FROM users")  # forged, not minted by auth
    with pytest.raises(PermissionError):
        env.auth.login("admin.ann", "wrong")


def test_admin_sees_real_values_support_sees_card_format(env):
    _, rows = env.run("admin", "SELECT ssn FROM users LIMIT 5")
    assert len(leaked(env, rows, "admin")) == 5
    cards = [r[0] for r in env.run("support", "SELECT credit_card FROM accounts")[1]]
    dashed = [c for c in cards if c.count("-") == 3]
    assert dashed and all(c[:4].isdigit() and c[5:14] == "XXXX-XXXX" and c[-4:].isdigit() for c in dashed)


def test_analyst_hmac_tokens_are_stable_and_joinable(env):
    a = env.run("analyst", "SELECT email FROM users ORDER BY id LIMIT 3")[1]
    b = env.run("analyst", "SELECT email FROM users ORDER BY id LIMIT 3")[1]
    assert a == b and all(len(r[0]) == 32 for r in a)
    n = env.run("analyst", "SELECT count(*) FROM users u JOIN users v ON u.email = v.email")[1][0][0]
    assert int(n) == 300


def test_row_cap_per_role(env):
    assert len(env.run("support", "SELECT id FROM users")[1]) == 100
    assert len(env.run("support", "SELECT id FROM users LIMIT 7")[1]) == 7
    assert len(env.run("admin", "SELECT id FROM users")[1]) == 300


def test_small_groups_are_suppressed_for_non_admin(env):
    big = "SELECT status, count(*) FROM accounts GROUP BY status"            # two groups of ~150
    small = "SELECT status, count(*) FROM accounts WHERE id <= 6 GROUP BY status"  # groups of < 5
    assert len(env.run("admin", small)[1]) >= 1 and all(int(n) < 5 for _, n in env.run("admin", small)[1])
    assert env.run("analyst", small)[1] == []
    assert sorted(env.run("analyst", big)[1]) == sorted(env.run("admin", big)[1])
    assert env.run("analyst", "SELECT avg(balance) FROM accounts WHERE id = 1")[1] == []
    assert env.run("support", "SELECT count(*) FROM users WHERE id = 1")[1] == []
    assert int(env.run("admin", "SELECT count(*) FROM users WHERE id = 1")[1][0][0]) == 1


@pytest.mark.parametrize("role", ROLES)
def test_attack_suite_zero_leaks_and_baseline_leaks(env, role):
    sc = score(run_suite(env.gw, env.login(role)))
    assert sc["maskguard_leaks"] == 0
    assert sc["firewall_rejected"] == sc["firewall_attacks"]
    assert sc["naive_leaks"] >= 10  # the comparison is meaningful: naive masking really does leak


def test_tables_unchanged_after_attacks(env):
    before = {t: env.backend.checksum(t) for t in env.backend.tables()}
    for role in ROLES:
        run_suite(env.gw, env.login(role))
    assert before == {t: env.backend.checksum(t) for t in env.backend.tables()}


def test_audit_log_has_no_pii_literals_and_chain_verifies(env):
    known = env.real("email")
    env.run("analyst", f"SELECT id FROM users WHERE email = '{known}'")
    with pytest.raises(Rejected):
        env.run("analyst", f"DELETE FROM users WHERE email = '{known}'")
    text = open(env.gw.audit.path).read()
    assert known not in text and '"decision": "reject"' in text and env.gw.audit.verify()


def test_admin_is_not_reported_as_leaking(env):
    sc = score(run_suite(env.gw, env.login("admin")))
    assert sc["maskguard_leaks"] == 0 and sc["naive_leaks"] == 0


@pytest.mark.parametrize("sql", [
    "SELECT id FROM users WHERE id = 1 OR id = 2",
    "SELECT id FROM users WHERE id > 1 AND NOT id = 3 AND city <> 'x'",
    "SELECT EXISTS (SELECT 1 FROM users WHERE id = 1)",
])
def test_ordinary_boolean_logic_is_allowed(env, sql):
    assert env.run("support", sql)[1]
