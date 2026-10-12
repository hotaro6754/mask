import pytest
from maskguard.rewriter import Rejected

U = {"admin": "ann", "support": "sam", "analyst": "ali", "intern": "eve"}
ROLES = ["support", "analyst"]

def run(env, role, sql):
    return env.gw.execute(env.auth.login(U[role], "pw"), sql)

def leaked(env, rows, role):
    secrets = env.raw | (env.names if role == "analyst" else set())  # Support may see names by policy
    return {str(c) for r in rows for c in r} & secrets

def real(env, col):
    return env.conn.execute(f"SELECT {col} FROM users LIMIT 1").fetchone()[0]

@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("sql", [
    "SELECT email FROM users",
    "SELECT email AS contact FROM users",                                           # alias
    "SELECT * FROM users",                                                           # star
    "SeLeCt /* x */ ssn FROM USERS",                                                 # case + comment
    "WITH c AS (SELECT email AS contact FROM users) SELECT * FROM c",                # CTE
    "WITH users AS (SELECT * FROM users) SELECT aadhaar FROM users",                 # CTE shadowing
    "SELECT * FROM (SELECT ssn FROM users) t",                                       # subquery
    "SELECT pan FROM users UNION SELECT aadhaar FROM users",                         # set operation
    "SELECT (SELECT ssn FROM users u2 WHERE u2.id = u.id) FROM users u",             # correlated
    "SELECT a.credit_card, u.pan FROM accounts a JOIN users u ON u.id = a.user_id",  # join
    "SELECT ssn FROM users ORDER BY ssn",                                            # ordering probe
    "SELECT min(ssn), max(ssn), min(balance) FROM users, accounts",                  # aggregate probe
])
def test_no_raw_value_in_output(env, role, sql):
    _, rows = run(env, role, sql)
    assert rows and not leaked(env, rows, role)

@pytest.mark.parametrize("role", ROLES)
def test_predicates_on_masked_columns_learn_nothing(env, role):
    ssn = real(env, "ssn")
    assert run(env, role, f"SELECT id FROM users WHERE email = '{real(env, 'email')}'")[1] == []
    assert run(env, role, f"SELECT id FROM users WHERE ssn LIKE '{ssn[:3]}%'")[1] == []

@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("sql", ["DROP TABLE users", "SELECT 1; DROP TABLE users", "UPDATE users SET ssn='0'",
                                 "SELECT load_extension('x')", "SELECT * FROM sqlite_master", "SELECT ssn INTO t FROM users"])
def test_unsafe_statements_are_rejected(env, role, sql):
    with pytest.raises(Rejected):
        run(env, role, sql)

def test_role_comes_from_session_only(env):
    from maskguard.gateway import Session
    with pytest.raises(PermissionError):
        env.gw.execute(Session("mallory", "admin"), "SELECT ssn FROM users")
    with pytest.raises(Rejected):
        run(env, "intern", "SELECT 1 FROM users")  # role not in policy -> deny

def test_admin_sees_real_values_support_sees_card_format(env):
    assert len(leaked(env, run(env, "admin", "SELECT ssn FROM users LIMIT 5")[1], "admin")) == 5
    cc = run(env, "support", "SELECT credit_card FROM accounts LIMIT 1")[1][0][0]
    assert cc[:4].isdigit() and "X" in cc and cc[-4:].isdigit()

def test_audit_log_never_contains_pii_literals(env):
    known = real(env, "email")
    run(env, "analyst", f"SELECT id FROM users WHERE email = '{known}'")
    assert known not in open(env.gw.audit.path).read() and env.gw.audit.verify()
