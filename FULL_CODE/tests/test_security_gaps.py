"""Security properties from the October 2026 engineering audit (docs/SECURITY_ANALYSIS.md) that had no test yet.

* every statement that is not one SELECT is refused before the database sees it, in all three dialects
* tokens: expired, signed with another algorithm, or for a user whose role changed are refused
* a failed audit write withholds the result and leaves the hash chain verifiable
"""

import time

import jwt
import pytest

from maskguard.audit import AuditLog
from maskguard.rewriter import Rejected, rewrite

NOT_A_SELECT = [
    "TRUNCATE users",
    "TRUNCATE TABLE users",
    "DELETE FROM users",
    "UPDATE users SET name = 'x'",
    "INSERT INTO users (name) VALUES ('x')",
    "DROP TABLE users",
    "ALTER TABLE users ADD COLUMN x INT",
    "CREATE TABLE x (a INT)",
    "CREATE TABLE x AS SELECT ssn FROM users",
    "GRANT ALL ON users TO public",
    "BEGIN",
    "COMMIT",
    "ROLLBACK",
    "SET search_path = public",
    "CALL refresh_all()",
    "EXPLAIN SELECT ssn FROM users",
    "SELECT name FROM users; DELETE FROM users",
    "SELECT name FROM users; SELECT ssn FROM users",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT n FROM r",
]
DIALECT_SPECIFIC = {
    "sqlite": ["ATTACH DATABASE 'x.db' AS x", "PRAGMA table_info(users)", "VACUUM"],
    "postgres": [
        "COPY users TO '/tmp/out.csv'",
        "COPY (SELECT ssn FROM users) TO STDOUT",
        "LOCK TABLE users",
        "SELECT ssn INTO stolen FROM users",
        "DO $$ BEGIN END $$",
    ],
    "mysql": [
        "LOAD DATA INFILE '/tmp/x' INTO TABLE users",
        "SELECT ssn FROM users INTO OUTFILE '/tmp/x'",
        "LOCK TABLES users READ",
        "HANDLER users OPEN",
    ],
}
CASES = [(d, sql) for d in DIALECT_SPECIFIC for sql in NOT_A_SELECT + DIALECT_SPECIFIC[d]]


@pytest.mark.parametrize(("dialect", "sql"), CASES)
def test_anything_but_one_select_is_refused_before_the_database(sqlite_env, dialect, sql):
    with pytest.raises(Rejected):
        rewrite(sql, "support", sqlite_env.gw.registry, sqlite_env.gw.policy, dialect)


def test_refused_statements_change_nothing(sqlite_env):
    before = sqlite_env.backend.checksum("users")
    for sql in ["TRUNCATE users", "DELETE FROM users", "SELECT name FROM users; DELETE FROM users"]:
        with pytest.raises(Rejected):
            sqlite_env.run("admin", sql)
    assert sqlite_env.backend.checksum("users") == before


# ---------------------------------------------------------------- identity


def _claims(env, role="support"):
    session = env.login(role)
    return jwt.decode(env.auth.issue_token(session), env.auth.jwt_secret, algorithms=["HS256"])


def test_an_expired_token_is_refused(sqlite_env):
    claims = _claims(sqlite_env) | {"exp": int(time.time()) - 1}
    with pytest.raises(PermissionError, match="expired"):
        sqlite_env.auth.session_from_token(jwt.encode(claims, sqlite_env.auth.jwt_secret, algorithm="HS256"))


def test_a_token_signed_with_another_algorithm_is_refused_even_with_the_right_key(sqlite_env):
    token = jwt.encode(_claims(sqlite_env), sqlite_env.auth.jwt_secret, algorithm="HS512")
    with pytest.raises(PermissionError, match="invalid token"):
        sqlite_env.auth.session_from_token(token)


def test_a_valid_token_stops_working_when_the_users_role_changes(sqlite_env):
    token = sqlite_env.auth.issue_token(sqlite_env.login("support"))
    user = sqlite_env.auth.session_from_token(token).user
    sqlite_env.auth.users[user]["role"] = "analyst"
    with pytest.raises(PermissionError, match="no longer valid"):
        sqlite_env.auth.session_from_token(token)


def test_a_token_claiming_a_higher_role_is_refused(sqlite_env):
    claims = _claims(sqlite_env) | {"role": "admin"}  # validly signed, but the user store says support
    with pytest.raises(PermissionError, match="no longer valid"):
        sqlite_env.auth.session_from_token(jwt.encode(claims, sqlite_env.auth.jwt_secret, algorithm="HS256"))


# ---------------------------------------------------------------- audit failures fail closed


def test_a_failed_audit_write_withholds_the_result_and_keeps_the_chain_verifiable(sqlite_env, tmp_path, monkeypatch):
    log = AuditLog(str(tmp_path / "audit.jsonl"))
    sqlite_env.gw.audit = log
    sqlite_env.run("support", "SELECT name FROM users LIMIT 1")
    real_open = __import__("os").open

    def full_disk(path, *a, **kw):
        if str(path).endswith("audit.jsonl"):
            raise OSError(28, "No space left on device")
        return real_open(path, *a, **kw)

    monkeypatch.setattr("maskguard.audit.os.open", full_disk)
    with pytest.raises(OSError):
        sqlite_env.run("support", "SELECT ssn FROM users LIMIT 1")  # no audit entry, so no result
    monkeypatch.undo()
    sqlite_env.run("support", "SELECT name FROM users LIMIT 1")
    assert log.verify() and log.head()["entries"] == 2


# ---------------------------------------------------------------- identifiers from the catalogue


def test_a_quote_inside_a_table_or_column_name_stays_inside_the_identifier(sqlite_env):
    from maskguard.backends import quote_ident
    from maskguard.scanner import scan_table

    assert quote_ident('a"b') == '"a""b"'
    name, column = 'odd"table', 'x" FROM users --'
    sqlite_env.backend.conn.execute(f"CREATE TABLE {quote_ident(name)} ({quote_ident(column)} TEXT)")
    sqlite_env.backend.conn.executemany(f"INSERT INTO {quote_ident(name)} VALUES (?)", [("ravi@bank.in",)] * 5)
    assert sqlite_env.backend.sample(name, column) == ["ravi@bank.in"] * 5  # its own values, not users'
    assert column in scan_table(sqlite_env.backend, name)
