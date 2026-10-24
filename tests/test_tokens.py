"""Analyst tokens (the `hmac` action): 128-bit by default, identical on every backend, optionally scoped per column so
equal values in different columns can't be linked through their tokens."""
import copy, re

import pytest

from maskguard import masks, policy as P


def _join_matches(env):
    """How many ticket contacts match a user's phone, seen through the analyst's tokens."""
    return len(env.run("analyst", "SELECT u.id FROM users u JOIN support_tickets t ON u.phone = t.contact")[1])


def test_tokens_are_128_bit_and_the_same_on_every_backend(env):
    real = env.real("ssn")
    tok = env.run("analyst", "SELECT ssn FROM users ORDER BY id LIMIT 1")[1][0][0]
    assert re.fullmatch(r"[0-9a-f]{32}", tok) and tok == masks.token(real)  # SQL function == Python, per backend
    assert tok[:16] == masks.token(real, 16)  # a 1.0.x token is a prefix of the 1.1 token (global scope)


def test_global_scope_keeps_tokens_joinable_and_column_scope_unlinks_columns(env, monkeypatch):
    env.backend.admin_script("UPDATE support_tickets SET contact = (SELECT phone FROM users WHERE id = 1) WHERE id = 1")
    assert _join_matches(env) >= 1  # default: the same phone number has the same token in both columns
    monkeypatch.setitem(env.gw.policy, "hmac", {"length": 32, "scope": "column"})
    assert _join_matches(env) == 0  # per-column tokens: nothing links the two columns
    tok = env.run("analyst", "SELECT ssn FROM users ORDER BY id LIMIT 1")[1][0][0]
    assert tok == masks.token(env.real("ssn"), 32, "users.ssn") and tok != masks.token(env.real("ssn"))
    a = env.run("analyst", "SELECT ssn FROM users ORDER BY id LIMIT 3")[1]
    assert a == env.run("analyst", "SELECT ssn FROM users ORDER BY id LIMIT 3")[1]  # still deterministic in its column


def test_token_length_is_configurable_and_validated(sqlite_env, monkeypatch):
    monkeypatch.setitem(sqlite_env.gw.policy, "hmac", {"length": 64, "scope": "global"})
    assert len(sqlite_env.run("analyst", "SELECT ssn FROM users LIMIT 1")[1][0][0]) == 64
    pol = copy.deepcopy(sqlite_env.gw.policy)
    for bad in ({"length": 8}, {"length": 99}, {"length": "32"}, {"scope": "table"}):
        pol["hmac"] = bad
        assert P.validate(pol), bad


def test_explain_preview_shows_the_configured_token(sqlite_env):
    cols = {c["column"]: c for c in P.explain("analyst", "users", sqlite_env.gw.registry, sqlite_env.gw.policy)["columns"]}
    assert re.fullmatch(r"[0-9a-f]{32}", cols["ssn"]["example_out"]) and "128-bit" in cols["ssn"]["transformation"]


@pytest.mark.parametrize("sql", ["SELECT mg_token(ssn, '', 32) FROM users", "SELECT mg_hmac(ssn) FROM users"])
def test_users_cannot_call_the_token_functions_themselves(sqlite_env, sql):
    from maskguard.rewriter import Rejected
    with pytest.raises(Rejected, match="function not allowed"):
        sqlite_env.run("analyst", sql)
