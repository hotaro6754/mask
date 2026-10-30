"""Regressions for the external source audit of October 2026: each test plants a sentinel and checks it can't get out.

* unreviewed columns: a column the scanner found nothing in is masked for non-admin roles until a person approves it
* SQL comments never reach the audit log or the database
* database error text never reaches a client (REST, proxy simple and extended protocol, classic dashboard)
* the `query` capability is enforced on every path, not only implied by being logged in
"""

import copy
import json
import shutil
import subprocess

import psycopg
import pytest

from maskguard import config
from maskguard import policy as P
from maskguard.audit import fingerprint
from maskguard.rewriter import Rejected, action_for, rewrite
from maskguard.scanner import scan, unreviewed
from tests.test_proxy import connect, proxy  # noqa: F401  (proxy is a fixture)

SENTINEL = "ZQX-SENTINEL-4417"
EMAIL = "sentinel@example.com"


# ---------------------------------------------------------------- unreviewed columns fail closed


def _plant(env):
    env.backend.admin_script(f"UPDATE users SET city = '{SENTINEL}'")
    reg = scan(env.backend)  # no approvals: what a real database looks like before anyone reviews it
    assert not reg["users"]["city"].get("tag")  # the scanner finds nothing in it
    env.gw.update_registry(reg)


def test_a_column_nobody_reviewed_is_masked_for_every_role_but_admin(env):
    _plant(env)
    assert ("users", "city") in unreviewed(env.gw.registry)
    for role in ("support", "analyst", "auditor"):
        rows = env.run(role, "SELECT city FROM users LIMIT 1")[1]
        assert rows == [("REDACTED",)], role
        # the unreviewed id is masked too, so filtering on it finds nothing: approve keys to use them
        assert env.run(role, "SELECT city FROM users WHERE id = 1")[1] == []
        # nor through a predicate, an alias or an expression on it
        for sql in (
            f"SELECT count(*) FROM users WHERE city = '{SENTINEL}'",
            "SELECT c FROM (SELECT city AS c FROM users) q",
            "SELECT upper(city) || '' FROM users",
        ):
            assert SENTINEL not in json.dumps(env.run(role, sql)[1]), (role, sql)
        # a small count is hidden by the group floor; either way no row matches the sentinel
        assert env.run(role, f"SELECT count(*) FROM users WHERE city = '{SENTINEL}'")[1] in ([], [(0,)])
    assert env.run("admin", "SELECT city FROM users WHERE id = 1")[1] == [(SENTINEL,)]  # admin: UNREVIEWED is allow


def test_approving_a_column_as_public_is_what_shows_it(env, tmp_path):
    _plant(env)
    path = tmp_path / "overrides.yaml"
    path.write_text("users:\n  city: {tag: PUBLIC}\n")
    env.gw.update_registry(scan(env.backend, overrides=config._load_yaml(str(path))))
    assert env.run("support", "SELECT city FROM users LIMIT 1")[1] == [(SENTINEL,)]


def test_a_policy_without_an_unreviewed_rule_falls_back_to_default_deny_for_everyone(sqlite_env):
    pol = copy.deepcopy(sqlite_env.gw.policy)
    for rules in pol["roles"].values():
        rules.pop("UNREVIEWED")
    assert {action_for({}, r, pol) for r in pol["roles"]} == {"deny"}
    assert action_for({"tag": "PUBLIC"}, "auditor", pol) == "allow"


def test_conditional_approvals_never_hide_a_detection(sqlite_env):
    reg = scan(
        sqlite_env.backend,
        overrides={
            "users": {"email": {"tag": "PUBLIC", "if_untagged": True}, "city": {"tag": "PUBLIC", "if_untagged": True}}
        },
    )
    assert reg["users"]["email"]["tag"] == "PII_HIGH" and reg["users"]["city"]["tag"] == "PUBLIC"


def test_demo_approvals_load_only_in_demo_mode_and_never_in_production(sqlite_env, monkeypatch):
    s = sqlite_env.app.settings
    assert config.load_overrides(s)["users"]["city"]["tag"] == "PUBLIC"  # demo mode (tests run with MASKGUARD_DEMO=1)
    monkeypatch.setenv("MASKGUARD_DEMO", "0")
    assert config.load_overrides(s) == {}
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.delenv("MASKGUARD_DEMO")
    assert config.load_overrides(s) == {}


def test_policy_views_label_the_two_states(sqlite_env):
    reg = scan(sqlite_env.backend)
    cols = {c["column"]: c for c in P.explain("support", "users", reg, sqlite_env.gw.policy)["columns"]}
    assert cols["city"]["tag"] == "UNREVIEWED" and cols["city"]["action"] == "redact"
    assert cols["city"]["rule"] == "roles.support.UNREVIEWED"
    assert "UNREVIEWED" in P.known_tags(sqlite_env.gw.policy, reg) and "PUBLIC" not in P.known_tags(
        sqlite_env.gw.policy, reg
    )
    bad = copy.deepcopy(sqlite_env.gw.policy)
    bad["roles"]["support"]["PUBLIC"] = "redact"
    assert any("PUBLIC" in e for e in P.validate(bad))
    _, warnings, _ = P.PolicyStore(copy.deepcopy(sqlite_env.gw.policy)).check_rule("support", "UNREVIEWED", "allow")
    assert any("nobody has reviewed" in w for w in warnings)


# ---------------------------------------------------------------- comments never reach the log or the database

COMMENTED = [
    f"SELECT id /* {EMAIL} */ FROM users",
    "SELECT /*+ MAX_EXECUTION_TIME(999999999) SET_VAR(sort_buffer_size=1) */ id FROM users",
    f"SELECT id FROM users -- {EMAIL}",
    f"SELECT /*+ {EMAIL} */ id FROM users",
    "SELECT id FROM users /*! UNION SELECT ssn FROM users */",
]


@pytest.mark.parametrize("dialect", ["sqlite", "postgres", "mysql"])
def test_fingerprints_and_rewritten_sql_carry_no_comments(sqlite_env, dialect):
    for sql in COMMENTED:
        fp = fingerprint(sql, dialect)
        assert EMAIL not in fp and "UNION" not in fp and "/*" not in fp and "--" not in fp, fp
        try:
            out = rewrite(sql, "support", sqlite_env.gw.registry, sqlite_env.gw.policy, dialect).sql
        except Rejected as e:  # MySQL parses /*+ f(...) */ as a hint; its functions are outside the allowlist
            assert dialect == "mysql" and "function not allowed" in str(e)
            continue
        assert EMAIL not in out and "UNION" not in out and "/*" not in out and "EXECUTION" not in out, out


def test_audit_entries_carry_no_comment_text(env):
    for sql in COMMENTED:
        try:
            env.run("support", sql)
        except Rejected:  # MySQL refuses the hint with functions; the refusal is audited too
            assert env.backend.dialect == "mysql"
    with open(env.gw.audit.path) as f:
        log = f.read()
    assert EMAIL not in log and "UNION SELECT ssn" not in log


# ---------------------------------------------------------------- database error text never reaches a client


def _leaky_backend(monkeypatch, app):
    def boom(sql):
        raise RuntimeError(f'invalid input syntax: "{EMAIL}"')  # what a real database error can quote

    monkeypatch.setattr(app.backend, "execute", boom)


def test_rest_cli_and_audit_never_echo_database_error_text(sqlite_env, monkeypatch):
    from fastapi.testclient import TestClient

    from maskguard import api
    from maskguard.service import Denied, LocalService

    _leaky_backend(monkeypatch, sqlite_env.app)
    monkeypatch.setitem(api.state, "app", sqlite_env.app)
    c = TestClient(api.app)
    tok = c.post("/auth/demo", json={"role": "support"}).json()["token"]
    r = c.post("/query", json={"sql": "SELECT id FROM users"}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 400 and r.json()["detail"] == "query failed: RuntimeError"
    with pytest.raises(Denied) as e:
        LocalService(sqlite_env.app).query("SELECT id FROM users", role="support")
    assert EMAIL not in str(e.value)
    with open(sqlite_env.gw.audit.path) as f:
        assert EMAIL not in f.read()


def test_proxy_never_echoes_database_error_text_on_the_extended_protocol(proxy, monkeypatch):
    env, port = proxy
    _leaky_backend(monkeypatch, env.app)
    conn = connect(port, "support.sam", "support123")  # psycopg: Parse/Bind/Describe/Execute
    for prepare in (False, True):
        with pytest.raises(psycopg.Error) as e:
            conn.execute("SELECT id FROM users WHERE id = %s", (1,), prepare=prepare)
        assert EMAIL not in str(e.value) and "query failed: RuntimeError" in str(e.value), prepare


@pytest.mark.skipif(not shutil.which("psql"), reason="psql not installed")
def test_proxy_never_echoes_database_error_text_on_the_simple_protocol(proxy, monkeypatch):
    env, port = proxy
    _leaky_backend(monkeypatch, env.app)
    out = subprocess.run(
        [
            "psql",
            f"host=127.0.0.1 port={port} user=support.sam dbname=bank sslmode=disable",
            "-At",
            "-c",
            "SELECT id FROM users",
        ],
        env={"PGPASSWORD": "support123", "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert out.returncode != 0 and "query failed: RuntimeError" in out.stderr and EMAIL not in out.stderr + out.stdout


def test_classic_dashboard_never_echoes_database_error_text(sqlite_env, monkeypatch):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setattr(config, "build", lambda *a, **k: sqlite_env.app)
    _leaky_backend(monkeypatch, sqlite_env.app)
    st.cache_resource.clear()
    try:
        at = AppTest.from_file("../src/maskguard/dashboard.py", default_timeout=60).run()
        user, pw = config.DEMO_ACCOUNTS["support"]
        at.text_input[0].set_value(user)
        at.text_input[1].set_value(pw)
        next(b for b in at.button if b.label == "Log in").click().run()
        next(b for b in at.button if b.label == "Run query").click().run()
        errors = [e.value for e in at.error]
        assert errors and all(EMAIL not in e for e in errors) and "query failed: RuntimeError" in errors
    finally:
        st.cache_resource.clear()


# ---------------------------------------------------------------- the query capability


def _no_query(policy):
    pol = copy.deepcopy(policy)
    pol["role_info"]["support"]["capabilities"] = []
    return pol


def test_a_role_without_the_query_capability_reads_nothing_on_any_path(sqlite_env, monkeypatch):
    from fastapi.testclient import TestClient

    from maskguard import api

    gw = sqlite_env.gw
    monkeypatch.setattr(gw, "policy", _no_query(gw.policy))
    reads = []
    orig = gw.backend.execute
    monkeypatch.setattr(gw.backend, "execute", lambda sql: (reads.append(sql), orig(sql))[1])
    with pytest.raises(Rejected, match="lacks capability 'query'"):  # engine, CLI, SDK, dashboards, proxy
        sqlite_env.run("support", "SELECT id FROM users")
    monkeypatch.setitem(api.state, "app", sqlite_env.app)
    c = TestClient(api.app)
    h = {"Authorization": f"Bearer {c.post('/auth/demo', json={'role': 'support'}).json()['token']}"}
    assert c.post("/query", json={"sql": "SELECT id FROM users"}, headers=h).status_code == 403
    assert c.post("/query/table", json={"table": "users", "columns": ["id"]}, headers=h).status_code == 403
    assert reads == []
    assert sqlite_env.run("analyst", "SELECT id FROM users LIMIT 1")[1]  # roles that keep it still work


def test_proxy_describe_also_needs_the_query_capability(proxy, monkeypatch):
    env, port = proxy
    monkeypatch.setattr(env.gw, "policy", _no_query(env.gw.policy))
    conn = connect(port, "support.sam", "support123")
    with pytest.raises(psycopg.Error, match="lacks capability 'query'"):
        conn.execute("SELECT id FROM users WHERE id = %s", (1,), prepare=True)
