"""API, auth, audit, CLI, cross-backend function parity and the dashboard."""
import json
import jwt
import pytest
from fastapi.testclient import TestClient

from maskguard import api, masks
from maskguard.audit import AuditLog
from maskguard.auth import check_password, hash_password
from tests.conftest import MYSQL_URL, PG_URL


@pytest.fixture
def client(sqlite_env):
    api.state["app"] = sqlite_env.app
    yield TestClient(api.app)
    api.state.clear()


def token(client, user, pw):
    r = client.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_api_masks_per_role(client):
    q = {"sql": "SELECT credit_card, balance FROM accounts ORDER BY id LIMIT 1"}
    admin = client.post("/query", json=q, headers=token(client, "admin.ann", "admin123")).json()
    support = client.post("/query", json=q, headers=token(client, "support.sam", "support123")).json()
    analyst = client.post("/query", json=q, headers=token(client, "analyst.ali", "analyst123")).json()
    assert "X" not in admin["rows"][0][0] and "X" in support["rows"][0][0]
    assert analyst["rows"][0] == ["REDACTED", None]
    assert "mg_partial" in support["rewritten_sql"].lower()


def test_api_auth_errors(client):
    assert client.post("/auth/login", json={"username": "admin.ann", "password": "x"}).status_code == 401
    assert client.post("/query", json={"sql": "SELECT 1"}).status_code == 401
    forged = jwt.encode({"sub": "admin.ann", "role": "admin", "exp": 9999999999}, "attacker-secret", algorithm="HS256")
    assert client.get("/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
    h = token(client, "support.sam", "support123")
    assert client.get("/registry", headers=h).status_code == 403
    assert client.post("/query", json={"sql": "DROP TABLE users"}, headers=h).status_code == 400


def test_api_admin_endpoints_and_attacks(client):
    h = token(client, "admin.ann", "admin123")
    assert len(client.get("/registry", headers=h).json()["tagged"]) >= 10
    assert client.get("/audit", headers=h).json()["chain_valid"] is True
    assert set(client.get("/integrity", headers=h).json()) == {"users", "accounts", "support_tickets"}
    r = client.get("/attacks", headers=token(client, "analyst.ali", "analyst123")).json()
    assert r["score"]["maskguard_leaks"] == 0


def test_role_change_invalidates_existing_token(sqlite_env):
    auth = sqlite_env.auth
    t = auth.issue_token(auth.login("support.sam", "support123"))
    auth.users["support.sam"]["role"] = "analyst"
    with pytest.raises(PermissionError):
        auth.session_from_token(t)


def test_password_hashing():
    h = hash_password("s3cret")
    assert check_password("s3cret", h) and not check_password("nope", h) and "s3cret" not in h


def test_audit_chain_survives_restart_and_detects_tampering(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(str(p)).append(user="u", decision="allow")
    AuditLog(str(p)).append(user="u", decision="allow")  # new process, same file
    assert AuditLog(str(p)).verify()
    lines = p.read_text().splitlines()
    e = json.loads(lines[0]); e["decision"] = "reject"
    p.write_text(json.dumps(e) + "\n" + lines[1] + "\n")
    assert not AuditLog(str(p)).verify()


def test_cli_roles_and_attack(sqlite_env, capsys, monkeypatch, tmp_path):
    from maskguard import cli
    monkeypatch.setenv("MASKGUARD_DB", f"sqlite:///{tmp_path}/cli.db")
    monkeypatch.setenv("MASKGUARD_SEED_IF_EMPTY", "1")
    monkeypatch.setenv("MASKGUARD_AUDIT", str(tmp_path / "cli-audit.jsonl"))
    monkeypatch.setenv("MASKGUARD_REGISTRY", str(tmp_path / "cli-reg.yaml"))
    assert cli.main(["roles", "SELECT ssn FROM users ORDER BY id LIMIT 1"]) == 0
    out = capsys.readouterr().out
    assert "XXX-XX-" in out and "REDACTED" not in out.split("ANALYST ·")[0]
    assert cli.main(["attack", "-u", "support.sam", "-p", "support123"]) == 0
    assert "MaskGuard 0/" in capsys.readouterr().out
    assert cli.main(["audit", "--verify"]) == 0


@pytest.mark.skipif(not PG_URL, reason="MASKGUARD_TEST_PG not set")
def test_postgres_functions_match_python():
    from maskguard.backends import PostgresBackend
    b = PostgresBackend(PG_URL)
    for v in ["4111-2222-3333-1111", "123-45-6789", "ABCDE1234F", "x", "", "अंकिता साहा", "Ravi*Kumar!", "+91 98765 43210"]:
        for pre, suf in [(4, 4), (0, 4), (2, 1), (1, 0)]:
            assert b.admin_query("SELECT mg_partial(%s, %s, %s)", (v, pre, suf))[1][0][0] == masks.partial(v, pre, suf)
    for v in ["ravi@bank.in", "noatsign", "a@", "@b.c"]:
        assert b.admin_query("SELECT mg_email(%s)", (v,))[1][0][0] == masks.email(v)
    for v in ["ravi@bank.in", "123-45-6789"]:
        assert b.admin_query("SELECT mg_hmac(%s)", (v,))[1][0][0] == masks.token(v, 16)  # 1.0.x function, kept
        for scope, n in [("", 32), ("users.ssn", 32), ("t.c", 64)]:
            assert b.admin_query("SELECT mg_token(%s, %s, %s)", (v, scope, n))[1][0][0] == masks.token(v, n, scope)


def test_dashboard_renders_for_every_role(tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("MASKGUARD_DB", f"sqlite:///{tmp_path}/dash.db")
    monkeypatch.setenv("MASKGUARD_SEED_IF_EMPTY", "1")
    monkeypatch.setenv("MASKGUARD_AUDIT", str(tmp_path / "dash-audit.jsonl"))
    monkeypatch.setenv("MASKGUARD_REGISTRY", str(tmp_path / "dash-reg.yaml"))
    at = AppTest.from_file("../src/maskguard/dashboard.py", default_timeout=60).run()
    assert not at.exception
    for role in ["admin", "support", "analyst"]:
        at.radio(key="role_toggle").set_value(role).run()
        assert not at.exception
        at.button[0].click().run()  # "Run query" (compare all roles)
        assert not at.exception and not at.error
    at.radio(key="role_toggle").set_value("admin").run()
    next(b for b in at.button if b.label == "Run simulated attack").click().run()
    assert not at.exception and any("blocked at query" in e.value for e in at.error)


@pytest.mark.skipif(not MYSQL_URL, reason="MASKGUARD_TEST_MYSQL not set")
def test_mysql_functions_match_python():
    from maskguard import textpii
    from maskguard.backends import MySQLBackend
    b = MySQLBackend(MYSQL_URL)
    q = lambda sql, *a: b.admin_query(sql, a)[1][0][0]
    for v in ["4111-2222-3333-1111", "123-45-6789", "ABCDE1234F", "x", "", "अंकिता साहा", "Ravi*Kumar!", "+91 98765 43210"]:
        for pre, suf in [(4, 4), (0, 4), (2, 1), (1, 0)]:
            assert q("SELECT mg_partial(%s, %s, %s)", v, pre, suf) == masks.partial(v, pre, suf)
    for v in ["ravi@bank.in", "noatsign", "a@", "@b.c"]:
        assert q("SELECT mg_email(%s)", v) == masks.email(v)
    for v in ["ravi@bank.in", "123-45-6789", "x" * 200]:
        assert q("SELECT mg_hmac(%s)", v) == masks.token(v, 16)  # 1.0.x function, kept
        for scope, n in [("", 32), ("users.ssn", 32), ("t.c", 64)]:
            assert q("SELECT mg_token(%s, %s, %s)", v, scope, n) == masks.token(v, n, scope)
    for t in ["Call 98765 43210 or mail a@b.co", "Aadhaar 2345 6789 0124, PAN ABCPK1234L", "दर्ज मूल्य 12 जनवरी 1961 है।",
              "UPI ravi.k@okaxis, card 4111-1111-1111-1111, pin 560001"]:
        assert q("SELECT mg_redact_text(%s)", t) == textpii.redact(t)


def test_automated_pia(sqlite_env):
    from maskguard.pia import build, to_markdown
    from maskguard.threat_sim import live_attack
    env = sqlite_env
    env.run("support", "SELECT ssn FROM users LIMIT 1")
    live_attack(env.gw, env.auth.login("intruder.ian", "intruder123"), "enumeration", n=40)
    env.gw.query(env.login("analyst"), "SELECT avg(balance) FROM accounts")
    r = build(env.app)
    cols = {f"{i['table']}.{i['column']}" for i in r["inventory"]}
    assert {"users.aadhaar", "accounts.balance", "support_tickets.message"} <= cols
    row = next(m for m in r["access_matrix"] if m["column"] == "accounts.balance")
    assert row == {"column": "accounts.balance", "admin": "full value", "support": "partially masked",
                   "analyst": "noisy SUM/AVG/COUNT only", "auditor": "redacted"}
    assert any(t["user"] == "intruder.ian" and t["action"] == "block" for t in r["activity"]["threat_events"])
    assert r["activity"]["epsilon_spent"]["analyst.ali"] == 0.5 and r["controls"]["audit_chain_valid"]
    md = to_markdown(r)
    assert "Who sees what" in md and "Rule 6" in md and "8876" not in md
