"""REST API v1: health, demo identities, policy, query builder, integrity, and authorization regressions."""
import base64, json

import pytest
from fastapi.testclient import TestClient

from maskguard import api, config


@pytest.fixture
def client(sqlite_env):
    api.state["app"] = sqlite_env.app
    yield TestClient(api.app)
    api.state.clear()


def demo(client, role):
    r = client.post("/auth/demo", json={"role": role})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_health_ready_meta(client):
    assert client.get("/health").json()["status"] == "ok"
    r = client.get("/ready")
    assert r.status_code == 200 and r.json()["ready"] and r.json()["checks"]["database"]["tables"] == 3
    m = client.get("/meta").json()
    assert m["demo_mode"] and {d["role"] for d in m["demo_identities"]} == {"admin", "support", "analyst", "auditor"}
    assert "password" not in json.dumps(m)


def test_same_query_different_roles(client):
    sql = {"sql": "SELECT name, ssn, email FROM users ORDER BY id LIMIT 1"}
    rows = {r: client.post("/query", json=sql, headers=demo(client, r)).json()["rows"][0]
            for r in ("admin", "support", "analyst", "auditor")}
    real = rows["admin"]
    assert rows["support"][1].startswith("XXX-XX-") and rows["support"][1][-4:] == real[1][-4:]
    assert rows["analyst"][0] == "REDACTED" and len(rows["analyst"][1]) == 32 and rows["analyst"][1] != real[1]
    assert rows["auditor"] == ["REDACTED"] * 3
    c = client.post("/demo/compare", json=sql, headers=demo(client, "admin")).json()["results"]
    assert c["support"]["rows"][0] == rows["support"] and c["admin"]["rows"][0] == real


def test_query_builder_validates_identifiers(client):
    h = demo(client, "support")
    r = client.post("/query/table", json={"table": "accounts", "columns": ["credit_card", "status"], "limit": 3}, headers=h)
    assert r.status_code == 200 and all("X" in row[0] and row[1] == "active" for row in r.json()["rows"])
    assert client.post("/query/table", json={"table": "users; DROP TABLE users", "limit": 1}, headers=h).status_code == 404
    assert client.post("/query/table", json={"table": "users", "columns": ["ssn) FROM users --"]}, headers=h).status_code == 400
    assert client.post("/query/table", json={"table": "users", "limit": 100000}, headers=h).status_code == 422


def test_role_cannot_be_chosen_by_the_client(client):
    h = demo(client, "support")
    r = client.post("/query", json={"sql": "SELECT ssn FROM users LIMIT 1", "role": "admin"}, headers=h).json()
    assert r["role"] == "support" and r["rows"][0][0].startswith("XXX")
    # forged and unsigned tokens
    tok = h["Authorization"].split()[1]
    head, body, sig = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["role"] = "admin"
    forged = head + "." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + "." + sig
    none = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=") + "." + \
        base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + "."
    for t in (forged, none, "garbage"):
        assert client.get("/me", headers={"Authorization": f"Bearer {t}"}).status_code == 401
    assert client.post("/auth/demo", json={"role": "root"}).status_code == 404


def test_capabilities_are_enforced_and_denials_audited(client, sqlite_env):
    sup, aud, adm = demo(client, "support"), demo(client, "auditor"), demo(client, "admin")
    for method, path in [("get", "/audit"), ("get", "/registry"), ("post", "/integrity/verify"), ("get", "/policy/matrix"),
                         ("get", "/threats"), ("get", "/pia"), ("post", "/scan"), ("get", "/diagnostics")]:
        assert getattr(client, method)(path, headers=sup).status_code == 403, path
    assert client.get("/audit", headers=aud).status_code == 200
    assert client.post("/integrity/verify", headers=aud).json()["status"] == "MATCH"
    assert client.post("/integrity/baseline", headers=aud).status_code == 403
    assert client.put("/policy/rules", json={"role": "support", "tag": "PII_HIGH", "action": "allow"}, headers=aud).status_code == 403
    assert client.post("/scan", headers=aud).status_code == 403
    denied = sqlite_env.gw.audit.search(decision="denied")
    assert {e["user"] for e in denied} == {"support.sam", "auditor.aud"}
    assert client.post("/integrity/baseline", json={"reason": "t"}, headers=adm).status_code == 200


def test_explain_other_roles_needs_policy_read(client):
    sup = demo(client, "support")
    ex = client.get("/policy/explain", params={"table": "accounts"}, headers=sup).json()
    assert ex["role"] == "support" and ex["row_filter"] == "status <> 'frozen'"
    assert client.get("/policy/explain", params={"table": "users", "role": "admin"}, headers=sup).status_code == 403
    assert client.get("/policy/explain", params={"table": "nope"}, headers=sup).status_code == 404
    aud = demo(client, "auditor")
    assert client.get("/policy/explain", params={"table": "users", "role": "analyst"}, headers=aud).status_code == 200
    roles = client.get("/roles", headers=sup).json()["roles"]
    assert next(r for r in roles if r["role"] == "admin").keys() == {"role", "label", "description"}


def test_policy_edit_flow(client, sqlite_env):
    adm = demo(client, "admin")
    q = {"sql": "SELECT phone FROM users ORDER BY id LIMIT 1"}
    chk = client.post("/policy/check", json={"role": "support", "tag": "PII_HIGH", "action": "allow"}, headers=adm).json()
    assert chk["weakening"] and chk["needs_confirmation"]
    r = client.put("/policy/rules", json={"role": "support", "tag": "PII_HIGH", "action": "allow"}, headers=adm)
    assert r.status_code == 409
    r = client.put("/policy/rules", json={"role": "support", "tag": "PII_HIGH", "action": "hmac"}, headers=adm).json()
    assert r["changed"]
    out = client.post("/query", json=q, headers=demo(client, "support")).json()
    assert out["policy_version"] == r["version"] and len(out["rows"][0][0]) == 32
    assert client.put("/policy/rules", json={"role": "support", "tag": "PII_HIGH", "action": "drop"}, headers=adm).status_code == 400
    hist = client.get("/policy/history", headers=adm).json()["history"]
    assert hist[-1]["to"] == "hmac" and hist[-1]["actor"] == "admin.ann"
    assert client.post("/policy/reset", headers=adm).status_code == 200
    assert sqlite_env.gw.audit.search(decision="policy_change")


def test_errors_do_not_leak_values(client, sqlite_env):
    h = demo(client, "support")
    ssn = sqlite_env.real("ssn")
    for sql in [f"SELECT * FROM users WHERE ssn = '{ssn}' AND", f"SELECT CAST(ssn AS INTEGER) / 0 FROM users",
                "SELECT nosuchcol FROM users", f"SELECT load_extension('{ssn}')", "SELECT * FROM sqlite_master"]:
        r = client.post("/query", json={"sql": sql}, headers=h)
        assert r.status_code == 400 or ssn not in r.text
        assert ssn not in r.text
    assert ssn not in open(sqlite_env.gw.audit.path).read()


def test_bypass_routes_return_nothing_raw(client, sqlite_env):
    h = demo(client, "analyst")
    raw = {v for v in sqlite_env.raw if len(v) >= 8}
    for method, path, body in [("get", "/tables", None), ("get", "/policy", None), ("get", "/me", None),
                               ("get", "/policy/explain?table=users", None), ("get", "/attacks", None),
                               ("post", "/query/table", {"table": "users", "limit": 50}),
                               ("post", "/demo/compare", {"sql": "SELECT * FROM users LIMIT 3", "roles": ["analyst"]})]:
        r = client.request(method.upper(), path, json=body, headers=h)
        assert r.status_code == 200, path
        assert not any(v in r.text for v in raw), path


def test_demo_mode_off_and_production_guard(client, monkeypatch):
    monkeypatch.setenv("MASKGUARD_DEMO", "0")
    assert client.post("/auth/demo", json={"role": "admin"}).status_code == 404
    assert client.get("/meta").json()["demo_identities"] == []
    tok = client.post("/auth/login", json={"username": "support.sam", "password": "support123"}).json()["token"]
    assert client.post("/demo/compare", json={"sql": "SELECT 1"}, headers={"Authorization": f"Bearer {tok}"}).status_code == 404
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.delenv("MASKGUARD_DEMO")
    assert config.demo_enabled() is False
    monkeypatch.setenv("MASKGUARD_DEMO", "1")
    with pytest.raises(RuntimeError):
        config.demo_enabled()


def test_production_refuses_the_demo_user_store(sqlite_env, monkeypatch, tmp_path):
    """Turning demo mode off removes /auth/demo only; production must also refuse to start with the demo users,
    otherwise admin.ann/admin123 still logs in through /auth/login."""
    from maskguard.auth import Authenticator, hash_password
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.delenv("MASKGUARD_DEMO", raising=False)
    demo_store = Authenticator.from_file(config.Settings().users)
    with pytest.raises(RuntimeError, match="demo identities"):
        config.check_production_identity(demo_store)
    prod = Authenticator({"ops.lead": {"role": "admin", "password_hash": hash_password("a-long-production-pass")}})
    config.check_production_identity(prod)  # a real user store is accepted
    with pytest.raises(RuntimeError, match="no users"):
        config.check_production_identity(Authenticator({}))


def test_scan_dry_run_does_not_change_registry(client, sqlite_env):
    adm = demo(client, "admin")
    before = dict(sqlite_env.gw.registry)
    r = client.post("/scan", json={"dry_run": True, "tables": ["users"], "sample_limit": 20}, headers=adm).json()
    assert r["dry_run"] and not r["applied"] and r["tables"] == ["users"] and "limitations" in r
    assert sqlite_env.gw.registry == before
    assert client.post("/scan", json={"tables": ["ghost"]}, headers=adm).status_code == 404


def test_ui_is_served_with_csp(client):
    r = client.get("/ui/")
    assert r.status_code == 200 and "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_demo_compare_cannot_borrow_a_stronger_role(client, sqlite_env):
    sql = {"sql": "SELECT ssn FROM users ORDER BY id LIMIT 1"}
    for low in ("auditor", "analyst", "support"):
        r = client.post("/demo/compare", json={**sql, "roles": ["admin"]}, headers=demo(client, low))
        assert r.status_code == 403 and sqlite_env.real("ssn") not in r.text, low
    # support may not borrow analyst/auditor either: they have no row filter, so they would see frozen accounts
    assert client.post("/demo/compare", json={**sql, "roles": ["analyst"]}, headers=demo(client, "support")).status_code == 403
    # defaults to the roles the caller may see as; admin may compare every role
    r = client.post("/demo/compare", json=sql, headers=demo(client, "auditor")).json()["results"]
    assert set(r) == {"auditor"}
    r = client.post("/demo/compare", json=sql, headers=demo(client, "admin")).json()["results"]
    assert set(r) == {"admin", "support", "analyst", "auditor"}
    assert any(e["target"].startswith("demo/compare") for e in sqlite_env.gw.audit.search(decision="denied"))


def test_demo_login_only_from_this_machine_unless_explicit(client, monkeypatch):
    monkeypatch.delenv("MASKGUARD_DEMO")       # demo on by default in development, but TestClient is not loopback
    r = client.post("/auth/demo", json={"role": "admin"})
    assert r.status_code == 403 and "this machine" in r.json()["detail"]
    monkeypatch.setenv("MASKGUARD_DEMO", "1")  # explicit opt-in allows remote demo logins
    assert client.post("/auth/demo", json={"role": "admin"}).status_code == 200


def test_recursive_queries_and_runaway_sqlite_queries_are_stopped(client, sqlite_env):
    h = demo(client, "analyst")
    r = client.post("/query", json={"sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c"}, headers=h)
    assert r.status_code == 400 and "recursive" in r.json()["detail"]
    b = sqlite_env.backend
    b.timeout_s = 0.2
    import time
    t0 = time.time()
    with pytest.raises(Exception) as e:  # a cross join big enough to run for minutes is interrupted
        b.execute("SELECT count(*) FROM users a, users b, users c, users d")
    assert time.time() - t0 < 3 and "interrupt" in str(e.value).lower()


def test_ambiguous_column_gets_a_helpful_safe_message(client):
    r = client.post("/query", json={"sql": "SELECT id FROM users u JOIN accounts a ON a.user_id = u.id LIMIT 1"}, headers=demo(client, "support"))
    assert r.status_code == 400 and "ambiguous column" in r.json()["detail"]
