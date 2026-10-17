"""Production profile: startup refuses unsafe configurations, the gateway's DB account is least-privilege, the API
only leaves loopback over TLS, and the shipped Compose files keep the database behind the gateway."""
import os, re, secrets, shutil, socket, subprocess, sys, time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import pytest
import yaml

from maskguard import cli, config
from maskguard.attacks import SELF_TEST_REFUSAL, SelfTestDisabled, run_suite, self_test_allowed
from maskguard.auth import Authenticator, hash_password
from maskguard.rewriter import Rejected
from tests.conftest import MYSQL_URL, PG_URL

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_USERS = {"ops.lead": ("admin", "ops-lead-test-passphrase"), "desk.agent": ("support", "desk-agent-test-passphrase")}


def _users_file(path):
    path.write_text(yaml.safe_dump({"users": {u: {"role": r, "password_hash": hash_password(p)}
                                              for u, (r, p) in PROD_USERS.items()}}))
    return str(path)


@pytest.fixture
def prod(monkeypatch, tmp_path):
    """A complete, valid production environment (database URL set per test)."""
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.setenv("MASKGUARD_DEMO", "0")
    monkeypatch.delenv("MASKGUARD_SEED_IF_EMPTY", raising=False)
    monkeypatch.setenv("MASKGUARD_USERS", _users_file(tmp_path / "users.yaml"))
    monkeypatch.setenv("MASKGUARD_JWT_SECRET", secrets.token_hex(32))
    monkeypatch.setenv("MASKGUARD_HMAC_KEY", secrets.token_hex(32))
    monkeypatch.setenv("MASKGUARD_DB", "postgresql://gateway@db.internal:5432/bank")
    monkeypatch.setenv("MASKGUARD_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("MASKGUARD_REGISTRY", str(tmp_path / "registry.yaml"))
    return tmp_path


# ---------------------------------------------------------------- startup validation

def test_complete_production_configuration_has_no_problems(prod):
    assert config.production_problems(config.Settings()) == []


def test_unknown_environment_is_refused_not_treated_as_development(monkeypatch):
    monkeypatch.setenv("MASKGUARD_ENV", "prod")
    with pytest.raises(config.UnsafeConfiguration, match="not one of"):
        config.environment()


def test_bare_production_lists_every_problem_at_once(prod, monkeypatch):
    for name in ("MASKGUARD_USERS", "MASKGUARD_JWT_SECRET", "MASKGUARD_HMAC_KEY", "MASKGUARD_DB"):
        monkeypatch.delenv(name)
    problems = "\n".join(config.production_problems(config.Settings()))
    for expected in ("demo user store", "MASKGUARD_JWT_SECRET is not set", "MASKGUARD_HMAC_KEY is not set",
                     "SQLite demo database"):
        assert expected in problems


@pytest.mark.parametrize("name", ["MASKGUARD_JWT_SECRET", "MASKGUARD_HMAC_KEY"])
@pytest.mark.parametrize("value,why", [("short-but-random-9f2c", "shorter than"),
                                       ("dev-only-jwt-secret-change-me-0123456789", "placeholder"),
                                       ("test-key-not-for-prod-0123456789abcdef0123", "placeholder")])
def test_weak_or_example_secrets_are_refused(prod, monkeypatch, name, value, why):
    monkeypatch.setenv(name, value)
    assert any(name in p and why in p for p in config.production_problems(config.Settings()))


def test_demo_user_store_and_demo_mode_are_refused(prod, monkeypatch):
    monkeypatch.setenv("MASKGUARD_USERS", os.path.join(ROOT, "policies", "users.demo.yaml"))
    monkeypatch.setenv("MASKGUARD_DEMO", "1")
    problems = "\n".join(config.production_problems(config.Settings()))
    assert "demo user store" in problems and "MASKGUARD_DEMO must be 0" in problems
    with pytest.raises(config.UnsafeConfiguration, match="demo identities"):  # a copy elsewhere is caught too
        config.check_production_identity(Authenticator.from_file(os.path.join(ROOT, "policies", "users.demo.yaml")))


def test_seeding_is_off_by_default_and_cannot_be_switched_on(prod, monkeypatch):
    assert config.Settings().seed_if_empty is False
    monkeypatch.setenv("MASKGUARD_SEED_IF_EMPTY", "1")
    assert any("SEED_IF_EMPTY" in p for p in config.production_problems(config.Settings()))
    monkeypatch.delenv("MASKGUARD_SEED_IF_EMPTY")
    assert any("SEED_IF_EMPTY" in p for p in config.production_problems(config.Settings(seed_if_empty=True)))


def test_build_refuses_before_touching_the_database(prod, monkeypatch):
    db = prod / "never-created.db"
    monkeypatch.setenv("MASKGUARD_DB", f"sqlite:///{db}")
    with pytest.raises(config.UnsafeConfiguration, match="PostgreSQL or MySQL"):
        config.build()
    assert not db.exists()


def test_development_defaults_are_unchanged(monkeypatch):
    monkeypatch.delenv("MASKGUARD_ENV", raising=False)
    monkeypatch.delenv("MASKGUARD_SEED_IF_EMPTY", raising=False)
    assert config.environment() == "development" and config.Settings().seed_if_empty is True
    assert config.listen_problems("api", "0.0.0.0") == [] and config.listen_problems("proxy", "0.0.0.0") == []


# ---------------------------------------------------------------- noisy aggregates off in production (D11)

def test_production_refuses_noisy_aggregates_but_keeps_masking(sqlite_env):
    """docs/design/PRIVACY_ACCOUNTING.md D11. Same gateway as production builds (allow_dp=False), on synthetic data."""
    gw = sqlite_env.gw
    assert gw.allow_dp is True  # development default is unchanged
    gw.allow_dp = False
    analyst, before = sqlite_env.login("analyst"), gw.dp_ledger.remaining("analyst.ali")
    with pytest.raises(Rejected, match="disabled in production"):
        gw.query(analyst, "SELECT status, avg(balance) AS a FROM accounts GROUP BY status", observe=False)
    assert gw.dp_ledger.remaining("analyst.ali") == before  # refused before any budget was charged
    assert gw.audit.tail(1)[0]["reason"] == "noisy aggregates disabled in production"
    token = gw.query(analyst, "SELECT email FROM users ORDER BY id LIMIT 1", observe=False).rows[0][0]
    assert re.fullmatch(r"[0-9a-f]{16}", token)  # ordinary masking still works for analysts
    assert gw.query(analyst, "SELECT balance FROM accounts LIMIT 1", observe=False).rows[0][0] in (None, "REDACTED")
    admin = sqlite_env.login("admin")
    assert gw.query(admin, "SELECT SUM(balance) FROM accounts", observe=False).rows[0][0] > 0  # admins unaffected
    from maskguard.pia import build, to_markdown
    assert "Noisy aggregates: disabled in production" in to_markdown(build(sqlite_env.app))


# ---------------------------------------------------------------- self-tests off in production

def _db_calls(monkeypatch, gw):
    """Records every way a self-test could reach the data: direct backend calls and gateway queries."""
    calls = []

    def spy(obj, name):
        orig = getattr(obj, name)
        monkeypatch.setattr(obj, name, lambda *a, **k: (calls.append(name), orig(*a, **k))[1])
    for name in ("execute", "admin_query", "admin_script", "checksum"):
        spy(gw.backend, name)
    spy(gw, "query")
    return calls


def _self_test_refusals(gw, n):
    entries = gw.audit.tail(n)
    assert len(entries) == n and all(e["decision"] == "reject" and SELF_TEST_REFUSAL in e["reason"] for e in entries)
    assert not any("sql" in e or "rewritten" in e for e in entries)  # who asked and how, never what would have run
    return entries


REFUSING_ENVIRONMENTS = {"production": {"MASKGUARD_ENV": "production"},
                         "production, demo mode on": {"MASKGUARD_ENV": "production", "MASKGUARD_DEMO": "1"},
                         "unrecognised environment": {"MASKGUARD_ENV": "prod"},
                         "gateway built for production": {}}


@pytest.mark.parametrize("case", REFUSING_ENVIRONMENTS)
def test_self_tests_refuse_outside_development_before_touching_the_database(sqlite_env, monkeypatch, case):
    from maskguard import threat_sim
    gw = sqlite_env.gw
    sessions = {r: sqlite_env.login(r) for r in ("support", "admin")}
    for k, v in REFUSING_ENVIRONMENTS[case].items():
        monkeypatch.setenv(k, v)
    if case == "gateway built for production":  # what config.build does in production, whatever the env says now
        monkeypatch.setattr(gw, "allow_self_test", False)
    assert not self_test_allowed(gw)
    calls = _db_calls(monkeypatch, gw)
    for s in sessions.values():
        with pytest.raises(SelfTestDisabled, match=f"^{SELF_TEST_REFUSAL}$"):
            run_suite(gw, s)
        with pytest.raises(SelfTestDisabled):
            threat_sim.live_attack(gw, s)
    with pytest.raises(SelfTestDisabled):
        threat_sim.sessions(sqlite_env.app, seed=0)
    assert calls == []
    _self_test_refusals(gw, 5)


def test_a_failing_audit_log_still_refuses_the_self_test(sqlite_env, monkeypatch):
    gw = sqlite_env.gw
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.setattr(gw.audit, "append", lambda **_: (_ for _ in ()).throw(OSError("disk full")))
    calls = _db_calls(monkeypatch, gw)
    with pytest.raises(SelfTestDisabled):
        run_suite(gw, sqlite_env.login("admin"))
    assert calls == []


def test_attacks_endpoint_is_refused_in_production_for_every_role(sqlite_env, monkeypatch):
    from fastapi.testclient import TestClient

    from maskguard import api
    monkeypatch.setitem(api.state, "app", sqlite_env.app)
    c = TestClient(api.app)
    auth = {r: {"Authorization": "Bearer " + c.post("/auth/login", json={"username": u, "password": p}).json()["token"]}
            for r, (u, p) in config.DEMO_ACCOUNTS.items() if r in ("support", "admin")}
    r = c.get("/attacks", headers=auth["support"])
    assert r.status_code == 200 and r.json()["score"]["maskguard_leaks"] == 0  # development: unchanged
    calls = _db_calls(monkeypatch, sqlite_env.gw)
    for env in REFUSING_ENVIRONMENTS["production"], REFUSING_ENVIRONMENTS["production, demo mode on"]:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        for role, h in auth.items():
            for query in ("", "?role=admin", "?demo=1&env=development"):  # no parameter reopens it
                r = c.get("/attacks" + query, headers=h)
                assert r.status_code == 403 and r.json() == {"detail": SELF_TEST_REFUSAL}, (role, query)
    assert calls == []
    assert {e["channel"] for e in _self_test_refusals(sqlite_env.gw, 12)} == {"rest"}


def test_cli_and_dashboard_self_tests_are_refused_in_production(sqlite_env, monkeypatch, run):
    from streamlit.testing.v1 import AppTest
    import streamlit as st

    from maskguard.service import LocalService
    gw = sqlite_env.gw
    monkeypatch.setitem(cli.state, "service", LocalService(sqlite_env.app))
    monkeypatch.setattr(config, "build", lambda *a, **k: sqlite_env.app)  # simulate-attack and the dashboard build their own
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    calls = _db_calls(monkeypatch, gw)
    for user, pw in (config.DEMO_ACCOUNTS["support"], config.DEMO_ACCOUNTS["admin"]):
        rc, text = run("attack", "--user", user, "--password", pw)
        assert rc == cli.DENIED and SELF_TEST_REFUSAL in text
    rc, text = run("simulate-attack")  # refused before it logs in as the demo intruder
    assert rc == cli.DENIED and SELF_TEST_REFUSAL in text
    rc, text = run("test")  # the security regression command runs the attack suite: refused too
    assert rc == cli.DENIED and SELF_TEST_REFUSAL in text
    assert calls == []
    _self_test_refusals(gw, 4)

    monkeypatch.setenv("MASKGUARD_DEMO", "0")  # as in any real production deployment (1 is refused there)
    from maskguard import attacks, threat_sim
    runner = []  # the self-test internals: full-column reads, the naive baseline, the attack query generator
    for mod, name in ((attacks, "_facts"), (attacks, "_secrets"), (attacks, "naive_query"), (threat_sim, "_attack_query")):
        orig = getattr(mod, name)
        monkeypatch.setattr(mod, name, lambda *a, _o=orig, _n=name, **k: (runner.append(_n), _o(*a, **k))[1])
    calls.clear()
    st.cache_resource.clear()  # the dashboard caches its engine; make it pick up this one
    try:
        at = AppTest.from_file("../src/maskguard/dashboard.py", default_timeout=60).run()
        assert not at.exception and not any(r.key == "role_toggle" for r in at.radio)  # no demo role switch
        user, pw = config.DEMO_ACCOUNTS["admin"]
        at.text_input[0].set_value(user)
        at.text_input[1].set_value(pw)
        next(b for b in at.button if b.label == "Log in").click().run()
        assert not at.exception
        labels = {b.label for b in at.button}
        assert "Run query" in labels  # signed in; masking works as usual
        assert not labels & {"Run attack suite", "Run simulated attack", "Measure"}
        assert sum(SELF_TEST_REFUSAL in i.value for i in at.info) == 3
        assert runner == [] and "execute" not in calls and "query" not in calls  # no self-test, no benchmark baseline
    finally:
        st.cache_resource.clear()


# ---------------------------------------------------------------- network exposure

@pytest.mark.parametrize("service,host,tls,ok", [
    ("api", "127.0.0.1", False, True), ("api", "::1", False, True), ("api", "localhost", False, True),
    ("api", "0.0.0.0", False, False), ("api", "10.0.0.5", False, False), ("api", "0.0.0.0", True, True),
    ("proxy", "127.0.0.1", False, True), ("proxy", "0.0.0.0", False, False), ("proxy", "0.0.0.0", True, False),
    ("classic dashboard", "0.0.0.0", False, False), ("classic dashboard", "127.0.0.1", False, True)])
def test_production_listen_rules(prod, service, host, tls, ok):
    assert (config.listen_problems(service, host, tls) == []) is ok


@pytest.fixture
def run(capsys):
    def go(*args):
        capsys.readouterr()
        rc = cli.main(list(args))
        o = capsys.readouterr()
        return rc, o.out + o.err
    return go


def test_cli_refuses_unsafe_listeners_and_seeding_in_production(prod, run):
    rc, text = run("serve", "--host", "0.0.0.0")
    assert rc == cli.UNAVAILABLE and "without TLS" in text
    rc, text = run("serve", "--host", "0.0.0.0", "--ssl-certfile", "cert.pem")
    assert rc == cli.USAGE and "both" in text
    rc, text = run("proxy", "--host", "0.0.0.0")
    assert rc == cli.UNAVAILABLE and "no TLS" in text
    rc, text = run("dashboard", "--classic", "--host", "0.0.0.0")
    assert rc == cli.UNAVAILABLE and "loopback only" in text
    rc, text = run("seed")
    assert rc == cli.DENIED and "disabled in production" in text


def test_db_install_needs_an_explicit_admin_url(run, monkeypatch):
    monkeypatch.delenv("MASKGUARD_DB_ADMIN", raising=False)
    rc, _ = run("db-install")
    assert rc == cli.USAGE


# ---------------------------------------------------------------- Compose files

def _compose(name):
    with open(os.path.join(ROOT, name)) as f:
        return yaml.safe_load(f)


def test_production_compose_keeps_the_database_behind_the_gateway():
    c = _compose("docker-compose.prod.yml")
    services = c["services"]
    assert set(services) == {"db", "db-install", "api"}  # no PG proxy, no Streamlit dashboard
    assert "ports" not in services["db"] and "ports" not in services["db-install"]
    assert c["networks"]["data"]["internal"] is True and services["db"]["networks"] == ["data"]
    assert services["api"]["ports"] == ["${MASKGUARD_PUBLISH_ADDR:-127.0.0.1}:8443:8443"]
    env = services["api"]["environment"]
    assert env["MASKGUARD_ENV"] == "production" and env["MASKGUARD_DEMO"] == "0" and env["MASKGUARD_SEED_IF_EMPTY"] == "0"
    assert env["MASKGUARD_DB"].startswith("postgresql://maskguard_gateway:")
    assert env["MASKGUARD_TLS_CERT"] and env["MASKGUARD_TLS_KEY"]
    assert not any("OWNER" in str(v) for v in env.values())  # the owner credentials never reach the gateway


def test_production_compose_has_no_secret_fallbacks():
    text = Path(ROOT, "docker-compose.prod.yml").read_text()
    refs = re.findall(r"\$\{([A-Z_]+)(:?[-?])?", text)
    with_default = {name for name, op in refs if op in (":-", "-")}
    assert with_default == {"MASKGUARD_PUBLISH_ADDR"}  # the only default, and it is the safe one (loopback)
    for name in ("MASKGUARD_HMAC_KEY", "MASKGUARD_JWT_SECRET", "MASKGUARD_DB_OWNER_PASSWORD",
                 "MASKGUARD_GATEWAY_DB_PASSWORD", "MASKGUARD_USERS_FILE", "MASKGUARD_TLS_CERT_FILE",
                 "MASKGUARD_TLS_KEY_FILE"):
        assert f"${{{name}:?" in text


def test_demo_compose_is_labelled_and_refuses_production():
    text = Path(ROOT, "docker-compose.yml").read_text()
    assert "NOT for real customer data" in text
    c = _compose("docker-compose.yml")
    assert c["x-maskguard"]["environment"]["MASKGUARD_ENV"] == "${MASKGUARD_ENV:-development}"
    assert "--host" in c["services"]["dashboard"]["command"]  # the classic dashboard now honours --host


@pytest.mark.skipif(not shutil.which("docker"), reason="docker not installed")
def test_production_compose_renders_only_with_every_secret(tmp_path):
    base = [k for k in os.environ if k.startswith("MASKGUARD_")]
    env = {k: v for k, v in os.environ.items() if k not in base}
    cmd = ["docker", "compose", "-f", os.path.join(ROOT, "docker-compose.prod.yml"), "config", "--quiet"]
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    if "unknown" in r.stderr and "compose" in r.stderr:
        pytest.skip("docker compose plugin not available")
    assert r.returncode != 0 and "required variable" in r.stderr
    full = dict(env, MASKGUARD_HMAC_KEY="a" * 64, MASKGUARD_JWT_SECRET="b" * 64, MASKGUARD_DB_OWNER_PASSWORD="c" * 32,
                MASKGUARD_GATEWAY_DB_PASSWORD="d" * 32, MASKGUARD_USERS_FILE=str(tmp_path / "u.yaml"),
                MASKGUARD_TLS_CERT_FILE=str(tmp_path / "t.crt"), MASKGUARD_TLS_KEY_FILE=str(tmp_path / "t.key"))
    assert subprocess.run(cmd, env=full, capture_output=True, text=True, check=False).returncode == 0


# ---------------------------------------------------------------- least-privilege database account (PostgreSQL)

def _with_user(url, user, dbname=None):
    u = urlparse(url)
    netloc = f"{user}@{u.hostname}" + (f":{u.port}" if u.port else "")
    return urlunparse(u._replace(netloc=netloc, path=f"/{dbname}" if dbname else u.path))


@pytest.fixture
def pg_prod_db():
    """A scratch database with owner-loaded data and a read-only gateway role (dropped afterwards)."""
    if not PG_URL:
        pytest.skip("MASKGUARD_TEST_PG not set")
    import psycopg
    name, role = f"mg_prod_{secrets.token_hex(4)}", f"mg_gw_{secrets.token_hex(4)}"
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute(f'CREATE DATABASE "{name}"')
        c.execute(f'CREATE ROLE "{role}" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE')
    admin = _with_user(PG_URL, urlparse(PG_URL).username, name)
    with psycopg.connect(admin, autocommit=True) as c:
        c.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
        c.execute("CREATE TABLE customers (id int PRIMARY KEY, name text, ssn text)")
        c.execute("INSERT INTO customers VALUES (1, 'Asha Rao', '901-23-4501'), (2, 'Ben Okafor', '902-34-5602')")
        c.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        c.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{role}"')
    yield {"admin": admin, "gateway": _with_user(PG_URL, role, name), "role": role}
    with psycopg.connect(PG_URL, autocommit=True) as c:
        c.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        c.execute(f'DROP ROLE IF EXISTS "{role}"')


def test_read_only_runtime_needs_db_install_then_passes_the_privilege_check(pg_prod_db, monkeypatch):
    import psycopg

    from maskguard.backends import connect, install_functions
    monkeypatch.setenv("MASKGUARD_HMAC_KEY", secrets.token_hex(32))
    with pytest.raises(RuntimeError, match="maskguard db-install"):
        connect(pg_prod_db["gateway"], install=False)
    assert install_functions(pg_prod_db["admin"]) == "postgres"
    gw = connect(pg_prod_db["gateway"], install=False)
    assert gw.privilege_problems() == []
    with psycopg.connect(pg_prod_db["admin"], autocommit=True) as c:  # one stray write grant is enough to refuse
        c.execute(f'GRANT INSERT ON customers TO "{pg_prod_db["role"]}"')
    assert any("can write to or owns 1 table(s): customers" in p for p in gw.privilege_problems())
    with psycopg.connect(pg_prod_db["admin"], autocommit=True) as c:  # owning a masking function = can redefine it
        c.execute(f'REVOKE INSERT ON customers FROM "{pg_prod_db["role"]}"')
        c.execute(f'ALTER FUNCTION mg_partial(text, int, int) OWNER TO "{pg_prod_db["role"]}"')
    assert any("owns the masking functions (mg_partial)" in p for p in gw.privilege_problems())
    admin = connect(pg_prod_db["admin"], install=False)
    problems = "\n".join(admin.privilege_problems())
    assert "SUPERUSER" in problems and "create objects in schema public" in problems


def test_production_build_end_to_end_on_postgres(pg_prod_db, prod, monkeypatch):
    from maskguard.backends import install_functions
    install_functions(pg_prod_db["admin"])
    monkeypatch.setenv("MASKGUARD_DB", pg_prod_db["gateway"])
    app = config.build()
    with pytest.raises(PermissionError):
        app.auth.login("admin.ann", "admin123")  # the shipped demo credentials don't exist here
    s = app.auth.login("desk.agent", PROD_USERS["desk.agent"][1])
    r = app.gateway.query(s, "SELECT name, ssn FROM customers ORDER BY id", observe=False)
    assert r.rows[0][1] == "XXX-XX-4501" and "customers.ssn:partial" in r.masked
    with pytest.raises(Rejected):
        app.gateway.query(s, "UPDATE customers SET name = 'x'", observe=False)
    assert app.gateway.allow_dp is False  # D11: no noisy aggregates in production
    monkeypatch.setenv("MASKGUARD_DB", pg_prod_db["admin"])  # the owner/superuser account is refused outright
    with pytest.raises(config.UnsafeConfiguration, match="SUPERUSER"):
        config.build()


def test_production_build_refuses_every_self_test_entry_point(pg_prod_db, prod, monkeypatch, run):
    """The attack suite's schema is loaded by the owner, so nothing but the environment stops it."""
    from fastapi.testclient import TestClient
    from streamlit.testing.v1 import AppTest
    import streamlit as st

    from maskguard import api
    from maskguard.backends import connect, install_functions
    from maskguard.seed import make_db
    install_functions(pg_prod_db["admin"])
    make_db(connect(pg_prod_db["admin"], install=False), n=20)
    import psycopg
    with psycopg.connect(pg_prod_db["admin"], autocommit=True) as c:
        c.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{pg_prod_db["role"]}"')
    monkeypatch.setenv("MASKGUARD_DB", pg_prod_db["gateway"])
    app = config.build()
    assert app.gateway.allow_self_test is False and not self_test_allowed(app.gateway)
    calls = _db_calls(monkeypatch, app.gateway)

    monkeypatch.setitem(api.state, "app", app)
    c = TestClient(api.app)
    for user, (role, pw) in PROD_USERS.items():  # ops.lead is admin, desk.agent is support
        tok = c.post("/auth/login", json={"username": user, "password": pw}).json()["token"]
        r = c.get("/attacks", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 403 and r.json() == {"detail": SELF_TEST_REFUSAL}, role
    monkeypatch.setitem(cli.state, "service", None)  # the CLI builds its own production engine
    rc, text = run("attack", "--user", "ops.lead", "--password", PROD_USERS["ops.lead"][1])
    assert rc == cli.DENIED and SELF_TEST_REFUSAL in text
    rc, text = run("simulate-attack")
    assert rc == cli.DENIED and SELF_TEST_REFUSAL in text
    assert calls == []
    _self_test_refusals(app.gateway, 2)

    st.cache_resource.clear()
    try:
        at = AppTest.from_file("../src/maskguard/dashboard.py", default_timeout=60).run()
        at.text_input[0].set_value("desk.agent")
        at.text_input[1].set_value(PROD_USERS["desk.agent"][1])
        next(b for b in at.button if b.label == "Log in").click().run()
        labels = {b.label for b in at.button}
        assert not at.exception and "Run query" in labels
        assert not labels & {"Run attack suite", "Run simulated attack", "Measure"}
    finally:
        st.cache_resource.clear()


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")
def test_production_api_serves_verified_tls_and_refuses_demo_logins(pg_prod_db, prod, monkeypatch):
    import httpx

    from maskguard.backends import install_functions
    install_functions(pg_prod_db["admin"])
    d = str(prod)
    ossl = lambda *a: subprocess.run(["openssl", *a], cwd=d, check=True, capture_output=True)
    # A CA and leaf with the extensions strict verifiers (e.g. Python 3.13's default) require
    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout", "ca.key", "-out", "ca.crt",
         "-subj", "/CN=test CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tls.key", "-out", "tls.csr", "-subj", "/CN=localhost")
    (prod / "san.ext").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n"
                                  "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
                                  "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    ossl("x509", "-req", "-in", "tls.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1",
         "-extfile", "san.ext", "-out", "tls.crt")
    port = _free_port()
    env = dict(os.environ, MASKGUARD_DB=pg_prod_db["gateway"], MASKGUARD_TLS_CERT=f"{d}/tls.crt",
               MASKGUARD_TLS_KEY=f"{d}/tls.key")
    proc = subprocess.Popen([sys.executable, "-c", "from maskguard.cli import main; raise SystemExit(main())",
                             "serve", "--host", "0.0.0.0", "--port", str(port)],
                            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    url = f"https://127.0.0.1:{port}"
    try:
        with httpx.Client(verify=f"{d}/ca.crt", timeout=5) as c:
            for _ in range(120):
                try:
                    if c.get(f"{url}/health").status_code == 200:
                        break
                except httpx.TransportError:
                    time.sleep(0.5)
            else:
                pytest.fail("server did not start: " + proc.stdout.read1(4000).decode(errors="replace"))
            assert c.post(f"{url}/auth/demo", json={"role": "admin"}).status_code == 404
            assert c.post(f"{url}/auth/login", json={"username": "admin.ann", "password": "admin123"}).status_code == 401
            tok = c.post(f"{url}/auth/login", json={"username": "ops.lead", "password": PROD_USERS["ops.lead"][1]}).json()
            assert tok["role"] == "admin"
        with pytest.raises(httpx.TransportError):  # an untrusted certificate is rejected by a verifying client
            httpx.get(f"{url}/health", timeout=5)
        with pytest.raises(httpx.TransportError):  # and there is no plain-HTTP listener on that port
            httpx.get(f"http://127.0.0.1:{port}/health", timeout=5)
    finally:
        proc.terminate()
        proc.wait(timeout=10)


# ---------------------------------------------------------------- MySQL privilege check

@pytest.mark.parametrize("grants,bad", [
    (["GRANT USAGE ON *.* TO `gw`@`%`", "GRANT SELECT, EXECUTE ON `bank`.* TO `gw`@`%`"], []),
    (["GRANT SELECT (`id`, `name`) ON `bank`.`customers` TO `gw`@`%`"], []),
    (["GRANT SELECT, INSERT ON `bank`.* TO `gw`@`%`"], ["INSERT on `bank`.*"]),
    (["GRANT ALL PRIVILEGES ON `bank`.* TO `gw`@`%`"], ["ALL PRIVILEGES"]),
    (["GRANT SELECT ON *.* TO `gw`@`%`"], ["SELECT on *.*"]),
    (["GRANT EXECUTE ON *.* TO `gw`@`%`"], ["EXECUTE on *.*"]),
    (["GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO `gw`@`%`"], ["SYSTEM_VARIABLES_ADMIN"]),
    (["GRANT `reader`@`%` TO `gw`@`%`"], ["inherits a role"])])
def test_mysql_grant_parser(grants, bad):
    from maskguard.backends import MySQLBackend
    b = MySQLBackend.__new__(MySQLBackend)  # parser only: no connection
    b.admin_query = lambda sql: (["Grants"], [(g,) for g in grants])
    problems = b.privilege_problems()
    assert len(problems) == len(bad) and all(any(x in p for p in problems) for x in bad)


def test_mysql_account_with_write_grants_is_reported():
    if not MYSQL_URL:
        pytest.skip("MASKGUARD_TEST_MYSQL not set")
    from maskguard.backends import connect
    problems = "\n".join(connect(MYSQL_URL).privilege_problems())  # the test account holds ALL on its database
    assert "INSERT" in problems or "ALL PRIVILEGES" in problems


def test_mysql_read_only_runtime_end_to_end(monkeypatch):
    """A gateway account with only SELECT + EXECUTE passes; one write grant is refused. Needs an admin URL."""
    admin = os.environ.get("MASKGUARD_TEST_MYSQL_ADMIN")  # e.g. mysql://root:pw@127.0.0.1:3306/bank
    if not admin:
        pytest.skip("MASKGUARD_TEST_MYSQL_ADMIN not set")
    from maskguard.backends import (
        MYSQL_FUNCTION_NAMES,
        _mysql_connect,
        connect,
        install_functions,
    )
    monkeypatch.setenv("MASKGUARD_HMAC_KEY", secrets.token_hex(32))
    user, pw, db = f"mg_gw_{secrets.token_hex(3)}", secrets.token_hex(16), urlparse(admin).path.lstrip("/")
    conn = _mysql_connect(admin)

    def sql(stmt):
        with conn.cursor() as c:
            c.execute(stmt)
    try:
        sql(f"CREATE USER '{user}'@'%' IDENTIFIED BY '{pw}'")
        sql(f"GRANT SELECT, EXECUTE ON `{db}`.* TO '{user}'@'%'")
        assert install_functions(admin) == "mysql"
        u = urlparse(admin)
        gateway_url = urlunparse(u._replace(netloc=f"{user}:{pw}@{u.hostname}:{u.port or 3306}"))
        gw = connect(gateway_url, install=False)
        assert gw.privilege_problems() == []
        assert gw.execute("SELECT mg_partial('901-23-4501', 0, 4)")[1][0][0] == "XXX-XX-4501"
        sql(f"GRANT INSERT ON `{db}`.* TO '{user}'@'%'")
        assert any("INSERT" in p for p in connect(gateway_url, install=False).privilege_problems())
    finally:  # leave nothing behind: admin-defined functions can't be replaced by the ordinary test account
        sql(f"DROP USER IF EXISTS '{user}'@'%'")
        for name in MYSQL_FUNCTION_NAMES:
            sql(f"DROP FUNCTION IF EXISTS {name}")
        conn.close()
