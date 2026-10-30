"""CLI: commands, JSON output, exit codes, legacy invocations. Runs the real engine in-process (and over the API)."""
import json, os, socket, threading, time

import pytest

from maskguard import cli


@pytest.fixture
def run(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MASKGUARD_DB", f"sqlite:///{tmp_path}/cli.db")
    monkeypatch.setenv("MASKGUARD_SEED_IF_EMPTY", "1")  # a database named in MASKGUARD_DB only gets demo data on request
    monkeypatch.setenv("MASKGUARD_AUDIT", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("MASKGUARD_REGISTRY", str(tmp_path / "registry.yaml"))
    monkeypatch.setenv("COLUMNS", "120")
    monkeypatch.delenv("MASKGUARD_API", raising=False)

    def go(*args):
        capsys.readouterr()
        rc = cli.main(list(args))
        o = capsys.readouterr()
        return rc, o.out, o.err
    return go


def test_status_and_doctor(run):
    rc, out, _ = run("status", "--json")
    st = json.loads(out)
    assert rc == 0 and st["backend"] == "sqlite" and all(c["ok"] for c in st["checks"])
    rc, out, _ = run("doctor", "--json")
    assert rc == 0 and json.loads(out)["ok"]
    rc, out, err = run("status")
    assert rc == 0 and "PASS" in out and "DATABASE" in out


def test_query_json_is_masked_per_role(run):
    rows = {}
    for role in ("admin", "support", "analyst", "auditor"):
        rc, out, _ = run("query", "--role", role, "SELECT ssn FROM users ORDER BY id LIMIT 1", "--json")
        assert rc == 0
        r = json.loads(out)
        assert r["role"] == role and r["request_id"].startswith("req-")
        rows[role] = r["rows"][0][0]
    assert rows["support"] == "XXX-XX-" + rows["admin"][-4:]
    assert len(rows["analyst"]) == 32 and rows["auditor"] == "REDACTED"


def test_query_builder_csv_and_explain(run, tmp_path):
    p = tmp_path / "out.csv"
    rc, out, err = run("query", "--role", "support", "--table", "accounts", "--columns", "credit_card,status", "-n", "3",
                       "--csv", str(p), "--explain")
    assert rc == 0 and "[PARTIAL]" in out and "Decided by" in out
    lines = p.read_text().splitlines()
    assert lines[0] == "credit_card,status" and len(lines) == 4 and all("X" in l for l in lines[1:])


def test_exit_codes(run):
    assert run("query", "--role", "support", "DROP TABLE users")[0] == cli.DENIED
    assert run("query", "--role", "root", "SELECT 1")[0] == cli.DENIED
    assert run("query", "SELECT 1")[0] == cli.USAGE
    assert run("query", "--role", "support", "--table", "nope")[0] == cli.DENIED
    assert run("nonsense-command")[0] == cli.USAGE
    assert run("policy", "explain", "--role", "support", "--table", "ghost")[0] == cli.DENIED


def test_unavailable_database(run, monkeypatch):
    monkeypatch.setenv("MASKGUARD_DB", "postgresql://nobody@127.0.0.1:1/none")
    rc, out, err = run("status")
    assert rc == cli.UNAVAILABLE and "UNAVAILABLE" in err


def test_compare_and_legacy_roles(run):
    rc, out, _ = run("compare", "SELECT ssn FROM users ORDER BY id LIMIT 1", "--roles", "admin,support,analyst", "--json")
    res = json.loads(out)["results"]
    assert rc == 0 and res["support"]["rows"][0][0].startswith("XXX-XX-")
    rc, out, _ = run("roles", "SELECT ssn FROM users ORDER BY id LIMIT 1")
    assert rc == 0 and "AUDITOR" in out and "XXX-XX-" in out
    rc, out, _ = run("compare", "--table", "users", "--columns", "name,ssn", "-n", "2")
    assert rc == 0 and "[REDACT]" in out


def test_scan_never_prints_values(run, sqlite_env):
    raw = {v for v in sqlite_env.raw if len(v) >= 6}
    rc, out, err = run("scan", "--sample-limit", "50", "--dry-run")
    assert rc == 0 and "DRY RUN" in out and "PII_HIGH" in out
    rc, out2, _ = run("pii", "show", "users", "--json")
    rc3, out3, _ = run("db", "inspect")
    assert rc3 == 0 and "support_tickets" in out3
    assert not any(v in out + out2 + out3 + err for v in raw)


def test_policy_commands(run):
    rc, out, _ = run("policy", "list", "--json")
    m = json.loads(out)
    assert rc == 0 and set(m["roles"]) == {"admin", "support", "analyst", "auditor"}
    rc, out, _ = run("policy", "explain", "-r", "support", "-t", "accounts", "--json")
    assert json.loads(out)["row_filter"] == "status <> 'frozen'"
    assert run("policy", "set", "support", "PII_HIGH", "allow")[0] == cli.DENIED           # weakening needs --confirm
    rc, out, err = run("policy", "set", "support", "PII_HIGH", "allow", "--confirm", "--reason", "test")
    assert rc == 0 and "non-admin" in err
    assert run("roles", "show", "auditor")[0] == 0 and run("roles", "list", "--json")[0] == 0


def test_audit_integrity_and_security_test(run):
    run("query", "--role", "support", "SELECT ssn FROM users LIMIT 1")
    rc, out, _ = run("audit", "list", "-n", "5", "--json")
    a = json.loads(out)
    assert rc == 0 and a["chain_valid"] and a["entries"][-1]["channel"] == "cli"
    assert run("audit", "--verify")[0] == 0 and run("audit", "-n", "3")[0] == 0     # legacy forms
    assert run("integrity")[0] == 0
    rc, out, _ = run("integrity", "proof", "--json")
    p = json.loads(out)
    assert rc == 0 and p["status"] == "PASS" and p["before"] == p["after"]
    rc, out, _ = run("test", "--roles", "support,analyst", "--json")
    assert rc == 0 and json.loads(out)["passed"]


def test_integrity_failure_exit_code(run, tmp_path):
    import sqlite3
    run("integrity", "baseline")
    con = sqlite3.connect(f"{tmp_path}/cli.db"); con.execute("UPDATE users SET city = 'X' WHERE id = 2"); con.commit(); con.close()
    rc, out, _ = run("integrity", "verify", "--json")
    assert rc == cli.INTEGRITY_FAILED and json.loads(out)["status"] == "CHANGED"


def test_banner_fallback_on_narrow_terminal():
    from rich.console import Console
    import io
    buf = io.StringIO()
    cli.banner(Console(file=buf, width=50))
    assert "MASKGUARD" in buf.getvalue() and "███" not in buf.getvalue()
    buf = io.StringIO()
    cli.banner(Console(file=buf, width=100))
    assert "███" in buf.getvalue()


def test_remote_mode_uses_the_api(sqlite_env, monkeypatch, capsys):
    import uvicorn
    from maskguard import api
    api.state["app"] = sqlite_env.app
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(api.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True); t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    try:
        url = f"http://127.0.0.1:{port}"
        assert cli.main(["--api", url, "query", "--role", "support", "SELECT ssn FROM users LIMIT 1", "--json"]) == 0
        r = json.loads(capsys.readouterr().out)
        assert r["rows"][0][0].startswith("XXX-XX-")
        assert cli.main(["--api", url, "query", "--role", "support", "--table", "users", "-n", "2", "--json"]) == 0
        capsys.readouterr()
        assert cli.main(["--api", url, "integrity", "verify", "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "MATCH"
        assert cli.main(["--api", url, "--as-user", "support.sam", "--as-password", "support123", "audit", "list"]) == cli.DENIED
        assert cli.main(["--api", "http://127.0.0.1:1", "status"]) == cli.UNAVAILABLE
        entries = sqlite_env.gw.audit.search(user="support.sam")
        assert entries and entries[0]["channel"] == "rest"
    finally:
        server.should_exit = True; t.join(5); api.state.clear()


def test_users_import_from_csv(run, tmp_path, monkeypatch):
    import stat

    import yaml

    from maskguard.auth import check_password
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MASKGUARD_CONFIG", str(tmp_path / "maskguard.yaml"))
    (tmp_path / "staff.csv").write_text("username,display_name,role,email\n"
                                        "admin_anita,Anita Rao (Admin),Admin,a@x.example\n"
                                        "support_ravi,Ravi,Support,r@x.example\n"
                                        "analyst_kavya,,ANALYST,k@x.example\n", encoding="utf-8")
    rc, out, _ = run("users", "import", "staff.csv", "--use")
    assert rc == 0 and "3 users" in out
    users = yaml.safe_load(open("users.yaml"))["users"]
    pw = yaml.safe_load(open("passwords.yaml"))
    assert {u: m["role"] for u, m in users.items()} == {"admin_anita": "admin", "support_ravi": "support",
                                                         "analyst_kavya": "analyst"}
    assert users["admin_anita"]["display_name"] == "Anita Rao (Admin)" and "display_name" not in users["analyst_kavya"]
    for u in users:
        assert check_password(pw[u], users[u]["password_hash"]) and pw[u] not in open("users.yaml").read()
        assert pw[u] not in out  # passwords go to the file only
    for f in ("users.yaml", "passwords.yaml"):
        assert stat.S_IMODE(os.stat(f).st_mode) == 0o600
    saved = yaml.safe_load(open("maskguard.yaml"))
    assert saved["MASKGUARD_USERS"] == str(tmp_path / "users.yaml") and saved["MASKGUARD_DEMO"] == "0"
    assert run("users", "import", "staff.csv")[0] == 2  # files exist: --force needed
    (tmp_path / "bad.csv").write_text("username,role\nx,superuser\n")
    rc, _, err = run("users", "import", "bad.csv", "--out", "u2.yaml", "--passwords", "p2.yaml")
    assert rc == 2 and "superuser" in err and not os.path.exists("u2.yaml")
