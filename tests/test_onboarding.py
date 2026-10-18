"""Using your own database: connect, generated development keys, reviewing columns, automatic detection of money,
health data and staff names, and the integrity proof outside demo mode."""
import json, os, sqlite3, stat

import pytest
import yaml

from maskguard import cli, config, scanner
from maskguard.auth import hash_password

ICD = ["E11.9", "I10", "J45.909", "K21.9", "M54.5"]


def _clinic(path):
    """A small database that is not the demo: different tables, names and kinds of data."""
    c = sqlite3.connect(path)
    c.executescript("""CREATE TABLE visits (visit_id INTEGER PRIMARY KEY, patient_no INTEGER, doctor TEXT,
                       diagnosis_code TEXT, blood_group TEXT, fee_amount REAL, status TEXT, gender TEXT, city TEXT);""")
    rows = [(i, 100 + i % 40, f"Dr. {['Rao', 'Iyer', 'Khan', 'Das'][i % 4]}", ICD[i % 5], ["A+", "O-", "B+", "AB+"][i % 4],
             round(250 + i * 13.37, 2), ["open", "closed", "billed"][i % 3], "MF"[i % 2], f"City{i}") for i in range(1, 61)]
    c.executemany("INSERT INTO visits VALUES (?,?,?,?,?,?,?,?,?)", rows)
    c.commit(); c.close()


@pytest.fixture
def folder(tmp_path, monkeypatch, capsys):
    """A fresh working folder with nothing configured, like a new `pip install` user's."""
    monkeypatch.chdir(tmp_path)
    for v in ("MASKGUARD_DB", "MASKGUARD_AUDIT", "MASKGUARD_REGISTRY", "MASKGUARD_STATE_DIR", "MASKGUARD_SEED_IF_EMPTY",
              "MASKGUARD_OVERRIDES", "MASKGUARD_API", "MASKGUARD_CONFIG"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setitem(cli.state, "service", None)
    monkeypatch.setenv("COLUMNS", "160")

    def go(*args):
        capsys.readouterr()
        cli.state["service"] = None  # every command builds its engine like a new process would
        rc = cli.main(list(args))
        o = capsys.readouterr()
        return rc, o.out + o.err
    go.path = tmp_path
    return go


def _inv(run):
    rc, out = run("pii", "list", "--json")
    return {f"{r['table']}.{r['column']}": r for r in json.loads(out)}


# ---------------------------------------------------------------- connect

def test_connect_uses_your_database_without_demo_data_and_remembers_it(folder):
    _clinic("clinic.db")
    rc, out = folder("connect", "sqlite:///clinic.db")
    assert rc == 0 and "connected" in out and "unreviewed" in out
    saved = yaml.safe_load(open("maskguard.yaml"))
    assert saved["MASKGUARD_DB"] == "sqlite:///clinic.db" and saved["MASKGUARD_SEED_IF_EMPTY"] == "0"
    assert saved["MASKGUARD_STATE_DIR"] == os.path.join("data", "clinic")
    assert stat.S_IMODE(os.stat("maskguard.yaml").st_mode) == 0o600  # it can hold a database password
    assert [r[0] for r in sqlite3.connect("clinic.db").execute("SELECT name FROM sqlite_master WHERE type='table'")] == ["visits"]
    assert not os.path.exists(os.path.join("data", "bank.db"))  # no demo database either
    inv = _inv(folder)  # a later command finds the same database through the saved settings
    assert set(inv) == {f"visits.{c}" for c in ("visit_id", "patient_no", "doctor", "diagnosis_code", "blood_group",
                                                "fee_amount", "status", "gender", "city")}
    assert all(r.get("source") != "approval" for r in inv.values())  # demo approvals never apply to your tables
    rc, out = folder("connect", "--demo")
    assert rc == 0 and "MASKGUARD_DB" not in yaml.safe_load(open("maskguard.yaml")) or {}
    assert "users.ssn" in _inv(folder)


def test_connect_keeps_the_previous_setup_when_the_new_database_fails(folder):
    _clinic("clinic.db")
    assert folder("connect", "sqlite:///clinic.db")[0] == 0
    rc, out = folder("connect", "postgresql://nobody@127.0.0.1:1/none")
    assert rc == cli.UNAVAILABLE and "db-install" in out
    assert yaml.safe_load(open("maskguard.yaml"))["MASKGUARD_DB"] == "sqlite:///clinic.db"


def test_an_environment_database_wins_and_connect_says_so(folder, monkeypatch):
    monkeypatch.setenv("MASKGUARD_DB", "sqlite:///other.db")
    rc, out = folder("connect", "sqlite:///clinic.db")
    assert rc == cli.UNAVAILABLE and "unset it first" in out and not os.path.exists("maskguard.yaml")


def test_first_run_is_only_when_nothing_was_chosen(folder, monkeypatch):
    assert cli._first_run()
    _clinic("clinic.db")
    folder("connect", "sqlite:///clinic.db")
    assert not cli._first_run()


def test_demo_data_only_goes_into_the_demo_database(monkeypatch):
    monkeypatch.delenv("MASKGUARD_SEED_IF_EMPTY", raising=False)
    monkeypatch.delenv("MASKGUARD_DB", raising=False)
    monkeypatch.setenv("MASKGUARD_CONFIG", "/nonexistent/maskguard.yaml")
    assert config.Settings().seed_if_empty
    monkeypatch.setenv("MASKGUARD_DB", "postgresql://u@h/yours")
    assert not config.Settings().seed_if_empty
    monkeypatch.setenv("MASKGUARD_SEED_IF_EMPTY", "1")
    assert config.Settings().seed_if_empty


# ---------------------------------------------------------------- generated development keys

def test_development_keys_are_generated_once_kept_private_and_reused(folder, monkeypatch):
    for n in config.SECRET_NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setattr(config, "GENERATED", {})
    rc, out = folder("status")
    assert rc == 0 and "generated for this machine" in out
    path = os.path.join("data", "secrets.yaml")
    stored = yaml.safe_load(open(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600 and len(stored["MASKGUARD_HMAC_KEY"]) == 64
    token = lambda: json.loads(folder("query", "--role", "analyst", "SELECT ssn FROM users ORDER BY id LIMIT 1", "--json")[1])["rows"]
    first = token()
    for n in config.SECRET_NAMES:
        monkeypatch.delenv(n, raising=False)  # a new process: the key comes back from the file, tokens stay the same
    assert token() == first and len(first[0][0]) == 16
    assert yaml.safe_load(open(path)) == stored


def test_production_never_generates_keys(folder, monkeypatch):
    for n in config.SECRET_NAMES:
        monkeypatch.delenv(n, raising=False)
    monkeypatch.setenv("MASKGUARD_ENV", "production")
    monkeypatch.setenv("MASKGUARD_DEMO", "0")
    config.ensure_dev_secrets(config.Settings())
    assert not os.environ.get("MASKGUARD_HMAC_KEY") and not os.path.exists(os.path.join("data", "secrets.yaml"))


# ---------------------------------------------------------------- automatic detection

def test_money_health_staff_names_and_personal_attributes_are_found_automatically(folder):
    _clinic("clinic.db")
    folder("connect", "sqlite:///clinic.db")
    inv = _inv(folder)
    assert inv["visits.diagnosis_code"]["tag"] == "HEALTH" and "ICD-10" in inv["visits.diagnosis_code"]["evidence"]
    assert inv["visits.blood_group"]["tag"] == "HEALTH"
    assert inv["visits.doctor"]["tag"] == "PII_MEDIUM"
    assert inv["visits.fee_amount"]["tag"] == "FINANCIAL_CONFIDENTIAL"
    assert inv["visits.gender"]["tag"] == "PII_MEDIUM"  # "M"/"F" look harmless; the header alone masks it
    assert inv["visits.city"]["tag"] == "UNREVIEWED" and not inv["visits.city"].get("suggest")
    assert inv["visits.visit_id"].get("suggest") == "PUBLIC" and inv["visits.status"].get("suggest") == "PUBLIC"


def test_value_and_header_rules_need_real_evidence():
    assert scanner.value_kind(["E11.9", "I10", "J45.909"] * 5)[0] == "health"
    assert scanner.value_kind(["A+", "O-", "B+"] * 5)[0] == "health"
    assert scanner.value_kind(["Dr. Rao", "Mrs. Iyer Kumar", "Shri Das"] * 5)[0] == "name"
    assert scanner.value_kind(["open", "closed"] * 5) == (None, None)
    assert scanner.value_kind(["E11.9"] * 10) == (None, None)  # one repeated value is not evidence
    assert scanner.classify_column("diagnosis_notes", ["follow up", "stable", "improving"] * 5)["tag"] == "HEALTH"
    assert scanner.classify_column("doctor_id", list(range(1, 30))) is None  # a numeric key is not a name
    assert scanner.classify_column("unit_price", [12.5, 99.0, 45.25] * 10) is None  # a product price isn't personal


def test_the_rules_scanner_finds_the_same_kinds_without_lightgbm(monkeypatch):
    monkeypatch.setitem(scanner._ML, "ok", False)
    assert scanner.classify_column("code", ICD * 4)["tag"] == "HEALTH"
    assert scanner.classify_column("treating", ["Dr. Rao", "Dr. Khan", "Dr. Das"] * 5)["tag"] == "PII_MEDIUM"
    assert scanner.classify_column("fee_amount", [250.0, 990.5]) ["tag"] == "FINANCIAL_CONFIDENTIAL"


# ---------------------------------------------------------------- reviewing columns

def test_approve_and_tag_save_the_review_and_apply_it_at_once(folder):
    _clinic("clinic.db")
    folder("connect", "sqlite:///clinic.db")
    rc, out = folder("pii", "approve", "--suggested")
    assert rc == 0 and "visits.visit_id" in out and "visits.city" not in out
    rc, out = folder("pii", "tag", "visits.city", "--tag", "PII_MEDIUM", "--kind", "address")
    assert rc == 0
    saved = yaml.safe_load(open(os.path.join("policies", "overrides.yaml")))
    assert saved["visits"]["visit_id"] == {"tag": "PUBLIC"} and saved["visits"]["city"]["tag"] == "PII_MEDIUM"
    inv = _inv(folder)
    assert not [k for k, r in inv.items() if r["tag"] == "UNREVIEWED"]
    rc, out = folder("query", "--role", "support", "SELECT visit_id, patient_no, diagnosis_code, city FROM visits "
                     "ORDER BY visit_id LIMIT 1", "--json")
    row = json.loads(out)["rows"][0]
    assert row[:2] == [1, 101] and row[2] == "REDACTED" and row[3] == "City1"  # PII_MEDIUM: support sees it
    audit = [json.loads(l) for l in open(os.path.join("data", "clinic", "audit.jsonl"))]
    assert {e["decision"] for e in audit} >= {"pii_review"}


def test_review_refuses_unknown_columns_and_classifications(folder):
    _clinic("clinic.db")
    folder("connect", "sqlite:///clinic.db")
    assert folder("pii", "approve", "visits.nope")[0] == cli.DENIED
    assert folder("pii", "tag", "visits.city", "--tag", "SECRETISH")[0] == cli.DENIED
    assert folder("pii", "approve")[0] == cli.USAGE
    assert not os.path.exists(os.path.join("policies", "overrides.yaml"))


# ---------------------------------------------------------------- integrity proof outside demo mode

def test_integrity_proof_runs_as_a_real_account_outside_demo_mode(folder, monkeypatch, tmp_path):
    users = tmp_path / "users.yaml"
    users.write_text(yaml.safe_dump({"users": {
        "ops.lead": {"role": "admin", "password_hash": hash_password("s3cret-ops")},
        "desk.agent": {"role": "support", "password_hash": hash_password("s3cret-desk")}}}))
    monkeypatch.setenv("MASKGUARD_USERS", str(users))
    monkeypatch.setenv("MASKGUARD_DEMO", "0")
    _clinic("clinic.db")
    folder("connect", "sqlite:///clinic.db")
    rc, out = folder("integrity", "proof")
    assert rc == cli.DENIED and "--user" in out
    rc, out = folder("integrity", "proof", "-u", "desk.agent", "-p", "s3cret-desk")
    assert rc == cli.DENIED and "integrity.verify" in out
    rc, out = folder("integrity", "proof", "-u", "ops.lead", "-p", "s3cret-ops", "--json")
    p = json.loads(out)
    assert rc == 0 and p["status"] == "PASS" and p["sql"] == "SELECT * FROM visits LIMIT 5"
    assert [q["role"] for q in p["queries"]] == ["admin"] and all(a["status"] == "REJECTED" for a in p["unauthorized_attempts"])
