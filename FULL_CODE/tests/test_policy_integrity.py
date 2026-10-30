"""Policy engine (explain, versions, runtime edits, row filters, auditor role) and source-data integrity proofs."""

from pathlib import Path

import pytest

from maskguard import policy as P
from maskguard.integrity import compare, proof, snapshot
from maskguard.rewriter import Rejected


def test_explain_matches_what_the_gateway_returns(env):
    pol, reg = env.gw.policy, env.gw.registry
    ex = {c["column"]: c for c in P.explain("support", "users", reg, pol)["columns"]}
    assert ex["ssn"]["action_label"] == "Partial mask" and ex["ssn"]["rule"] == "roles.support.PII_HIGH"
    assert ex["ssn"]["example_out"] == "XXX-XX-6789" and ex["id"]["tag"] == "PUBLIC" and ex["id"]["action"] == "allow"
    _cols, rows = env.run("support", "SELECT ssn FROM users ORDER BY id LIMIT 1")
    assert rows[0][0].startswith("XXX-XX-")
    an = {c["column"]: c for c in P.explain("analyst", "accounts", reg, pol)["columns"]}
    assert an["balance"]["action"] == "aggregate" and an["credit_card"]["example_out"] == "REDACTED"
    assert {c["column"]: c for c in P.explain("analyst", "users", reg, pol)["columns"]}["email"]["action"] == "hmac"
    with pytest.raises(KeyError):
        P.explain("root", "users", reg, pol)


def test_explain_never_contains_database_values(env):
    reg, pol = env.gw.registry, env.gw.policy
    text = repr([P.explain(r, t, reg, pol) for r in pol["roles"] for t in reg])
    assert not any(v in text for v in env.raw if len(v) >= 6)


def test_auditor_sees_no_raw_pii(env):
    _cols, rows = env.run("auditor", "SELECT name, ssn, email, phone FROM users ORDER BY id LIMIT 5")
    assert all(v == "REDACTED" for r in rows for v in r)
    _, rows = env.run("auditor", "SELECT credit_card, balance FROM accounts LIMIT 5")
    assert all(r[0] == "REDACTED" and r[1] is None for r in rows)


def test_row_filter_hides_frozen_accounts_from_support(env):
    total = env.backend.admin_query("SELECT count(*) FROM accounts")[1][0][0]
    frozen = env.backend.admin_query("SELECT count(*) FROM accounts WHERE status = 'frozen'")[1][0][0]
    assert frozen > 0
    _, rows = env.run("support", "SELECT status, count(*) FROM accounts GROUP BY status")
    assert {r[0] for r in rows} == {"active"}
    _, rows = env.run("admin", "SELECT count(*) FROM accounts")
    assert rows[0][0] == total
    # the filter sits inside the masked view, so no query shape can reach the hidden rows
    for sql in [
        "WITH a AS (SELECT * FROM accounts) SELECT count(*) FROM a WHERE status = 'frozen'",
        "SELECT count(*) FROM (SELECT * FROM accounts) x WHERE x.status = 'frozen'",
        "SELECT count(*) FROM users u JOIN accounts a ON a.user_id = u.id WHERE a.status = 'frozen'",
        "SELECT count(*) FROM accounts WHERE status = 'frozen' OR 1 = 1 AND status = 'frozen'",
    ]:
        _, rows = env.run("support", sql)
        assert rows == [] or rows[0][0] in (0, None), sql


def test_invalid_row_filter_fails_closed(sqlite_env):
    pol = sqlite_env.gw.policy
    pol.setdefault("row_filters", {}).setdefault("analyst", {})["users"] = "nonexistent_col = 1"
    with pytest.raises(Rejected):
        sqlite_env.run("analyst", "SELECT id FROM users")
    assert P.validate({"roles": {"a": {}}, "row_filters": {"a": {"t": "(SELECT 1) = 1"}}})
    assert P.validate({"roles": {"a": {}}, "row_filters": {"a": {"t": "lower(x) = 'y'"}}})
    assert not P.validate({"roles": {"a": {}}, "row_filters": {"a": {"t": "x IN (1, 2) AND y <> 'z'"}}})


def test_policy_validation_rejects_unsafe_policies():
    assert P.validate({"default_action": "allow", "roles": {}})
    assert P.validate({"roles": {"r": {"PII_HIGH": "show_everything"}}})
    assert P.validate({"roles": {"r": {}}, "role_info": {"r": {"capabilities": ["root"]}}})


def test_policy_store_versions_and_requires_confirmation_to_weaken(sqlite_env):
    app = sqlite_env.app
    store, v0 = app.policy, P.version(app.policy.policy)
    with pytest.raises(P.PolicyError):
        store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann")  # weakening, unconfirmed
    with pytest.raises(P.PolicyError):
        store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann", confirm=True)  # no reason
    with pytest.raises(P.PolicyError):
        store.set_rule("support", "PII_HIGH", "show", actor="admin.ann")  # unknown action
    r = store.set_rule("support", "PII_HIGH", "redact", actor="admin.ann")  # stricter: no confirmation
    assert r["changed"] and r["version"] != v0
    _, rows = sqlite_env.run("support", "SELECT ssn FROM users LIMIT 1")
    assert rows[0][0] == "REDACTED"  # takes effect immediately
    r = store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann", reason="demo", confirm=True)
    assert any("non-admin" in w for w in r["warnings"])
    _, rows = sqlite_env.run("support", "SELECT ssn FROM users ORDER BY id LIMIT 1")
    assert rows[0][0] == sqlite_env.real("ssn")
    e = store.reset("admin.ann")
    assert e["version_after"] == v0 and [h["change"] for h in store.history()] == ["set_rule", "set_rule", "reset"]
    audit_versions = {x.get("policy_version") for x in app.gateway.audit.entries() if x.get("decision") == "allow"}
    assert (
        len(audit_versions) == 2 and None not in audit_versions
    )  # every audit entry names the policy version that decided it


def test_middle_actions_are_not_comparable():
    """allow < {partial, redact_text, hmac, aggregate} < redact < deny. Swapping two middle actions changes what is
    revealed (edge characters vs. linkable tokens), so it is never treated as "stricter"."""
    assert P.compare("redact", "hmac") == "stricter" and P.compare("allow", "partial") == "weaker"
    assert P.compare("partial", "hmac") == "different" and P.compare("aggregate", "hmac") == "different"
    assert P.compare("hmac", "partial") == "different" and P.compare("deny", "redact") == "stricter"
    assert P.compare("hmac", "hmac") == "same" and P.at_least_as_strict("bogus", "redact")  # unknown -> deny


def test_swapping_middle_actions_needs_confirmation(sqlite_env):
    store = sqlite_env.app.policy
    current, warnings, needs = store.check_rule("analyst", "PII_HIGH", "partial")  # hmac -> partial
    assert current == "hmac" and needs and "reveal different things" in warnings[0]
    with pytest.raises(P.PolicyError, match="changes what is revealed"):
        store.set_rule("analyst", "PII_HIGH", "partial", actor="admin.ann")
    r = store.set_rule("analyst", "PII_HIGH", "partial", actor="admin.ann", reason="support pilot", confirm=True)
    assert r["entry"]["weakening"] and r["entry"]["comparison"] == "different"
    assert not store.check_rule("analyst", "PII_HIGH", "redact")[2]  # partial -> redact: stricter, no confirmation


def test_capabilities():
    from maskguard.config import _load_yaml

    pol = _load_yaml("policies/default.yaml")
    assert P.can("admin", "policy.write", pol) and P.can("auditor", "audit.read", pol)
    assert not P.can("auditor", "policy.write", pol) and not P.can("support", "audit.read", pol)
    assert not P.can("nobody", "query", pol)


def test_integrity_baseline_and_proof(env):
    app = env.app
    base = snapshot(app.backend)
    assert compare(base, snapshot(app.backend))["status"] == "MATCH"
    p = proof(app, actor="test")
    assert p["status"] == "PASS" and p["before"] == p["after"]
    assert {q["role"] for q in p["queries"]} == {"admin", "support", "analyst", "auditor"}
    assert all(a["status"] == "REJECTED" for a in p["unauthorized_attempts"])
    # a real change (through the privileged connection, not the gateway) is detected and localised
    app.backend.admin_query("UPDATE users SET city = 'Changed' WHERE id = 1")
    r = compare(base, snapshot(app.backend))
    assert r["status"] == "CHANGED"
    changed = [t for t in r["tables"] if t["status"] != "MATCH"]
    assert (
        [t["table"] for t in changed] == ["users"]
        and changed[0]["content_changed"]
        and not changed[0]["schema_changed"]
    )


def test_integrity_store_verify_and_history(sqlite_env):
    app = sqlite_env.app
    assert app.integrity.verify("t")["status"] == "MATCH"
    app.backend.admin_query("DELETE FROM support_tickets WHERE id = 1")
    v = app.integrity.verify("t")
    assert v["status"] == "CHANGED"
    t = next(x for x in v["tables"] if x["table"] == "support_tickets")
    assert t["rows_before"] - t["rows_after"] == 1
    assert [h["status"] for h in app.integrity.history()] == ["MATCH", "CHANGED"]
    app.integrity.record_baseline("t", "accepted change")
    assert app.integrity.verify("t")["status"] == "MATCH"


def test_audit_entries_carry_request_id_and_channel(sqlite_env):
    r = sqlite_env.gw.query(sqlite_env.login("support"), "SELECT ssn FROM users LIMIT 1", channel="cli")
    e = sqlite_env.gw.audit.search(request_id=r.request_id)
    assert len(e) == 1 and e[0]["channel"] == "cli" and e[0]["policy_version"] == r.policy_version
    with pytest.raises(Rejected) as exc:
        sqlite_env.gw.query(sqlite_env.login("support"), "DROP TABLE users")
    assert sqlite_env.gw.audit.search(request_id=exc.value.request_id)[0]["decision"] == "reject"
    st = sqlite_env.gw.audit.stats(hours=1)
    assert st["totals"]["allow"] >= 1 and st["totals"]["reject"] >= 1


def test_audit_file_is_owner_only_and_the_head_anchors_the_chain(tmp_path):
    import os
    import stat

    from maskguard.audit import AuditLog

    path = str(tmp_path / "audit.jsonl")
    log = AuditLog(path)
    for i in range(3):
        log.append(user="u", decision="allow", sql=f"q{i}")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    head = log.head()
    assert head["entries"] == 3 and log.verify(anchor=head["head"]) and not log.verify(anchor="f" * 64)
    # someone rewrites the file and recomputes every hash: the chain verifies, but the recorded head is gone
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    forged = AuditLog(str(tmp_path / "forged.jsonl"))
    for line in lines:
        import json

        e = json.loads(line)
        forged.append(**{k: v for k, v in e.items() if k not in ("hash", "prev", "ts")}, note="edited")
    os.replace(forged.path, path)
    assert AuditLog(path).verify() and not AuditLog(path).verify(anchor=head["head"])
    os.chmod(path, 0o644)
    AuditLog(path)  # reopening tightens a too-open file
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_the_demo_row_filter_never_applies_to_your_own_database(tmp_path):
    """The demo bank's filter names `accounts.status`. A customer database with an `accounts` table but no such
    column (Saffron Bank: acct_status) used to refuse every support query on it."""
    import sqlite3

    from maskguard import config

    db = tmp_path / "own.db"
    c = sqlite3.connect(db)
    c.executescript(
        "CREATE TABLE accounts (account_no TEXT, acct_status TEXT, curr_bal NUMERIC);"
        "INSERT INTO accounts VALUES ('51145972248884', 'ACTIVE', 1200.5), ('46775843622712', 'FROZEN', 90);"
    )
    c.commit()
    c.close()
    app = config.build(
        config.Settings(
            db=f"sqlite:///{db}",
            audit=str(tmp_path / "a.jsonl"),
            registry_out=str(tmp_path / "r.yaml"),
            seed_if_empty=False,
        )
    )
    assert not (app.gateway.policy.get("row_filters") or {}).get("support")
    s = app.auth.login(*config.DEMO_ACCOUNTS["support"])
    rows = app.gateway.execute(s, "SELECT account_no, acct_status FROM accounts")[1]
    assert len(rows) == 2 and all(r[0] != "51145972248884" for r in rows)  # not refused, and still masked
