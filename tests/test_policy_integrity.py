"""Policy engine (explain, versions, runtime edits, row filters, auditor role) and source-data integrity proofs."""
import pytest

from maskguard import policy as P
from maskguard.integrity import compare, snapshot, proof
from maskguard.rewriter import Rejected


def test_explain_matches_what_the_gateway_returns(env):
    pol, reg = env.gw.policy, env.gw.registry
    ex = {c["column"]: c for c in P.explain("support", "users", reg, pol)["columns"]}
    assert ex["ssn"]["action_label"] == "Partial mask" and ex["ssn"]["rule"] == "roles.support.PII_HIGH"
    assert ex["ssn"]["example_out"] == "XXX-XX-6789" and ex["id"]["tag"] == "PUBLIC" and ex["id"]["action"] == "allow"
    cols, rows = env.run("support", "SELECT ssn FROM users ORDER BY id LIMIT 1")
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
    cols, rows = env.run("auditor", "SELECT name, ssn, email, phone FROM users ORDER BY id LIMIT 5")
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
    for sql in ["WITH a AS (SELECT * FROM accounts) SELECT count(*) FROM a WHERE status = 'frozen'",
                "SELECT count(*) FROM (SELECT * FROM accounts) x WHERE x.status = 'frozen'",
                "SELECT count(*) FROM users u JOIN accounts a ON a.user_id = u.id WHERE a.status = 'frozen'",
                "SELECT count(*) FROM accounts WHERE status = 'frozen' OR 1 = 1 AND status = 'frozen'"]:
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
        store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann")          # weakening, unconfirmed
    with pytest.raises(P.PolicyError):
        store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann", confirm=True)  # no reason
    with pytest.raises(P.PolicyError):
        store.set_rule("support", "PII_HIGH", "show", actor="admin.ann")          # unknown action
    r = store.set_rule("support", "PII_HIGH", "redact", actor="admin.ann")         # stricter: no confirmation
    assert r["changed"] and r["version"] != v0
    _, rows = sqlite_env.run("support", "SELECT ssn FROM users LIMIT 1")
    assert rows[0][0] == "REDACTED"                                                # takes effect immediately
    r = store.set_rule("support", "PII_HIGH", "allow", actor="admin.ann", reason="demo", confirm=True)
    assert any("non-admin" in w for w in r["warnings"])
    _, rows = sqlite_env.run("support", "SELECT ssn FROM users ORDER BY id LIMIT 1")
    assert rows[0][0] == sqlite_env.real("ssn")
    e = store.reset("admin.ann")
    assert e["version_after"] == v0 and [h["change"] for h in store.history()] == ["set_rule", "set_rule", "reset"]
    audit_versions = {x.get("policy_version") for x in app.gateway.audit.entries() if x.get("decision") == "allow"}
    assert len(audit_versions) == 2 and None not in audit_versions  # every audit entry names the policy version that decided it


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
    assert [t["table"] for t in changed] == ["users"] and changed[0]["content_changed"] and not changed[0]["schema_changed"]


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
