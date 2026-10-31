"""Generates Smart-Data-Masking.postman_collection.json (run: python postman/build_collection.py).

Kept as code so every request and assertion is reviewable in one place. Role tokens come from /auth/demo (synthetic
demo identities, demo mode only); one request also exercises password login with the synthetic support account
from the environment file.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
SAME_SQL = "SELECT id, name, ssn, email FROM users ORDER BY id LIMIT 3"


def req(name, method, path, body=None, token=None, tests=(), pre=(), raw_body=None, headers=None):
    h = [{"key": "Content-Type", "value": "application/json"}] + (headers or [])
    if token:
        h.append({"key": "Authorization", "value": "Bearer {{" + token + "}}"})
    r = {
        "method": method,
        "header": h,
        "url": {
            "raw": "{{baseUrl}}" + path,
            "host": ["{{baseUrl}}"],
            "path": [p for p in path.split("?")[0].split("/") if p],
            **(
                {
                    "query": [
                        {"key": k, "value": v} for k, v in (q.split("=", 1) for q in path.split("?", 1)[1].split("&"))
                    ]
                }
                if "?" in path
                else {}
            ),
        },
    }
    if body is not None or raw_body is not None:
        r["body"] = {
            "mode": "raw",
            "raw": raw_body if raw_body is not None else json.dumps(body, indent=2),
            "options": {"raw": {"language": "json"}},
        }
    ev = [{"listen": "test", "script": {"type": "text/javascript", "exec": list(tests)}}]
    if pre:
        ev.append({"listen": "prerequest", "script": {"type": "text/javascript", "exec": list(pre)}})
    return {"name": name, "request": r, "event": ev}


def demo(role):
    return req(
        f"Demo identity: {role}",
        "POST",
        "/auth/demo",
        {"role": role},
        tests=[
            "pm.test('200 and a signed token', () => { pm.response.to.have.status(200); pm.expect(pm.response.json().token.split('.').length).to.eql(3); });",
            f"pm.test('role comes from the server: {role}', () => pm.expect(pm.response.json().role).to.eql('{role}'));",
            f"pm.collectionVariables.set('{role}Token', pm.response.json().token);",
        ],
    )


def q(sql):
    return {"sql": sql}


NO_RAW_SSN = "pm.test('no raw SSN in the body', () => pm.expect(pm.response.text()).to.not.include(pm.collectionVariables.get('adminSsn')));"


def STATUS(c):
    return f"pm.test('HTTP {c}', () => pm.response.to.have.status({c}));"


REJECTED = [
    STATUS(400),
    "pm.test('rejected by the firewall', () => pm.expect(pm.response.json().detail).to.match(/^rejected/));",
]

folders = [
    (
        "00 · Service health",
        [
            req(
                "Health",
                "GET",
                "/health",
                tests=[STATUS(200), "pm.test('status ok', () => pm.expect(pm.response.json().status).to.eql('ok'));"],
            ),
            req(
                "Readiness: database, scanner, policy, audit, integrity",
                "GET",
                "/ready",
                tests=[
                    STATUS(200),
                    "const c = pm.response.json().checks;",
                    "pm.test('every dependency ready', () => Object.keys(c).forEach(k => pm.expect(c[k].ok, k).to.be.true));",
                    "pm.test('default action is deny', () => pm.expect(c.policy.default_action).to.eql('deny'));",
                ],
            ),
            req(
                "Meta: demo identities listed without passwords",
                "GET",
                "/meta",
                tests=[
                    STATUS(200),
                    "pm.test('demo mode on', () => pm.expect(pm.response.json().demo_mode).to.be.true);",
                    "pm.test('no secrets', () => pm.expect(pm.response.text()).to.not.match(/password|123/i));",
                ],
            ),
        ],
    ),
    (
        "01 · Authentication",
        [
            demo("admin"),
            demo("support"),
            demo("analyst"),
            demo("auditor"),
            req(
                "Password login (synthetic support account)",
                "POST",
                "/auth/login",
                {"username": "{{supportUser}}", "password": "{{supportPassword}}"},
                tests=[
                    STATUS(200),
                    "pm.test('role support', () => pm.expect(pm.response.json().role).to.eql('support'));",
                ],
            ),
            req(
                "Wrong password → 401",
                "POST",
                "/auth/login",
                {"username": "{{supportUser}}", "password": "wrong"},
                tests=[STATUS(401), "pm.test('no token', () => pm.expect(pm.response.json().token).to.be.undefined);"],
            ),
            req("Unknown demo role → 404", "POST", "/auth/demo", {"role": "superuser"}, tests=[STATUS(404)]),
        ],
    ),
    (
        "02 · Integrity baseline",
        [
            req(
                "Verify source tables before the experiment (auditor)",
                "POST",
                "/integrity/verify",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "pm.test('MATCH', () => pm.expect(pm.response.json().status).to.eql('MATCH'));",
                    "pm.collectionVariables.set('digestBefore', pm.response.json().combined_after);",
                ],
            ),
        ],
    ),
    (
        "03 · Same query, four roles",
        [
            req(
                "Admin: real values",
                "POST",
                "/query",
                q("{{sameQuery}}"),
                "adminToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('role admin, nothing masked', () => { pm.expect(r.role).to.eql('admin'); pm.expect(r.masked).to.eql([]); });",
                    "pm.test('real SSN format', () => pm.expect(r.rows[0][2]).to.match(/^\\d{3}-\\d{2}-\\d{4}$/));",
                    "pm.test('request id issued', () => pm.expect(r.request_id).to.match(/^req-/));",
                    "pm.collectionVariables.set('adminSsn', r.rows[0][2]); pm.collectionVariables.set('adminEmail', r.rows[0][3]);",
                    "pm.collectionVariables.set('adminName', r.rows[0][1]); pm.collectionVariables.set('policyVersion', r.policy_version);",
                ],
            ),
            req(
                "Support: partial masks",
                "POST",
                "/query",
                q("{{sameQuery}}"),
                "supportToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json(); const ssn = pm.collectionVariables.get('adminSsn');",
                    "pm.test('SSN keeps only the last 4', () => pm.expect(r.rows[0][2]).to.eql('XXX-XX-' + ssn.slice(-4)));",
                    "pm.test('email partially masked', () => pm.expect(r.rows[0][3]).to.match(/^.\\*\\*\\*@/));",
                    "pm.test('names are allowed for support', () => pm.expect(r.rows[0][1]).to.eql(pm.collectionVariables.get('adminName')));",
                    "pm.test('masking reported', () => pm.expect(r.masked).to.include('users.ssn:partial'));",
                    "pm.collectionVariables.set('supportRequestId', r.request_id);",
                    NO_RAW_SSN,
                ],
            ),
            req(
                "Analyst: tokens and redaction",
                "POST",
                "/query",
                q("{{sameQuery}}"),
                "analystToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('SSN is a 32-hex (128-bit) HMAC token', () => pm.expect(r.rows[0][2]).to.match(/^[0-9a-f]{32}$/));",
                    "pm.test('name redacted', () => pm.expect(r.rows[0][1]).to.eql('REDACTED'));",
                    NO_RAW_SSN,
                    "pm.test('email not present', () => pm.expect(pm.response.text()).to.not.include(pm.collectionVariables.get('adminEmail')));",
                ],
            ),
            req(
                "Auditor: no raw PII at all",
                "POST",
                "/query",
                q("{{sameQuery}}"),
                "auditorToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('every PII cell REDACTED', () => r.rows.forEach(row => pm.expect(row.slice(1)).to.eql(['REDACTED','REDACTED','REDACTED'])));",
                ],
            ),
            req(
                "Cross-role comparison as admin (demo identities, one audited query each)",
                "POST",
                "/demo/compare",
                {"sql": "{{sameQuery}}", "roles": ["admin", "support", "analyst"]},
                "adminToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json().results;",
                    "pm.test('admin real, support partial, analyst token', () => { pm.expect(r.admin.rows[0][2]).to.eql(pm.collectionVariables.get('adminSsn')); pm.expect(r.support.rows[0][2]).to.match(/^XXX-XX-/); pm.expect(r.analyst.rows[0][2]).to.match(/^[0-9a-f]{32}$/); });",
                    "pm.test('three distinct request ids', () => pm.expect(new Set([r.admin.request_id, r.support.request_id, r.analyst.request_id]).size).to.eql(3));",
                ],
            ),
            req(
                "Query builder: support sees card masks and only active accounts",
                "POST",
                "/query/table",
                {"table": "accounts", "columns": ["credit_card", "status"], "limit": 50},
                "supportToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('cards masked with X', () => r.rows.forEach(x => pm.expect(x[0]).to.include('X')));",
                    "pm.test('row filter: no frozen accounts', () => r.rows.forEach(x => pm.expect(x[1]).to.eql('active')));",
                ],
            ),
            req(
                "Analyst aggregate: noisy AVG with privacy budget",
                "POST",
                "/query",
                q("SELECT status, avg(balance) AS avg_balance FROM accounts GROUP BY status"),
                "analystToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('ε charged and budget reported', () => { pm.expect(r.dp.epsilon).to.be.above(0); pm.expect(r.dp.remaining).to.be.below(10); });",
                ],
            ),
        ],
    ),
    (
        "04 · Policy inspection",
        [
            req(
                "My effective policy (support)",
                "GET",
                "/policy",
                token="supportToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('support rules', () => pm.expect(r.rules.PII_HIGH).to.eql('partial'));",
                    "pm.test('row filter exposed', () => pm.expect(r.row_filters.accounts).to.include('frozen'));",
                    "pm.test('same version as the queries', () => pm.expect(r.policy_version).to.eql(pm.collectionVariables.get('policyVersion')));",
                ],
            ),
            req(
                "Explain support on accounts (synthetic examples only)",
                "GET",
                "/policy/explain?table=accounts",
                token="supportToken",
                tests=[
                    STATUS(200),
                    "const c = Object.fromEntries(pm.response.json().columns.map(x => [x.column, x]));",
                    "pm.test('card partial by rule', () => { pm.expect(c.credit_card.action).to.eql('partial'); pm.expect(c.credit_card.rule).to.eql('roles.support.FINANCIAL_CONFIDENTIAL'); });",
                    "pm.test('example is synthetic', () => pm.expect(c.credit_card.example_out).to.eql('4111-XXXX-XXXX-1111'));",
                ],
            ),
            req(
                "Support explaining another role → 403",
                "GET",
                "/policy/explain?table=users&role=admin",
                token="supportToken",
                tests=[STATUS(403)],
            ),
            req(
                "Role × column matrix (auditor)",
                "GET",
                "/policy/matrix",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "pm.test('four roles', () => pm.expect(pm.response.json().roles).to.have.members(['admin','support','analyst','auditor']));",
                ],
            ),
            req(
                "Roles visible to support (own rules only)",
                "GET",
                "/roles",
                token="supportToken",
                tests=[
                    STATUS(200),
                    "const a = pm.response.json().roles.find(r => r.role === 'admin');",
                    "pm.test('other roles show description only', () => pm.expect(a.rules).to.be.undefined);",
                ],
            ),
        ],
    ),
    (
        "05 · Negative and security regressions",
        [
            req("No token → 401", "POST", "/query", q("SELECT 1"), tests=[STATUS(401)]),
            req(
                "Tampered token → 401",
                "GET",
                "/me",
                headers=[{"key": "Authorization", "value": "Bearer {{supportToken}}x"}],
                tests=[STATUS(401)],
            ),
            req(
                "Unsigned alg:none token claiming admin → 401",
                "GET",
                "/me",
                headers=[{"key": "Authorization", "value": "Bearer {{noneToken}}"}],
                pre=[
                    "const b64 = s => btoa(s).replace(/=+$/, '').replace(/\\+/g, '-').replace(/\\//g, '_');",
                    "pm.collectionVariables.set('noneToken', b64(JSON.stringify({alg:'none',typ:'JWT'})) + '.' + b64(JSON.stringify({sub:'admin.ann',role:'admin',exp:9999999999})) + '.');",
                ],
                tests=[STATUS(401)],
            ),
            req(
                "Role in request body is ignored (support asks for admin)",
                "POST",
                "/query",
                {"sql": "SELECT ssn FROM users ORDER BY id LIMIT 1", "role": "admin"},
                "supportToken",
                tests=[
                    STATUS(200),
                    "pm.test('still support', () => pm.expect(pm.response.json().role).to.eql('support'));",
                    "pm.test('still masked', () => pm.expect(pm.response.json().rows[0][0]).to.match(/^XXX-XX-/));",
                ],
            ),
            req(
                "Support cannot borrow the admin view through demo/compare → 403",
                "POST",
                "/demo/compare",
                {"sql": "{{sameQuery}}", "roles": ["admin"]},
                "supportToken",
                tests=[STATUS(403), NO_RAW_SSN],
            ),
            req(
                "Stacked statement injection",
                "POST",
                "/query",
                q("SELECT 1; DROP TABLE users"),
                "supportToken",
                tests=REJECTED,
            ),
            req(
                "UPDATE through the gateway",
                "POST",
                "/query",
                q("UPDATE accounts SET balance = 0"),
                "adminToken",
                tests=REJECTED,
            ),
            req(
                "Catalog read",
                "POST",
                "/query",
                q("SELECT * FROM information_schema.tables"),
                "supportToken",
                tests=[STATUS(400)],
            ),
            req(
                "Dangerous function", "POST", "/query", q("SELECT load_extension('x')"), "supportToken", tests=REJECTED
            ),
            req(
                "Masking function called directly",
                "POST",
                "/query",
                q("SELECT mg_hmac(ssn) FROM users"),
                "analystToken",
                tests=REJECTED,
            ),
            req(
                "CTE named like the table cannot unmask",
                "POST",
                "/query",
                q("WITH users AS (SELECT * FROM users) SELECT ssn FROM users ORDER BY id LIMIT 1"),
                "supportToken",
                tests=[
                    STATUS(200),
                    "pm.test('masked', () => pm.expect(pm.response.json().rows[0][0]).to.match(/^XXX-XX-/));",
                    NO_RAW_SSN,
                ],
            ),
            req(
                "Expression bypass: lower(ssn)",
                "POST",
                "/query",
                q("SELECT lower(ssn) AS s, ssn || '' AS t FROM users"),
                "analystToken",
                tests=[
                    STATUS(200),
                    NO_RAW_SSN,
                    "pm.test('no SSN pattern anywhere', () => pm.expect(pm.response.text()).to.not.match(/\\d{3}-\\d{2}-\\d{4}/));",
                ],
            ),
            req(
                "Equality oracle on a masked column finds nothing",
                "POST",
                "/query",
                q("SELECT count(*) AS n FROM users WHERE ssn = '{{adminSsn}}'"),
                "supportToken",
                tests=[
                    STATUS(200),
                    "pm.test('predicate sees masked values only', () => pm.expect((pm.response.json().rows[0] || [0])[0]).to.eql(0));",
                ],
            ),
            req(
                "Frozen accounts unreachable for support via subquery",
                "POST",
                "/query",
                q("SELECT count(*) AS n FROM (SELECT * FROM accounts) a WHERE a.status = 'frozen'"),
                "supportToken",
                tests=[
                    STATUS(200),
                    "pm.test('zero rows', () => pm.expect((pm.response.json().rows[0] || [0])[0]).to.eql(0));",
                ],
            ),
            req(
                "Error message does not echo values",
                "POST",
                "/query",
                q("SELECT * FROM users WHERE ssn = '{{adminSsn}}' AND"),
                "supportToken",
                tests=[STATUS(400), NO_RAW_SSN],
            ),
            req(
                "Malformed JSON → 422", "POST", "/query", raw_body='{"sql": ', token="supportToken", tests=[STATUS(422)]
            ),
            req(
                "Missing sql field → 422", "POST", "/query", {"query": "SELECT 1"}, "supportToken", tests=[STATUS(422)]
            ),
            req(
                "Query builder: injected table name → 404",
                "POST",
                "/query/table",
                {"table": "users; DROP TABLE users"},
                "supportToken",
                tests=[STATUS(404)],
            ),
            req(
                "Query builder: unknown column → 400",
                "POST",
                "/query/table",
                {"table": "users", "columns": ["ssn) --"]},
                "supportToken",
                tests=[STATUS(400)],
            ),
            req("Support reading the audit log → 403", "GET", "/audit", token="supportToken", tests=[STATUS(403)]),
            req(
                "Support reading scanner evidence → 403", "GET", "/registry", token="supportToken", tests=[STATUS(403)]
            ),
            req(
                "Analyst running integrity checks → 403",
                "POST",
                "/integrity/verify",
                token="analystToken",
                tests=[STATUS(403)],
            ),
            req(
                "Auditor changing policy → 403",
                "PUT",
                "/policy/rules",
                {"role": "support", "tag": "PII_HIGH", "action": "allow"},
                "auditorToken",
                tests=[STATUS(403)],
            ),
            req(
                "Admin weakening a rule without confirmation → 409",
                "PUT",
                "/policy/rules",
                {"role": "support", "tag": "PII_HIGH", "action": "allow"},
                "adminToken",
                tests=[
                    STATUS(409),
                    "pm.test('explains why', () => pm.expect(pm.response.json().detail).to.include('confirm'));",
                ],
            ),
            req(
                "Unknown masking action → 400",
                "PUT",
                "/policy/rules",
                {"role": "support", "tag": "PII_HIGH", "action": "show_all"},
                "adminToken",
                tests=[STATUS(400)],
            ),
            req(
                "Policy unchanged after rejected edits",
                "GET",
                "/policy",
                token="supportToken",
                tests=[
                    STATUS(200),
                    "pm.test('same version', () => pm.expect(pm.response.json().policy_version).to.eql(pm.collectionVariables.get('policyVersion')));",
                ],
            ),
        ],
    ),
    (
        "06 · Audit trail",
        [
            req(
                "Audit chain intact (auditor)",
                "GET",
                "/audit?n=200",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "pm.test('hash chain valid', () => pm.expect(pm.response.json().chain_valid).to.be.true);",
                    "pm.test('literals stripped: no SSN in the log', () => pm.expect(pm.response.text()).to.not.include(pm.collectionVariables.get('adminSsn')));",
                ],
            ),
            req(
                "Find the support query by request id",
                "GET",
                "/audit?request_id={{supportRequestId}}",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "const e = pm.response.json().entries;",
                    "pm.test('exactly one entry', () => pm.expect(e.length).to.eql(1));",
                    "pm.test('who, how, which policy', () => { pm.expect(e[0].user).to.eql('support.sam'); pm.expect(e[0].channel).to.eql('rest'); pm.expect(e[0].policy_version).to.eql(pm.collectionVariables.get('policyVersion')); });",
                    "pm.test('masking recorded', () => pm.expect(e[0].masked).to.include('users.ssn:partial'));",
                ],
            ),
            req(
                "Rejections are recorded",
                "GET",
                "/audit?decision=reject&n=50",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "pm.test('firewall rejections logged', () => pm.expect(pm.response.json().entries.length).to.be.at.least(4));",
                ],
            ),
            req(
                "Capability denials are recorded",
                "GET",
                "/audit?decision=denied&n=50",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "const u = pm.response.json().entries.map(e => e.user);",
                    "pm.test('support and analyst denials logged', () => pm.expect(u).to.include.members(['support.sam', 'analyst.ali']));",
                ],
            ),
        ],
    ),
    (
        "07 · Integrity after the experiment",
        [
            req(
                "Source tables unchanged",
                "POST",
                "/integrity/verify",
                token="auditorToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('MATCH', () => pm.expect(r.status).to.eql('MATCH'));",
                    "pm.test('digest identical to before', () => pm.expect(r.combined_after).to.eql(pm.collectionVariables.get('digestBefore')));",
                    "pm.test('every table MATCH', () => r.tables.forEach(t => pm.expect(t.status, t.table).to.eql('MATCH')));",
                ],
            ),
            req(
                "Full immutability proof",
                "POST",
                "/integrity/proof",
                {"sql": "{{sameQuery}}"},
                "auditorToken",
                tests=[
                    STATUS(200),
                    "const r = pm.response.json();",
                    "pm.test('PASS', () => pm.expect(r.status).to.eql('PASS'));",
                    "pm.test('all write attempts rejected', () => r.unauthorized_attempts.forEach(a => pm.expect(a.status, a.attempt).to.eql('REJECTED')));",
                    "pm.test('before == after', () => pm.expect(r.before).to.eql(r.after));",
                ],
            ),
        ],
    ),
]

collection = {
    "info": {
        "name": "MaskGuard · Smart Data Masking",
        "description": "Role-based masking, end to end: same query as four roles, policy explanations, 26 negative and "
        "security regressions, audit evidence, and an integrity check before and after. Run the whole "
        "collection in order (Collection Runner or `newman run`). Uses synthetic demo identities only.",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "variable": [{"key": "sameQuery", "value": SAME_SQL}],
    "item": [{"name": n, "item": items} for n, items in folders],
}
environment = {
    "name": "MaskGuard · Local",
    "values": [
        {"key": "baseUrl", "value": "http://127.0.0.1:8000", "enabled": True},
        {"key": "supportUser", "value": "support.sam", "enabled": True},
        {"key": "supportPassword", "value": "support123", "enabled": True, "type": "secret"},
    ],
    "_postman_variable_scope": "environment",
}

if __name__ == "__main__":
    with open(os.path.join(HERE, "Smart-Data-Masking.postman_collection.json"), "w", encoding="utf-8") as f:
        json.dump(collection, f, indent=2, ensure_ascii=False)
    with open(os.path.join(HERE, "Local.postman_environment.json"), "w", encoding="utf-8") as f:
        json.dump(environment, f, indent=2)
    n = sum(len(i) for _, i in folders)
    a = sum(sum(t.count("pm.test(") for t in r["event"][0]["script"]["exec"]) for _, i in folders for r in i)
    print(f"{n} requests, {a} assertions")
