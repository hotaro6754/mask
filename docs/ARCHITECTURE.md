# Architecture and security boundary

## One enforcement path

```
 psql / any PG driver ──► PG wire proxy ─┐
 REST API / SDK / Postman ───────────────┤
 Control Room dashboard (/ui) ───────────┼──► Gateway.query(session, sql, channel)
 CLI (in-process, or --api URL) ─────────┤        │
 Streamlit dashboard (classic) ──────────┘        ├─ 1 session valid? (signed JWT / in-process login; role from user store)
                                                  ├─ 2 threat engine: is this user blocked?
                                                  ├─ 3 rewriter: parse → firewall → rewrite every base table into a
                                                  │    masked view (+ row filter) → row cap → small-group floor
                                                  ├─ 4 DP budget charged (analyst aggregates)
                                                  ├─ 5 execute READ ONLY on SQLite | PostgreSQL | MySQL
                                                  ├─ 6 Laplace noise for DP aggregates
                                                  └─ 7 audit (request id, channel, policy version, masked columns,
                                                       risk; literals stripped) → result
```

Every interface calls `Gateway.query`, and no interface has another route to the data. The policy engine in
`policy.py` (explain, versions, capabilities, validated edits) and the integrity checks in `integrity.py` sit beside
it and use the same policy dictionary the rewriter enforces.

## Trust boundary: what is and isn't protected

| Inside the boundary (MaskGuard enforces) | Outside (needs its own controls) |
|---|---|
| Every query through the REST API, the PG wire proxy, the CLI, the dashboards and the SDK | Anyone holding database credentials directly (DBAs, other applications). In production MaskGuard refuses to start unless its own DB account is read-only (no write, DDL or ownership); masking functions are installed separately by `maskguard db-install` with the owner account. Don't give apps direct credentials |
| Masking happens **inside the SQL that reaches the database**: the database returns already-masked values, and predicates, joins and aggregates only see masked values | Database backups, replicas and logs (the stored data is real) |
| Source records are never modified: execution is read-only (SQLite authorizer, `READ ONLY` transactions on PostgreSQL and MySQL), and integrity proofs verify it | MaskGuard's own state files (`data/`): protect with filesystem permissions |
| Role comes from the user store and is carried in a signed token; the request body can't change it | Token theft (TLS and short TTLs are deployment concerns; the default TTL is 8 h) |

The claim is not that MaskGuard "intercepts every query to the database". It controls every query that comes
through it, and it is built so that nothing needs to bypass it: SQL clients, drivers, REST and SDK all go through
the gateway.

## Identities, roles and capabilities

- **Authentication.** Users live in `policies/users*.yaml` with PBKDF2-SHA256 hashes (200k iterations). Login
  mints an HS256 JWT. Each request re-checks that the user still exists and still holds the role, so a role
  change revokes old tokens.
- **Demo identities** (`admin.ann`, `support.sam`, `analyst.ali`, `auditor.aud`) are ordinary users. Demo mode only
  adds `POST /auth/demo {role}`, which logs in as one of them so evaluators can switch roles without passwords.
  - It is on by default only when `MASKGUARD_ENV` isn't `production`.
  - With `MASKGUARD_ENV=production` it is off by default.
  - `MASKGUARD_DEMO=1` together with `production` stops startup with an error.
  - Production also stops startup if the user store contains any demo identity, because turning demo mode off
    only removes `/auth/demo`: the demo users would otherwise still log in through `/auth/login`. It also requires
    `MASKGUARD_JWT_SECRET`, so tokens survive restarts and are shared by every instance.
  - Demo logins are accepted only from the same machine (loopback) unless `MASKGUARD_DEMO=1` is set explicitly, and
    the server logs a DEMO MODE warning at startup. Anyone who can use demo mode can act as any demo role,
    including admin, so it is for synthetic data only.
  - `POST /demo/compare` only runs roles whose view is no more revealing than the caller's: every classification
    at least as strictly masked and the same row filters. A Support or Auditor token therefore can't borrow the
    Admin view; an Admin may compare every role.
- **Capabilities** (`role_info.<role>.capabilities` in the policy) gate everything except querying. Denials
  return 403 and are audited.

| Role | Sees | Capabilities beyond `query` |
|---|---|---|
| admin | Real values | policy.read, policy.write, registry.read, scan.run, audit.read, integrity.verify, integrity.baseline, threats.manage, pia.read |
| support | Partial masks (`XXX-XX-6789`, `4111-XXXX-XXXX-1111`, `r***@bank.in`), names, identifiers inside notes replaced by `[PHONE]` etc., balances rounded to 10,000; **no frozen accounts** (row filter) | none |
| analyst | Identifiers as keyed HMAC tokens (joinable, not reversible), names redacted, money only through noisy SUM/AVG/COUNT within a daily ε budget (development only; refused in production) | none |
| auditor | `REDACTED` for every personal-data column | policy.read, registry.read, audit.read, integrity.verify, pia.read |

## Policy semantics

- **Classification.** The scanner tags columns `PII_HIGH`, `FINANCIAL_CONFIDENTIAL`, `PII_MEDIUM`, `PII_IN_TEXT`,
  `HEALTH` (ICD-10 codes and blood groups by value, health words by name), or nothing. Unreviewed whole-number keys
  and short value lists carry a `suggest: PUBLIC` hint for `maskguard pii approve --suggested`. Nothing found is `UNREVIEWED`, not safe: it has its own rule per role (default policy: admin `allow`,
  everyone else `redact`; no rule falls back to `default_action`). Only `PUBLIC`, set by a person in
  `overrides.yaml`, means "approved, not personal" and is always allowed. Manual tags in `overrides.yaml` win over the
  scanner. Demo mode adds `policies/public.demo.yaml` (the demo schema's ids, statuses and cities), and only for
  columns the scanner left untagged; production never loads it.
- **Rule lookup.** `roles.<role>.<tag>` gives the action. A tag with no rule gets `default_action`, which must be
  `deny` or `redact`; validation refuses anything else. An unknown role is rejected. An unknown action becomes a
  NULL column (deny).
- **Strictness order:** allow < partial < redact_text < hmac < aggregate < redact < deny. A runtime edit that moves
  down this order is "weakening" and needs `confirm=true` plus a reason. Giving raw `PII_HIGH` or
  `FINANCIAL_CONFIDENTIAL` values to a non-admin role always raises a warning.
- **Field suppression.** `deny` returns a typed NULL rather than removing the column, so `SELECT *` and joins
  keep working. The value is withheld either way.
- **Row-level security.** `row_filters.<role>.<table>` is a column-versus-literal predicate placed *inside* the
  masked view. CTEs, subqueries and joins therefore can't see the hidden rows.
- **Versioning.** `policy_version` is a hash of the full effective policy. It is returned with every query and
  stored in every audit entry.
- **Runtime edits** (`PUT /policy/rules`, `maskguard policy set`) change the live policy in memory and are
  appended to `policy_history.jsonl`. The YAML file stays the reviewed baseline, and `reset` returns to it. To make
  an edit permanent, commit it to the YAML through code review.

## Masking transformations

| Action | SQL emitted | Notes |
|---|---|---|
| partial | `mg_partial(col, prefix, suffix)` / `mg_email(col)` / `mg_bucket(num, 10000)` | Separators kept, so formats stay readable. Output is byte-identical across SQLite (Python UDF), PostgreSQL (PL/pgSQL) and MySQL (stored function) |
| hmac | `mg_token(col, scope, 32)`, keyed HMAC-SHA256, 32 hex characters (128 bits; `hmac.length` 16–64). Scope is empty by default, or `table.column` with `hmac: {scope: column}` | Deterministic, so joins and counts still work (across columns only with the default global scope). Pseudonymous, not anonymous. The key comes from `MASKGUARD_HMAC_KEY` (fail closed if missing). It is **not** encryption: tokens can't be reversed, but equal values give equal tokens (frequency analysis) |
| redact_text | `mg_redact_text(col)` | 21 ordered patterns: identifiers inside text become `[PHONE]`, `[AADHAAR]` and so on |
| aggregate | `LEAST(GREATEST(col, lo), hi)` inside the view, plus Laplace noise on SUM/AVG/COUNT | Any other use of the column is redacted. Bounds are per table and column (`dp.bounds.<table>.<col>`); a reference that can't be tied to one table gets no noisy release. Not a formal DP guarantee: known gaps and the proposed fix are in `docs/design/PRIVACY_ACCOUNTING.md`. Refused in production (the gateway rejects the query before charging any budget) |
| redact | `'REDACTED'` / typed NULL | |
| deny | Typed NULL | |

## Source-data integrity

`integrity.snapshot()` reads every source table through the privileged connection and records, per table:
- the row count;
- the SHA-256 of the ordered `(column, type)` list;
- the SHA-256 of the sorted, canonical-JSON-encoded rows.

`verify` compares a fresh snapshot with the stored baseline. `proof` takes a digest, runs the same query as every
role, attempts six kinds of write through the gateway, takes the digest again, and reports PASS only if nothing
changed and every write was refused.

**Limitations.** The digest covers source tables only. MaskGuard's own files (audit log, policy history,
registry) change by design and have their own checks: the audit hash chain and policy versions. A mismatch means
the data changed, which is not necessarily tampering, since legitimate concurrent writes change it too. Each
check reads whole tables, so it is for demos and audits, not for every query.

## Audit

The audit log (`data/audit.jsonl`) is append-only JSON lines with a hash chain (`prev` → `hash`), and
`verify()` detects any edited, removed or reordered entry. The chain is unkeyed, so it shows accidental or partial
edits; someone who can rewrite the whole file on the host can recompute it. Ship entries to an external store if
that matters.
- **What it records:** request id, channel (`rest`, `rest-demo`, `cli`, `pgwire`, `dashboard`, `engine`), user,
  role, the SQL fingerprint with **every literal replaced by `?`**, policy version, masked columns, decision, rows,
  latency, threat risk and actions, and ε spent.
- **Other events logged:** capability denials, policy changes, scans, integrity checks and threat unblocks.
- **Error handling:** parse errors report only a position, so a malformed query can't copy its literals into
  the log or the response. Database errors are reported by exception type only.

## Dashboard security

- **No inline code.** The Control Room (`/ui/`) is static HTML, CSS and JS with no inline scripts or styles,
  served with `Content-Security-Policy: default-src 'self'`.
- **Headers.** `frame-ancestors 'none'`, `X-Frame-Options: DENY`, `nosniff`, and `no-store` on API responses.
- **Safe rendering.** Server values are always inserted as text, never as HTML.
- **Tokens and identity.** The token lives in the tab's `sessionStorage`. Every role switch is a real login, and
  every playground column comes from a separate request made with that role's own token.
