# Security analysis: what protects the data, and which test proves it

Written 31 October 2026 from the code, not from earlier claims. Every property names the function that enforces it
and the tests that would fail if it broke. Run them all with `uv run pytest -q` (set `MASKGUARD_TEST_PG` and
`MASKGUARD_TEST_MYSQL` to include PostgreSQL 16 and MySQL 8.4, as CI does).

## 1. The one path to the data

```
REST API / CLI / Python SDK / PostgreSQL wire proxy / dashboards
        │  identity: signed token or password  (auth.py)
        ▼
Gateway.query  (gateway.py) ── threat engine may block the session (threat.py)
        │
        ▼
rewrite()  (rewriter.py) ── parse → refuse anything but one SELECT → refuse unknown functions → replace every
        │                    protected column with its mask for this role → group-size floor → row filter
        ▼
read-only database account executes the rewritten SQL (backends.py)
        │
        ▼
audit entry appended to the hash chain (audit.py) ── only then is the result returned
```

All five interfaces call `Gateway.query`; none talks to the database for a user's query. The masks run inside the
database, so a filter, join, sort or aggregate sees the masked value, not the real one.

## 2. Properties, enforcement and evidence

| Property | Enforced by | Tests |
|---|---|---|
| Only one SELECT reaches the database: no writes, DDL, transactions, `COPY`, `ATTACH`, `PRAGMA`, `LOAD DATA`, `INTO OUTFILE`, `CALL`, `SET`, `GRANT`, stacked statements, recursive CTEs | `rewriter._validate`: allow-list of root statement types, forbidden node types, allow-list of functions | `test_security_gaps.py` (70 statements × 3 dialects, plus "a refused statement changes nothing"), `test_attacks.py` |
| A protected value cannot leak through any query shape: joins, subqueries, CTEs, `UNION`/`INTERSECT`/`EXCEPT`, window functions, `CASE`, `HAVING`, `ORDER BY`, `DISTINCT`, casts, aliases | `rewriter.rewrite`: each column reference is replaced by its mask before the query runs | `test_attack_matrix.py`: 672 cases, 12 query families × 3 roles × 3 databases + a fuzzer, each planting a sentinel and checking no raw value returns |
| Inference through predicates, ranges, sorting and repeated counts | Masks are applied before `WHERE`/`JOIN`/`ORDER BY` see the value; analysts get a minimum group size; the threat engine scores enumeration, binary search, ORDER BY probing, bulk paging | `test_attacks.py` (17 named attacks, 0 leak; output-only masking leaks 14–15 of 17), `test_threat.py`, `test_dp.py` |
| Prepared statements keep masking | At Bind the proxy substitutes the parameters and sends the whole statement through the gateway; a crafted parameter can only produce a SELECT the user could have typed, which meets the same allow-list and masks | `test_proxy.py::test_auto_prepared_statements_keep_masking` |
| Unreviewed columns are masked | A column the scanner found nothing in is `UNREVIEWED`, masked for every role but admin until a person approves it | `test_hardening.py` (sentinel columns), `test_onboarding.py` |
| Identity comes from a signed token, never from the request | `auth.session_from_token`: HS256 only, `exp` and `sub` required, the role re-checked against the user store on every request | `test_api_v1.py` (forged, unsigned, "role in body"), `test_platform.py` (wrong key), `test_security_gaps.py` (expired, other algorithm, changed role, higher role claimed) |
| No request's role reaches another request | Sessions are immutable values passed per call; no per-connection role state | `test_concurrency.py`: 120 mixed-role queries on 12 threads, three databases |
| Database error text never reaches a client | `gateway.safe_error` on REST, proxy (simple and extended protocol) and dashboards | `test_hardening.py` |
| A failure never falls back to unmasked data | Parse failure, unknown role, missing capability, bad row filter → `Rejected`; missing masking functions → start-up refused; a failed audit write withholds the result | `test_security_gaps.py::test_a_failed_audit_write_withholds_the_result_and_keeps_the_chain_verifiable`, `test_hardening.py`, `test_production.py` |
| The audit log shows edits, deletions and reordering | SHA-256 hash chain; `head()` exported as an outside anchor | `test_policy_integrity.py`, `test_security_gaps.py` |
| Production refuses unsafe set-ups | `config.build` in production: no demo identities, no default secrets, no writable or owner database account, TLS for the API | `test_production.py` (55 tests, incl. a live HTTPS server) |
| Names from the catalogue cannot break out of SQL | `backends.quote_ident` doubles quotes inside table, column and schema names | `test_security_gaps.py::test_a_quote_inside_a_table_or_column_name_stays_inside_the_identifier` |
| The data is never changed | Read-only account; SQLite authoriser allows reads only; integrity digests before and after | `test_policy_integrity.py`, `maskguard integrity` |

## 3. Bugs found by this audit and fixed

| Finding | Effect | Fix | Regression test |
|---|---|---|---|
| `AuditLog.append` moved the chain head before writing | After one failed write (disk full) every later entry linked to an entry that was never written, so `verify()` failed for good | Move the head only after the write succeeds | `test_a_failed_audit_write_…` (failed before the fix) |
| `check_password` checked the algorithm with `assert` | `python -O` strips asserts, so a hash of another scheme would have been parsed as PBKDF2 | Explicit check | existing login tests |
| Catalogue names were quoted without escaping | A table or column whose name contains `"` could break out of the identifier when the scanner sampled it | `quote_ident` everywhere identifiers are interpolated | `test_a_quote_inside_…` |
| The SDK client accepted any URL scheme | `file://` and custom schemes would have been opened | Only `http`/`https` | — |
| Known vulnerabilities in dependencies | Pillow 12.3.0 (39 advisories, via Streamlit) and certifi 2026.7.22 | Pillow 13.0.0, Streamlit 1.66.1, certifi 2026.10.23; Python 3.11+ (no fixed Pillow supports 3.10) | `pip-audit`: no known vulnerabilities |

## 4. What MaskGuard does not protect, by design or not yet

- **Direct database access.** Anyone holding database credentials bypasses MaskGuard. The deployment must keep the
  database on a private network, give MaskGuard a read-only account, and keep owner credentials elsewhere
  (`docs/DEPLOYMENT.md`, `docker-compose.prod.yml`). Production mode refuses a writable or owner account; it cannot
  see the network.
- **Token revocation** is by changing the user store (a removed user or changed role invalidates tokens at once);
  there is no token deny-list, so a stolen token of an unchanged user works until it expires (8 hours by default).
- **Threat state is in memory**, per gateway process. Several gateway instances do not share it (shared state in a
  database or Redis is the planned fix).
- **Noisy aggregates are not differential privacy** and are refused in production (decision D11,
  `docs/design/PRIVACY_ACCOUNTING.md`).
- **Inference from public columns.** Combinations of unmasked columns (age, city, date) can still single people out;
  a quasi-identifier risk report is planned (`docs/ROADMAP.md`).
