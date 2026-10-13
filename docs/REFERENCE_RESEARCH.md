# Reference research

What we studied before building the policy engine, CLI, API tests and dashboard, what we took from it, and what we
deliberately left out. No code was copied from any repository below; every idea was re-implemented in MaskGuard's own
stack, so no third-party license notices are required.

Method: each repo was shallow-cloned (`git clone --depth 1`) on 2026-10-12 and read with grep, cat and find only. Nothing from the clones was installed or run. "Verified" means I saw the behaviour in source code. "Claimed" means it appears only in the README or docs. Last-commit dates come from `git log -1`. Because the clones are shallow, I could not count commits.

---

## A. Repositories suggested in the brief

### 1. Raj-git23/rbac-dashboard-platform
- **License:** none. The README says only "provided as-is for educational and evaluation purposes", so **we cannot reuse its code**. Last commit 2026-05-12.
- **Worth studying:** `backend/app/middleware/__init__.py`. `RBACEnforcer.has_permission` builds a set of `(module, action)` pairs across all of a user's roles. `FieldFilter.apply_filter` loads `FieldRule` rows for the user's roles and deletes keys where `is_visible=False` from the response dicts. `backend/app/api/dependencies.py` provides `require_permission(module, action)` as a FastAPI dependency factory, and it reloads the user and roles from the database on every request.
- **Verified:** backend permission checks on every route in `widget_data.py` and `audit_logs.py`; Argon2 hashing; JWT in HttpOnly cookies. The README's "attribute-level filtering" is verified, but it only removes fields. There is no masking.
- **Limitations:** field filtering is a **denylist applied after the query runs**. Any column without a rule is visible, so the design fails open. `secret_key` has a hardcoded default (`config.py`). There are 2 unit tests, both using mock objects.
- **What we can adapt:** the `require_permission()` dependency-factory pattern for our FastAPI admin endpoints. We should not copy the denylist model.

### 2. RandyRozario/rbac-engine
- **License:** none, so code cannot be reused. Last commit 2026-05-31. Node/Express. No tests (`package.json` has no test script).
- **Worth studying:** `backend/src/middleware/rbac.js`. `authorize(...roles)` and `authorize.minLevel()` check the roles in an RS256 JWT. Every GRANTED or DENIED decision goes to `auditService.logAccess`. The 403 body contains `detail`, `requiredRoles` and `auditReference` (the token `jti`). `identityProvider.js` rotates refresh tokens and stores them only as bcrypt hashes.
- **Verified:** the audit columns (`db/init.sql`: `access_status`, `denial_reason`, `token_jti`, `roles_claimed`, `ip_address`, `user_agent`, `session_id`), refresh rotation, and server-side route guards. **Only claimed:** an "immutable" audit trail. `init.sql` has no trigger, rule or REVOKE that would block UPDATE or DELETE.
- **Limitations:** an audit write failure is caught and logged to the console (`logAccess`), so it **fails open**. The client IP is taken from `X-Forwarded-For` without any trusted-proxy check. Roles come from the token, so revoking a role takes effect only after up to 15 minutes. The 403 response echoes `yourRoles`.
- **What we can adapt:** the audit field set and the idea of a structured denial body that points to an audit record.

### 3. sderosiaux/agent-data-gateway (most architecturally similar)
- **License:** none, so code cannot be reused. Last commit 2026-03-11. Go. Has unit and integration tests (`*_test.go`).
- **Worth studying:**
  - `internal/policy/engine.go` evaluates OPA/Rego in-process. It returns `{allow, allowed_fields, masked_fields{field:strategy}, denied_fields, policy_id}` and reloads atomically on fsnotify. If compilation fails, it keeps the last good bundle.
  - `internal/connector/postgres/viewddl.go` and `provision.go` create one PostgreSQL role and schema per agent, with views that leave out denied columns. `hash` becomes `MD5(col)` and `generalize` becomes `'*@'||split_part`. They then run `REVOKE ALL ON ALL TABLES IN SCHEMA public`.
  - `internal/qi/detect.go` flags a result row with `_qi_warning` when it contains at least k fields from a configured quasi-identifier set.
  - `internal/audit/audit.go` audits `query_hash` (SHA-256), `fields_req/exp/mask`, `field_tags`, `qi_flag`, `policy_id`, `latency_ms` and `error`.
- **Verified vs claimed:** the views and REVOKE are verified. The README says that even with a direct DB connection "Postgres still enforces the view boundary". That holds **only for denied, hash and generalize fields**. `redact` and `noise` are selected **in plaintext** in the view and masked later in Go (`viewddl.go`, `masking.ApplyToRow`).
- **Limitations:** `internal/sqlparse/extract.go` is regex-based and falls back to `*` when parsing fails. The hash is unsalted MD5, which can be reversed by dictionary attack for SSNs and phone numbers. The audit buffer **drops events when full** (`Record`). API keys are stored in plaintext config.
- **What we can adapt:** the quasi-identifier co-occurrence warning, the audit field set, and the policy decision shape (a good template for our `explain` JSON). It also confirms our choice of AST rewriting over regex.

### 4. awslabs/tolap (best reference for masking semantics)
- **License:** Apache-2.0. Last commit 2026-10-01. SDKs in Python, TypeScript and .NET, with large test suites (`sdk/python/tests`, 55+ files) and shared JSON fixtures.
- **Worth studying** (all under `sdk/python/tolap-core/tolap_core/`):
  - `enums.py`: the `MaskType` values `partial|hash|full|redact|null`, ranked by **how much they disclose**. An unknown type ranks above every known one.
  - `merger.py`: merging multiple policies. Allowed sets are intersected, hidden sets are unioned, row filters are concatenated, masks take the most restrictive type, limits take the minimum, and an empty input gives deny-all.
  - `enforcement.py::_apply_mask`: `partial` falls back to a full mask if `show_first+show_last >= len`. `hash` uses an HMAC keyed by a deployment-wide salt. An unknown algorithm or type returns `[REDACTED]`, so it fails closed.
  - `sql_rewriter.py`: pushes field and row filters into SQL. It is regex and depth-scan based and uses only the standard library. It declines CTEs and set operations and leaves them to post-fetch enforcement. Its docstring records a real bug: inferring `"` quoting on MySQL silently matched 0 rows. The dialect is therefore always explicit and never inferred.
  - `fixtures/merge-scenarios/*.json` and `fixtures/enforcement/*.json`: language-neutral golden test cases.
- **Verified:** everything listed above. There is also a STRIDE threat model in `docs/security/threat-model.md`.
- **Python compatibility:** Python 3.10 or later with zero runtime dependencies. We could use it directly, but its policy model is not ours. Adopting the ideas is the better path.
- **What we can adapt:** the restrictiveness ordering for resolving a user with several roles, fail-closed handling of unknown actions, explicit dialects, and JSON golden fixtures for rewrite cases.

### 5. daryal89/api-database-testing-portfolio
- **License:** MIT. Last commit 2026-08-14. Postman/Newman against the public Restful Booker API, plus PostgreSQL SQL checks.
- **Worth studying:** `.github/workflows/newman-api-tests.yml` runs a **strict smoke collection as the CI gate**. The **full negative suite** runs with `continue-on-error: true`, and the step summary separates "known findings" from regressions. The workflow fails fast if repository secrets are missing, exports JUnit and JSON results, and uploads them as artifacts. The test scripts take the test-case ID from the request name (`pm.info.requestName.split(" - ")[0]`) and assert that a field is absent (`pm.expect(json).to.not.have.property("token")`). `sql/05_constraint_negative_tests.sql` contains database negative tests.
- **Verified:** yes, by reading the collection JSON and the workflow.
- **What we can adapt:** the two-tier CI split, TC-ID naming, and assertions that something must *not* be present.

### 6. BrianGator/Postman-Rest-API-Automation-Testing-Showcase
- **License:** none, so code cannot be reused. Last commit 2026-05-30.
- **Finding:** most collections (`postman-rest-api-tests/*`, `newman-rest-api-test/*`) contain **one request each**. The bundled Flask mock (`servers/flask/app.py`) implements only 3 routes, so most collections target endpoints that do not exist (for example `/auth/profile`). CI runs only `collections/2_advanced_chaining.json` and never starts the mock server. The "security compliance" claims are therefore mostly unverified stubs.
- **Useful patterns:** `data/users_mock_data.json` drives iterations with `{username, role, expectedStatus}` per row. The collection chains a token through `pm.environment.set`. It validates JSON Schema with `tv4`, which is deprecated in Postman; prefer `pm.response.to.have.jsonSchema`.
- **What we can adapt:** a data-driven role matrix (role × query → expected status and mask pattern).

### 7. OWASP/Amass (CLI UX only)
- **License:** Apache-2.0. Last commit 2026-04-06.
- **Worth studying:** `internal/afmt/print.go` prints the banner, version and author **to stderr** (`color.Error`) so that stdout holds only results. `internal/subs/cli.go` defines the flags `-nocolor`, `-silent`, `-o file`, `-config`, `-h/-help`, and **`-demo` ("Censor output to make it suitable for demonstrations")**. The censoring is done by `censorDomain`/`censorIP`, which replace characters with `x` while keeping `.`, `/`, `-` and spaces. Running with no arguments prints the banner and short usage.
- **What we can adapt:** banner on stderr and data on stdout, `--no-color`, `--quiet`, and a `--demo` mode that censors hostnames and DSNs in CLI output.

### 8. owasp-dep-scan/dep-scan (CLI UX and reports)
- **License:** MIT. Last commit 2026-10-12. Python with Rich, and has tests (`test/`).
- **Worth studying:**
  - `depscan/cli.py` has a small ASCII `LOGO` that is suppressed by `--no-banner`. It **validates inputs before running and exits 1** instead of producing an empty "successful" scan.
  - `depscan/cli_options.py` makes `-q/--quiet` and `--explain` a **mutually exclusive** group. Every option has an env-var default (`DEPSCAN_SEVERITY`, `DEPSCAN_FAIL_ON_ERROR`). It also has `--severity` thresholds, `--fail-on-error`, `--reports-dir` and `--report-template`.
  - `depscan/lib/logger.py` uses one shared Rich `Console` with a theme. When `CI` is set it fixes the width at 140 and turns off highlighting. Unknown color schemes fall back safely, and `DISABLE_CONSOLE_EMOJI` is supported.
  - `depscan/lib/explainer.py` renders explanations with Rich `Table` and `Markdown`.
- **What we can adapt:** env-var defaults, a quiet/explain output split, CI-aware console settings, fail-fast input validation, and exit codes.

---

## B. Additional projects found

### 9. microsoft/presidio
- **License:** MIT. Last commit 2026-10-08. Python 3.10–3.14, with extensive tests.
- **Worth studying:**
  - `presidio-analyzer/.../pattern_recognizer.py`: each regex hit goes through `validate_result()`, which raises the score when a checksum passes, and `invalidate_result()`, which drops the score to `MIN_SCORE`. For example, `us_ssn_recognizer.py` rejects mismatched delimiters and numbers made of one repeated digit.
  - `analysis_explanation.py` records `original_score`, `score_context_improvement`, `validation_result` and `textual_explanation` for each finding.
  - `presidio-structured/.../analysis_builder.py` (`PandasAnalysisBuilder`) assigns one entity per **column** from sampled values, using the `most_common`, `highest_confidence` or `mixed` strategy.
  - `presidio-anonymizer/.../operators/hash.py` **rejects salts shorter than 16 bytes**.
- **Python compatibility:** native, but heavy (spaCy NLP models). Use the ideas, or offer it as an optional extra only.
- **What we can adapt:** invalidation rules and per-finding explanations for our LightGBM and checksum scanner, a column-level aggregation strategy, and a minimum HMAC key length.

### 10. dalibo/postgresql_anonymizer (hosted on **GitLab**; the GitHub clone failed, so I cloned from gitlab.com)
- **License:** PostgreSQL License (permissive). Last commit 2026-10-11. Rust (pgrx) with pg_regress tests.
- **Worth studying:**
  - `src/hooks.rs::pa_rewrite_select` with `src/walker.rs` implements transparent dynamic masking. It replaces each `RTE_RELATION` with an `RTE_SUBQUERY` masking subquery. This is **the same design as MaskGuard's derived-table rewrite**, done inside the planner.
  - Masked roles get an error on anything except SELECT or utility statements. Calling a `RESTRICTED` function directly (for example `anon.hash`, which reads a superuser-only salt) is rejected. Non-superusers cannot change masking GUCs. `COPY t TO` is rewritten to `COPY (SELECT …)`.
  - Masking rules are declared with `SECURITY LABEL FOR anon ON COLUMN t.c IS 'MASKED WITH FUNCTION anon.partial(c,2,'***',2)'`, and rule functions must come from a schema labelled `TRUSTED` (`src/label_providers.rs`).
  - The function catalog in `sql/anon.sql` and `sql/hash.sql` includes `partial`, `partial_email`, `noise`, the `generalize_*range` family, `hash` and `digest`. A `k_anonymity` label marks quasi-identifiers.
- **Compatibility:** PostgreSQL-only extension. Use it as a concept source.
- **What we can adapt:** a function allowlist on user SQL, blocking direct calls to the masking and HMAC helpers, and the `partial_email` format.

### 11. apache/ranger
- **License:** Apache-2.0. Active (last commit 2026-10-12). Java.
- **Worth studying:**
  - `agents-common/src/main/resources/service-defs/ranger-servicedef-hive.json` (and `-presto`, `-trino`) defines `maskTypes`: `MASK`, `MASK_SHOW_LAST_4`, `MASK_SHOW_FIRST_4`, `MASK_HASH`, `MASK_NULL`, `MASK_NONE`, `MASK_DATE_SHOW_YEAR` and `CUSTOM`. Each has a **per-engine SQL `transformer` template** written with `{col}` and `{type}`.
  - `agents-audit/core/.../AuthzAuditEvent.java` defines audit fields including `reqUser`, `access`, `resource`, `action`, `result`, `policy`, `policy_version`, `reason`, `enforcer`, `cliIP`, `reqData`, `seq_num` and `tags`.
- **What we can adapt:** a masking catalog with one SQL template per dialect, and `policy_version` and `enforcer` in our audit log.

### 12. open-policy-agent/opa
- **License:** Apache-2.0. Last commit 2026-10-12. Go.
- **Worth studying:**
  - `cmd/flags.go` defines the explain modes `off|full|notes|fails|debug`.
  - `v1/plugins/logs/plugin.go` defines the decision-log `EventV1` (`decision_id`, `path`, `input`, `result`, `bundles` with revision, `erased`, `masked`, `requested_by`, `timestamp`). A `/system/log/mask` policy erases or masks fields **in the audit log itself** before it is written (`maskEvent`).
- **Compatibility:** Go and Rego. Using it would need a sidecar, so take the concepts only.
- **What we can adapt:** explain levels, and masking our own audit records so they never store literal PII from WHERE clauses.

### 13. cossacklabs/acra (SQL proxy for PostgreSQL and MySQL)
- **License:** Apache-2.0, Community Edition. Several features are Enterprise-only. Last commit 2025-12-05.
- **Worth studying:**
  - `acra-censor/handlers/deny_handler.go` and `configs/acra-censor.example.yaml` deny queries by exact query, table or pattern, and write unparsed queries to a log. `ignore_parse_error: false` is the default, so the censor fails closed on parse errors.
  - `encryptor/base/config/encryptionSettings.go` has a per-column `masking` setting with `plaintext_length` and `plaintext_side`.
- **What we can adapt:** a "query firewall" stage before rewriting, plus logging of unparsed queries.

### 14. fastapi/typer (0.27.3, MIT) and Textualize/rich (15.0.0, MIT)
- **Verified:**
  - `typer/main.py` has `pretty_exceptions_show_locals`, which **defaults to False** and whose docstring warns that local variables may contain sensitive data. `rich_markup_mode` is also there.
  - `rich/console.py` respects `NO_COLOR`, `FORCE_COLOR` and `TTY_COMPATIBLE`, and provides `print_json`, `export_html` and `export_svg`.
- **Compatibility:** these are already our stack.

---

## C. What we adopted, and what we did not

Status labels: **IMPLEMENTED** (in the code and covered by tests), **NOT IMPLEMENTED** (considered, left for later).

| Idea (source) | Status | Where |
|---|---|---|
| Masking actions ranked by strictness, unknown action treated as the strictest (TOLAP `enums.py`, Ranger mask types) | IMPLEMENTED | `policy.ACTIONS`: allow < partial < redact_text < hmac < aggregate < redact < deny. Used to flag and gate weakening edits; the rewriter maps an unknown action to a NULL column (deny) |
| Policy edits validated, versioned and audited; weakening needs explicit confirmation | IMPLEMENTED | `policy.PolicyStore`, `PUT /policy/rules` (409 without `confirm` and a reason), `maskguard policy set --confirm` |
| Policy version in every decision (Ranger `policy_version`, OPA bundle revision) | IMPLEMENTED | `policy.version()` written into every audit entry and every query response |
| Per-field explanation of a decision (OPA explain, Presidio `AnalysisExplanation`, gateway decision shape) | IMPLEMENTED | `GET /policy/explain`, `maskguard policy explain`, playground "Why each field looks the way it does"; examples are synthetic |
| Capability-based route guards as a FastAPI dependency factory (Raj-git23 `require_permission`) | IMPLEMENTED | `api.require(capability)`; capabilities come from the policy, not from role names in code |
| Structured denial that points to an audit record (RandyRozario `auditReference`) | IMPLEMENTED | rejections carry `X-Request-ID`; capability denials are audited as `denied` |
| Audit fields: request id, channel, policy version, masked columns, latency, risk (gateway, Ranger, RandyRozario) | IMPLEMENTED | `Gateway.query` audit entries; literals are already stripped before logging (the OPA log-masking idea) |
| Audit fails closed (both Node/Go references fail open) | IMPLEMENTED | the audit write happens before a result is returned; if it raises, the caller gets an error, not data |
| SQL guard: single SELECT only, function allowlist, no direct calls to masking/HMAC helpers, parse errors denied and logged (PostgreSQL Anonymizer, Acra censor) | IMPLEMENTED (existing) | `rewriter._validate`; Postman cases "Masking function called directly", "Dangerous function", "Stacked statement injection" |
| Table-to-masking-subquery rewrite (PostgreSQL Anonymizer `walker.rs`) | IMPLEMENTED (existing; independent design, confirmed by the reference) | `rewriter.rewrite` |
| Row-level filters pushed into the rewritten SQL (TOLAP `sql_rewriter.py`) | IMPLEMENTED | `policy.row_filters`, applied inside the masked view so no query shape can reach filtered rows |
| Negative API tests that assert what must *not* appear (daryal89) | IMPLEMENTED | `postman/`: 26 negative and security requests, `NO_RAW_SSN` assertions |
| CLI: banner and diagnostics on stderr, results on stdout, `--json`, `--no-color` and `NO_COLOR`, env-var defaults, input validation before running, stable exit codes, `pretty_exceptions_show_locals=False` (Amass, dep-scan, Typer) | IMPLEMENTED | `cli.py`; exit codes 0/1/2/3/4/5/6 (2 is reserved for usage errors by Click, so "denied" is 3) |
| Minimum HMAC key length (Presidio `hash.py` rejects salts under 16 bytes) | IMPLEMENTED | `maskguard doctor` fails if `MASKGUARD_HMAC_KEY` is shorter than 16 bytes |
| Quasi-identifier co-occurrence warning (gateway `qi/detect.go`, Anonymizer `k_anonymity`) | NOT IMPLEMENTED | candidate next step: flag results that expose ≥ k of {name, DOB, PIN code, city} unmasked |
| Language-neutral golden fixtures for rewrite cases (TOLAP `fixtures/`) | NOT IMPLEMENTED | the rewrite is covered by Python tests on three databases instead |
| Two-tier Newman CI (strict smoke gate + non-blocking full suite) | NOT IMPLEMENTED | we run the full suite as a single blocking gate: it passes, so there is no "known findings" tier |
| Presidio-style invalidation rules (e.g. SSN with one repeated digit) | NOT IMPLEMENTED | our scanner works per column (checksums + LightGBM), where these rules matter less |
| `--demo` output censoring of hosts and DSNs (Amass) | NOT IMPLEMENTED | the CLI never prints credentials; DSNs are reduced to host/db in `db list` and `/diagnostics` |

**Deliberately not adopted**
- Field filtering after the query (Raj-git23 denylist) and masking in application code after fetching plaintext
  (the gateway's `redact`/`noise`). MaskGuard masks inside the SQL it generates, and a missing rule means deny.
- Regex SQL parsing (gateway, TOLAP). MaskGuard uses the sqlglot AST.
- Unsalted MD5/SHA hashing (gateway; TOLAP's unsalted mode). MaskGuard uses keyed HMAC-SHA256 only.
- OPA/Rego, Ranger or Presidio as runtime dependencies: not Python or too heavy (spaCy) for the problem; YAML policy
  plus a Python engine keeps one enforcement path shared by API, CLI, proxy and dashboards.
- Any code from the four repositories without a license.

## D. Summary table

| Repo | License | Relevant feature | Verified in source? | Idea we used |
|---|---|---|---|---|
| Raj-git23/rbac-dashboard-platform | None | `require_permission` dependency; field hide filter | Yes (hide only; no masking) | Dependency-factory pattern; we avoid the denylist |
| RandyRozario/rbac-engine | None | GRANTED/DENIED audit, JWT `jti`, refresh rotation | Yes; "immutable" claim **unverified** | Audit fields, structured 403 |
| sderosiaux/agent-data-gateway | None | OPA decision, per-agent views, QI detector, audit | Yes; "direct connection safe" only partly true | QI warning, decision shape, audit fields |
| awslabs/tolap | Apache-2.0 | Mask ranking, policy merge, fail-closed masks, dialect-explicit rewriter | Yes, with tests and fixtures | Restrictiveness order, fixtures, explicit dialect |
| daryal89/api-database-testing-portfolio | MIT | Smoke-gate plus full negative suite in Newman CI | Yes | Two-tier CI, TC-IDs, absence assertions |
| BrianGator/Postman-…-Showcase | None | Data-driven `expectedStatus` iterations | Partly; most collections are stubs | Role matrix data file |
| OWASP/Amass | Apache-2.0 | Banner on stderr, `-silent/-nocolor/-demo` | Yes | `--demo` censoring, stream split |
| owasp-dep-scan/dep-scan | MIT | `--no-banner`, quiet/explain group, env defaults, Rich console | Yes | CLI flags, CI console, exit codes |
| microsoft/presidio | MIT | validate/invalidate scoring, explanations, column builder | Yes | Scanner invalidation and explanations |
| dalibo/postgresql_anonymizer (GitLab) | PostgreSQL | Table-to-masking-subquery rewrite; restricted functions | Yes | SQL guard rules, function catalog |
| apache/ranger | Apache-2.0 | Mask types with per-engine SQL templates; audit event | Yes | Dialect templates, `policy_version` |
| open-policy-agent/opa | Apache-2.0 | Explain modes; decision-log masking | Yes | Explain levels, audit-log masking |
| cossacklabs/acra | Apache-2.0 (CE) | SQL censor deny/allow; unparsed-query log | Yes | Query-firewall stage |
| fastapi/typer + Textualize/rich | MIT | `show_locals=False`, `NO_COLOR`, `print_json` | Yes | CLI defaults |
