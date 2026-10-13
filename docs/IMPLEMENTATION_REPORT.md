# Implementation report

Problem Statement 1, Smart Data Masking System for PII Protection: what was built in this iteration, how it was
verified, and what is still open. The status labels are evidence-based:
- **VALIDATED**: measured against external data or exercised end to end with the result recorded;
- **TESTED**: covered by automated tests that ran and passed;
- **IMPLEMENTED**: in the code but not separately tested;
- **IN PROGRESS** / **NOT IMPLEMENTED**: as named.

## 1. Starting point

The repository already had (phases 1–6, see `docs/EVALUATION.md`):
- a sqlglot rewriter that masks inside generated SQL on SQLite, PostgreSQL and MySQL;
- a LightGBM + checksum PII scanner (macro-F1 0.999 on unseen bharat-pii-bench seeds);
- free-text redaction, an insider-threat engine and differential-privacy aggregates;
- a PostgreSQL wire proxy, a basic REST API, an argparse CLI, a Streamlit dashboard and a 17-request Postman
  collection.

The baseline test run before this iteration had 272 passed and 93 skipped on SQLite and PostgreSQL. MySQL had not
been started for that run.

**Gaps against the brief:**
- no Auditor role, no capability model and no row-level security;
- no policy explanation, versioning or audited edits;
- no integrity baseline or proof (only per-table checksums);
- a plain CLI with no JSON or exit-code contract;
- no request ids;
- no negative or security cases in Postman;
- no dashboard beyond Streamlit.

## 2. Research

See `docs/REFERENCE_RESEARCH.md`. It covers 14 repositories read at source level: the six from the brief, Amass,
dep-scan, Presidio, PostgreSQL Anonymizer, Ranger, OPA, Acra, and Typer/Rich. We copied no code; the ideas we used
are listed with their status in the report.

## 3. Architecture decisions

| Decision | Why |
|---|---|
| Keep **one enforcement path** (`Gateway.query`) and add a policy module beside it, rather than a second engine | The CLI, API, proxy and both dashboards then cannot disagree. The new `policy.explain()` calls the rewriter's own `action_for()` |
| **Capabilities** in the policy file (`role_info.<role>.capabilities`) instead of hard-coded `role == "admin"` checks | Lets the Auditor read the audit log and verify integrity without seeing raw PII. Denials are audited |
| **Row filters inside the masked view** | CTEs, subqueries and joins can't reach rows outside a role's scope; tested with four bypass shapes |
| **Runtime policy edits in memory plus a history file; the YAML stays the baseline** | Edits take effect immediately and are versioned and audited, while permanent changes still go through code review |
| **Integrity = per-table row count + schema SHA-256 + sorted canonical-JSON content SHA-256**, baseline stored per database id | Independent of row order and storage format; states exactly what is covered and what isn't |
| **Demo identities are real users;** demo mode only adds one-click login, is off in production and refused there | Role switching is demonstrable without a "role=admin" shortcut |
| **Dashboard as static JS served by the API** under a strict CSP, no build step, no CDN | One process, runs offline, no third-party scripts near tokens. Every role column is a separate real request |
| **CLI is a thin client of a service layer** (in-process `LocalService` or `RemoteService` over REST) | Same engine, with the choice of running locally or through the API (`--api URL`) |

## 4. What was built

| Area | Feature | Status | Evidence |
|---|---|---|---|
| Masking engine | Auditor role (everything personal REDACTED) | TESTED | `test_auditor_sees_no_raw_pii` on 3 DBs |
| | Row-level security (Support never sees frozen accounts), bypass-proof | TESTED | `test_row_filter_hides_frozen_accounts_from_support` (CTE, subquery, join, OR-trick) on 3 DBs |
| | Row filters restricted to column-vs-literal predicates; an invalid filter refuses the query | TESTED | `test_invalid_row_filter_fails_closed` |
| | Policy validation (default must be deny or redact, known actions and capabilities only) | TESTED | `test_policy_validation_rejects_unsafe_policies` |
| | Strictness order; weakening needs confirmation and a reason; history; reset | TESTED | `test_policy_store_versions_and_requires_confirmation_to_weaken` |
| | Policy version and request id in every audit entry and response | TESTED | `test_audit_entries_carry_request_id_and_channel` |
| | Per-field explanation with synthetic examples, never DB values | TESTED | `test_explain_matches_what_the_gateway_returns`, `test_explain_never_contains_database_values` |
| | **Fixed:** parse errors no longer echo the SQL (literals leaked into the error and the audit log) | TESTED | `test_errors_do_not_leak_values` |
| Integrity | Baseline, verify, history, proof (all roles + 6 write attempts) | VALIDATED | `test_integrity_baseline_and_proof` (3 DBs); Newman folder 07 on all 3 DBs; `maskguard integrity proof` → PASS |
| | Real changes detected and localised (content vs schema vs rows) | TESTED | Same test plus `test_integrity_store_verify_and_history`; CLI exit code 5 |
| API | `/health`, `/ready`, `/meta`, `/auth/demo`, `/tables`, `/query/table`, `/policy*`, `/roles`, `/diagnostics`, `/scan` (dry run, scope, sample limit), `/audit` filters, `/audit/stats`, `/integrity/*`, `/demo/compare` | TESTED | `tests/test_api_v1.py` (12 tests): forged, `alg:none` and garbage tokens; role in the body ignored; capability denials audited; demo off → 404; production + demo refused; query-builder injection; nothing raw reachable through any route |
| | Security headers and CSP | TESTED | `test_ui_is_served_with_csp` |
| CLI | Typer + Rich, branded banner (falls back on narrow or non-UTF-8 terminals), interactive console with playground | TESTED | `tests/test_cli.py` (12 tests); console driven through a pseudo-terminal during development |
| | `doctor`, `status`, `db list/test/inspect`, `scan --dry-run --sample-limit --table --out`, `pii list/show`, `roles list/show`, `policy list/explain/set/history`, `query --role/--user/--table/--columns/--csv/--explain`, `compare`, `audit list/verify`, `integrity verify/baseline/proof/history`, `test`, plus every earlier command | TESTED | Same; exit codes 0/2/3/4/5/6 asserted; JSON on stdout, diagnostics on stderr |
| | Remote mode through the REST API (`--api`) | TESTED | `test_remote_mode_uses_the_api` |
| Postman | 55 requests and 121 body assertions: 4 roles, 26 negative and security cases, audit evidence, integrity before and after | VALIDATED | Newman: 55/55 requests and 121/121 assertions passed against the API on **SQLite, PostgreSQL 16 and MySQL 8.4**; added to CI |
| Dashboard | Control Room: overview (real readiness, audit stats chart, events), playground (builder or SQL, multi-role, per-field explanations, integrity strip), PII discovery (dry-run and apply scans), policy studio (matrix, validated edit dialog, history, reset), role explorer, audit explorer (filters, expandable rows, chain status), integrity (baseline, verify, proof, history), API lab (OpenAPI-driven, cURL without tokens), CLI guide, diagnostics | TESTED | `tests/test_dashboard_ui.py`: Playwright walkthrough of every page with no JS errors and no horizontal overflow at 390 px; screenshots in `docs/img/control-room-*.png` |
| | Accessibility: text labels on every status, keyboard focus styles, skip link, ARIA roles on tabs, chips and live regions, table view for the chart, reduced-motion support | IMPLEMENTED | Checked manually in screenshots; no automated a11y audit was run |
| Docs | `ARCHITECTURE.md` (trust boundary), `DEMO_RUNBOOK.md` (exact commands, expected output, PowerShell), `REFERENCE_RESEARCH.md`, `postman/README.md`, `.env.example` | IMPLEMENTED | — |
| OCR / Tesseract | Document-image redaction | NOT IMPLEMENTED | Not part of the problem statement and not in the repository; listed as future work |

## 5. Test totals (this run)

| Check | Result |
|---|---|
| `pytest` on SQLite + PostgreSQL 16 + MySQL 8.4 (`MASKGUARD_TEST_PG`, `MASKGUARD_TEST_MYSQL` set) | **416 passed, 0 failed, 0 skipped** (8 min 31 s; rerun after the audit fixes on 13 Oct) |
| Baseline before this iteration (SQLite + PostgreSQL) | 272 passed, 93 skipped |
| New test files | `test_policy_integrity.py` (11 tests × backends), `test_api_v1.py` (16), `test_cli.py` (12), `test_dashboard_ui.py` (2, incl. Playwright) |
| Newman, `postman/` collection | 55/55 requests, 121/121 assertions, against the API on **SQLite, PostgreSQL and MySQL** |
| `maskguard test` (attack suite as support, analyst, auditor + audit chain + integrity proof) | all PASS; 0/17 leaks per role (naive masking: 14/17) |

A pre-existing warning remains: asyncio prints "Task was destroyed but it is pending" when the PG-proxy test
fixture shuts its server down at the end of the session. It does not affect results.

## 5b. Adversarial security audit (13 Oct 2026)

An independent pass tried to break a running API as Support, Analyst and Auditor. It checked every recovered value
against the raw SQLite file.

**Confirmed and fixed**

| Severity | Finding | Fix | Regression test |
|---|---|---|---|
| Medium (High if exposed) | **Demo mode let a low role borrow the Admin view.** `POST /demo/compare {"roles": ["admin"]}` with an Auditor token returned raw SSN, PAN and email. `/auth/demo` also issued admin tokens to any client that could reach the API | `/demo/compare` only runs roles whose view is no more revealing than the caller's (`policy.view_within`: every classification at least as strict, same row filters), and audits refusals. Demo logins are accepted only from the same machine unless `MASKGUARD_DEMO=1` is set explicitly. A DEMO MODE warning is logged at startup | `test_demo_compare_cannot_borrow_a_stronger_role`, `test_demo_login_only_from_this_machine_unless_explicit`; Postman "Support cannot borrow the admin view" |
| Low (availability) | SQLite had no statement time limit, and recursive CTEs were allowed (possible runaway query) | Recursive queries are refused by the firewall. SQLite now has a 5 s limit through a progress handler (PostgreSQL and MySQL already had one) | `test_recursive_queries_and_runaway_sqlite_queries_are_stopped` |
| Usability | An ambiguous column (`SELECT id … JOIN …`) gave a bare "query failed: OperationalError" | `gateway.safe_error` maps only identifier-only messages (ambiguous or unknown column, time limit) to a helpful text; everything else still reports the exception type only | `test_ambiguous_column_gets_a_helpful_safe_message` |

The audit also found a stuck chart tooltip in the dashboard while recording the demo; it is fixed.

**Held up:**
- Support's row filter, including a hex-literal trick.
- Writes, stacked statements and `SELECT … INTO`.
- Catalog access, `pragma_*`, `load_extension`, and direct calls to `mg_*` functions.
- UNION, CTE, subquery, comment+UNION and self-join shapes.
- LIKE, substring and CASE oracles: they only see masked values.
- Analyst balance via MIN/MAX/GROUP BY: returns NULL.
- Small-group floor: a user HAVING clause can't override it.
- DP budget: exhausted after 20 queries, with noise far larger than any single balance.
- Forged JWT; role sent in the request body.
- Every capability gate.
- Policy weakening without confirmation and a reason.
- Error-message and audit-log leakage.
- Scanner evidence: contains no values.
- Integrity proof.
- CLI.
- Dashboard XSS: no `innerHTML` anywhere, plus a strict CSP.

**Not changed (judged acceptable, documented):**
- Identifiers inside free text that the 21 patterns don't recognise are shown to Support as written.
- A patient analyst could average DP answers across days: about 800 days to pin down one balance.

## 6. Evidence that masking left the database unchanged

- **Automated, on all three databases:** `test_integrity_baseline_and_proof` takes the digest, runs the same query
  as admin, support, analyst and auditor, tries UPDATE, DELETE, DROP, a stacked write, INSERT…SELECT and SELECT
  INTO through the gateway, takes the digest again, and asserts PASS with `before == after`. The same test then
  changes a row through the privileged connection and asserts the change is detected in `users` only, as content
  rather than schema.
- **Over HTTP:** Newman folders 02 and 07 record the combined digest before anything runs and assert it is
  identical after 50 requests, including every negative case. This passed against SQLite, PostgreSQL and MySQL.
- **CLI:** `maskguard integrity proof` printed `source digest ed72f4a6c26de4a4251d… → ed72f4a6c26de4a4251d… PASS
  source mutation: NONE` on the demo SQLite database. `maskguard test` printed PASS on every line.

## 7. Known limitations

- **Outside the boundary.** Direct database credentials bypass MaskGuard; see the trust boundary in
  `ARCHITECTURE.md`. Applications should only hold gateway credentials.
- **Tokens and partial masks** (unchanged): HMAC tokens allow equality joins and frequency analysis, and partial
  masks reveal the characters they keep.
- **Runtime policy edits** live in memory and in the history file. They return to the YAML on restart, by
  design, because permanent changes go through review.
- **Integrity checks** read whole tables (fine for demos and audits, not for every query on large data). A
  mismatch means the data changed, not necessarily tampering.
- **Demo identities' passwords** are public by design (synthetic). Production deployments set
  `MASKGUARD_ENV=production` and their own users file.
- **Threat engine** numbers are from simulated sessions. Running the Postman negative folder many times in a
  row can legitimately trip it for `support.sam`.
- **Dashboard tokens** sit in `sessionStorage`, so an XSS would expose them. The CSP forbids inline and
  third-party scripts and values are rendered as text, but no external penetration test was done.
- **Not done:** an automated accessibility audit (axe or Lighthouse), and NER for names and addresses inside free
  text (needs Hugging Face access).
- **Database support:** SQLite, PostgreSQL and MySQL are tested. Other databases are not supported.

## 8. Remaining work, ranked by evaluator impact and security risk

1. **Security:** deploy behind TLS with short token TTLs and a production users file. Make the database account
   read-only at the database level (GRANT SELECT only), not just per transaction.
2. **Security:** quasi-identifier co-occurrence warning (k of {name, DOB, PIN code, city} exposed together).
3. **Evaluator impact:** a short screen recording of the Control Room playground (the current `demo.mp4` shows the
   classic dashboard).
4. **Evaluator impact:** an automated accessibility audit in CI.
5. **Coverage:** NER for names and addresses in free text (ai4privacy/pii-masker), once huggingface.co is
   reachable.
6. **Coverage:** OCR document redaction (Tesseract): extract text, run the same `textpii` patterns, and black out
   the boxes.
7. **Operations:** persist threat-engine blocks and DP budgets across restarts (both are in memory today).
