# Response to the external security review (2026-10-17)

The review was a source-and-documentation read and said so. Each finding below was checked against the code on
`claude/zealous-bell-me62fn`; where it was cheap, it was also reproduced at runtime on a scratch SQLite database with
synthetic data. Status words: **Reproduced** (seen at runtime), **Confirmed in source** (the code does what the review
says; not exercised at runtime), **Documented** (already stated in the repo's docs).

| # | Finding | Verdict | Action in this change |
|---|---|---|---|
| 1 | Production can still accept the demo logins | **Reproduced.** With `MASKGUARD_ENV=production` and no `MASKGUARD_USERS`, `/auth/demo` returned 404 but `/auth/login` with `admin.ann`/`admin123` returned 200 and an admin token that read unmasked data. | **Fixed.** `config.check_production_identity` stops startup in production if the user store contains any demo identity or `MASKGUARD_JWT_SECRET` is unset. Test: `test_production_refuses_the_demo_user_store`. |
| 2 | DP ledger is in memory | **Confirmed in source** (`dp.py`, `PrivacyLedger.spent` is a `defaultdict`). A restart or a second instance starts with a fresh budget; budgets are per account, not per person. | Documented in README and ARCHITECTURE. Not fixed yet: needs a decision on the store (see below). |
| 3 | Small-group suppression happens before noise | **Confirmed in source** (`rewriter._apply_group_floor` adds `HAVING COUNT(*) >= k` on the true count; noise comes later in `dp.apply_noise`). Whether a group is present at all depends on the true count. | The "differentially private" wording is replaced with "noisy aggregates within an ε budget", and the README now says this is not yet a formal DP guarantee. The mechanism itself is unchanged. |
| 4 | DP metadata keyed by column name | **Reproduced, with a correction.** With two joined tables both holding `amount` (bounds 100 and 1,000,000), whichever table came last in the `FROM` supplied the bound for **both**. Clip and noise came from the same entry, so they stayed consistent (no under-noising in the cases run), but one table's configured bound was silently ignored, depending on join order. | **Fixed.** DP columns are keyed by `(table alias, column)`. A reference that can't be tied to one table gets no noisy release, so the column stays redacted (fail-closed). Tests: `test_dp_bounds_follow_the_source_table_not_the_column_name` (both join orders), `test_ambiguous_protected_column_gets_no_dp_release`. |
| 5 | PG proxy has no TLS | **Documented** (`pgwire.py` docstring; `SSLRequest` is answered "not offered"). The proxy binds `127.0.0.1` by default; Compose binds `0.0.0.0`. | README "Known limits" now says it directly. Not fixed: native TLS is a feature decision. |
| 6 | Compose publishes the database ports | **Confirmed in source** (`5432`, `3306` published with demo passwords; `MASKGUARD_DEMO` defaults to 1). | README now calls Compose a demo profile. A production profile is not built yet. |
| — | Untagged columns are allowed | **Confirmed in source** (`rewriter.action_for` returns `allow` when a column has no tag). | Stated in "Known limits". "Unknown until reviewed" is a policy-model change, listed below. |
| — | Audit chain is unkeyed | **Confirmed in source** (`audit._digest` is plain SHA-256). | ARCHITECTURE and README now say what it does and doesn't protect against. |
| — | "Leak-proof" wording | Fair. 0/17 is evidence for those 17 cases. | README headline and feature list reworded. The submitted application text (`APPLICATION_TalentAP.md`) is left as the record of what was sent. |

Test suite after the change: **420 passed** on SQLite, PostgreSQL 16 and MySQL 8.4. That is the previous 416 plus the
4 new regression tests.

## Not done here, and why

Each of these is a design decision rather than a bug fix:

- **Persistent, shared ε ledger** (finding 2). Needs a store (the database itself, Redis, or a file with locking),
  a defined privacy unit (account or person) and composition rules. It must fail closed when the store is unavailable.
- **The suppression mechanism** (finding 3). Either apply the threshold to a noisy count, or drop formal DP language
  for good. Both change results the demo shows.
- **Native TLS for the proxy and a production Compose profile** (findings 5–6). The profile needs no published
  database ports, a least-privilege DB role, demo off and a required user store.
- **Unclassified columns treated as unknown** instead of allowed. This changes every role's view of every table the
  scanner hasn't tagged.
- **The "MaskGuard Assurance" toolkit.** The review's split, with a small enforcement core and a separate test runner,
  is sound. The cheapest first step already exists: `rea_experiment/harness/` runs a scenario matrix against a role
  and checks the source digest. Making that a policy-driven, CI-run corpus is the natural start, before generic
  scanners.
