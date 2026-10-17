# Phase 1 — MaskGuard baseline feature map

Built by reading the repository only. **No files were modified in this phase.**
Every row cites where the behaviour lives and the test(s) that exercise it, so
the later comparison measures MaskGuard as it actually is, not as the pitch
describes it. "Known limitations" are stated plainly; they feed
`IMPROVEMENT_BACKLOG.md`.

| Feature | Implementation location | Existing tests | Known limitations |
|---|---|---|---|
| **Single enforcement path** — every interface (REST, CLI, PG-wire proxy, dashboards, SDK) calls one `Gateway.query` | `src/maskguard/gateway.py:59` (`query` → `_query`) | `test_api_v1.py`, `test_cli.py` | The claim is "controls every query *through* it", not "intercepts every query to the DB". A holder of direct DB credentials is **outside** the boundary by design (`docs/ARCHITECTURE.md`, trust-boundary table). |
| **SQL firewall** — single statement; function allowlist; forbidden nodes; recursive-CTE rejection | `rewriter.py:18` `ALLOWED_FUNCS`, `:23` `FORBIDDEN`, `:152` `_validate` (`recursive` → reject, `exp.Command`/`Into`/`Set`/… → reject, non-allowlisted `exp.Func` → reject) | `test_api_v1.py` (write-attempt/negative cases), `test_cli.py` | Allowlist is deliberately small; many legitimate functions (`md5`, `row_to_json`, `array_agg`, regex, window fns) are refused — **fail-closed, but narrow** (see finding E). |
| **Table→masked-view rewrite** — each base table becomes a derived table whose columns are the masking expressions; predicates/joins/aggregates see only masked values | `rewriter.py:214` `rewrite`, `:124` `_mask_expr`, `:208` `action_for` | `test_policy_integrity.py::test_explain_*`, scenario matrix S01–S10 | Masks the **value**, not predicate truth: boolean/comparison/anti-join *existence* inference is still possible where the query is allowed (finding D). |
| **Per-role actions** allow / partial / hmac / redact_text / aggregate(DP) / redact / deny | `policy.py` (ACTIONS strictness order), `rewriter.py:124` | `test_policy_integrity.py::test_explain_*`, `::test_auditor_sees_no_raw_pii` | `hmac` is deterministic — joinable, **not** reversible, but equal values give equal tokens (frequency analysis), documented in `ARCHITECTURE.md`. |
| **Row-level security** — column-vs-literal predicate placed *inside* the masked view, so CTEs/joins/subqueries can't see hidden rows | `rewriter.py:177` `ROW_FILTER_NODES`, `:182` `compile_row_filter`, `:191` `_row_filter` | `test_policy_integrity.py::test_row_filter_hides_frozen_accounts_from_support`, `::test_invalid_row_filter_fails_closed`; scenario S19–S21 | Predicate restricted to a safe node allowlist; anything else fails closed. Hidden-row *count* could still leak via aggregates if a count were allowed on an unfiltered path — not reachable through the gateway (no catalog access). |
| **Row caps & small-group floor** | `policy.py` (`max_rows`, `min_group_size`), `rewriter.py:170` `_apply_group_floor` | `test_api_v1.py` | Demo thresholds (k=5); not tuned for production. |
| **Differential-privacy aggregates** (Laplace, ε budget) for analyst | `rewriter.py:39`–`:102` (`_dp_*`, `_shape`), `backends.py`/noise | `test_api_v1.py`, `test_cli.py` | ε accounting is per-user/day in memory; resets on restart. |
| **Hash-chained audit, literals stripped** | `gateway.py` (`fingerprint`, audit append; parse errors report position only) | `test_policy_integrity.py::test_audit_entries_carry_request_id_and_channel`, `::test_explain_never_contains_database_values` | Audit file integrity is a hash chain, not external notarisation. |
| **Integrity snapshot / verify / proof** — per-table canonical-JSON SHA-256 | `src/maskguard/integrity.py` (`table_state`, `snapshot`, `compare`, `proof`) | `test_policy_integrity.py::test_integrity_baseline_and_proof`, `::test_integrity_store_verify_and_history` | Covers source tables only; whole-table reads — for demos/audits, not per query. |
| **Policy engine** — explain, versioning (`v1-<sha10>`), capabilities RBAC, validated/weakening-confirmed edits | `src/maskguard/policy.py` (`version`, `capabilities`, `can`, `view_within`, `validate`, `PolicyStore.set_rule`) | `test_policy_integrity.py::test_policy_validation_rejects_unsafe_policies`, `::test_policy_store_versions_and_requires_confirmation_to_weaken`, `::test_capabilities` | Default-action must be `deny`/`redact` (validated); unknown role rejected; unknown action → NULL (deny). |
| **Read-only execution** — SQLite authorizer + progress-handler timeout; `READ ONLY` txns on PG/MySQL | `src/maskguard/backends.py` (`timeout_s = 5.0`) | `test_policy_integrity.py::test_integrity_*` (source unchanged), scenario matrix `data_unchanged` | SQLite 5 s wall-clock guard; per-engine. |

**Test suite baseline (pre-existing, unchanged by this experiment):** 416
pytest tests across SQLite/PostgreSQL/MySQL; 121 Postman/Newman assertions.
Counts of the engine-level tests touched by the comparison:
`test_policy_integrity.py` 11, `test_api_v1.py` 16, `test_cli.py` 12,
`test_dashboard_ui.py` 2.

**The boundary this experiment probes (restated for the comparison):** the
masking transformation is applied *inside the SQL that reaches the database*;
the restricted role never holds a direct SQL connection. That assumption — no
direct DB session for the masked principal — is what makes MaskGuard's job
smaller than the target's, and it is held fixed throughout.
