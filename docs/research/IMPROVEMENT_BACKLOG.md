# Improvement backlog (from the REA experiment)

Candidate work items for **MaskGuard only** (the experiment changed no app
code). Each item names the finding it comes from, the smallest test that would
decide it, the cost, and a recommendation. **Nothing here is approved for
implementation** — per the experiment's terms, a fix waits on explicit sign-off
and a separate plan.

| # | Item | From | Smallest decisive test | Cost | Recommendation |
|---|---|---|---|---|---|
| 1 | **Regression test: CTAS / `SELECT INTO` / multi-statement stay rejected.** Pin MaskGuard's fail-closed behaviour against the exact inputs that leak on the target, so a future firewall change can't silently open them. | A, E | Add the S28–S32 inputs to `tests/test_api_v1.py`; assert `Rejected`. | Low (test only) | **Do.** Cheap insurance; turns an incidental refusal into a guaranteed one. |
| 2 | **Parser-differential regression tests.** Assert fail-closed on Unicode-escaped identifiers, alias-shadowing and schema/db-qualified names (S36–S39). | F | Add the four inputs; assert either correct masking or `Rejected`, never an unmasked protected column. | Low | **Do.** Directly guards the one soft spot (F). |
| 3 | **Document the trust boundary vs an in-DB masker.** A short note in `docs/ARCHITECTURE.md` stating that MaskGuard assumes the masked principal has *no direct SQL session*, and that catalogue/materialisation side channels (target findings B/C/A) are out of scope precisely because of that assumption. | A–C | n/a (doc) | Low | **Do.** Prevents the comparison being mis-sold; sharpens the pitch honestly. |
| 4 | **Selectively widen the function allowlist** for safe, mask-preserving functions (e.g. `md5`/`sha256` over already-masked output, `array_agg`, `row_to_json`) so analysts aren't pushed to request direct DB access. | E | For each candidate, add to `ALLOWED_FUNCS`, re-run the 47-scenario matrix, and confirm 0 new leaks. | Medium (per-fn review) | **Consider.** Real usability gain; must be gated on the matrix staying clean — widening is where leaks get introduced. |
| 5 | **Document existence/ordering residuals.** Note in the policy/threat docs that anti-join existence (S22) and masked-sort order (S14) are expected disclosures on any value-masking system, with the option of a query-shape rule for restricted tables. | D | n/a (doc); optional rule testable by re-running S22 and asserting rejection if the rule is enabled. | Low (doc) / High (rule) | **Do the doc; skip the rule** for the current threat model. |
| 6 | **Keep the scenario harness as a reusable differential tester.** `rea_experiment/harness/` already runs any SQL against both a MaskGuard role and a reference PostgreSQL masker with a data-unchanged check. Fold it into CI as an optional job that re-runs the matrix on each rewriter change. | A–F | CI job runs `run.py`; fails if MaskGuard leaks any scenario or mutates source. | Medium | **Consider.** Turns this one-off experiment into a standing regression guard for the masking boundary. |

## On REA itself

No backlog item depends on REA. On this (readable, mostly-Python) target it was
redundant with source reading + binutils. Reconsider REA only if MaskGuard ever
needs to be evaluated against a **closed-source, binary-only** masking product,
and only with a deep analysis provider (Ghidra) configured — the setup this run
deliberately did not install. See `REA_EXPERIMENT.md` §7 for the one experiment
that would actually test REA's headline capability.

## Responsible-disclosure reminder

Target finding **A** (CTAS/`SELECT INTO` bypass) is a reproduced weakness in a
third-party product and must be reported privately to Dalibo (their
`SECURITY.md` names the process) before any public or competitive use. Treat
this folder as an internal research record until the vendor has responded.
