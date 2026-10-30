# Engineering audit

Written 31 October 2026 by reading the code, running the tests and re-running the evaluations, not from earlier
claims. Status words: **IMPLEMENTED** (code and a test or evaluation that exercises it), **PARTIAL** (works, with a
named gap), **MISSING**, **UNVERIFIED** (code exists, no evidence it works as described).

## 1. What the repository actually is

About 9,400 lines of Python in `src/maskguard/` plus a 1,400-line browser dashboard, 1,300+ tests, benchmark and
training scripts, and documents. One package, layered:

| Layer | Modules | Role |
|---|---|---|
| Discovery | `scanner.py`, `ml/features.py`, `ml/model.py`, `ml/synth.py`, `textpii.py` | Finds personal data: check digits, a LightGBM column classifier (99 features, 21 kinds), value patterns, identifiers inside free text, column-name rules |
| Policy | `policy.py`, `policies/*.yaml` | Who sees what: per-role action for each sensitivity tag, row filters, group-size floors; versioned, explained, changes audited |
| Enforcement | `rewriter.py`, `masks.py`, `backends.py` | Parses SQL with sqlglot, refuses anything but one SELECT, replaces protected columns with masking functions that run inside SQLite, PostgreSQL or MySQL |
| Gateway | `gateway.py`, `auth.py`, `audit.py`, `threat.py` | The one path to the data: identity → threat check → rewrite → read-only execution → hash-chained audit entry → result |
| Interfaces | `api.py` (REST), `cli.py`, `client.py` (SDK), `pgwire.py` (PostgreSQL proxy), `dashboard.py` + `web/` | All call the gateway through `service.py` or directly; none queries the database for a user |
| Proof | `integrity.py`, `attacks.py`, `pia.py`, `naive.py` | Data-unchanged digests, the attack self-test, the privacy impact summary, the naive baseline the attacks are compared with |

## 2. Status of each capability

| Capability | Status | Evidence or gap |
|---|---|---|
| Column discovery (rules + LightGBM) | IMPLEMENTED | `docs/AI_EVALUATION.md`: macro-F1 0.888 on 9,780 held-out columns vs 0.578 for regex and check digits |
| Messy-data robustness | IMPLEMENTED | `bench/stress.py`: 90.9% of PII columns protected over 11 kinds of damage (version 1: 77.2%) |
| Free-text identifiers | PARTIAL | Phones, PAN, Aadhaar, UPI, email, dates found in text; **names in prose are not** |
| Role-based masking inside the query | IMPLEMENTED | 672-case attack matrix and 17 named attacks, three databases, 0 leaks |
| Fail-closed defaults | IMPLEMENTED | Unreviewed columns masked; refusal on any parse, policy or function failure; `docs/SECURITY_ANALYSIS.md` |
| Human review of uncertain columns | IMPLEMENTED | `maskguard pii approve/tag`, dashboard review; approvals audited |
| Identity and roles | IMPLEMENTED | Signed tokens, role re-checked per request; no token deny-list (see §3) |
| Threat detection | PARTIAL | Rules + IsolationForest, 95–100% of simulated attacks alerted; **simulated traffic only**, **state in memory per process** |
| Noisy aggregates | PARTIAL, off in production | Not differential privacy (decision D11); refused in production |
| PostgreSQL wire proxy | IMPLEMENTED | Real `psql` and psycopg clients in tests, simple and extended protocol |
| Audit chain | IMPLEMENTED | Hash chain, outside anchor; a failed write now leaves it verifiable (fixed in this audit) |
| Quasi-identifier risk (combinations of ordinary columns) | MISSING | Planned; see §7 |
| Names in free text (NER) | MISSING | Planned with a benchmarked recogniser |
| Shared threat state across gateway instances | MISSING | Planned (database table or Redis) |
| Schema drift | PARTIAL | New tables are refused until scanned (`ScanWorker`); changed distributions of known columns are not re-checked |
| Model lifecycle | PARTIAL | Versioned model with metadata and model card; retraining reproduces the shipped model exactly; no registry or shadow deployment |

## 3. Security risks

Covered in [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md). The open ones: direct database access is the deployer's to
prevent (production mode refuses a writable account but cannot see the network); stolen tokens stay valid until
they expire unless the user's entry changes; threat state is per process.

## 4. ML and dataset findings

| Finding | Effect | Action |
|---|---|---|
| The synthetic generator cached label sets across calls, so `dataset(n, seed)` depended on what ran before | Retraining in a process that had already generated data gave a different model (best iteration 136, not 127) | **Fixed**: `synth.reset_state()` at the start of training; retraining now reproduces the shipped model exactly (maximum probability difference 0.0). Regression test added |
| No single command compared the model with simple baselines on the same columns | Accuracy claims were spread over several scripts | **Added** `bench/evaluate.py`: five detectors, per-class metrics, confusion matrices, calibration, latency, leakage check, ablation, quality gates (exit code 1 on failure) |
| Calibration was measured on the synthetic benchmark only | ECE 0.009 there looked better than it is | **Measured** on all held-out columns: ECE 0.047, Brier 0.046; the 0.1–0.5 band under-predicts (`docs/eval/calibration_metrics.json`). Probabilities are not presented as calibrated |
| urchade's IBAN values are invented (0 of 4,821 pass the check digits) | IBAN F1 0.0, though all 120 columns are masked | Documented; not "fixed" with an IBAN-shape rule tuned to a test set |
| PAN-shaped values are masked even when the check fails (the organisers' PANs fail it) | IndiaPII false positives 4% → 27% for the full scanner | Kept on purpose (over-masking, not a leak), stated in the evaluation |
| The organisers' Saffron data was seen while fixing the scanner | It cannot be a blind test | Reported apart: first contact F1 0.68 (blind) and after fixes 0.91 (not blind) |

## 5. Tests and gaps

1,328 tests (SQLite always; PostgreSQL 16 and MySQL 8.4 when their URLs are set, as in CI). Added in this audit:
statement refusals in three dialects, expired and re-signed tokens, a failed audit write, quoted identifiers,
generator determinism. Gaps: no property-based fuzzing of the policy engine itself (the SQL fuzzer covers queries);
one MySQL cross-join case is slow on small machines and times out locally (it passes in CI).

## 6. Code quality

| Item | Status |
|---|---|
| Formatter and linter | `ruff format` and `ruff check` with pycodestyle, pyflakes, import order, bugbear, pyupgrade, bandit, blind-except and simplification rules: clean. Every remaining `noqa` names its reason |
| Repeated logic | The validator helper existed three times (scanner, features, model); now one `features.passes` |
| Files closed | 66 `open()` calls without a context manager replaced |
| Assertions in library code | Removed (`python -O` strips them; one guarded the password-hash algorithm) |
| Type hints | **PARTIAL**: new modules (`bench/baselines.py`, `bench/evaluate.py`, `training/train_candidate.py`) are typed; most of `src/` is not |
| Large files | **PARTIAL**: `cli.py` is 1,870 lines (one function per command); splitting it into a package of command groups is the next refactor |

## 7. Dependencies

`pip-audit` on the lockfile found Pillow 12.3.0 (39 advisories, via Streamlit) and certifi 2026.7.22. Both upgraded;
the minimum Python is now 3.11 because no fixed Pillow supports 3.10. `pip-audit` now reports no known
vulnerabilities. `joblib`, declared but never imported, was removed from the direct dependencies.

## 8. Submission compliance

The repository did not follow the coding guidelines' layout (code at the top level, not in `FULL_CODE/`), and the
packaging script zipped `git archive` output rather than a fresh clone. Both fixed; details and the full checklist in
[SUBMISSION_COMPLIANCE.md](SUBMISSION_COMPLIANCE.md).

## 9. Next, in order of value

1. Quasi-identifier risk report: group sizes for combinations of unmasked columns.
2. Shared threat state for more than one gateway instance.
3. Names in free text, with a recogniser benchmarked on the same test sets.
4. Split `cli.py`; add type hints to `rewriter.py`, `gateway.py` and `policy.py` first (the security core).
5. A token deny-list for revoking a single stolen token.
