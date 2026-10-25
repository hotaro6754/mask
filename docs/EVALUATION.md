# MaskGuard evaluation

Every number here comes from a script in `bench/` and a JSON file in `docs/eval/`. Commands to reproduce each one are
given with the result. Where we used our own simulations rather than an external dataset, we say so.

## 1. PII discovery (ML scanner) — external benchmark

**Data.** [bharat-pii-bench](https://github.com/dnanatihor/bharat-pii-bench) (Apache-2.0), task T2: label a column
from its name and 20 sample values, under three name conditions: *truthful* (`aadhaar_no`), *obfuscated* (`col_07`),
*misleading* (an Aadhaar column named `order_id`). 16 labels (15 Indian PII types + NONE). We added *hard-negative*
columns built from the benchmark's own decoy generators (12-digit transaction refs that fail Verhoeff, PAN-shaped
SKUs, OTPs, UTRs, invoice numbers, IPs, currency amounts, timestamps, GSTINs with a wrong check character).

**Protocol.** The model is trained only on MaskGuard's own synthetic generator (`maskguard.ml.synth`); no benchmark code
or data is used for training. We did two rounds of error analysis on exported seeds 1–60 and 101–160, then scored
once on seeds **301–360** (2,880 T2 columns + 540 hard-negative columns), which were never inspected.

| Detector | Truthful | Obfuscated | Misleading | Hard-negative false positives |
|---|---|---|---|---|
| bharat-pii-bench `regex_checksum` (their baseline) | 0.844 | 0.844 | 0.844 | 22.2% |
| MaskGuard v1 (rules + header words) | 0.450 | 0.259 | 0.259 | 0.0% |
| MaskGuard ML only (LightGBM) | 0.986 | 0.997 | 0.997 | 1.5% |
| **MaskGuard hybrid (checksums + LightGBM)** | **0.999** | **0.999** | **0.999** | **1.5%** |

Macro-F1 over the 16 labels. With only 5 values per column (harder), the hybrid scores 0.965 / 0.965 / 0.965 with
6.3% hard-negative false positives; the baseline stays at 0.844 / 22.2%.
All remaining hard-negative errors are 6-digit OTP columns read as PIN codes: with no leading zero in the sample,
the two are indistinguishable from values alone.

`bench/bpb_export.py` (run in the benchmark's venv) → `bench/eval_scanner.py` → `docs/eval/scanner_holdout_*.json`.

**How many values does the scanner need? (1.1, 24 Oct 2026)** `bench/eval_sampling.py` scores the same holdout at 5,
10 and 20 values per column (the export has 20). It uses non-null values first, as the scanner reads them. It scores
both the hybrid decision and the **full production scanner** (`classify_column`: hybrid + value patterns + free text
+ the sparse-identifier band + header rules). For hard negatives it counts *any* tag as a false alarm.

| Values per column | Macro-F1 truthful / obfuscated / misleading | PII columns missed (of 2,880) | Hard-negative columns tagged (of 540) | ms per column |
|---|---|---|---|---|
| 5 | 0.972 / 0.968 / 0.968 | 82 | 6.3% (all OTP columns) | 1.6 |
| 10 | 0.989 / 0.995 / 0.995 | 21 | 3.5% (OTP) | 1.8 |
| 20 | 0.999 / 0.999 / 0.999 | 3 | 1.5% (OTP) | 2.6 |

Per label at 5 values, the weakest recalls are postal address (0.78), bank account number (0.82) and date of birth
(0.91); precision is 1.0 for all three. At 10 values every label is at or above 0.92 recall; at 20, all above 0.97.
A missed column is not exposed: it stays `UNREVIEWED`, which is masked for every role except admin.

The first run of this benchmark caught a regression before release: the new sparse-identifier band (one email, PAN
or IBAN in an ordinary column → tag for review) flagged 46 of 60 `pan_sku` decoy columns, because a few PAN-shaped
product codes pass the PAN check by chance. The band now ignores columns where most values already have the
identifier's shape; the numbers above are after that fix, and identical to the hybrid's own hard-negative rate.

50 and 200 values could not be scored on the benchmark without re-exporting it, which needs running the benchmark's
own code; we did not. Instead, part B of the same script uses MaskGuard's own generator on a held-out seed (9001; 920
columns, 200 values each). That is the distribution the model was trained on, so it shows the effect of sample size
only, not generalisation: macro-F1 0.955 at 5 values, 0.977 at 20, 0.976 at 50, 0.977 at 200, and non-PII columns
tagged 6.7% at 5 values, 0% from 20 up. More values than 20 did not help. (`amount` recall is 0.43 at every size by
design: money is tagged only when the column name ties it to a person; `unit_price` is not personal.)
`docs/eval/scanner_sampling.json`.

**Not covered by this benchmark (added in 1.0.3):** health data (ICD-10 codes and blood groups by value, health words
by column name), names with a title, personal attributes by column name, and more money headers. They sit outside the
ML decision the benchmark scores, and money maps to its `NONE` label, so the numbers above are unchanged. They were
checked on the synthetic clinic database of `scripts/e2e/` (13 of 13 sensitive columns found, the 12-digit decoy not
flagged) and by `tests/test_onboarding.py`; that is a check, not a benchmark result.

## 2. PII inside free text — external benchmark

**Data.** bharat-pii-bench T3: 4,500 sentences (English, Hindi, Hinglish; seeds 401–403), one identifier each.
Metric for masking: share of identifiers fully redacted, and share of ordinary characters destroyed.

| | Benchmark baseline | MaskGuard |
|---|---|---|
| 13 structured ID types (Aadhaar, PAN, GSTIN, UPI, IFSC, phone, passport, EPIC, vehicle, account, PIN, email, DOB) | 100% | 100% |
| Names and postal addresses inside sentences | 0% | 0% |
| Over-redaction of ordinary text | 0% | 0% |

MaskGuard ties the baseline on detection; its contribution is *enforcement*: the same redaction runs inside SQLite,
PostgreSQL and MySQL at query time (byte-identical, tested), so filters on the column also see redacted text.
Names and addresses in running text need a neural NER model; ai4privacy/pii-masking-300k and HydroXai/pii-masker
are the planned resources (both hosted on Hugging Face). `bench/eval_textpii.py` → `docs/eval/textpii_t3_seeds401-403.json`.

## 3. Masking against inference and bypass attacks

`maskguard attack` runs 21 attacks per role through MaskGuard and through a naive baseline that masks result columns
by name (how a simple display filter works): projection tricks (alias, expressions, concatenation, `*`), nesting
(CTE, CTE shadowing the table, derived table, UNION, correlated subquery, join), aggregates (MAX, one-row AVG),
inference oracles (equality, LIKE prefix, BETWEEN range, each with a true and a false guess; ORDER BY), and
firewall cases (stacked statements, writes, catalog reads, dangerous functions).

| Role, database | Naive masking: PII leaks | MaskGuard: PII leaks | Unsafe statements rejected |
|---|---|---|---|
| Support / Analyst / Auditor, PostgreSQL | 15 / 17 | **0 / 17** | 4 / 4 |
| Support / Analyst / Auditor, SQLite | 14 / 17 | **0 / 17** | 4 / 4 |
| Support / Analyst / Auditor, MySQL | 14 / 17 | **0 / 17** | 4 / 4 |

Run on every CI build (`.github/workflows/ci.yml`); tests assert zero leaks on all three databases. Re-measured on
13 Oct 2026 with the current policy (SQLite naive count rose from 13 to 14 after the Auditor role and row filters were added).

**Attack matrix (1.1, 24 Oct 2026).** `tests/test_attack_matrix.py` crosses database × role (support, analyst,
auditor) × attack family:
- 40 queries in 12 families: aliases (including one named like a mask function), quoted and schema-qualified names,
  wildcards, expressions (`upper`, `CONCAT`, `substr`, `replace`, `CASE`), nested and table-shadowing CTEs,
  correlated subqueries, `JOIN … USING`, window functions, `UNION ALL` / `INTERSECT` / `EXCEPT`, `GROUP BY` on a
  protected column, comments and optimizer hints;
- 10 predicate oracles on three protected columns, each filtering on the first customer's real value (equality,
  `LIKE` prefix, `BETWEEN`, `IN`, a function on both sides, `HAVING`, `EXISTS`, inside a CTE, a scalar subquery,
  inside `CASE`). Admin must get the row back, and the other roles must get nothing;
- 7 query shapes against support's row filter (frozen accounts must never appear);
- user calls to the mask functions themselves;
- a seeded fuzzer: 120 random compositions per role of functions, misleading aliases, CTE, derived-table and union
  wrappers, a third with a real-value filter;
- a column added after the scan.

A case passes when the gateway refuses the query, or when no cell contains a raw protected value: whole, or the first
10 characters of a value of 12 or more characters. **672 cases, all passing, on SQLite, PostgreSQL 16 and MySQL 8.4**
(24 Oct 2026). At least 100 of the 120 fuzz queries must actually run, so the fuzzer can't pass by being refused.
This tests query-level inference. It does not test inference through business dependencies between columns that are
shown and columns that are hidden (Pappachan et al., TKDE 2024; see [REFERENCE_RESEARCH.md §E](REFERENCE_RESEARCH.md)).

## 4. Insider-threat engine — simulated sessions

**Honest caveat: simulated traffic.** Normal personas (support lookups, analyst aggregates, paging, typos,
off-hours) and six attacker strategies run through the real rewriter and database. The IsolationForest is fitted on
normal sessions only (seed 1001, 8,691 windows); evaluation uses different sessions (seed 2002: 200 normal, 40 per
attack). ML may alert but never block on its own (policy `ml_can_block: false`).

| Detector | Normal: alerted / blocked | Enumeration | Binary search | ORDER BY probe | Bulk paging | Firewall probing | Slow & low |
|---|---|---|---|---|---|---|---|
| Rules only | 0.0% / 0.0% | 100% (18) | 100% (18) | 100% (13) | 100% (13) | 98% (16) | 95% (48) |
| ML only | 2.0% / 0.0% | 78% (8) | 25% (9) | 98% (8) | 100% (8) | 62% (9) | 40% (24) |
| **Rules + ML** | **2.0% / 0.0%** | **100% (8)** | 100% (18) | **100% (8)** | **100% (8)** | 98% (12) | 95% (44) |

Cells: share of attack sessions alerted (median queries until the first alert). `bench/eval_threat.py` →
`docs/eval/threat_sim.json`.

## 5. Differential privacy for analysts

> **Status (2026-10-17).** These measurements describe the experimental noisy-aggregate mechanism, which is **not** a
> differential-privacy guarantee. Its budget renews daily and is per analyst account, and joins and ordering can leak
> more than the ε charged. Each gap is reproduced in `tests/test_dp_findings.py` and analysed in
> `docs/design/PRIVACY_ACCOUNTING.md`. The feature is disabled in production until that design is implemented and
> reviewed. The differencing-attack figures below cover **one day** of one analyst's budget only.

Policy action `aggregate`: a protected number is usable only as SUM/AVG/COUNT, clipped to [0, 10 lakh], with Laplace
noise and a daily ε budget of 10 per user.

| ε per query | AVG error, n = 25 | n = 50 | n = 150 | n = 300 |
|---|---|---|---|---|
| 0.1 | 100% | 91% | 31% | 12.0% |
| **0.5 (default)** | 36% | 17% | **5.4%** | **2.7%** |
| 1.0 | 17% | 9.4% | 2.4% | 1.0% |
| 2.0 | 8.8% | 4.1% | 1.3% | 0.6% |

**Differencing attack** (SUM over 100 customers minus SUM without the target) on a mean balance of ₹4.45 lakh: at
ε = 0.5 the median error is **₹22 lakh**, the estimate lands within 10% of the truth **0.5%** of the time, and
averaging every query a full day's budget allows still leaves a median error of **₹7 lakh**. Without DP the attack
recovers the exact balance. `bench/eval_dp.py` → `docs/eval/dp.json`.

## 6. Performance

`make bench`: 800 queries as Analyst (4 query shapes, including a DP aggregate), 300 rows per table, 4-CPU Linux VM,
with every feature on: rewriting, masking functions, DP noise, threat scoring and the audit write.

| Backend | Direct p50 | Through MaskGuard p50 | Added p50 |
|---|---|---|---|
| SQLite | 0.21 ms | 8.6 ms | 8.3 ms |
| PostgreSQL 16 | 1.1 ms | 9.2 ms | 8.1 ms |
| MySQL 8.4 | 2.3 ms | 23.7 ms | 21.4 ms |

MySQL's stored functions (character loops, HMAC built from SHA2) are slower than PL/pgSQL or Python UDFs, and the
gateway materialises each masked view once per query there. Threat scoring uses a direct tree walk over the fitted
IsolationForest (0.22 ms per call; identical to scikit-learn's `score_samples` to 1e-16, tested) instead of the
library call (~15 ms per call).

## 7. Tests

The full suite runs against SQLite, PostgreSQL 16 and MySQL 8.4 (CI services), including: masking per role,
attack suite, free-text redaction parity (Python vs PL/pgSQL vs MySQL, byte-identical), HMAC parity across engines,
DP fail-closed cases, budget enforcement, threat blocking/unblocking, the PostgreSQL wire proxy with real `psql` and
`psycopg` clients, the REST API (including forged/unsigned tokens, capability denials and error-message leakage),
the Python SDK, the CLI (exit codes, JSON output, local and remote mode), row-level filters, policy edits,
integrity proofs, and both dashboards (the Control Room through a Playwright browser walkthrough). The Postman
collection (`postman/`, 55 requests, 121 body assertions, 26 of them negative/security cases) passes under Newman
against the API on SQLite, PostgreSQL 16 and MySQL 8.4.

## Known limits

- HMAC tokens still allow equality joins and frequency analysis; partial masks reveal their visible characters.
- A column the scanner finds nothing in is `UNREVIEWED`: masked for every role except admin until a person approves
  it as `PUBLIC` in `policies/overrides.yaml` (since 18 Oct 2026; before that it was returned as it was). A
  personal-data column wrongly approved as `PUBLIC` is exposed, so approvals need review like code.
- Threat-engine numbers are from simulated sessions; real deployments should recalibrate on their own normal traffic.
- Names/addresses inside free text need NER (not yet integrated).
- Applications must not hold direct database credentials, or they bypass the gateway; give MaskGuard a
  least-privilege, read-only database role.
