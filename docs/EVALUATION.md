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

**Method** (after Fotache et al., IEEE Access 2023: the same queries with and without masking, several sizes and
shapes, median and spread). `bench/scale.py` seeds the demo schema at 300, 10,000 and 100,000 rows per table and runs
six query shapes directly and through the gateway, 30 warm runs each:
- a projection with `ORDER BY … LIMIT 100`;
- a filter;
- a two-table join;
- a CTE;
- a full-table `GROUP BY` aggregate;
- a point lookup.

Every shape must return rows through the gateway (the script asserts it), and row counts are recorded.
"All features on" means rewriting, mask functions, threat scoring and the audit write. Setup: 4-CPU Linux VM (Intel
Xeon 2.1 GHz), Python 3.13, SQLite 3.45, PostgreSQL 16 and MySQL 8.4 on the same machine, 25 Oct 2026.
`docs/eval/perf_{sqlite,postgres,mysql}.json`.

**SQLite** (ms, p50 / p95; gateway = all features on, as the analyst and as support)

| Shape | 300 rows: direct · analyst · support | 10,000 rows: direct · analyst · support | 100,000 rows: direct · analyst · support |
|---|---|---|---|
| projection | 0.09 · 6.0 / 7.2 · 5.4 / 5.9 | 0.11 · 6.0 / 6.7 · 5.8 / 7.3 | 0.10 · 6.3 / 7.1 · 5.6 / 6.4 |
| filter | 0.03 · 4.6 / 4.9 · 4.5 / 5.0 | 0.72 · 6.2 / 7.7 · 8.0 / 9.3 | 0.93 · 6.3 / 7.0 · 6.2 / 8.4 |
| join | 0.04 · 7.0 / 7.8 · 7.2 / 8.9 | 0.04 · 6.7 / 7.5 · 7.5 / 8.6 | 0.04 · 6.6 / 7.8 · 7.6 / 9.0 |
| cte | 0.05 · 5.8 / 6.5 · 5.5 / 6.0 | 0.05 · 6.6 / 7.8 · 5.7 / 6.9 | 0.05 · 6.0 / 6.8 · 5.6 / 6.3 |
| aggregate | 0.05 · 3.6 / 4.1 · 4.4 / 5.8 | 1.57 · 5.1 / 6.0 · 5.5 / 6.3 | 22.44 · 27.0 / 31.6 · 17.2 / 26.4 |
| point | 0.01 · 4.8 / 5.8 · 5.2 / 5.9 | 0.01 · 5.0 / 5.7 · 4.8 / 5.3 | 0.01 · 4.8 / 5.5 · 5.2 / 6.3 |

**PostgreSQL 16** (ms, p50 / p95; gateway = all features on, as the analyst and as support)

| Shape | 300 rows: direct · analyst · support | 10,000 rows: direct · analyst · support | 100,000 rows: direct · analyst · support |
|---|---|---|---|
| projection | 0.33 · 7.0 / 8.6 · 7.2 / 8.4 | 0.27 · 5.7 / 6.4 · 6.5 / 7.6 | 0.27 · 6.2 / 7.0 · 6.9 / 8.6 |
| filter | 0.24 · 5.2 / 6.7 · 5.0 / 7.2 | 1.03 · 5.7 / 6.4 · 6.5 / 7.5 | 1.32 · 6.6 / 8.1 · 7.1 / 8.2 |
| join | 0.30 · 6.7 / 9.8 · 8.9 / 11.8 | 0.27 · 6.5 / 7.8 · 8.1 / 10.0 | 0.29 · 7.3 / 7.9 · 8.6 / 10.1 |
| cte | 0.24 · 6.6 / 7.9 · 7.3 / 9.3 | 0.23 · 5.9 / 6.5 · 6.0 / 7.1 | 0.28 · 7.0 / 10.6 · 6.4 / 7.3 |
| aggregate | 0.30 · 4.2 / 4.8 · 4.8 / 5.5 | 1.37 · 5.7 / 6.5 · 6.5 / 7.5 | 11.44 · 16.1 / 18.6 · 16.6 / 23.4 |
| point | 0.21 · 5.3 / 6.2 · 5.2 / 5.8 | 0.21 · 5.2 / 6.3 · 5.1 / 5.7 | 0.27 · 5.1 / 6.1 · 5.3 / 6.3 |

**MySQL 8.4** (ms, p50 / p95; gateway = all features on, as the analyst and as support)

| Shape | 300 rows: direct · analyst · support | 10,000 rows: direct · analyst · support | 100,000 rows: direct · analyst · support |
|---|---|---|---|
| projection | 1.00 · 9.8 / 11.2 · 16.1 / 17.7 | 0.99 · 9.2 / 11.4 · 15.5 / 19.3 | 1.01 · 11.1 / 14.9 · 16.4 / 25.2 |
| filter | 0.62 · 6.6 / 11.6 · 6.6 / 7.9 | 5.21 · 12.1 / 14.9 · 17.9 / 29.2 | 7.76 · 14.4 / 17.0 · 22.0 / 37.4 |
| join | 0.69 · 8.7 / 10.6 · 13.5 / 18.1 | 0.65 · 9.5 / 13.1 · 14.3 / 19.5 | 0.73 · 9.5 / 14.7 · 13.3 / 15.8 |
| cte | 0.82 · 9.9 / 11.3 · 10.3 / 12.2 | 0.78 · 9.4 / 12.4 · 11.1 / 17.5 | 0.74 · 7.9 / 8.8 · 10.9 / 15.7 |
| aggregate | 0.78 · 5.5 / 7.1 · 6.7 / 7.4 | 8.15 · 12.6 / 14.6 · 11.5 / 13.2 | 70.88 · 80.7 / 109.2 · 64.5 / 120.2 |
| point | 0.41 · 7.1 / 8.4 · 6.7 / 7.9 | 0.39 · 6.9 / 9.2 · 8.3 / 9.8 | 0.45 · 8.0 / 10.2 · 7.0 / 9.7 |

**Reading it.** The gateway adds a roughly constant 4–8 ms on SQLite and PostgreSQL and 6–22 ms on MySQL, whatever
the table size, for every shape that reads a bounded number of rows. That time goes to parsing, rewriting, the audit
write and a second round trip. The one shape that reads the whole table, a `GROUP BY` over every account, grows with
the table in the direct query too: through the gateway it costs about 5 ms more on SQLite and PostgreSQL. On MySQL it is
within the measurement spread of the direct query (65–81 ms against 71 ms at 100,000 rows). Support's aggregate returns one group, not two, because
its row filter hides frozen accounts.

**A MySQL fix found by this benchmark (1.1).** Up to 1.0.3 the MySQL backend turned off `derived_merge`, so each masked
view was computed in full before the outer query ran: `ORDER BY … LIMIT 100` masked every row of the table first. At
10,000 rows that took 0.35 s (analyst) to 2.5 s (support), and at 100,000 rows such queries exceeded the 5-second
statement limit and were refused. Views are now merged into the query, so mask functions run only on rows that are
returned. A view whose masked column is used in a join condition gets a `NO_MERGE` hint, because a merged view would
re-run the function for every pair of rows compared; for that case the time is unchanged. Results are identical in
both modes, except the order of rows that tie on a masked value. The full test suite and the attack matrix pass with
the change on all three databases.

Threat scoring uses a direct tree walk over the fitted IsolationForest: 0.22 ms per call, identical to scikit-learn's
`score_samples` to 1e-16 (tested), instead of the library call (~15 ms per call).

**Limits.** Synthetic tables of 3 narrow tables, one machine, warm cache, one client at a time. Not comparable to
Fotache et al.'s Oracle/TPC-H numbers. Wider schemas, cold caches and concurrent clients are not measured. The 1.0.x
figures (`make bench`: 8.3 / 8.1 / 21.4 ms added on SQLite / PostgreSQL / MySQL at 300 rows) used a different query
mix and are superseded.

## 7. Tests

**25 Oct 2026, version 1.1.0: 1,227 passed, 1 skipped, 6 expected failures** (the documented noisy-aggregate gaps)
with `MASKGUARD_TEST_PG` and `MASKGUARD_TEST_MYSQL` set, on SQLite 3.45, PostgreSQL 16 and MySQL 8.4. Earlier figures
(416 on 13 Oct, 513 for 1.0.3 on 18 Oct) are snapshots of smaller suites. The count grew mainly through the attack
matrix (672 cases).

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
