# Industry landscape, honest differentiators, and an audit of outside advice

Written 30 October 2026, after checking vendor documentation, open-source projects and dataset licences, and after
auditing a long strategy write-up produced by ChatGPT ("ChatGPT notes" below) against this repository. Every claim
here either links a source or points to a test or result file in the repository.

## 1. The short version

- **Banks already have masking.** IBM Guardium, Oracle Data Safe, DataSunrise, SQL Server Dynamic Data Masking,
  Google Sensitive Data Protection, Protegrity, Immuta and Delphix all cover parts of this problem. MaskGuard does not
  replace them, and the pitch must not say so.
- **Two "differentiators" in circulation are not unique:**
  - Rewriting SQL so masking runs inside the query: IBM Guardium does this too, wrapping the column in a masking
    UDF ([IBM](https://community.ibm.com/community/user/security/blogs/walid-rjaibi1/2023/10/04/unified-data-access-policy-management-and-enforcem)).
  - Indian identifiers: Google Sensitive Data Protection has Aadhaar, PAN and GST detectors
    ([infoTypes](https://cloud.google.com/sensitive-data-protection/docs/infotypes-reference), [overview](https://blog.nashtechglobal.com/cloud-data-loss-prevention-dlp-infotype-detector/)),
    and Presidio ships Aadhaar, voter ID, passport and vehicle recognisers ([Presidio](https://microsoft.github.io/presidio/supported_entities)).
- **What is defensible** is the combination, measured in public:
  - discovery that feeds enforcement directly;
  - columns it is unsure about are masked until a person approves them;
  - masking inside the query on three engines;
  - every claim backed by a reproducible test on public data, including the failures.

## 2. Who does what (checked sources)

| Product | Discovery | Enforcement | Notes |
|---|---|---|---|
| IBM Guardium Data Protection | Yes | Query rewrite with masking UDFs, row filtering ([IBM](https://community.ibm.com/community/user/security/blogs/walid-rjaibi1/2023/10/04/unified-data-access-policy-management-and-enforcem)) | Same core technique as MaskGuard; enterprise appliance and agents |
| Oracle Data Safe | 150+ sensitive types, scans data and metadata, finds primary/foreign-key relationships ([Oracle](https://www.oracle.com/security/database-security/data-safe/features/)) | Masking aimed at non-production copies; SQL Firewall in the database kernel ([docs](https://docs.oracle.com/en-us/iaas/data-safe/doc/oracle-data-safe-overview.html)) | Oracle databases |
| DataSunrise | Discovery and compliance roles ([Bloor](https://bloorresearch.com/?p=19839)) | Proxy between clients and database, dynamic masking at query time, many engines ([DataSunrise](https://www.datasunrise.com/data-masking/dynamic-data-masking/)) | Closest commercial architecture to MaskGuard |
| SQL Server Dynamic Data Masking | No | Masks results; Microsoft documents that it does not stop inference through filters | SQL Server only |
| Google Sensitive Data Protection | Built-in detectors (infoTypes), including Aadhaar, PAN and GST | De-identification APIs | Cloud service; data is sent to Google |
| Microsoft Presidio (open source) | Text recognisers incl. India | Anonymiser for text | No database gateway |
| PostgreSQL Anonymizer (open source) | Declared by labels | Masking views and roles in PostgreSQL | PostgreSQL only |
| Iron Veil, Tonic Masquerade, pg_masking (open source) | Regex heuristics or none | Wire-protocol proxies that mask results ([Iron Veil](https://awesome.ecosyste.ms/projects/github.com%2Fuppnrise%2Firon-veil), [Masquerade](https://tonic.ai/blog/masquerade-a-postgres-proxy)) | Result masking, no published evaluation |

## 3. What MaskGuard can claim, with evidence

| Claim | Evidence in this repository |
|---|---|
| Finds PII from values when column names lie | Version 2 model on 9 test sets never trained on (`docs/MODEL_CARD.md`); `col_7` holding PANs found in the organisers' data |
| Holds up on messy exports | 2,800 test columns damaged 11 ways ("NULL" text, quotes, half-masked, regrouped digits): 91% of PII columns protected, version 1 77% (`bench/stress.py`, `docs/eval/stress_v2.json`) |
| Fails closed | Unreviewed columns are masked for every role but admin; 13 first-contact misses on Saffron Bank returned 0 of 1,300 real values (`docs/eval/saffron_first_contact.json`) |
| Masking happens before filters and joins see the value | 17 named attacks and a 672-case matrix on three engines, 0 leaks; output-only masking leaks 14 of 17 (`docs/EVALUATION.md`) |
| One role never receives another's view under load | `tests/test_concurrency.py`: 120 interleaved queries on 12 threads, three engines |
| Read-only, data unchanged | Integrity digests before and after; writes refused for every role |
| Evidence is public and reproducible | Every number has a script in `bench/` and a result file in `docs/eval/`, including rejected model candidates |
| Runs offline on a CPU | 0.71 MB model, about 3 ms per column; no external calls |

## 4. Audit of the ChatGPT notes

| ChatGPT note | Verdict | What we did |
|---|---|---|
| Indian identifiers are a differentiator | **Not unique**: Google and Presidio detect them | Pitch them as evaluated (three Indian benchmarks), not as unique |
| SQL-aware rewriting is a differentiator | **Not unique**: Guardium rewrites queries too | Pitch the measured inference resistance, not the technique |
| Relationship-aware discovery would differentiate | **Partly**: Oracle Data Safe already finds key relationships | Combination risk (quasi-identifiers) remains open work |
| Connection pools may leak one user's role to another | **Tested, no leak** | `tests/test_concurrency.py` on SQLite, PostgreSQL, MySQL |
| Prepared statements may bypass masking | **Already covered** | `tests/test_proxy.py::test_auto_prepared_statements_keep_masking` |
| Train LightGBM on more datasets | **Done, with care** | 6,300 Hugging Face columns + 1,080 public business columns; adopted only after it beat version 1 on held-out data (`docs/MODEL_CARD.md`) |
| Use ai4privacy for training | **Licence forbids** (non-commercial, no derivatives) | Used as a test set only |
| Measure calibration (ECE, Brier) | **Done** | ECE 0.025 → 0.009 on the benchmark holdout |
| Split by source, not by row | **Done** | Test datasets never share a source with training |
| Build a policy simulator | **Partly exists** | `maskguard policy explain`, `/policy/explain`, the playground's "why each field looks the way it does" |
| Don't claim differential privacy | **Already the case** | Noisy aggregates are refused in production (decision D11) |
| Shared threat state across instances | **Open**: threat state is in memory | Listed limit; needs Redis or a database table |
| Database bypass must be blocked | **Partly**: production refuses a writable account; network isolation is the deployer's job | `docs/DEPLOYMENT.md` |
| Presidio for names in text | **Open** | Names inside prose remain a stated limit |
| "Latest CI: 1,234 passed" | **Stale figure** | Use the current CI run |

## 5. Datasets: what we may use for what

| Dataset | Licence | Role |
|---|---|---|
| nvidia/Nemotron-PII | CC BY 4.0 | Training (train split), model selection (test split) |
| gretelai/synthetic_pii_finance_multilingual | Apache-2.0 | Training |
| github.com/datasets public business data | ODC-PDDL / CC BY 4.0 | Training (train sources), testing (other sources) |
| gretelai/gretel-pii-masking-en-v1 | Apache-2.0 | Test |
| urchade/synthetic-pii-ner-mistral-v1 | Apache-2.0 | Test |
| maskflow-ai/indiapii-bench | CC BY 4.0 | Test |
| Pranshurs/ylemis-india-pii-benchmark | CC0 | Test |
| ai4privacy/pii-masking-openpii-1.5m | Non-commercial | Test only |
| bharat-pii-bench | Apache-2.0 | Model selection (seeds 1-60, 101-160), test (301-360) |
| Organisers' Saffron Bank | CC BY 4.0 | Test |
| GitTables, Sherlock/VizNet | Per-table licences / unclear | Not used |

## 6. What to build next, in order

1. **Quasi-identifier risk report**: which combinations of ordinary columns single people out (group sizes per
   combination). Oracle finds key relationships; few tools report combination risk.
2. **Names in free text** with Presidio behind the existing text detector, measured on the same test sets.
3. **Shared threat state** for more than one gateway instance.
4. **Model refresh routine**: rerun `training/` when new permissively licensed data appears, adopt only on held-out
   improvement, keep the rejected candidates' results.
