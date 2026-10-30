# Validation on the organisers' dataset: Saffron Bank (TalentAP 2026, B1)

The hackathon pack for problem B1 is **Saffron Bank Ltd**, a synthetic Indian retail bank:
- 9 tables, 120 columns and 129,260 rows;
- shipped for SQLite, PostgreSQL and MySQL, plus CSV;
- licensed CC BY 4.0.

MaskGuard had never seen it. This page records what we did with it, in order, including what failed first. The
organisers' data is not in this repository; every script below takes the path to your copy of the pack.

## 1. The data is the same everywhere

| Check | Result |
|---|---|
| CSV row counts against the pack README | 129,260 rows, every table exact |
| A database we built from the CSVs (`bench/saffron/build_from_csv.py`, schema taken from the README's column tables) vs the shipped `saffron_bank.db` | 9/9 tables identical |
| The pack's own `load/load_sqlite.py` rebuilding from `saffron_bank.sql` vs the shipped `.db` | 9/9 tables identical |
| The official `sql/postgres` and `sql/mysql` scripts loaded into PostgreSQL 16 and MySQL 8.4, compared cell by cell with SQLite (`bench/saffron/compare_dbs.py`; money precision, `T` vs space in timestamps and JSON key order normalised, as the README describes) | 9/9 tables identical on all three |

The PostgreSQL and MySQL scripts are dialect-specific files, not copies. MySQL uses `DATETIME`, `DECIMAL`, `JSON` and
InnoDB; PostgreSQL uses `TIMESTAMP`, `NUMERIC`, `JSONB` and 10 indexes. They load the same data.

## 2. What the pack does to break a scanner

- **Column names:**
  - mixed case (`cards` is all capitals, so PostgreSQL needs quoted identifiers);
  - abbreviations (`curr_bal`, `pita_nm`, `od_limit_inr`);
  - a generic `col_7` that holds PANs in 137 of 1,500 rows.
- **Identifiers built to be impossible:**
  - every Aadhaar-format number fails its Verhoeff check digit;
  - every PAN has `0000` as its digits, so standard validators reject them;
  - 1,682 Aadhaar values are already masked at source (`XXXX XXXX 7738`).
- **Formats:**
  - SSNs in three formats (`935-22-8793`, `960 46 5982`, `969266389`);
  - Indian phones in three formats, and US phones as `+1 (510) 555-0165`;
  - cards with and without spaces.
- **Decoys:** `transactions.ref_no` holds 16-digit numbers with test-card prefixes that fail the Luhn check (the README
  says references are random), mixed with `SAFFN…` references.
- **Free text in English and Hinglish, with typos and emoji:**
  - `ticket_text` has phones, accounts and UPI IDs;
  - `notes` has phones and dates of birth;
  - `remarks` has co-applicants' names and phones;
  - `narration` has UPI handles;
  - `extra_info` has emails and old account numbers.
- **JSON** (`kyc_meta`), and mostly-empty columns.

## 3. Discovery: answer key first, then the scanner

Before changing anything, we wrote an answer key (`bench/saffron/truth.py`) from the pack README and value samples.
Each of the 120 columns is labelled:
- **S, sensitive** (35): must be masked from non-admin roles.
- **Q, personal attribute or quasi-identifier** (14): masking is right, not masking is a judgement call.
- **N, not personal** (71): keys, codes, dates, statuses, and the bank's own branch data.

`ref_no` is labelled N, as a decoy. We then ran `maskguard connect` on a copy of the database and scored it with
`bench/saffron/score_scan.py`.

| Sensitive columns (35) | First contact (1.1.0) | After the fixes below |
|---|---|---|
| Tagged with the right kind | 22 | **35** |
| Not tagged, left `UNREVIEWED`: masked for every role but admin, so not exposed | 11 | 0 |
| Not tagged and **suggested PUBLIC** (exposed if a reviewer accepted the suggestion) | **2** (`account_no` ×2) | **0** |

As detection scores (sensitive columns against not-personal ones; the 14 judgement-call columns left out):

| | Precision | Recall | F1 |
|---|---|---|---|
| First contact (1.1.0) | 0.73 (22 of 30 tagged) | 0.63 (22 of 35) | 0.68 |
| After the fixes below | 0.81 (35 of 43 tagged) | 1.00 (35 of 35) | 0.90 |

The fixes were made after seeing this dataset, so the second row is not a blind score; the first row is.

On first contact nothing was exposed by default: untagged columns are masked as `UNREVIEWED`. We checked this on the
saved first-contact registry (`bench/saffron/first_contact_leaks.py`, `docs/eval/saffron_first_contact.json`): the 13
missed columns, 50 values each, queried as `support_ravi` and `analyst_kavya`, returned **0 of 1,300** real values.
The catch: two account-number columns were wrongly suggested as non-personal. A reviewer who accepted every suggestion
without looking (`pii approve --suggested`) would have exposed both (200 of the 1,300 values). Money columns were
also mislabelled as PIN codes. Every miss had a general cause:

| Miss | Cause | Fix (general, not for this dataset) |
|---|---|---|
| `account_no` suggested PUBLIC | "whole numbers ending in `_no`" looks like a key | Never suggest PUBLIC when the column name names a sensitive kind; `account` and `acct` are now name words |
| `pan_no`, `col_7` | PANs with `0000` digits fail the PAN validator; the model said "not PII" | A PAN-shaped column (5 letters, 4 digits, 1 letter, valid holder letter) is PAN even when the check fails: fail closed |
| `curr_bal`, `bal_after`, `amt_*`, `CREDIT_LIMIT`; `od_limit_inr` labelled as a PIN code | Money was recognised only as whole words (`balance`, `amount`) | Banking abbreviations (`bal`, `amt`, `limit`, `od`, `sanctioned` …) on numeric values mean money; rates are not money |
| `credit_score` | No such kind | Credit score is `FINANCIAL_CONFIDENTIAL` |
| `us_addr`, `addr_line2` | `addr` was not a name word | Added |

**Regression check:** the external benchmark did not move. On bharat-pii-bench the hybrid scanner is still 0.999
macro-F1 with 1.5% false alarms on hard negatives. At 5 values the full scanner misses 74 PII columns instead of 82,
and the rules-only fallback is back to 0.450 on truthful names.

**Still flagged unnecessarily:**
- 8 non-personal columns: the bank's own branch phone, email, address, name, PIN code and IFSC, and `CARD_REF`.
  They are masked, not leaked. A scanner cannot tell a branch's phone number from a customer's; the reviewer approves
  them in one step.
- 3 personal attributes that are short value lists are suggested PUBLIC: `nominee_rel`, `risk_cat`,
  `residency_status`. The reviewer decides.

## 4. Masking, as the organisers' users, on all three databases

`data/users.csv` lists 9 users: 3 each for Admin, Support and Analyst. We made them MaskGuard logins with generated
passwords, kept outside the repository.

First, the review step a bank would do:
- `pii approve --suggested` for keys and status lists (20 columns);
- the reviewer approves the remaining non-personal columns (51).

Personal attributes stay `UNREVIEWED`, so they remain masked. Then `bench/saffron/eval_masking.py` ran as
`admin_anita`, `support_ravi` and `analyst_kavya`:

| Check | SQLite | PostgreSQL 16 | MySQL 8.4 |
|---|---|---|---|
| Masked cells checked (9 tables × 200 rows × Support and Analyst) | 13,700 | 13,700 | 13,700 |
| Raw values returned where the policy masks | **0** | **0** | **0** |
| `WHERE pan_no = '<real PAN>'`: rows found (Admin / Support / Analyst) | 1 / 0 / 0 | 1 / 0 / 0 | 1 / 0 / 0 |
| `UPDATE`, `DELETE`, `DROP`, `INSERT` refused, every role including Admin | 4/4 | 4/4 | 4/4 |
| Stored data unchanged (table digests before and after) | yes | yes | yes |
| Audit hash chain intact | yes | yes | yes |

How the sweep counts a leak:
- **Rounded money:** a leak only if an unrounded amount comes back.
- **Partial masks:** a value already masked at source is not counted.
- **Free text:** a leak only if an identifier is still inside the returned text.

What the roles see (PostgreSQL; values are synthetic):

| | Admin | Support | Analyst |
|---|---|---|---|
| `CARD_NO` | `5105 1051 5305 9696` | `5105 XXXX XXXX 9696` | `REDACTED` |
| `ssn` | `935-22-8793`, `960 46 5982` | `XXX-XX-8793`, `XXX XX 5982` | 128-bit token |
| `us_phone` | `+1 (510) 555-0165` | `+X (XXX) XXX-0165` | token |
| `notes` | Called cust on +91 90000 80247. Verified DOB 22 Apr 1948. | Called cust on [PHONE]. Verified DOB [DATE]. | `REDACTED` |

`docs/eval/saffron_masking.json` holds the summary for the three databases.

## 5. A product bug the pack exposed (fixed)

The default policy carried the demo bank's row filter, under which support never sees frozen accounts:
`accounts: "status <> 'frozen'"`. Saffron Bank also has an `accounts` table, but its column is `acct_status`. The
filter could not compile, so MaskGuard refused every support query on `accounts`. That is fail-closed, but unusable.

The demo filter now lives in `policies/row_filters.demo.yaml` and applies only to the demo data. For Saffron, a bank
would write its own filter: `accounts: "acct_status <> 'FROZEN'"` (68 accounts).

## Reproduce

```bash
PACK=/path/to/B1_Smart_Data_Masking_PII
python bench/saffron/compare_dbs.py $PACK/sql/sqlite/saffron_bank.db      # needs the PG and MySQL loads (README)
mkdir run && cp $PACK/sql/sqlite/saffron_bank.db run/ && cd run
maskguard connect sqlite:///$PWD/saffron_bank.db && maskguard pii list --json > pii.json
python ../bench/saffron/score_scan.py pii.json ../bench/saffron
python ../bench/saffron/eval_masking.py sqlite:///$PWD/saffron_bank.db work users.yaml passwords.yaml ../bench/saffron out.json
python ../bench/saffron/first_contact_leaks.py data/saffron_bank/registry.yaml sqlite:///$PWD/saffron_bank.db fc users.yaml passwords.yaml fc.json   # run on the first-contact registry, before any approvals
```

`users.yaml` lists the 9 users from `data/users.csv` in the format of `deploy/users.example.yaml` (role in lower case,
`password_hash` from `maskguard hash-password`); `passwords.yaml` maps each username to its password. Keep both out of
version control.
