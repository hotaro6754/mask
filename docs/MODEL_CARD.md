# Model card: the PII column classifier

MaskGuard has one machine-learning model that decides what is personal data: a LightGBM classifier that reads one
column (its name and a sample of its values) and says which kind of personal data it holds, if any. A second, smaller
model (an IsolationForest) scores query behaviour for insider-threat alerts; it is described in
[EVALUATION.md](EVALUATION.md) and never decides who sees what.

## What it is

| | |
|---|---|
| Algorithm | LightGBM gradient-boosted trees, multiclass |
| Output | 21 classes: 20 kinds of personal data + `none` |
| The 20 kinds | Aadhaar, PAN, GSTIN, UPI ID, phone, PIN code, passport, voter ID, IFSC, vehicle registration, bank account, name, address, email, date of birth, card number, IBAN, SSN, amount, free text with identifiers |
| Input | One column: its name and up to 200 non-null sample values |
| Features | 99 numbers per column: 79 value statistics (length, digit and letter share, separators, word counts, how many values pass each checksum or match each pattern, distinct ratio, nulls) and 20 column-name hints |
| Size and speed | 0.45 MB file (`src/maskguard/ml/pii_lgbm.txt.gz`); about 2.6 ms per column at 20 values, 17 ms at 200, on a normal CPU. No GPU, no network |
| Code | `src/maskguard/ml/features.py`, `model.py`, `synth.py` |

Values are read in memory only. They are never logged, stored or shown; the scanner records evidence such as
"100% of values look like PAN numbers", never the values.

## What it was trained on

**Only synthetic data from our own generator** (`src/maskguard/ml/synth.py`). No real personal data, no benchmark
data, and none of the organisers' Saffron Bank data.

| | |
|---|---|
| Training set | 6,900 columns: 300 per kind for the 20 kinds, and 900 `none` columns |
| Column size | 20 to 60 values each |
| Values | Generated in 8 locales (Indian English and Hindi, US, UK, German, French, Dutch, Spanish) with Faker, plus our own generators for Indian identifiers with valid check digits (Aadhaar Verhoeff, PAN, GSTIN, IFSC…), Devanagari names and Indian number grouping |
| Noise | 0, 5 or 10% empty values and 0, 5 or 10% corrupted values per column |
| Column names | 40% truthful (`aadhaar_no`), 30% generic (`col_07`, `field_x`), 30% unrelated or misleading (`ref_no`, `token`), so the model learns from values, not names |
| `none` columns | Look-alikes on purpose: order and invoice numbers, SKUs, OTPs, timestamps, prices, codes |
| Validation | A separate generated set (seed 1007, 1,380 columns), used only for early stopping |
| Settings | Learning rate 0.08, 15 leaves, at least 10 rows per leaf, 80% feature and row sampling, L2 1.0; early stopping picked 127 trees; seed 7 |
| Training time | 36 seconds on 4 CPU threads |
| Synthetic validation accuracy | 0.996: the model's own data, so it says nothing about real data |

The model was trained once (12 October 2026) and has not been retrained since. Reproduce with
`maskguard train-scanner` (seed 7).

## How the model is used: it is one step of four

1. **Checksums first.** If at least 60% of values pass a check-digit test (Aadhaar, card, IBAN…), the column is tagged
   and the model cannot downgrade it.
2. **The model.** Long columns are scored in blocks of 20 values (the size it was trained on), up to 10 blocks, and the
   probabilities are averaged. A tag needs probability 0.5 or more.
3. **Banking rules.** A column name that agrees with the value shape (`pan_no` holding PAN-shaped values), money
   words and abbreviations (`bal`, `amt`, `limit`) on numbers, credit scores, and identifiers inside free text.
4. **Anything unsure stays `UNREVIEWED`**: masked for every role except admin until a person approves it.

## How it was tested

| Test | Data | Used for training? | Result (F1: 1.0 = every column right) |
|---|---|---|---|
| Our own generator, held-out seed 9001 | 920 columns of 200 values | Same generator, different seed | 0.955 at 5 values, 0.977 at 20 or more. Optimistic: it is the training distribution |
| bharat-pii-bench, an external public benchmark | Seeds 301–360: 2,880 PII columns and 540 look-alike columns, with truthful, generic and misleading names | No. Its code and data were never used for training; seeds 301–360 were scored once, never inspected | Misleading names: 0.968 at 5 values, 0.999 at 20, 1.000 at 200. The benchmark's own regex + checksum baseline: 0.844. Look-alikes wrongly tagged: 1.5% at 20 values (all 6-digit OTPs that look like PIN codes), baseline 22.2% |
| The organisers' Saffron Bank data | 9 tables, 120 columns, answer key written before any change | No | First contact: F1 0.68 (22 of 35 sensitive columns). After general rule fixes: 0.90 (35 of 35, 8 false alarms on the bank's own branch details). The 13 first-contact misses returned 0 of 1,300 real values to Support and Analyst |

The benchmark is synthetic and clean, so read its numbers as an upper bound. The Saffron numbers are the realistic
ones; the second row was measured after fixes made with that data in view, which is why the first-contact row is
shown too. Details: [EVALUATION.md](EVALUATION.md) and [SAFFRON_VALIDATION.md](SAFFRON_VALIDATION.md).

## What changed after seeing the organisers' data

**The model did not change.** Only the rules around it did (commit 93c342f, `src/maskguard/scanner.py`):

- a column name that agrees with the value shape is enough;
- banking money abbreviations on numeric columns mean money;
- PAN-shaped values count as PAN even when the check fails;
- credit score is financial data;
- `addr`, `account`, `acct` and `cibil` are recognised column-name words;
- the scanner never suggests "public" for a column whose name names a sensitive kind.

After the change, the external benchmark was re-run and did not get worse.

## Known limits

- **Names and addresses inside long prose** need a language model for named entities; identifiers inside text
  (phones, PAN, Aadhaar, UPI, email, dates of birth) are found, names are not yet.
- **With very few values (5)**, recall drops for postal addresses (0.78), bank account numbers (0.82) and dates of
  birth (0.91) on the benchmark. Those columns stay `UNREVIEWED`, so they are masked, not exposed.
- **6-digit OTP columns** can look like PIN codes when no value starts with 0. That is a false alarm, so it means
  over-masking, not a leak.
- **The bank's own contact data** (branch phone, email, address) looks exactly like a customer's; a reviewer approves
  it in one step.
- **Money** is tagged only when the column name ties it to a person (`curr_bal`, `salary`); `unit_price` is not
  personal, by design.

## Why this model and not an LLM or quantum ML

- It runs inside the bank, offline, on a normal CPU, so customer values never leave.
- The same column always gets the same answer.
- It costs milliseconds, not seconds and money per call.
- Its features can be explained.
- On table data, recent benchmarks find quantum classifiers do not beat tuned classical models.
