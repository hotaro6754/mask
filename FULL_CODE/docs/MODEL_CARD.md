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
| Size and speed | 0.71 MB file (`src/maskguard/ml/pii_lgbm.txt.gz`); about 2.8 ms per column at 20 values, 19 ms at 200, on a normal CPU. No GPU, no network |
| Code | `src/maskguard/ml/features.py`, `model.py`, `synth.py` |

Values are read in memory only. They are never logged, stored or shown; the scanner records evidence such as
"100% of values look like PAN numbers", never the values.

## What it was trained on

Version 2 (30 October 2026) keeps the same 99 features and settings as version 1; only the training data changed.
No real personal data, no test data, and none of the organisers' Saffron Bank data.

| Source | Columns | Licence | What it adds |
|---|---|---|---|
| Our generator (`src/maskguard/ml/synth.py`) | 6,900 | ours | All 20 kinds, Indian identifiers with valid check digits, Devanagari names, look-alikes (order ids, SKUs, OTPs) |
| [nvidia/Nemotron-PII](https://huggingface.co/datasets/nvidia/Nemotron-PII), train split | 3,000 | CC BY 4.0 | Real-world formats of names, phones, street addresses, dates of birth, cards, SSNs, account numbers, licence plates, plus company names and URLs as negatives |
| [gretelai/synthetic_pii_finance_multilingual](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual) | 3,300 | Apache-2.0 | The same kinds in 6 languages (English, Spanish, German, Italian, Dutch, Swedish), IBANs, BBANs, passports |
| Public business data from [github.com/datasets](https://github.com/datasets) (`training/realworld/sources.yaml`, train split) | 1,080 | ODC-PDDL / CC BY 4.0 | Real non-personal columns: codes, numeric ids, coordinates, tickers, company names, prices |

| | |
|---|---|
| Column size | 20 to 60 values each |
| Column names | 40% truthful (`aadhaar_no`), 30% generic (`col_07`), 30% unrelated or misleading (`ref_no`), so the model learns from values, not names |
| Noise (generator) | 0, 5 or 10% empty values and 0, 5 or 10% corrupted values per column |
| Hugging Face columns | Built by `training/hf/convert.py`: the dataset's annotated spans of one label, pooled and drawn into columns. Labels map to the 20 kinds by an explicit table in `training/hf/sources.yaml`; ambiguous labels (city, state, generic dates, user names) are left out |
| Validation | A separate generated set (seed 1007, 1,380 columns), used only for early stopping |
| Settings | Learning rate 0.08, 15 leaves, at least 10 rows per leaf, 80% feature and row sampling, L2 1.0; early stopping picked 127 trees; seed 7 |
| Training time | About 1 minute on 4 CPU threads |

Reproduce:

```bash
python training/realworld/build.py            # public business data, cached
python training/hf/convert.py --download      # Hugging Face datasets, cached
python training/train_candidate.py OUT --extra training/hf/cache/nemotron_train.json training/hf/cache/gretelfin_train.json
python bench/evaluate.py --ablation            # baselines, ablation; also checks retraining reproduces this model
```

**How version 2 was chosen.** Candidates were compared only on development data: Nemotron's test split, the two
development exports of bharat-pii-bench (seeds 1-60 and 101-160) and the public business data. Five candidates
were rejected on the way (`docs/eval/model_candidates_*.json`): adding only real non-personal columns cut false
alarms to 0% but dropped postal-address recall to 0.0-0.49, because nothing showed the model what real addresses
look like; leaving the public business data out of an otherwise identical model raised false alarms on it to 24%.
The test sets below were scored once, after the choice.

## How the model is used: it is one step of five

0. **Read the values as a person would.** Spaces, non-breaking spaces and wrapping quotes are stripped. Text that
   stands for a missing value ("NULL", "N/A", "", "-") is dropped, and values a legacy system already masked
   ("XXXXXX1234") are dropped while real ones remain. PIN codes and passports written with a space ("530 017",
   "J12 34567") are read whole, and 0 in a numeric identifier column counts as missing. If most of the 200 sampled
   values are placeholders, the scanner reads 2,000. Masking still applies to the stored values unchanged.
1. **Checksums first.** If at least 60% of values pass a check-digit test (Aadhaar, card, IBAN…), the column is tagged
   and the model cannot downgrade it.
2. **The model.** Long columns are scored in blocks of 20 values (the size it was trained on), up to 10 blocks, and the
   probabilities are averaged. A tag needs probability 0.5 or more.
3. **Banking rules.** A column name that agrees with the value shape (`pan_no` holding PAN-shaped values), money
   words and abbreviations (`bal`, `amt`, `limit`) on numbers, credit scores, and identifiers inside free text. A
   column name made only of identifier words (`ssn`, `vehicle_no`, `account_number`) or naming a person
   (`customer_name`, `nominee_name`) masks the column even when the model reads the values as ordinary, unless the
   values are a few repeated categories. `account_id` and `uid` alone do not count: they are usually keys.
4. **Anything unsure stays `UNREVIEWED`**: masked for every role except admin until a person approves it.

## How it was tested

Every test set is from a source never used for training. Version 1 is the model and scanner shipped before 30 October
2026; version 2 is the new model with the scanner of 30 October (step 0 and the column-name rules above).
"Protected" means the full scanner tags the column with its kind. A column it misses is still masked by default
(`UNREVIEWED`) until a person approves it, so a miss costs review attention rather than exposing data at once.

| Test set (never trained on) | Licence | PII columns protected, v1 → v2 | Non-personal columns wrongly tagged, v1 → v2 |
|---|---|---|---|
| [gretelai/gretel-pii-masking-en-v1](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1), test | Apache-2.0 | 63.4% → **84.0%** | 27.5% → **10.0%** |
| [urchade/synthetic-pii-ner-mistral-v1](https://huggingface.co/datasets/urchade/synthetic-pii-ner-mistral-v1) | Apache-2.0 | 79.5% → **95.5%** | 98.3% → **4.2%** |
| [ai4privacy/pii-masking-openpii-1.5m](https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1.5m), validation (non-commercial: test only) | ai4privacy | 61.5% → **91.3%** | (no negatives) |
| [maskflow-ai/indiapii-bench](https://huggingface.co/datasets/maskflow-ai/indiapii-bench) | CC BY 4.0 | 94.8% → 94.8% | 36.7% → 37.5% |
| [Pranshurs/ylemis-india-pii-benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | CC0 | 99.8% → **100%** | 10.8% → 24.2% |
| bharat-pii-bench holdout (seeds 301-360), 5 values per column | Apache-2.0 | missed 74 → **50** of 2,880 | 6.3% → 6.3% |
| bharat-pii-bench holdout, 20 values | | missed 3 → **2** (F1 0.999) | 1.5% → 1.5% |
| bharat-pii-bench holdout, 50 / 200 values | | missed 8 → **0** / 0 → 0 (F1 1.000) | 0.2% → 0.2% / 0% → 0% |
| Public business data, test sources (`training/realworld`) | ODC-PDDL | (no PII) | 6.4% → **4.1%** |
| The organisers' Saffron Bank data, full scanner | CC BY 4.0 | 35 of 35 → **35 of 35** | 8 → **7** of 71 |

Across the five Hugging Face test sets, missed PII columns fall from 938 to 361. Calibration improved too: on the
benchmark holdout the expected calibration error of the model's PII probability fell from 0.025 to 0.009 and the
Brier score from 0.011 to 0.005, so a 90% score now means close to 90%.

**Where version 2 is worse.** Ylemis organisation names are wrongly tagged more often (11% → 24%), and IndiaPII's
look-alike negatives slightly more (36.7% → 37.5%). That is over-masking, not a leak. The new model alone protected
fewer IndiaPII names (27% → 13%) and passports (100% → 90%); the scanner's column-name rule and its reading of
"J12 34567" brought both back to version 1's level (28% and 100%).

### Messy data: the stress test

Production data is rarely clean. `bench/stress.py` takes 2,800 test columns (2,560 with PII) from the five test
sets and the benchmark holdout, damages each one in 11 ways real exports do, and scans it again. Share of PII columns
still protected:

| Damage | Version 1 | Version 2 |
|---|---|---|
| none (clean) | 88.0% | **95.5%** |
| 80% of values are "NULL", "N/A", "" or "-" text | 48.9% | **79.1%** |
| only 3 values | 82.7% | **89.9%** |
| 30% of values from an unrelated column | 84.4% | **87.8%** |
| random case, leading and trailing spaces | 91.6% | **93.4%** |
| regrouped digits ("+91 98765 43210", "530 017") | 85.3% | **94.7%** |
| half the values masked by a legacy system | 87.5% | **93.6%** |
| digits handed over as numbers (BIGINT) | 88.0% | **95.5%** |
| values wrapped in quotes (CSV import) | 35.0% | **95.5%** |
| non-breaking spaces (pasted from a spreadsheet) | 84.3% | **95.5%** |
| only 2 distinct values, repeated | 72.9% | **79.3%** |

Missed PII columns over all 11 damages fall from 6,431 to 2,565. Non-personal columns wrongly tagged on clean data
fall from 29.6% to 13.8%. The placeholder row is pessimistic: these test columns hold 20 to 60 values, so 80%
placeholders leave 4 to 12 real ones, while the scanner reads 200 values (2,000 when most are placeholders). The two
hardest cases, very few values and two repeated values, are where values alone cannot tell, and the column-name
rules carry the weight. Results: `docs/eval/stress_v1_baseline.json` (commit f55cfaa) and `docs/eval/stress_v2.json`.

Version 1's results on its own generator and on the benchmark at first release are kept in
[EVALUATION.md](EVALUATION.md). The Saffron first-contact numbers (F1 0.68, 22 of 35 found, 0 of 1,300 values
leaked) were measured with version 1 and are unchanged history. Reproduce the tests with `bench/eval_hf.py`,
`bench/compare_models.py`, `bench/eval_realworld.py` and `bench/stress.py`; results are in `docs/eval/model_v1_hf.json`,
`model_v2_hf.json`, `model_v1_v2_holdout.json`, `scanner_sampling_v2.json`, `scanner_sampling_200_v2.json`,
`realworld_v2_scanner.json` and `stress_v2.json`.

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
- **With very few values (5)**, recall drops for dates of birth (0.89), bank account numbers (0.88) and postal
  addresses (0.88) on the benchmark (version 1: 0.89, 0.82, 0.77). Those columns stay `UNREVIEWED`, so they are
  masked, not exposed.
- **Weakest kinds on unseen real-world formats** (version 2, held-out sets): account numbers without a bank format
  (Gretel: 27% protected), Gretel's licence and plate numbers (30%), dates of birth written in words (urchade: 69%),
  names from ai4privacy's 23 languages (58%) and invented Indian names (IndiaPII: 28%). A missed column is still masked
  as `UNREVIEWED` until a reviewer approves it, so the risk is a reviewer approving it without looking.
- **Organisation names** are sometimes read as person names (Ylemis: 24% of organisation columns tagged). That is
  over-masking, not a leak.
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
