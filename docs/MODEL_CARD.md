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
```

**How version 2 was chosen.** Candidates were compared only on development data: Nemotron's test split, the two
development exports of bharat-pii-bench (seeds 1-60 and 101-160) and the public business data. Five candidates
were rejected on the way (`docs/eval/model_candidates_*.json`): adding only real non-personal columns cut false
alarms to 0% but dropped postal-address recall to 0.0-0.49, because nothing showed the model what real addresses
look like; leaving the public business data out of an otherwise identical model raised false alarms on it to 24%.
The test sets below were scored once, after the choice.

## How the model is used: it is one step of four

1. **Checksums first.** If at least 60% of values pass a check-digit test (Aadhaar, card, IBAN…), the column is tagged
   and the model cannot downgrade it.
2. **The model.** Long columns are scored in blocks of 20 values (the size it was trained on), up to 10 blocks, and the
   probabilities are averaged. A tag needs probability 0.5 or more.
3. **Banking rules.** A column name that agrees with the value shape (`pan_no` holding PAN-shaped values), money
   words and abbreviations (`bal`, `amt`, `limit`) on numbers, credit scores, and identifiers inside free text.
4. **Anything unsure stays `UNREVIEWED`**: masked for every role except admin until a person approves it.

## How it was tested

Every test set is from a source never used for training. Version 1 is the model shipped before 30 October 2026.
"Protected" means the full scanner tags the column with its kind. A column it misses is still masked by default
(`UNREVIEWED`) until a person approves it, so a miss costs review attention rather than exposing data at once.

| Test set (never trained on) | Licence | PII columns protected, v1 → v2 | Non-personal columns wrongly tagged, v1 → v2 |
|---|---|---|---|
| [gretelai/gretel-pii-masking-en-v1](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1), test | Apache-2.0 | 63.4% → **82.2%** | 27.5% → **10.0%** |
| [urchade/synthetic-pii-ner-mistral-v1](https://huggingface.co/datasets/urchade/synthetic-pii-ner-mistral-v1) | Apache-2.0 | 79.5% → **95.3%** | 98.3% → **4.2%** |
| [ai4privacy/pii-masking-openpii-1.5m](https://huggingface.co/datasets/ai4privacy/pii-masking-openpii-1.5m), validation (non-commercial: test only) | ai4privacy | 61.5% → **91.3%** | (no negatives) |
| [maskflow-ai/indiapii-bench](https://huggingface.co/datasets/maskflow-ai/indiapii-bench) | CC BY 4.0 | 94.8% → 93.0% | 36.7% → 37.5% |
| [Pranshurs/ylemis-india-pii-benchmark](https://huggingface.co/datasets/Pranshurs/ylemis-india-pii-benchmark) | CC0 | 99.8% → **100%** | 10.8% → 24.2% |
| bharat-pii-bench holdout (seeds 301-360), 5 values per column | Apache-2.0 | missed 74 → **50** of 2,880 | 6.3% → 6.3% |
| bharat-pii-bench holdout, 20 values | | missed 3 → **2** (F1 0.999) | 1.5% → 1.5% |
| bharat-pii-bench holdout, 50 / 200 values | | missed 8 → **0** / 0 → 0 (F1 1.000) | 0.2% → 0.2% / 0% → 0% |
| Public business data, test sources (`training/realworld`) | ODC-PDDL | (no PII) | 6.4% → **4.1%** |
| The organisers' Saffron Bank data, full scanner | CC BY 4.0 | 35 of 35 → **35 of 35** | 8 → **7** of 71 |

Across the five Hugging Face test sets, missed PII columns fall from 938 to 412. Calibration improved too: on the
benchmark holdout the expected calibration error of the model's PII probability fell from 0.025 to 0.009 and the
Brier score from 0.011 to 0.005, so a 90% score now means close to 90%.

**Where version 2 is worse.** IndiaPII person names are protected less often (27% → 13%): its names
("Anurupini Kashvee") are invented, and the model now leans on real-world name shapes. Ylemis organisation names are
wrongly tagged more often (11% → 24%). Both are known, measured and listed under limits.

Version 1's results on its own generator and on the benchmark at first release are kept in
[EVALUATION.md](EVALUATION.md). The Saffron first-contact numbers (F1 0.68, 22 of 35 found, 0 of 1,300 values
leaked) were measured with version 1 and are unchanged history. Reproduce the tests with `bench/eval_hf.py`,
`bench/compare_models.py` and `bench/eval_realworld.py`; results are in `docs/eval/model_v1_hf.json`, `model_v2_hf.json` and `model_v1_v2_holdout.json`.

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
  (Gretel: 27% protected), US licence plates (Gretel: 14%), dates of birth written in words (urchade: 69%), names
  from ai4privacy's 23 languages (58%) and invented Indian names (IndiaPII: 13%). A missed column is still masked
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
