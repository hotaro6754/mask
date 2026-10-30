# AI evaluation: PII column discovery

One command produces every number on this page, from data the model never trained on:

```bash
cd FULL_CODE
uv run python bench/evaluate.py --ablation    # about 25 minutes; without --ablation about 2
```

It writes `docs/eval/baseline_comparison.json`, `per_class_metrics.json`, `confusion_matrix.json`,
`calibration_metrics.json`, `latency_metrics.json`, `leakage_check.json`, `dataset_manifest.json` and
`ablation_results.json`, and exits with status 1 if a quality gate fails (§7). Results below: 31 October 2026,
MaskGuard 1.1.0, model version 2, Python 3.13, Linux x86-64 with 4 CPUs.

## 1. The task

**Input:** one database column: its name and a sample of its values (20 here; the scanner reads up to 200).
**Output:** the kind of personal data it holds (one of 19 kinds: Aadhaar, PAN, GSTIN, UPI ID, phone, PIN code,
passport, voter ID, IFSC, vehicle registration, bank account, name, address, email, date of birth, card, IBAN, SSN,
plus money) or "not personal".

This is column classification, not entity recognition in text: finding identifiers inside free-text cells is a
separate component (`textpii.py`) and is not scored here.

**Why it matters:** a column found is masked for the roles that may not see it. A column missed is still masked,
because unreviewed columns are hidden until a person approves them, but it costs the reviewer's attention and
risks a careless approval. A false alarm masks a harmless column until someone approves it.

## 2. The detectors compared

All five see the same 9,780 columns with the same 20 values each.

| | Detector | Uses |
|---|---|---|
| A | Header only | The column name, through the same word list the model's header features use |
| B | Rules only | Check digits (Aadhaar Verhoeff, PAN, GSTIN, voter ID, card Luhn, IBAN) and regular expressions for 9 more kinds, on the values; 60% of values must match |
| C | LightGBM only | The classifier's most probable kind (threshold 0.5), no check-digit override |
| D | Rules + LightGBM | Check digits first, then the classifier, then a review band for uncertain columns (`ml.model.decide`) |
| E | Full scanner | D, plus reading values as a person would (quotes, placeholders, legacy masks), value patterns, the sparse-identifier band and column-name rules: what production runs (`scanner.classify_column`) |

Code: `bench/baselines.py`.

## 3. The test data

| Test set | Columns | Source | Licence |
|---|---|---|---|
| gretel-pii-masking-en-v1, test split | 1,200 | Gretel | Apache-2.0 |
| synthetic-pii-ner-mistral-v1 | 1,200 | urchade | Apache-2.0 |
| pii-masking-openpii-1.5m, validation | 600 | ai4privacy | non-commercial: test only |
| indiapii-bench | 1,800 | maskflow-ai | CC BY 4.0 |
| ylemis-india-pii-benchmark | 1,560 | Pranshurs | CC0 |
| bharat-pii-bench T2 holdout (seeds 301–360, hard negatives 777) | 3,420 | bharat-pii-bench | Apache-2.0 |

Each Hugging Face set is span-annotated text; `training/hf/convert.py` pools the values of each label and draws
columns of 20–60 values, with truthful, generic or misleading column names in equal parts. Labels map to kinds by an
explicit table in `training/hf/sources.yaml`.

**Separation from training.** The model was trained on MaskGuard's synthetic generator, Nemotron-PII (train split),
Gretel's finance dataset and public business data (train sources). No test set shares a source with training.
`docs/eval/leakage_check.json`: **no test column is identical to a training column**; the share of individual test
values that also occur in training is 0.1–5.7% for five sets and 11.4% for urchade (common first names and cities,
which recur in any two datasets). Model choices were made on separate development data (Nemotron's test split and
bharat-pii-bench seeds 1–60 and 101–160), never on these sets.

**Not in this evaluation:** the organisers' Saffron Bank data. We saw it while fixing the scanner, so it is not a blind
test; [SAFFRON_VALIDATION.md](SAFFRON_VALIDATION.md) reports first contact (blind, F1 0.68) and after fixes
(F1 0.91) separately.

## 4. Results

Pooled over all 9,780 columns. Macro averages are over the kinds present plus "not personal"; the 95% interval is a
bootstrap over columns (200 resamples). "Protected" means the column was tagged with any personal kind, so it is
masked; "high-risk" covers direct identifiers and financial data (Aadhaar, PAN, passport, voter ID, SSN, phone, email,
UPI, card, IBAN, bank account, GSTIN).

| Detector | Macro-F1 (95% CI) | Macro precision | Macro recall | Weighted F1 | Accuracy | PII protected | High-risk protected | False-positive rate |
|---|---|---|---|---|---|---|---|---|
| A Header only | 0.468 (0.454–0.480) | 0.946 | 0.350 | 0.459 | 0.399 | 32.2% | 32.2% | 4.8% |
| B Rules only | 0.578 (0.573–0.585) | 0.656 | 0.572 | 0.557 | 0.584 | 56.8% | 68.3% | 10.0% |
| C LightGBM only | 0.878 (0.874–0.882) | 0.893 | 0.874 | 0.895 | 0.897 | 92.1% | 95.0% | 4.5% |
| D Rules + LightGBM | 0.882 (0.878–0.885) | 0.891 | 0.881 | 0.902 | 0.906 | 93.8% | 97.4% | 4.7% |
| **E Full scanner** | **0.888 (0.884–0.892)** | 0.891 | **0.891** | **0.911** | **0.915** | **95.4%** | **98.1%** | 7.8% |

**What this shows.**
- Column names alone are precise but find a third of the data: half the test columns have generic or misleading names.
- Regular expressions and check digits find the Indian identifiers that have a fixed format, and little else: names,
  addresses, dates of birth and free-form account numbers have none.
- The classifier is the step change: +0.30 macro-F1 over rules, and 92% of personal columns found from values alone.
- Rules on top of the classifier add recall where a check digit is certain (high-risk protected 95.0% → 97.4%).
- The full scanner adds the rest of the recall (95.4% protected, 4.6% missed) at the price of more false alarms
  (4.7% → 7.8%). That trade is deliberate: an unmasked identifier is a leak, a masked harmless column is a review.

**Per test set (full scanner):**

| Test set | Macro-F1 | PII protected | High-risk protected | False-positive rate |
|---|---|---|---|---|
| bharat-pii-bench holdout | 0.998 | 100% | 100% | 1.4% |
| ylemis | 0.977 | 100% | 100% | 29.2% |
| openpii | 0.925 | 89.0% | 98.3% | (no negatives) |
| indiapii | 0.838 | 94.8% | 100% | 26.7% |
| gretelen | 0.793 | 85.3% | 86.2% | 9.2% |
| urchade | 0.758 | 92.3% | 97.9% | 5.0% |

The synthetic bharat-pii-bench is near the ceiling; the LLM-generated sets are harder and closer to real data. The
high false-positive rates on ylemis and indiapii come from look-alikes the scanner masks on purpose: PAN-shaped
invoice numbers (real PANs in the organisers' data fail the check digit, so the scanner masks PAN-shaped values
without it) and organisation names read as person names.

## 5. Per class and errors

Full scanner, pooled (`docs/eval/per_class_metrics.json`, confusion matrices in `confusion_matrix.json`):

| Kind | Precision | Recall | F1 | Columns |
|---|---|---|---|---|
| Aadhaar, GSTIN, IFSC, phone, SSN, voter ID | 1.000 | 1.000 | 1.000 | 120–780 each |
| PIN code | 0.968 | 1.000 | 0.984 | 300 |
| PAN | 0.955 | 1.000 | 0.977 | 420 |
| address | 0.945 | 0.964 | 0.954 | 660 |
| date of birth | 1.000 | 0.893 | 0.943 | 420 |
| passport | 0.920 | 0.921 | 0.920 | 660 |
| email | 1.000 | 0.846 | 0.917 | 780 |
| vehicle registration | 1.000 | 0.819 | 0.900 | 540 |
| card | 0.806 | 0.972 | 0.882 | 360 |
| UPI ID | 0.778 | 1.000 | 0.875 | 420 |
| name | 0.914 | 0.806 | 0.857 | 780 |
| bank account | 0.910 | 0.789 | 0.845 | 540 |
| not personal | 0.736 | 0.922 | 0.819 | 1,200 |
| IBAN | 0.000 | 0.000 | 0.000 | 120 |

**IBAN at zero, explained.** All 120 IBAN columns come from urchade, whose IBANs were invented by a language model:
none of the 4,821 values passes the IBAN check digits, and many have impossible lengths. The scanner masks all 120
(as card or address numbers), so nothing is exposed, but it never calls them IBAN. We did not add an "IBAN-shaped"
rule tuned to this test set. **Other weak spots:** names (single first names in columns with meaningless headers),
bank accounts in formats without a bank's shape (`ACCT-4929099273`), vehicle numbers that are really licence numbers
in Gretel's data, and dates of birth written in words (`22. Mai 1980`).

## 6. Calibration

The classifier's probability that a column is personal, against how often it is (`calibration_metrics.json`):
**expected calibration error 0.047, Brier score 0.046** over all 9,780 columns. Most columns sit at the extremes
(7,628 above 0.9, of which 99.8% are personal; 1,140 below 0.1). Below 0.9 the model is under-confident: columns
scored 0.1–0.5 are personal 52–71% of the time, and even below 0.1, 18% are. MaskGuard therefore never presents the score as a calibrated probability, and no score unmasks anything: a column
the scanner does not tag stays `UNREVIEWED`, masked for every role but admin until a person approves it.

## 7. Quality gates

`bench/evaluate.py` exits with status 1 unless the full scanner beats every simpler detector on macro-F1, protects
at least 90% of high-risk columns, and wrongly tags at most 20% of non-personal columns. All six gates pass.

## 8. Ablation

Each variant retrains the classifier with the same data, seed and settings, minus one group of features, and is scored
with detector C's decision on the same columns (`ablation_results.json`). The run first retrains with every feature
and checks it reproduces the shipped model: **identical** (largest probability difference 0.0).

| Variant | Features | Macro-F1 | PII protected | High-risk protected | False-positive rate |
|---|---|---|---|---|---|
| All features (= shipped model) | 99 | 0.878 | 92.1% | 95.0% | 4.5% |
| Without column-name features | 77 | 0.872 | 91.2% | 93.8% | 4.2% |
| Without regular-expression shapes | 77 | 0.837 | 90.8% | 95.2% | 12.8% |
| Without check-digit pass rates | 93 | 0.903 | 91.3% | 93.2% | 19.3% |
| Without shapes and check digits | 71 | 0.855 | 89.5% | 92.2% | 22.8% |
| Without value statistics | 50 | 0.784 | 80.9% | 92.9% | 13.4% |
| Column-name features only | 22 | 0.468 | 32.2% | 32.2% | 4.8% |

**What each part does.**
- **Value statistics carry the model** (lengths, digit runs, character mix, entropy): without them macro-F1 falls by
  0.09 and a fifth of personal columns are missed.
- **Column names barely matter** (−0.006): the model reads values, which is the point when names lie.
- **Shapes and check digits keep false alarms down.** Without check-digit features macro-F1 is *higher* (0.903),
  because several test sets contain identifiers invented by language models that fail their check digits, and a model
  blind to check digits labels those by shape. But the false-positive rate quadruples (4.5% → 19.3%) and high-risk
  recall drops. For masking, the shipped model's trade is the right one, and we keep it.

## 9. Speed

Per column with 20 values, on 300 columns, warm model, an idle 4-CPU machine (`latency_metrics.json`):

| Detector | Median | 95th percentile |
|---|---|---|
| A Header only | 0.003 ms | 0.004 ms |
| B Rules only | 0.69 ms | 1.24 ms |
| C LightGBM only | 1.58 ms | 2.12 ms |
| D Rules + LightGBM | 2.30 ms | 4.42 ms |
| E Full scanner | 2.27 ms | 3.26 ms |

A 1,000-column database is scanned in about 2–3 seconds of classification time, on a CPU, with no network calls.

## 10. Reproducing

1. `uv sync` in `FULL_CODE/`.
2. `uv run python training/hf/convert.py --download` and `uv run python training/realworld/build.py` (downloads into
   ignored caches).
3. For the bharat-pii-bench track: in a checkout of the benchmark, run `bench/bpb_export.py` (see `docs/EVALUATION.md`)
   and save the 200-value holdout export as `FULL_CODE/data/eval/bpb_holdout_200.json`. Without it, the evaluation
   runs on the five Hugging Face sets and says the track is missing.
4. `uv run python bench/evaluate.py --ablation`.

Seeds are fixed throughout: generator 7 (training) and 1007 (early stopping), column drawing 23, bootstrap 0, latency
sample 1. Training is reproducible to the last digit (§8).

## 11. Limitations

- All test sets are synthetic or LLM-generated; none is a real bank's data. The organisers' data is the closest and is
  reported separately because it is not blind.
- Columns are drawn from pooled spans, so each column is cleaner than a real one; `bench/stress.py` damages them 11
  ways real exports do (90.9% of personal columns still protected; version 1: 77.2%).
- Names inside free text and quasi-identifiers (combinations of harmless columns) are not covered by this task.
