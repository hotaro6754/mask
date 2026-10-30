"""One command for the PII discovery evaluation: five detectors on the same held-out columns, with per-class metrics,
confusion matrices, calibration, latency, a leakage check, a dataset manifest and (optionally) a feature ablation.

    uv run python bench/evaluate.py                    # every test set that is present (see below)
    uv run python bench/evaluate.py --ablation         # also retrain the classifier with feature groups removed
    uv run python bench/evaluate.py --out docs/eval    # where the JSON results go (default)

Test sets (none were used for training or for choosing the model; see docs/AI_EVALUATION.md):
    training/hf/cache/{gretelen,urchade,openpii,indiapii,ylemis}_test.json   python training/hf/convert.py --download
    data/eval/bpb_holdout_200.json   bharat-pii-bench holdout (seeds 301-360, hard negatives 777), bench/bpb_export.py
The organisers' Saffron Bank data is not used here: it was seen while fixing the scanner, so it is not a blind test.

Exit status: 0 when every quality gate passes, 1 when a gate fails, 2 when no test set is present.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import statistics
import sys
import time
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path

import numpy as np
import yaml
from sklearn.metrics import precision_recall_fscore_support

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(ROOT, "src"), ROOT, os.path.join(ROOT, "training")]
from bench.baselines import DETECTORS, NOT_PII
from bench.eval_scanner import TO_LABEL
from maskguard import __version__
from maskguard.ml import model as M
from maskguard.ml.features import FEATURE_NAMES, column_features
from maskguard.scanner import KIND_TAG

HF_TEST_SETS = ["gretelen", "urchade", "openpii", "indiapii", "ylemis"]
BPB_DEFAULT = os.path.join(ROOT, "data", "eval", "bpb_holdout_200.json")
FROM_LABEL = {label: kind for kind, label in TO_LABEL.items()} | {"NONE": "none"}
HIGH_RISK = {k for k, tag in KIND_TAG.items() if tag in ("PII_HIGH", "FINANCIAL_CONFIDENTIAL")}
FEATURE_GROUPS = {
    "header": [f for f in FEATURE_NAMES if f.startswith("hdr_")],
    "regex_shape": [f for f in FEATURE_NAMES if f.startswith("pat_")],
    "checksum": [f for f in FEATURE_NAMES if f.startswith("val_")],
}
FEATURE_GROUPS["value_statistics"] = [f for f in FEATURE_NAMES if not any(f in g for g in FEATURE_GROUPS.values())]
# Quality gates: the production scanner must beat every simpler detector on macro-F1 and protect high-risk columns.
GATES = {"min_high_risk_recall": 0.90, "max_false_positive_rate": 0.20}


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_test_columns(bpb_path: str, n_values: int) -> tuple[list[dict], dict]:
    """Every present test set as columns {set, header, values, kind, condition}; kind "none" means not personal."""
    cols, sets = [], {}
    for name in HF_TEST_SETS:
        path = os.path.join(ROOT, "training", "hf", "cache", f"{name}_test.json")
        if not os.path.exists(path):
            sets[name] = "missing: python training/hf/convert.py --download"
            continue
        part = [
            {
                "set": name,
                "header": c["header"],
                "values": c["values"][:n_values],
                "kind": c["label"],
                "condition": c["condition"],
            }
            for c in load_json(path)
        ]
        cols += part
        sets[name] = f"{len(part)} columns"
    if os.path.exists(bpb_path):
        part = [
            {
                "set": "bharat_holdout",
                "header": r["name"],
                "kind": FROM_LABEL[r["label"]],
                "values": [v for v in r["values"] if v is not None and str(v).strip()][:n_values],
                "condition": r.get("condition") or "hard_negative",
            }
            for r in load_json(bpb_path)
        ]
        cols += part
        sets["bharat_holdout"] = f"{len(part)} columns"
    else:
        sets["bharat_holdout"] = "missing: bench/bpb_export.py in the benchmark's checkout, saved to data/eval/"
    return cols, sets


def scores(truth: Sequence[str], pred: Sequence[str]) -> dict:
    """Kind-level and protection-level metrics. pred holds a kind, "none", or a kind outside the label set."""
    labels = sorted(set(truth))
    pred = [p if p in labels or p == "none" else "other_pii" for p in pred]
    p, r, f, s = precision_recall_fscore_support(truth, pred, labels=labels, zero_division=0)
    weighted = float(np.average(f, weights=s)) if s.sum() else 0.0
    is_t = np.array([t != "none" for t in truth])
    is_p = np.array([x != "none" for x in pred])
    high = np.array([t in HIGH_RISK for t in truth])
    out = {
        "columns": len(truth),
        "accuracy": round(float(np.mean([a == b for a, b in zip(truth, pred, strict=False)])), 4),
        "macro_precision": round(float(p.mean()), 4),
        "macro_recall": round(float(r.mean()), 4),
        "macro_f1": round(float(f.mean()), 4),
        "weighted_f1": round(weighted, 4),
        "protection_recall": round(float(is_p[is_t].mean()), 4) if is_t.any() else None,
        "false_negative_rate": round(float(1 - is_p[is_t].mean()), 4) if is_t.any() else None,
        "false_positive_rate": round(float(is_p[~is_t].mean()), 4) if (~is_t).any() else None,
        "high_risk_recall": round(float(is_p[high].mean()), 4) if high.any() else None,
        "per_class": {
            lab: {
                "precision": round(float(a), 4),
                "recall": round(float(b), 4),
                "f1": round(float(c), 4),
                "support": int(d),
            }
            for lab, a, b, c, d in zip(labels, p, r, f, s, strict=False)
        },
    }
    return out


def bootstrap_macro_f1(truth: list[str], pred: list[str], n: int = 200, seed: int = 0) -> list[float]:
    rng, idx = random.Random(seed), range(len(truth))
    vals = []
    for _ in range(n):
        pick = [rng.choice(idx) for _ in idx]
        vals.append(scores([truth[i] for i in pick], [pred[i] for i in pick])["macro_f1"])
    vals.sort()
    return [round(vals[int(0.025 * n)], 4), round(vals[int(0.975 * n) - 1], 4)]


def confusion(truth: Sequence[str], pred: Sequence[str]) -> dict:
    m: dict[str, Counter] = defaultdict(Counter)
    for t, p in zip(truth, pred, strict=False):
        m[t][p if p in set(truth) or p == "none" else "other_pii"] += 1
    return {t: dict(sorted(c.items())) for t, c in sorted(m.items())}


def p_personal(probs: np.ndarray) -> float:
    return float(1.0 - sum(probs[M.KINDS.index(k)] for k in ("none", "free_text", "amount")))


def calibration(p: Sequence[float], y: Sequence[bool], bins: int = 10) -> dict:
    p_arr, y_arr = np.asarray(p), np.asarray(y, dtype=float)
    table, ece = [], 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        m = (p_arr >= lo) & ((p_arr < hi) if b < bins - 1 else (p_arr <= hi))
        if m.any():
            ece += m.mean() * abs(p_arr[m].mean() - y_arr[m].mean())
            table.append(
                {
                    "bin": f"{lo:.1f}-{hi:.1f}",
                    "columns": int(m.sum()),
                    "mean_predicted": round(float(p_arr[m].mean()), 4),
                    "observed_personal": round(float(y_arr[m].mean()), 4),
                }
            )
    return {
        "columns": len(p_arr),
        "ece": round(float(ece), 4),
        "brier": round(float(((p_arr - y_arr) ** 2).mean()), 4),
        "reliability": table,
    }


def latency(cols: list[dict], sample: int = 300) -> dict:
    """Milliseconds per column for each detector, on the same columns (a warm model; one process)."""
    pick = random.Random(1).sample(cols, min(sample, len(cols)))
    out = {}
    for name, fn in DETECTORS.items():
        fn(pick[0]["header"], pick[0]["values"])  # warm-up: loads the model once
        ms = []
        for c in pick:
            t0 = time.perf_counter()
            fn(c["header"], c["values"])
            ms.append((time.perf_counter() - t0) * 1000)
        ms.sort()
        out[name] = {
            "p50_ms": round(statistics.median(ms), 3),
            "p95_ms": round(ms[int(0.95 * len(ms)) - 1], 3),
            "mean_ms": round(statistics.fmean(ms), 3),
        }
    return out


def evaluate_detectors(cols: list[dict]) -> tuple[dict, dict, dict, dict]:
    """Predictions of every detector, metrics per test set and pooled, confusion matrices and calibration."""
    probs = [M.Classifier.get().proba(c["header"], c["values"]) for c in cols]
    preds: dict[str, list[str]] = {}
    for name, fn in DETECTORS.items():
        if name == "C_lightgbm_only":  # same decision as baselines.lightgbm_only, from the probabilities above
            ks = [M.KINDS[int(pr.argmax())] if pr.max() >= 0.5 else None for pr in probs]
        elif name == "D_rules_lightgbm":
            ks = [M.decide(c["header"], c["values"], probs=pr)["kind"] for c, pr in zip(cols, probs, strict=False)]
        else:
            ks = [fn(c["header"], c["values"]) for c in cols]
        preds[name] = ["none" if k in NOT_PII else k for k in ks]
    truth = [c["kind"] for c in cols]
    results: dict = {}
    for name, pred in preds.items():
        per_set = {}
        for s in sorted({c["set"] for c in cols}):
            idx = [i for i, c in enumerate(cols) if c["set"] == s]
            per_set[s] = scores([truth[i] for i in idx], [pred[i] for i in idx])
        pooled = scores(truth, pred)
        pooled["macro_f1_95ci"] = bootstrap_macro_f1(truth, pred)
        results[name] = {"pooled": pooled, "per_test_set": per_set}
    confusions = {name: confusion(truth, pred) for name, pred in preds.items()}
    cal = calibration([p_personal(pr) for pr in probs], [t != "none" for t in truth])
    return results, confusions, cal, preds


# ---------------------------------------------------------------- feature ablation (retrains the classifier)


def block_features(cols: list[dict]) -> list[np.ndarray]:
    return [np.stack([column_features(c["header"], b) for b in M.blocks(c["values"])]) for c in cols]


def ablation(cols: list[dict]) -> dict:
    """Retrain with each feature group removed (same data, seed and settings as the shipped model) and score the
    classifier's own decision (detector C) on the test columns. "all_features" also checks that training reproduces."""
    from train_candidate import V2_EXTRA, featurize, train_booster, training_columns

    missing = [f for f in V2_EXTRA if not os.path.exists(f)]
    if missing or not os.path.exists(os.path.join(ROOT, "training", "realworld", "cache", "train.json")):
        return {
            "status": "not run: training caches missing (training/realworld/build.py, training/hf/convert.py --download)"
        }
    train, valid, counts = training_columns(extra=V2_EXTRA)
    X, Xv = featurize(train), featurize(valid)
    y = np.array([M.KINDS.index(c[2]) for c in train])
    w = np.array([c[3] for c in train])
    yv = np.array([M.KINDS.index(k) for _, _, k in valid])
    test_blocks, truth = block_features(cols), [c["kind"] for c in cols]
    variants = {"all_features": []} | {f"without_{g}": [g] for g in FEATURE_GROUPS}
    variants["without_regex_shape_and_checksum"] = ["regex_shape", "checksum"]
    variants["header_only"] = ["regex_shape", "checksum", "value_statistics"]
    out = {"training_columns": counts, "groups": {g: len(f) for g, f in FEATURE_GROUPS.items()}, "variants": {}}
    for name, drop in variants.items():
        keep = [i for i, f in enumerate(FEATURE_NAMES) if not any(f in FEATURE_GROUPS[g] for g in drop)]
        booster = train_booster(X[:, keep], y, w, Xv[:, keep], yv, feature_names=[FEATURE_NAMES[i] for i in keep])
        pred = []
        for blocks in test_blocks:
            pr = booster.predict(blocks[:, keep], num_iteration=booster.best_iteration).mean(0)
            k = M.KINDS[int(pr.argmax())]
            pred.append("none" if k in NOT_PII or pr.max() < 0.5 else k)
        s = scores(truth, pred)
        out["variants"][name] = {
            "features": len(keep),
            "best_iteration": booster.best_iteration,
            **{
                k: s[k]
                for k in ("macro_f1", "accuracy", "protection_recall", "false_positive_rate", "high_risk_recall")
            },
        }
        if name == "all_features":  # retraining with the shipped settings must give the shipped model's answers
            shipped = M.Classifier.get().booster
            diff = max(
                float(
                    np.abs(
                        booster.predict(b, num_iteration=booster.best_iteration).mean(0) - shipped.predict(b).mean(0)
                    ).max()
                )
                for b in test_blocks
            )
            out["reproduces_shipped_model"] = {"max_probability_difference": round(diff, 6), "identical": diff < 1e-9}
    return out


# ---------------------------------------------------------------- provenance and leakage


def dataset_manifest() -> dict:
    hf = yaml.safe_load(Path(os.path.join(ROOT, "training", "hf", "sources.yaml")).read_text(encoding="utf-8"))[
        "datasets"
    ]
    rw = yaml.safe_load(Path(os.path.join(ROOT, "training", "realworld", "sources.yaml")).read_text(encoding="utf-8"))[
        "sources"
    ]
    entries = [
        {
            "name": "maskguard synthetic generator",
            "source": "src/maskguard/ml/synth.py",
            "licence": "this project",
            "synthetic": True,
            "role": "train (seed 7) and early stopping (seed 1007)",
        }
    ]
    for name, s in hf.items():
        entries.append(
            {
                "name": name,
                "source": f"https://huggingface.co/datasets/{s['id']}",
                "licence": s["licence"],
                "synthetic": True,
                "role": s["role"],
                "label_map": s["map"],
                "transformation": "annotated spans pooled per label, drawn into columns of 20-60 values "
                "(training/hf/convert.py, seed 23); headers truthful, generic or misleading",
            }
        )
    for s in rw:
        entries.append(
            {
                "name": f"datasets/{s['repo']}",
                "source": f"https://github.com/datasets/{s['repo']}/blob/main/{s['file']}",
                "licence": s["licence"],
                "synthetic": False,
                "role": s["split"],
                "columns": s["columns"],
            }
        )
    entries.append(
        {
            "name": "bharat-pii-bench T2",
            "source": "https://github.com/dnanatihor/bharat-pii-bench",
            "licence": "Apache-2.0",
            "synthetic": True,
            "role": "model selection (seeds 1-60, 101-160); test (seeds 301-360, hard negatives 777)",
        }
    )
    entries.append(
        {
            "name": "Saffron Bank (organisers' pack)",
            "licence": "CC BY 4.0",
            "synthetic": True,
            "role": "validation after fixes: not blind, never committed (kept in FULL_CODE/data/)",
        }
    )
    return {"datasets": entries}


def leakage_check(cols: list[dict]) -> dict:
    """Verbatim overlap between test values and training values, and test columns identical to a training column."""
    from train_candidate import V2_EXTRA, training_columns

    if any(not os.path.exists(f) for f in V2_EXTRA):
        return {"status": "not run: training caches missing"}
    train, _, _ = training_columns(extra=V2_EXTRA)
    seen = {str(v) for _, vals, _, _ in train for v in vals}
    train_cols = {tuple(sorted(map(str, vals))) for _, vals, _, _ in train}
    out = {}
    for s in sorted({c["set"] for c in cols}):
        part = [c for c in cols if c["set"] == s]
        vals = [str(v) for c in part for v in c["values"]]
        mostly_seen = sum(np.mean([str(v) in seen for v in c["values"]]) > 0.5 for c in part if c["values"])
        out[s] = {
            "test_values_seen_in_training": round(sum(v in seen for v in vals) / max(1, len(vals)), 4),
            "columns_mostly_seen": int(mostly_seen),
            "columns_identical_to_a_training_column": sum(
                tuple(sorted(map(str, c["values"]))) in train_cols for c in part
            ),
        }
    out["note"] = (
        "Common values (first names, 'United States') legitimately recur across datasets; an identical "
        "column would indicate leakage. Training and test sets come from different sources."
    )
    return out


def gates(results: dict) -> dict:
    full = results["E_full_scanner"]["pooled"]
    checks = {
        f"E beats {name} on macro-F1": full["macro_f1"] > r["pooled"]["macro_f1"]
        for name, r in results.items()
        if name != "E_full_scanner"
    }
    checks[f"high-risk recall >= {GATES['min_high_risk_recall']}"] = (full["high_risk_recall"] or 0) >= GATES[
        "min_high_risk_recall"
    ]
    checks[f"false-positive rate <= {GATES['max_false_positive_rate']}"] = (full["false_positive_rate"] or 0) <= GATES[
        "max_false_positive_rate"
    ]
    return checks


def write(out_dir: str, name: str, obj) -> None:
    with open(os.path.join(out_dir, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default=os.path.join(ROOT, "docs", "eval"))
    ap.add_argument("--bpb", default=BPB_DEFAULT, help="bharat-pii-bench holdout export")
    ap.add_argument("--values", type=int, default=20, help="values per column (the scanner's training block size)")
    ap.add_argument("--ablation", action="store_true", help="retrain with feature groups removed (a few minutes)")
    a = ap.parse_args()
    cols, sets = load_test_columns(a.bpb, a.values)
    print("test sets:", json.dumps(sets))
    if not cols:
        print("no test set present", file=sys.stderr)
        return 2
    t0 = time.time()
    results, confusions, cal, _ = evaluate_detectors(cols)
    env = {
        "maskguard": __version__,
        "model": json.loads(Path(M.META_PATH).read_text(encoding="utf-8")).get("version"),
        "python": platform.python_version(),
        "machine": f"{platform.system()} {platform.machine()}, {os.cpu_count()} CPUs",
        "values_per_column": a.values,
        "test_sets": sets,
        "seconds": round(time.time() - t0, 1),
    }
    checks = gates(results)
    os.makedirs(a.out, exist_ok=True)
    write(
        a.out,
        "baseline_comparison.json",
        {
            "environment": env,
            "gates": checks,
            "detectors": {
                n: {k: v for k, v in r["pooled"].items() if k != "per_class"}
                | {
                    "per_test_set": {
                        s: {k: v for k, v in m.items() if k != "per_class"} for s, m in r["per_test_set"].items()
                    }
                }
                for n, r in results.items()
            },
        },
    )
    write(a.out, "per_class_metrics.json", {n: r["pooled"]["per_class"] for n, r in results.items()})
    write(a.out, "confusion_matrix.json", {"rows_truth_columns_predicted": confusions})
    write(
        a.out,
        "calibration_metrics.json",
        {"probability": "P(personal) = 1 - P(none) - P(free_text) - P(amount)", **cal},
    )
    write(a.out, "latency_metrics.json", {"environment": env, "detectors": latency(cols)})
    write(a.out, "dataset_manifest.json", dataset_manifest())
    write(a.out, "leakage_check.json", leakage_check(cols))
    if a.ablation:
        write(a.out, "ablation_results.json", ablation(cols))
    for name, r in results.items():
        p = r["pooled"]
        print(
            f"{name:18} macro-F1 {p['macro_f1']:.3f} {p['macro_f1_95ci']}  protect {p['protection_recall']:.3f}  "
            f"high-risk {p['high_risk_recall']:.3f}  false-pos {p['false_positive_rate']:.3f}"
        )
    print(f"calibration: ECE {cal['ece']}  Brier {cal['brier']}")
    for check, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + check)
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
