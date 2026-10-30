"""Compare classifier models on the same data: bharat-pii-bench exports (development sets for decisions, the holdout
only once), the real-world test columns, and calibration (expected calibration error and Brier score on the
benchmark's misleading-name columns, PII-vs-not). A model is a directory holding pii_lgbm.txt.gz; "shipped" means
the model in the package.

    python bench/compare_models.py --models shipped,/tmp/cand --bpb dev1.json,dev2.json [--out FILE]
"""
import argparse, json, os, sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from maskguard.ml import model as M  # noqa: E402
import eval_realworld  # noqa: E402
from eval_sampling import part_a  # noqa: E402


def calibration(rows, n=20, bins=10):
    """Binary: probability that a column holds PII (1 - p(none) - p(amount) - p(free_text)) vs the truth."""
    t2 = [r for r in rows if r["set"] == "t2" and r["condition"] == "misleading"] + [r for r in rows if r["set"] == "hardneg"]
    clf = M.Classifier.get()
    probs = clf.proba_many([(r["name"], [v for v in r["values"] if v not in (None, "")][:n]) for r in t2])
    k = clf.kinds
    nonpii = [k.index(x) for x in ("none", "amount", "free_text")]
    p = 1 - probs[:, nonpii].sum(1)
    y = np.array([r["set"] == "t2" and r["label"] != "NONE" for r in t2], dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    ece = 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi if hi < 1 else p <= hi)
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
    return {"columns": len(t2), "ece": round(float(ece), 4), "brier": round(float(((p - y) ** 2).mean()), 4)}


def evaluate(model_dir, bpb_files, sizes):
    M.Classifier._instance = None if model_dir == "shipped" else M.Classifier(os.path.join(model_dir, "pii_lgbm.txt.gz"))
    out = {"realworld": eval_realworld.run()}
    for f in bpb_files:
        rows = json.load(open(f))
        out[os.path.basename(f)] = {"bharat": part_a(rows, sizes), "calibration": calibration(rows)}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", required=True)
    ap.add_argument("--bpb", required=True)
    ap.add_argument("--sizes", default="5,20")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = {m: evaluate(m, a.bpb.split(","), [int(x) for x in a.sizes.split(",")]) for m in a.models.split(",")}
    if a.out:
        json.dump(res, open(a.out, "w"), indent=1)
    for m, r in res.items():
        print(f"\n### {m}\nreal-world: model false PII {r['realworld']['model_false_pii_rate']:.2%}, "
              f"scanner tagged {r['realworld']['scanner_tagged_rate']:.2%}")
        for f in a.bpb.split(","):
            b = r[os.path.basename(f)]
            print(f"{os.path.basename(f)} calibration {b['calibration']}")
            for n, d in b["bharat"]["by_sample_size"].items():
                for det in ("hybrid", "scanner"):
                    x = d[det]
                    print(f"  n={n:<3} {det:7} F1 t/o/m {x['macro_f1']['truthful']:.3f}/{x['macro_f1']['obfuscated']:.3f}/"
                          f"{x['macro_f1']['misleading']:.3f}  missed {x['missed_pii_columns']:3}  hard-neg tagged {x['hardneg_any_tag_rate']:.3f}")
