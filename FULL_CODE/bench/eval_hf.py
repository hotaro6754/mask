"""Score the classifier on columns built from Hugging Face PII datasets (training/hf/convert.py). For each class:
exact kind (the model's own decision), protected (the full scanner tags the column, so it is masked), and for
non-personal columns the false-tag rate. Broken down by header condition: truthful, obfuscated, misleading.

    python bench/eval_hf.py training/hf/cache/gretelen_test.json [...] [--model DIR] [--out FILE]
"""

import argparse
import collections
import json
import os
import sys
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from maskguard import scanner
from maskguard.ml import model as M


def score(cols):
    per = collections.defaultdict(lambda: {"n": 0, "kind": 0, "protected": 0})
    cond = collections.defaultdict(lambda: {"n": 0, "protected": 0})
    for c in cols:
        d = M.decide(c["header"], c["values"])
        r = scanner.classify_column(c["header"], c["values"])
        tagged = bool(r and r.get("tag") not in (None, "PUBLIC"))
        p = per[c["label"]]
        p["n"] += 1
        if c["label"] == "none":
            p["kind"] += not (d["kind"] and d["kind"] != "amount")
            p["protected"] += tagged  # here: a false tag
        else:
            p["kind"] += d["kind"] == c["label"]
            p["protected"] += tagged
            cond[c["condition"]]["n"] += 1
            cond[c["condition"]]["protected"] += tagged
    pii = [k for k in per if k != "none"]
    n_pii = sum(per[k]["n"] for k in pii)
    out = {
        "pii_columns": n_pii,
        "kind_accuracy": round(sum(per[k]["kind"] for k in pii) / max(1, n_pii), 4),
        "protected_rate": round(sum(per[k]["protected"] for k in pii) / max(1, n_pii), 4),
        "missed_pii_columns": n_pii - sum(per[k]["protected"] for k in pii),
        "by_condition_protected": {k: round(v["protected"] / v["n"], 4) for k, v in sorted(cond.items())},
        "per_class": {
            k: {"n": v["n"], "kind": round(v["kind"] / v["n"], 3), "protected": round(v["protected"] / v["n"], 3)}
            for k, v in sorted(per.items())
        },
    }
    if "none" in per:
        out["non_personal_false_tag_rate"] = round(per["none"]["protected"] / per["none"]["n"], 4)
    return out


def run(files, model_dir=None):
    if model_dir and model_dir != "shipped":
        M.Classifier._instance = M.Classifier(os.path.join(model_dir, "pii_lgbm.txt.gz"))
    elif model_dir == "shipped":
        M.Classifier._instance = None
    return {
        os.path.basename(f).replace(".json", ""): score(json.loads(Path(f).read_text(encoding="utf-8"))) for f in files
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--model")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = run(a.files, a.model)
    for name, r in res.items():
        print(
            f"{name:16} protected {r['protected_rate']:.3f} (missed {r['missed_pii_columns']:4} of {r['pii_columns']:4})  "
            f"kind {r['kind_accuracy']:.3f}  t/o/m {r['by_condition_protected']}  "
            f"false-tag {r.get('non_personal_false_tag_rate', '-')}"
        )
        weak = {k: v for k, v in r["per_class"].items() if k != "none" and v["protected"] < 0.95}
        if weak:
            print(f"{'':16} weak: {weak}")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
