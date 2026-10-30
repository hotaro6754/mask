"""False alarms on real-world, non-personal columns from sources the model never trained on
(training/realworld/sources.yaml, split: test). Scores the model's own decision and the full production scanner.

    python training/realworld/build.py && python bench/eval_realworld.py [--model PATH] [--out FILE]
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


def run(model_path=None):
    if model_path:
        M.Classifier._instance = M.Classifier(model_path)
    test = json.loads(
        Path(os.path.join(HERE, "..", "training", "realworld", "cache", "test.json")).read_text(encoding="utf-8")
    )
    by_src = collections.defaultdict(lambda: [0, 0])
    tagged_ml = tagged_scan = 0
    wrong_kind = collections.Counter()
    for e in test:
        d = M.decide(e["header"], e["values"])
        if d["kind"] and d["kind"] not in ("amount",):
            tagged_ml += 1
            wrong_kind[d["kind"]] += 1
        r = scanner.classify_column(e["header"], e["values"])
        hit = bool(r and r.get("tag") not in (None, "PUBLIC"))
        tagged_scan += hit
        by_src[e["source"].split("#")[0]][0] += hit
        by_src[e["source"].split("#")[0]][1] += 1
    n = len(test)
    return {
        "columns": n,
        "model_false_pii": tagged_ml,
        "model_false_pii_rate": round(tagged_ml / n, 4),
        "scanner_tagged": tagged_scan,
        "scanner_tagged_rate": round(tagged_scan / n, 4),
        "model_wrong_kinds": dict(wrong_kind.most_common()),
        "scanner_by_source": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_src.items())},
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--model")
    ap.add_argument("--out")
    a = ap.parse_args()
    res = run(a.model)
    print(json.dumps(res, indent=1))
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")
