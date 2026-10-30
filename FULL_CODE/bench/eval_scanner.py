"""Score MaskGuard's scanners on columns exported from bharat-pii-bench (see docs/EVALUATION.md).

    uv run python bench/eval_scanner.py bpb_columns.json [--out docs/eval/scanner.json]

Compares, on identical columns: the benchmark's own baselines (regex_checksum, regex_checksum+names), MaskGuard's
v1 rules scanner, the ML model alone, and the hybrid scanner. Metric: macro-F1 over the benchmark's 16 labels,
per name condition (truthful / obfuscated / misleading), plus false-positive rate on hard-negative columns.
"""

import argparse
import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score

from maskguard.ml.model import Classifier, decide
from maskguard.scanner import classify_column_rules as v1_classify

TO_LABEL = {
    "aadhaar": "IN_AADHAAR",
    "pan": "IN_PAN",
    "gstin": "IN_GSTIN",
    "upi": "IN_UPI_ID",
    "phone": "IN_MOBILE",
    "pincode": "IN_PINCODE",
    "passport": "IN_PASSPORT",
    "voter_id": "IN_VOTER_ID",
    "ifsc": "IN_IFSC",
    "vehicle_reg": "IN_VEHICLE_REG",
    "bank_account": "IN_BANK_ACCOUNT",
    "name": "PERSON_NAME",
    "address": "POSTAL_ADDRESS",
    "email": "EMAIL",
    "dob": "DATE_OF_BIRTH",
}
LABELS = [*sorted(set(TO_LABEL.values())), "NONE"]


def label_of(kind):
    return TO_LABEL.get(kind, "NONE") if kind else "NONE"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("columns")
    ap.add_argument("--out")
    ap.add_argument("--max-values", type=int, default=0, help="keep only the first N values per column (harder)")
    args = ap.parse_args()
    rows = json.loads(Path(args.columns).read_text(encoding="utf-8"))
    if args.max_values:
        for r in rows:
            r["values"] = r["values"][: args.max_values]
    clf = Classifier.get()
    t0 = time.perf_counter()
    probs = clf.proba_many([(r["name"], r["values"]) for r in rows])
    ml_ms = (time.perf_counter() - t0) * 1000 / len(rows)
    preds = defaultdict(list)
    t0 = time.perf_counter()
    hybrid = [decide(r["name"], r["values"], p, clf.kinds) for r, p in zip(rows, probs, strict=False)]
    hy_ms = (time.perf_counter() - t0) * 1000 / len(rows) + ml_ms
    for r, p, h in zip(rows, probs, hybrid, strict=False):
        base = r["baseline5"] if args.max_values == 5 and "baseline5" in r else r["baseline"]
        preds["bpb regex_checksum"].append(base["regex_checksum"])
        preds["bpb regex_checksum+names"].append(base["regex_checksum+names"])
        v1 = v1_classify(r["name"], r["values"])
        preds["MaskGuard v1 rules"].append(label_of(v1["kind"] if v1 else None))
        preds["MaskGuard ML only"].append(label_of(clf.kinds[int(np.argmax(p))]))
        preds["MaskGuard hybrid"].append(label_of(h["kind"]))
    truth = [r["label"] for r in rows]
    report = {
        "columns": len(rows),
        "max_values": args.max_values or None,
        "ms_per_column": {"ml": round(ml_ms, 2), "hybrid": round(hy_ms, 2)},
        "results": {},
    }
    print(f"{'detector':28} {'truthful':>9} {'obfusc.':>9} {'mislead.':>9} {'hard-neg FP':>12}")
    for det, pr in preds.items():
        res = {}
        for cond in ("truthful", "obfuscated", "misleading"):
            idx = [i for i, r in enumerate(rows) if r["set"] == "t2" and r["condition"] == cond]
            res[cond] = round(
                f1_score(
                    [truth[i] for i in idx], [pr[i] for i in idx], labels=LABELS, average="macro", zero_division=0
                ),
                4,
            )
        hn = [i for i, r in enumerate(rows) if r["set"] == "hardneg"]
        res["hardneg_fp_rate"] = round(sum(pr[i] != "NONE" for i in hn) / len(hn), 4)
        res["hardneg_fp_by_variant"] = dict(Counter(rows[i]["variant"] for i in hn if pr[i] != "NONE"))
        report["results"][det] = res
        print(
            f"{det:28} {res['truthful']:9.4f} {res['obfuscated']:9.4f} {res['misleading']:9.4f} {res['hardneg_fp_rate']:12.4f}"
        )
    t2 = [i for i, r in enumerate(rows) if r["set"] == "t2" and r["condition"] == "obfuscated"]
    per = f1_score(
        [truth[i] for i in t2], [preds["MaskGuard hybrid"][i] for i in t2], labels=LABELS, average=None, zero_division=0
    )
    report["hybrid_per_label_f1_obfuscated"] = {lab: round(float(s), 3) for lab, s in zip(LABELS, per, strict=False)}
    bpb = f1_score(
        [truth[i] for i in t2],
        [preds["bpb regex_checksum"][i] for i in t2],
        labels=LABELS,
        average=None,
        zero_division=0,
    )
    report["bpb_per_label_f1_obfuscated"] = {lab: round(float(s), 3) for lab, s in zip(LABELS, bpb, strict=False)}
    errs = Counter((truth[i], preds["MaskGuard hybrid"][i]) for i in t2 if truth[i] != preds["MaskGuard hybrid"][i])
    report["hybrid_confusions_obfuscated"] = [f"{a} -> {b}: {n}" for (a, b), n in errs.most_common(10)]
    print("hybrid per-label (obfuscated):", report["hybrid_per_label_f1_obfuscated"])
    print("bpb per-label (obfuscated):   ", report["bpb_per_label_f1_obfuscated"])
    print("hybrid confusions:", report["hybrid_confusions_obfuscated"])
    print("hard-neg FP by variant:", {d: r["hardneg_fp_by_variant"] for d, r in report["results"].items()})
    print("ms/column:", report["ms_per_column"])
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
