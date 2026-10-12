"""Score free-text redaction on bharat-pii-bench T3 sentences (export with bench/bpb_export_t3.py).

    uv run python bench/eval_textpii.py t3.json [--out docs/eval/textpii_t3.json]

For masking, what matters is whether each identifier ends up fully redacted, whatever label it gets, and how much
ordinary text is destroyed. So the headline metrics are:
  * redaction recall   - share of gold identifiers whose characters are all inside a redacted span
  * over-redaction     - share of non-identifier characters that were redacted
plus the benchmark's own strict metric (exact label + start + end) for reference.
"""
import argparse, json
from collections import defaultdict

from maskguard.textpii import find

TO_BPB = {"EMAIL": "EMAIL", "UPI": "IN_UPI_ID", "GSTIN": "IN_GSTIN", "PAN": "IN_PAN", "IFSC": "IN_IFSC",
          "VOTER_ID": "IN_VOTER_ID", "PASSPORT": "IN_PASSPORT", "VEHICLE": "IN_VEHICLE_REG", "PHONE": "IN_MOBILE",
          "AADHAAR": "IN_AADHAAR", "NUMBER": "IN_BANK_ACCOUNT", "PIN": "IN_PINCODE", "DATE": "DATE_OF_BIRTH"}


def score(rows, pred_key):
    covered, total, by_label = 0, 0, defaultdict(lambda: [0, 0])
    over_chars, clean_chars = 0, 0
    tp = fp = fn = 0
    for r in rows:
        pred = r[pred_key]
        mask = [False] * len(r["text"])
        for _, a, b in pred:
            for i in range(a, b):
                mask[i] = True
        gold_mask = [False] * len(r["text"])
        for label, a, b in r["gold"]:
            full = all(mask[a:b])
            covered += full; total += 1
            by_label[label][0] += full; by_label[label][1] += 1
            for i in range(a, b):
                gold_mask[i] = True
        over_chars += sum(m and not g for m, g in zip(mask, gold_mask))
        clean_chars += sum(not g for g in gold_mask)
        g = {tuple(x) for x in r["gold"]}
        p = {tuple(x) for x in pred}
        tp += len(g & p); fp += len(p - g); fn += len(g - p)
    return {"redaction_recall": round(covered / total, 4),
            "over_redaction": round(over_chars / max(clean_chars, 1), 4),
            "strict_precision": round(tp / max(tp + fp, 1), 4), "strict_recall": round(tp / max(tp + fn, 1), 4),
            "per_label_redaction_recall": {k: round(v[0] / v[1], 3) for k, v in sorted(by_label.items())}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sentences")
    ap.add_argument("--out")
    args = ap.parse_args()
    rows = json.load(open(args.sentences))
    for r in rows:
        r["maskguard"] = [[TO_BPB.get(label, label), a, b] for label, a, b, _ in find(r["text"])]
    report = {"sentences": len(rows), "detectors": {}}
    for det in ("baseline", "maskguard"):
        res = score(rows, det)
        res["by_language"] = {lang: score([r for r in rows if r["language"] == lang], det)["redaction_recall"]
                              for lang in sorted({r["language"] for r in rows})}
        report["detectors"]["bpb regex_checksum" if det == "baseline" else "MaskGuard text redactor"] = res
    for name, res in report["detectors"].items():
        print(f"{name:26} redaction recall {res['redaction_recall']:.3f}  over-redaction {res['over_redaction']:.3f}  "
              f"strict P/R {res['strict_precision']:.3f}/{res['strict_recall']:.3f}  by language {res['by_language']}")
        print("   per label:", res["per_label_redaction_recall"])
    if args.out:
        json.dump(report, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    main()
