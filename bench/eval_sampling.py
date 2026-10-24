"""How the scanner degrades with fewer sampled values per column, with per-label precision and recall.

    uv run python bench/eval_sampling.py bpb_holdout.json --out docs/eval/scanner_sampling.json

Part A: the bharat-pii-bench T2 holdout (seeds 301-360, never used for tuning; hard negatives from seed 777). The
export has 20 values per column, so it is scored at 5, 10 and 20 values. Detectors: the hybrid decision alone and
the full production scanner (classify_column: hybrid + value patterns + free text + the sparse band + header rules).
Part B: MaskGuard's own generator on a held-out seed, 200 values per column, scored at 5, 20, 50 and 200. It is the
distribution the model was trained on, so it shows the effect of sample size, not generalisation.
Values are read the way the scanner reads them: non-null values first (backend.sample skips NULLs).
"""
import argparse, json, random, time
from collections import Counter

from sklearn.metrics import f1_score, precision_recall_fscore_support

from maskguard.ml import synth
from maskguard.ml.model import decide
from maskguard.scanner import classify_column
from bench.eval_scanner import LABELS, label_of

GENERATOR_SEED = 9001  # training uses 7 and 1007 (validation); this seed appears nowhere else


def nonnull(values, n):
    return [v for v in values if v is not None and str(v).strip()][:n]


def per_label(truth, pred, labels):
    p, r, f, s = precision_recall_fscore_support(truth, pred, labels=labels, zero_division=0)
    return {l: {"precision": round(float(a), 3), "recall": round(float(b), 3), "f1": round(float(c), 3), "support": int(d)}
            for l, a, b, c, d in zip(labels, p, r, f, s)}


def part_a(rows, sizes):
    out = {}
    t2 = [r for r in rows if r["set"] == "t2"]
    hn = [r for r in rows if r["set"] == "hardneg"]
    for n in sizes:
        res = {}
        for det, fn in (("hybrid", lambda h, v: decide(h, v)["kind"]),
                        ("scanner", lambda h, v: (classify_column(h, v) or {}).get("kind"))):
            t0 = time.perf_counter()
            pred_t2 = [label_of(fn(r["name"], nonnull(r["values"], n))) for r in t2]
            pred_hn = [label_of(fn(r["name"], nonnull(r["values"], n))) for r in hn]
            # the scanner also tags kinds the benchmark has no label for (health, amount, free_text_pii ...): those
            # are masked, so for hard negatives count any tag at all as a false positive
            any_tag_hn = [fn(r["name"], nonnull(r["values"], n)) is not None for r in hn]
            ms = (time.perf_counter() - t0) * 1000 / (len(t2) + 2 * len(hn))
            truth = [r["label"] for r in t2]
            res[det] = {
                "macro_f1": {c: round(f1_score([t for t, r in zip(truth, t2) if r["condition"] == c],
                                               [p for p, r in zip(pred_t2, t2) if r["condition"] == c],
                                               labels=LABELS, average="macro", zero_division=0), 4)
                             for c in ("truthful", "obfuscated", "misleading")},
                "per_label_all_conditions": per_label(truth, pred_t2, LABELS),
                "hardneg_fp_rate_benchmark_labels": round(sum(p != "NONE" for p in pred_hn) / len(hn), 4),
                "hardneg_any_tag_rate": round(sum(any_tag_hn) / len(hn), 4),
                "hardneg_fp_by_variant": dict(Counter(r["variant"] for r, t in zip(hn, any_tag_hn) if t)),
                "missed_pii_columns": sum(t != "NONE" and p == "NONE" for t, p in zip(truth, pred_t2)),
                "ms_per_column": round(ms, 2),
            }
        out[n] = res
        print(f"A n={n:3}: " + "  ".join(f"{d} F1 t/o/m {r['macro_f1']['truthful']:.3f}/{r['macro_f1']['obfuscated']:.3f}/"
                                         f"{r['macro_f1']['misleading']:.3f} hn-any {r['hardneg_any_tag_rate']:.3f} "
                                         f"missed {r['missed_pii_columns']}" for d, r in res.items()))
    return {"columns_t2": len(t2), "columns_hardneg": len(hn), "by_sample_size": out}


class _Fixed(random.Random):
    """synth.make_column draws a column length with randint(20, 60); fix it so every column has 200 values."""
    def randint(self, a, b):
        return 200 if (a, b) == (20, 60) else super().randint(a, b)


def part_b(sizes, per_kind):
    r = _Fixed(GENERATOR_SEED)
    for loc in ("en_IN", "hi_IN", "en_US", "en_GB", "de_DE", "fr_FR", "nl_NL", "es_ES"):
        synth.fk(loc).seed_instance(GENERATOR_SEED)
    cols = [(*synth.make_column(r, k), k) for k in synth.KINDS for _ in range(per_kind * (3 if k == "none" else 1))]
    kinds = list(synth.KINDS)
    out = {}
    for n in sizes:
        truth = [k for _, _, k in cols]
        pred = [decide(h, nonnull(v, n))["kind"] or "none" for h, v, _ in cols]
        out[n] = {"macro_f1": round(f1_score(truth, pred, labels=kinds, average="macro", zero_division=0), 4),
                  "per_label": per_label(truth, pred, kinds),
                  "none_columns_tagged": round(sum(t == "none" and p != "none" for t, p in zip(truth, pred))
                                               / max(1, truth.count("none")), 4)}
        print(f"B n={n:3}: macro-F1 {out[n]['macro_f1']:.3f}  non-PII columns tagged {out[n]['none_columns_tagged']:.3f}")
    return {"generator_seed": GENERATOR_SEED, "columns": len(cols), "by_sample_size": out}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("columns", help="bench/bpb_export.py output (20 values per column)")
    ap.add_argument("--out")
    ap.add_argument("--per-kind", type=int, default=40)
    args = ap.parse_args()
    report = {"part_a_bharat_holdout": part_a(json.load(open(args.columns)), (5, 10, 20)),
              "part_b_own_generator_heldout_seed": part_b((5, 20, 50, 200), args.per_kind)}
    if args.out:
        json.dump(report, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    main()
