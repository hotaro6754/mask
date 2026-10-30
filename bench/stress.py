"""Stress test: does the scanner still protect PII columns when the data is messy the way production data is?

Takes test columns the model never trained on (the Hugging Face test sets from training/hf/convert.py and the
bharat-pii-bench holdout) and damages each one in a fixed way before scanning it:

    clean          as is
    placeholders   80% of values are text placeholders for missing data ("", "NULL", "N/A", "-" ...)
    tiny           only 3 values
    mixed          30% of values replaced by values of an unrelated non-personal column
    case_space     random upper/lower case, leading and trailing spaces, tabs
    reformat       digits regrouped with spaces, dashes, dots or brackets; "+91 " on phone-like values
    half_masked    half the values already masked by a legacy system ("XXXXXX1234"), half still real
    numbers        digit-only values handed over as Python ints, as a BIGINT column returns them
    quoted         values wrapped in quotes, a CSV import artefact
    nbsp           non-breaking spaces instead of spaces, as pasted from spreadsheets
    low_card       only 2 distinct values, repeated

Reports, per damage: share of PII columns still protected (tagged, so masked) and share of non-personal columns
falsely tagged. A column with any real PII left is a PII column.

    uv run python bench/stress.py training/hf/cache/*_test.json --bpb bpb_holdout_200.json [--model DIR] [--out FILE]
"""
import argparse, collections, json, os, random, re, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from maskguard.ml import model as M  # noqa: E402
from maskguard import scanner  # noqa: E402

PLACEHOLDERS = ["", "NULL", "null", "N/A", "n/a", "NA", "-", "None", "nan", "  ", "#N/A", "0"]
PER_CLASS = 40  # columns per (dataset, class)


GROUPS = {6: [(3, 3)], 9: [(3, 2, 4)], 10: [(5, 5), (3, 3, 4)], 12: [(4, 4, 4)], 16: [(4, 4, 4, 4)]}


def _regroup(v, rng):
    """Write a digits-only value the way people also write it: PIN 530 017, SSN 123 45 6789, phone +91 98765 43210,
    Aadhaar 1234 5678 9012, card 4111-1111-1111-1111. Values with letters are left alone."""
    digits = re.sub(r"[\s\-.()+]", "", v)
    if not digits.isdigit() or len(digits) not in GROUPS:
        return v
    if len(digits) == 10 and rng.random() < 0.5:
        return rng.choice(["+91 ", "+91-", "0"]) + digits[:5] + rng.choice([" ", ""]) + digits[5:]
    sep, parts, i = rng.choice([" ", "-"]), [], 0
    for g in rng.choice(GROUPS[len(digits)]):
        parts.append(digits[i:i + g])
        i += g
    return sep.join(parts)


def damage(name, values, rng, filler):
    v = [str(x) for x in values]
    if name == "clean":
        return v
    if name == "placeholders":
        return [rng.choice(PLACEHOLDERS) if rng.random() < 0.8 else x for x in v]
    if name == "tiny":
        return v[:3]
    if name == "mixed":
        return [rng.choice(filler) if filler and rng.random() < 0.3 else x for x in v]
    if name == "case_space":
        return [rng.choice([str.upper, str.lower, str.title, str])(x) + rng.choice(["", " ", "  ", "\t"]) for x in v]
    if name == "reformat":
        return [_regroup(x, rng) for x in v]
    if name == "half_masked":
        return [("X" * max(0, len(x) - 4) + x[-4:]) if rng.random() < 0.5 else x for x in v]
    if name == "numbers":
        return [int(x) if x.isdigit() and not x.startswith("0") else x for x in v]
    if name == "quoted":
        return [f'"{x}"' if rng.random() < 0.7 else f"'{x}'" for x in v]
    if name == "nbsp":
        return [x.replace(" ", " ") for x in v]
    if name == "low_card":
        two = v[:2] if len(set(v[:2])) == 2 else list(dict.fromkeys(v))[:2]
        return [rng.choice(two) for _ in v]
    raise ValueError(name)


DAMAGES = ["clean", "placeholders", "tiny", "mixed", "case_space", "reformat", "half_masked", "numbers", "quoted",
           "nbsp", "low_card"]


def load(files, bpb, rng):
    cols = []
    for f in files:
        by = collections.defaultdict(list)
        for c in json.load(open(f)):
            by[c["label"]].append(c)
        for label, cs in sorted(by.items()):
            rng.shuffle(cs)
            for c in cs[:PER_CLASS]:
                cols.append({"set": os.path.basename(f).replace("_test.json", ""), "header": c["header"],
                             "values": c["values"], "pii": label != "none", "label": label})
    if bpb:
        rows = json.load(open(bpb))
        by = collections.defaultdict(list)
        for r in rows:
            label = "none" if r["set"] == "hardneg" else r["label"]
            by[label].append(r)
        for label, rs in sorted(by.items()):
            rng.shuffle(rs)
            for r in rs[:PER_CLASS]:
                vals = [v for v in r["values"] if v is not None and str(v).strip()][:60]
                cols.append({"set": "bharat", "header": r["name"], "values": vals, "pii": label not in ("none", "NONE"),
                             "label": label})
    return cols


def tagged(header, values):
    sample = [x for x in values if x is not None]  # the scanner reads non-NULL values, as backend.sample does
    r = scanner.classify_column(header, sample)
    return bool(r and r.get("tag") not in (None, "PUBLIC"))


def run(cols, rng, damages=DAMAGES):
    filler = [str(v) for c in cols if not c["pii"] for v in c["values"]]
    out, misses = {}, collections.defaultdict(collections.Counter)
    for d in damages:
        t0 = time.perf_counter()
        n = collections.Counter()
        for c in cols:
            vals = damage(d, c["values"], rng, filler)
            t = tagged(c["header"], vals)
            key = "pii" if c["pii"] else "none"
            n[key] += 1
            n[key + "_tagged"] += t
            if c["pii"] and not t:
                misses[d][f"{c['set']}/{c['label']}"] += 1
        out[d] = {"pii_columns": n["pii"], "protected": round(n["pii_tagged"] / max(1, n["pii"]), 4),
                  "missed": n["pii"] - n["pii_tagged"], "non_personal_columns": n["none"],
                  "false_tag_rate": round(n["none_tagged"] / max(1, n["none"]), 4),
                  "ms_per_column": round((time.perf_counter() - t0) * 1000 / len(cols), 2),
                  "top_misses": dict(misses[d].most_common(6))}
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--bpb", help="bharat-pii-bench holdout export (bench/bpb_export.py)")
    ap.add_argument("--model")
    ap.add_argument("--only", help="comma-separated damages")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.model:
        M.Classifier._instance = M.Classifier(os.path.join(a.model, "pii_lgbm.txt.gz"))
    cols = load(a.files, a.bpb, random.Random(5))
    damages = a.only.split(",") if a.only else DAMAGES
    res = run(cols, random.Random(11), damages)
    print(f"{len(cols)} columns ({sum(c['pii'] for c in cols)} PII)")
    for d, r in res.items():
        print(f"{d:13} protected {r['protected']:.3f} (missed {r['missed']:4})  false-tag {r['false_tag_rate']:.3f}  "
              f"{r['ms_per_column']:5.1f} ms  {r['top_misses']}")
    if a.out:
        json.dump({"columns": len(cols), "results": res}, open(a.out, "w"), indent=1)
