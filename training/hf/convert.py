"""Turn the Hugging Face datasets in sources.yaml into classifier columns. Downloads go to training/hf/cache/ (not
in git). Output: cache/<dataset>_<split>.json, lists of {header, values, label, source, condition}.

    python training/hf/convert.py [--download]
"""
import argparse, ast, collections, json, os, random, re, sys, urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache")
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from maskguard.ml.synth import GENERIC, TRUTHFUL, UNRELATED  # noqa: E402

COLUMNS = {"train": 300, "dev": 120, "test": 120}  # columns per (dataset, class) at most


def path(name, key):
    return os.path.join(CACHE, name, key.replace("/", "_"))


def download(name, spec):
    for key in spec["files"].values():
        for lang in spec.get("languages", [None]):
            f = key.format(lang=lang) if lang else key
            dst = path(name, f)
            if os.path.exists(dst):
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            urllib.request.urlretrieve(f"https://huggingface.co/datasets/{spec['id']}/resolve/main/{f}", dst)


def spans(name, spec, split):
    """Yield (label, value) for every annotated span in the split."""
    import pandas as pd
    key = spec["files"][split]
    files = [key.format(lang=lang) for lang in spec["languages"]] if "languages" in spec else [key]
    for f in files:
        p = path(name, f)
        if name == "nemotron":
            for s in pd.read_parquet(p, columns=["spans"]).spans:
                for x in ast.literal_eval(s):
                    yield x["label"], x["text"]
        elif name == "gretelfin":
            df = pd.read_parquet(p, columns=["generated_text", "pii_spans"])
            for text, s in zip(df.generated_text, df.pii_spans):
                for x in json.loads(s):
                    yield x["label"], text[x["start"]:x["end"]]
        elif name == "gretelen":
            for s in pd.read_parquet(p, columns=["entities"]).entities:
                for x in ast.literal_eval(s):
                    for t in x["types"]:
                        yield t, x["entity"]
        elif name in ("indiapii", "ylemis"):
            for line in open(p, encoding="utf-8"):
                r = json.loads(line)
                for e in r["entities"]:
                    yield e.get("label") or e.get("type"), r["text"][e["start"]:e["end"]]
        elif name == "openpii":
            with open(p, encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if i >= spec.get("max_records", 10 ** 9):
                        break
                    for x in json.loads(line)["privacy_mask"]:
                        yield x["label"], x["value"]
        elif name == "urchade":
            for r in json.load(open(p, encoding="utf-8")):
                for a, b, lab in r.get("ner", []):
                    yield lab, detok(" ".join(r["tokenized_text"][a:b + 1]))


def detok(text):
    """urchade ships tokenised text ("jane . doe @ gmail . com"); rejoin the punctuation that tokens split."""
    return re.sub(r"\s*([.@_/\-+])\s*", r"\1", text)


def columns(name, spec, split, rng):
    pools = collections.defaultdict(list)
    for label, value in spans(name, spec, split):
        cls = spec["map"].get(label)
        value = str(value if value is not None else "").strip()
        if cls and 0 < len(value) <= 120:
            pools[cls].append(value)
    out = []
    for cls, pool in sorted(pools.items()):
        if len(pool) < 40:
            continue
        for i in range(COLUMNS[spec["role"][split]]):
            vals = [rng.choice(pool) for _ in range(rng.randint(20, 60))]
            cond = ("truthful", "obfuscated", "misleading")[i % 3]
            if cond == "truthful":
                header = rng.choice(TRUTHFUL.get(cls, [cls])) if cls != "none" else rng.choice(["name", "label", "title"])
            else:
                header = rng.choice(GENERIC if cond == "obfuscated" else UNRELATED)
            out.append({"header": header, "values": vals, "label": cls, "condition": cond, "source": f"{name}/{split}"})
    return out, {c: len(p) for c, p in pools.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--download", action="store_true")
    a = ap.parse_args()
    spec = yaml.safe_load(open(os.path.join(HERE, "sources.yaml")))["datasets"]
    rng = random.Random(23)
    manifest = {}
    for name, s in spec.items():
        if a.download:
            download(name, s)
        for split in s["files"]:
            cols, sizes = columns(name, s, split, rng)
            json.dump(cols, open(os.path.join(CACHE, f"{name}_{split}.json"), "w"))
            manifest[f"{name}_{split}"] = {"id": s["id"], "licence": s["licence"], "role": s["role"][split],
                                           "columns": len(cols), "values_per_class": sizes}
            print(f"{name}_{split:5} role={s['role'][split]:5} columns={len(cols):5} classes={sorted(sizes)}")
    json.dump(manifest, open(os.path.join(CACHE, "manifest.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
