"""Fetch the sources in sources.yaml (cached in training/realworld/cache/, not in git) and turn each listed column
into classifier examples: (header, values, label), with the same header mix as the synthetic generator (40% the
real header, 30% generic like col_07, 30% unrelated like ref_no) and 20-60 values per example.

    python training/realworld/build.py            # writes cache/train.json and cache/test.json
"""
import csv, hashlib, io, json, os, random, sys, urllib.request

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
CACHE = os.path.join(HERE, "cache")
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from maskguard.ml.synth import GENERIC, UNRELATED  # noqa: E402

PER_COLUMN = {"train": 40, "test": 20}
MAX_BYTES = 2_000_000


def fetch(repo, path):
    os.makedirs(CACHE, exist_ok=True)
    local = os.path.join(CACHE, f"{repo}__{path.replace('/', '_')}")
    if not os.path.exists(local):
        url = f"https://raw.githubusercontent.com/datasets/{repo}/main/{path}"
        with urllib.request.urlopen(url, timeout=60) as r:
            data = r.read(MAX_BYTES)
        with open(local, "wb") as f:
            f.write(data)
    raw = open(local, "rb").read()
    return raw.decode("utf-8", "replace"), hashlib.sha256(raw).hexdigest()


def columns_of(text, wanted):
    rows = list(csv.reader(io.StringIO(text)))
    header, body = rows[0], rows[1:-1]  # the last row may be cut off by MAX_BYTES
    out = {}
    for name in wanted:
        j = header.index(name)
        vals = [r[j].strip() for r in body if j < len(r) and r[j].strip()]
        out[name] = vals
    return out


def examples(header, values, label, n, rng):
    out = []
    for _ in range(n):
        k = rng.randint(20, 60)
        vals = [rng.choice(values) for _ in range(k)]  # sampled with repetition, as real columns repeat
        cond = rng.random()
        h = header if cond < 0.4 else rng.choice(GENERIC) if cond < 0.7 else rng.choice(UNRELATED)
        out.append({"header": h, "values": vals, "label": label})
    return out


def build(seed=11):
    spec = yaml.safe_load(open(os.path.join(HERE, "sources.yaml")))["sources"]
    rng = random.Random(seed)
    out = {"train": [], "test": []}
    manifest = []
    for s in spec:
        text, sha = fetch(s["repo"], s["file"])
        cols = columns_of(text, list(s["columns"]))
        for name, label in s["columns"].items():
            vals = cols[name]
            if len(vals) < 20:
                continue
            ex = examples(name, vals, label, PER_COLUMN[s["split"]], rng)
            for e in ex:
                e["source"] = f"{s['repo']}/{s['file']}#{name}"
            out[s["split"]] += ex
        manifest.append({"repo": s["repo"], "file": s["file"], "licence": s["licence"], "split": s["split"],
                         "sha256": sha, "columns": len(s["columns"])})
    for split, ex in out.items():
        json.dump(ex, open(os.path.join(CACHE, f"{split}.json"), "w"))
    json.dump(manifest, open(os.path.join(CACHE, "manifest.json"), "w"), indent=1)
    return out, manifest


if __name__ == "__main__":
    out, manifest = build()
    for split, ex in out.items():
        labels = {}
        for e in ex:
            labels[e["label"]] = labels.get(e["label"], 0) + 1
        print(split, len(ex), "examples from", len({e["source"] for e in ex}), "columns", labels)
