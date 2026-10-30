# Run with the bharat-pii-bench venv, e.g.:
#   python bench/bpb_export.py <bharat-pii-bench>/configs/bench.yaml out.json 60 301 777   (60 seeds from 301, hard-negative seed 777)
#   ... out.json 60 301 777 200   (optional 6th argument: values per column; default: the config's column_sample_size)
"""Run inside the bharat-pii-bench venv: export T2 columns for many seeds + hard-negative columns, with baseline predictions."""

import json
import random
import sys

from bharat_pii.config import load_bench_config
from bharat_pii.dataset import build_t2, with_seed
from bharat_pii.detect import detector_by_name
from bharat_pii.generate import HARD_NEGATIVE

cfg_path, out_path, n_seeds = sys.argv[1], sys.argv[2], int(sys.argv[3])
first_seed, hn_seed = (int(sys.argv[4]), int(sys.argv[5])) if len(sys.argv) > 5 else (1, 12345)
from dataclasses import replace
from pathlib import Path

base = load_bench_config(Path(cfg_path))
if len(sys.argv) > 6:
    base = replace(base, column_sample_size=int(sys.argv[6]))
n_values = base.column_sample_size
dets = {n: detector_by_name(n) for n in ("regex_checksum", "regex_checksum+names")}
rows = []
for seed in range(first_seed, first_seed + n_seeds):
    for col in build_t2(with_seed(base, seed)):
        samples = [v for v in col.values if v]
        rows.append(
            {
                "set": "t2",
                "seed": seed,
                "name": col.name,
                "condition": col.name_condition,
                "label": str(col.label),
                "values": list(col.values),
                "baseline": {n: str(d.classify_column(col.name, samples)) for n, d in dets.items()},
                "baseline5": {
                    n: str(d.classify_column(col.name, [v for v in list(col.values)[:5] if v])) for n, d in dets.items()
                },
            }
        )
# hard-negative columns: n_values decoys of one variant each, labelled NONE, under an obfuscated name
rng = random.Random(hn_seed)
for i in range(n_seeds):
    for variant in HARD_NEGATIVE.variants:
        vals = [HARD_NEGATIVE.generate(rng, variant).value for _ in range(n_values)]
        name = rng.choice(["col_07", "field_c", "ref", "code"])
        rows.append(
            {
                "set": "hardneg",
                "seed": i,
                "name": name,
                "condition": "obfuscated",
                "label": "NONE",
                "variant": variant,
                "values": vals,
                "baseline": {n: str(d.classify_column(name, vals)) for n, d in dets.items()},
                "baseline5": {n: str(d.classify_column(name, vals[:5])) for n, d in dets.items()},
            }
        )
Path(out_path).write_text(json.dumps(rows), encoding="utf-8")
print(len(rows), "columns;", "hard-negative variants:", HARD_NEGATIVE.variants)
