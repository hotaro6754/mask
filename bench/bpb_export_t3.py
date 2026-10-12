# Run with the bharat-pii-bench venv:
#   python bench/bpb_export_t3.py <bharat-pii-bench>/configs/bench.yaml out.json FIRST_SEED N_SEEDS
"""Export bharat-pii-bench T3 sentences (identifiers embedded in English / Hindi / Hinglish) + the
benchmark's own regex_checksum find() predictions."""
import json, sys
from pathlib import Path

from bharat_pii.config import load_bench_config
from bharat_pii.dataset import with_seed
from bharat_pii.detect import find
from bharat_pii.spans import build_t3

cfg, out, first, n = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
base = load_bench_config(cfg)
rows = []
for seed in range(first, first + n):
    for s in build_t3(with_seed(base, seed)):
        rows.append({"seed": seed, "text": s.text, "language": s.language,
                     "gold": [[str(sp.label), sp.start, sp.end] for sp in s.spans],
                     "baseline": [[str(sp.label), sp.start, sp.end] for sp in find(s.text)]})
json.dump(rows, open(out, "w"), ensure_ascii=False)
print(len(rows), "sentences")
