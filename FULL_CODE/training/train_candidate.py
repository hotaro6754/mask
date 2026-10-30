"""Train a candidate PII column classifier. Writes to OUT, never over the shipped model; promote it by copying only
after bench/compare_models.py and bench/evaluate.py show it is better.

Training data: MaskGuard's synthetic generator (300 columns per kind, seed 7), real-world non-personal columns from
training/realworld (train split only) and optional extra column files (training/hf/cache/*_train.json). Same 99
features and LightGBM settings as maskguard.ml.model.train, so a candidate differs from the shipped model only in data.

    python training/realworld/build.py
    python training/train_candidate.py OUT_DIR [--real-weight 1.0] [--extra FILES]

The shipped version 2 is: --extra training/hf/cache/nemotron_train.json training/hf/cache/gretelfin_train.json
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
from collections.abc import Sequence

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from maskguard.ml.features import FEATURE_NAMES, column_features
from maskguard.ml.synth import KINDS, dataset, reset_state

V2_EXTRA = [
    os.path.join(HERE, "hf", "cache", "nemotron_train.json"),
    os.path.join(HERE, "hf", "cache", "gretelfin_train.json"),
]
PARAMS = {
    "objective": "multiclass",
    "num_class": len(KINDS),
    "learning_rate": 0.08,
    "num_leaves": 15,
    "min_data_in_leaf": 10,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    "verbose": -1,
    "num_threads": 4,
}
Column = tuple[str, list, str, float]  # header, values, kind, sample weight


def load_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def training_columns(
    seed: int = 7,
    extra: Sequence[str] = (),
    real_weight: float = 1.0,
    extra_weight: float = 1.0,
    realworld: bool = True,
) -> tuple[list[Column], list[tuple[str, list, str]], dict]:
    """The training columns (with weights), the early-stopping validation columns and a count of each source.
    Deterministic: the generator starts from a clean state, as in a fresh process."""
    reset_state()
    synth, valid = dataset(300, seed), dataset(60, seed + 1000)
    real = load_json(os.path.join(HERE, "realworld", "cache", "train.json")) if realworld else []
    more = [e for f in extra for e in load_json(f)]
    cols = (
        [(h, v, k, 1.0) for h, v, k in synth]
        + [(e["header"], e["values"], e["label"], real_weight) for e in real]
        + [(e["header"], e["values"], e["label"], extra_weight) for e in more]
    )
    return cols, list(valid), {"synthetic": len(synth), "real_world": len(real), "extra": len(more)}


def featurize(columns: Sequence[tuple]) -> np.ndarray:
    return np.stack([column_features(c[0], c[1]) for c in columns])


def train_booster(
    X: np.ndarray,
    y: np.ndarray,
    w: np.ndarray,
    Xv: np.ndarray,
    yv: np.ndarray,
    seed: int = 7,
    feature_names: Sequence[str] = FEATURE_NAMES,
):
    """LightGBM with the shipped settings and early stopping on the synthetic validation set."""
    import lightgbm as lgb

    return lgb.train(
        {**PARAMS, "seed": seed},
        lgb.Dataset(X, y, weight=w, feature_name=list(feature_names)),
        400,
        valid_sets=[lgb.Dataset(Xv, yv)],
        callbacks=[lgb.early_stopping(30, verbose=False)],
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--real-weight", type=float, default=1.0, help="sample weight of each real-world column")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--extra", nargs="*", default=[], help="more column files ({header, values, label})")
    ap.add_argument("--extra-weight", type=float, default=1.0)
    ap.add_argument("--no-realworld", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    cols, valid, counts = training_columns(a.seed, a.extra, a.real_weight, a.extra_weight, not a.no_realworld)
    X, y, w = featurize(cols), np.array([KINDS.index(c[2]) for c in cols]), np.array([c[3] for c in cols])
    Xv, yv = featurize(valid), np.array([KINDS.index(k) for _, _, k in valid])
    booster = train_booster(X, y, w, Xv, yv, a.seed)
    acc = float((booster.predict(Xv, num_iteration=booster.best_iteration).argmax(1) == yv).mean())
    os.makedirs(a.out, exist_ok=True)
    with gzip.open(os.path.join(a.out, "pii_lgbm.txt.gz"), "wt") as f:
        f.write(booster.model_to_string(num_iteration=booster.best_iteration))
    meta = {
        "kinds": KINDS,
        "features": FEATURE_NAMES,
        "train_columns": len(cols),
        "synthetic_columns": counts["synthetic"],
        "real_world_columns": counts["real_world"],
        "real_weight": a.real_weight,
        "seed": a.seed,
        "extra_files": [os.path.basename(f) for f in a.extra],
        "extra_columns": counts["extra"],
        "extra_weight": a.extra_weight,
        "best_iteration": booster.best_iteration,
        "synthetic_validation_accuracy": round(acc, 4),
        "trained_seconds": round(time.time() - t0, 1),
        "real_world_manifest": load_json(os.path.join(HERE, "realworld", "cache", "manifest.json")),
    }
    with open(os.path.join(a.out, "pii_lgbm.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    print(
        json.dumps({k: v for k, v in meta.items() if k not in ("kinds", "features", "real_world_manifest")}, indent=1)
    )


if __name__ == "__main__":
    main()
