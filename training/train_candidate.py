"""Train a candidate PII column classifier: the synthetic generator (exactly as the shipped model: 300 columns per
kind, seed 7) plus real-world non-personal columns from training/realworld (train split only). Same 99 features
and LightGBM settings as maskguard.ml.model.train, so the only change is the data. Writes to OUT, never over the
shipped model; promote it by copying only after bench/compare_models.py shows it is better.

    python training/realworld/build.py
    python training/train_candidate.py OUT_DIR [--real-weight 1.0]
"""
import argparse, gzip, json, os, sys, time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
from maskguard.ml.features import FEATURE_NAMES, column_features  # noqa: E402
from maskguard.ml.synth import KINDS, dataset  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--real-weight", type=float, default=1.0, help="sample weight of each real-world column")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    import lightgbm as lgb
    t0 = time.time()
    synth, valid = dataset(300, a.seed), dataset(60, a.seed + 1000)
    real = json.load(open(os.path.join(HERE, "realworld", "cache", "train.json")))
    cols = [(h, v, k, 1.0) for h, v, k in synth] + [(e["header"], e["values"], e["label"], a.real_weight) for e in real]
    X = np.stack([column_features(h, v) for h, v, _, _ in cols])
    y = np.array([KINDS.index(k) for _, _, k, _ in cols])
    w = np.array([wt for *_, wt in cols])
    Xv = np.stack([column_features(h, v) for h, v, _ in valid])
    yv = np.array([KINDS.index(k) for _, _, k in valid])
    params = {"objective": "multiclass", "num_class": len(KINDS), "learning_rate": 0.08, "num_leaves": 15,
              "min_data_in_leaf": 10, "feature_fraction": 0.8, "bagging_fraction": 0.8, "bagging_freq": 1,
              "lambda_l2": 1.0, "verbose": -1, "seed": a.seed, "num_threads": 4}
    booster = lgb.train(params, lgb.Dataset(X, y, weight=w, feature_name=FEATURE_NAMES), 400,
                        valid_sets=[lgb.Dataset(Xv, yv)], callbacks=[lgb.early_stopping(30, verbose=False)])
    acc = float((booster.predict(Xv, num_iteration=booster.best_iteration).argmax(1) == yv).mean())
    os.makedirs(a.out, exist_ok=True)
    with gzip.open(os.path.join(a.out, "pii_lgbm.txt.gz"), "wt") as f:
        f.write(booster.model_to_string(num_iteration=booster.best_iteration))
    meta = {"kinds": KINDS, "features": FEATURE_NAMES, "train_columns": len(cols), "synthetic_columns": len(synth),
            "real_world_columns": len(real), "real_weight": a.real_weight, "seed": a.seed,
            "best_iteration": booster.best_iteration, "synthetic_validation_accuracy": round(acc, 4),
            "trained_seconds": round(time.time() - t0, 1),
            "real_world_manifest": json.load(open(os.path.join(HERE, "realworld", "cache", "manifest.json")))}
    json.dump(meta, open(os.path.join(a.out, "pii_lgbm.json"), "w"), indent=2)
    print(json.dumps({k: v for k, v in meta.items() if k not in ("kinds", "features", "real_world_manifest")}, indent=1))


if __name__ == "__main__":
    main()
