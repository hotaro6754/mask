"""LightGBM column classifier + the hybrid decision used by the scanner.

Decision order (fail closed):
  1. checksum rules: if >= 60% of values pass a strong checksum (Aadhaar Verhoeff, GSTIN mod-36, card Luhn, IBAN
     mod-97, PAN holder-type rule, EPIC), that kind wins; ML can never downgrade it
  2. ML: the most probable kind when p >= 0.5 ("high" if p >= 0.85)
  3. review band: if the model is not confident the column is non-PII (none + amount + free_text < 0.5) and
     some PII kind has p >= 0.25, the column is still tagged (and masked), marked "review"
"""
import gzip, json, os, random, time

import numpy as np

from .features import FEATURE_NAMES, VALIDATORS, _PATTERNS, column_features, header_kind
from .synth import KINDS, dataset

MODEL_PATH = os.path.join(os.path.dirname(__file__), "pii_lgbm.txt.gz")
META_PATH = os.path.join(os.path.dirname(__file__), "pii_lgbm.json")

STRONG_RULES = {"aadhaar": lambda v: VALIDATORS["aadhaar"](v) or bool(_PATTERNS["aadhaar_masked"].match(v.strip())),
                "gstin": VALIDATORS["gstin"], "card": VALIDATORS["card"], "iban": VALIDATORS["iban"],
                "pan": VALIDATORS["pan"], "voter_id": VALIDATORS["voter_epic"]}
SENSITIVE_AMOUNT_HEADERS = {"balance", "salary", "income", "outstanding", "networth", "credit_limit", "loan", "emi"}


def train(n_per_kind=300, seed=7, rounds=400, verbose=True):
    import lightgbm as lgb
    t0 = time.time()
    train_cols, valid_cols = dataset(n_per_kind, seed), dataset(max(40, n_per_kind // 5), seed + 1000)
    X = np.stack([column_features(h, v) for h, v, _ in train_cols])
    y = np.array([KINDS.index(k) for _, _, k in train_cols])
    Xv = np.stack([column_features(h, v) for h, v, _ in valid_cols])
    yv = np.array([KINDS.index(k) for _, _, k in valid_cols])
    params = {"objective": "multiclass", "num_class": len(KINDS), "learning_rate": 0.08, "num_leaves": 15,
              "min_data_in_leaf": 10, "feature_fraction": 0.8, "bagging_fraction": 0.8, "bagging_freq": 1,
              "lambda_l2": 1.0, "verbose": -1, "seed": seed, "num_threads": 4}
    booster = lgb.train(params, lgb.Dataset(X, y, feature_name=FEATURE_NAMES), rounds,
                        valid_sets=[lgb.Dataset(Xv, yv)], callbacks=[lgb.early_stopping(30, verbose=False)])
    acc = float((booster.predict(Xv, num_iteration=booster.best_iteration).argmax(1) == yv).mean())
    with gzip.open(MODEL_PATH, "wt") as f:
        f.write(booster.model_to_string(num_iteration=booster.best_iteration))
    meta = {"kinds": KINDS, "features": FEATURE_NAMES, "train_columns": len(train_cols), "seed": seed,
            "best_iteration": booster.best_iteration, "synthetic_validation_accuracy": round(acc, 4),
            "trained_seconds": round(time.time() - t0, 1)}
    json.dump(meta, open(META_PATH, "w"), indent=2)
    if verbose:
        print(json.dumps(meta, indent=2))
    return meta


class Classifier:
    _instance = None

    def __init__(self, path=MODEL_PATH):
        import lightgbm as lgb
        with gzip.open(path, "rt") as f:
            self.booster = lgb.Booster(model_str=f.read())
        self.kinds = json.load(open(META_PATH))["kinds"]

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def proba(self, header, values):
        return self.booster.predict(column_features(header, values)[None, :])[0]

    def proba_many(self, columns):
        X = np.stack([column_features(h, v) for h, v in columns])
        return self.booster.predict(X)


def rule_kind(values, threshold=0.6):
    vals = [str(v) for v in values if v is not None and str(v).strip()][:200]
    if not vals:
        return None, 0.0
    best, best_r = None, 0.0
    for kind, fn in STRONG_RULES.items():
        r = sum(1 for v in vals if _ok(fn, v)) / len(vals)
        if r > best_r:
            best, best_r = kind, r
    return (best, best_r) if best_r >= threshold else (None, best_r)


def _ok(fn, v):
    try:
        return bool(fn(v))
    except Exception:
        return False


def decide(header, values, probs=None, kinds=None):
    """Return dict(kind, confidence, source, evidence, probs) or kind=None for non-PII."""
    kinds = kinds or KINDS
    rk, rr = rule_kind(values)
    if probs is None:
        probs = Classifier.get().proba(header, values)
    order = np.argsort(probs)[::-1]
    top, p = kinds[order[0]], float(probs[order[0]])
    top3 = {kinds[i]: round(float(probs[i]), 3) for i in order[:3]}
    if rk:
        return {"kind": rk, "confidence": "high", "source": "checksum",
                "evidence": f"{rr:.0%} pass {rk} checksum; ML top={top} ({p:.2f})", "probs": top3}
    if top not in ("none", "free_text", "amount") and p >= 0.5:
        return {"kind": top, "confidence": "high" if p >= 0.85 else "medium", "source": "ml",
                "evidence": f"ML p={p:.2f}; header hint={header_kind(header)}", "probs": top3}
    p_amount = float(probs[kinds.index("amount")]) if "amount" in kinds else 0.0
    hdr = (header or "").lower()
    sensitive = any(w in hdr for w in SENSITIVE_AMOUNT_HEADERS)
    if (top == "amount" and p >= 0.5) or (sensitive and p_amount >= 0.3):
        p = max(p, p_amount)
        return {"kind": "amount" if sensitive else None, "confidence": "medium", "source": "ml+header",
                "evidence": f"money-like values (p={p:.2f}); header {'marks' if sensitive else 'does not mark'} it as personal",
                "probs": top3}
    if top == "free_text" and p >= 0.5:
        return {"kind": "free_text", "confidence": "medium", "source": "ml", "evidence": f"free text (p={p:.2f})",
                "probs": top3}
    pii = [(kinds[i], float(probs[i])) for i in order if kinds[i] not in ("none", "free_text", "amount")]
    non_pii_mass = sum(float(probs[kinds.index(k)]) for k in ("none", "free_text", "amount") if k in kinds)
    if pii and pii[0][1] >= 0.25 and non_pii_mass < 0.5:  # uncertain, and not confidently non-PII -> still mask
        k, pk = pii[0]
        return {"kind": k, "confidence": "review", "source": "ml", "evidence": f"uncertain: {k} p={pk:.2f}, top={top} {p:.2f}",
                "probs": top3}
    return {"kind": None, "confidence": "high" if p >= 0.85 else "medium", "source": "ml",
            "evidence": f"not PII: {top} p={p:.2f}", "probs": top3}


if __name__ == "__main__":
    train()
