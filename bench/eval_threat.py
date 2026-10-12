"""Train (normal sessions only) and evaluate the insider-threat engine on simulated sessions.

    uv run python bench/eval_threat.py [--train] [--out docs/eval/threat.json]

--train regenerates src/maskguard/ml/threat_benign_windows.npz from normal sessions (seed 1001).
Evaluation uses different sessions (seed 2002): 200 normal + 40 per attack type, through the real rewriter and DB.
Reported per detector (rules only, ML only, combined): share of sessions alerted / blocked, and how many queries
it took to raise the first alert.
"""
import argparse, json, os, statistics, tempfile

import numpy as np

os.environ.setdefault("MASKGUARD_HMAC_KEY", "sim-key")  # analysts' token columns need the key (fail closed without)

from maskguard import config
from maskguard.threat import TRAIN_PATH, AnomalyModel, ThreatEngine, iter_windows
from maskguard.threat_sim import ATTACKS, benign_session, sessions


def build_app():
    tmp = tempfile.mkdtemp()
    return config.build(config.Settings(db=f"sqlite:///{tmp}/sim.db", audit=f"{tmp}/a.jsonl", registry_out=f"{tmp}/r.yaml"))


def train(app, seed=1001, n=400):
    import random
    r = random.Random(seed)
    X = [x for _ in range(n) for x, *_ in iter_windows(benign_session(app, r).events)]
    np.savez_compressed(TRAIN_PATH, X=np.stack(X))
    print(f"trained on {len(X)} windows from {n} normal sessions -> {TRAIN_PATH}")


def run(engine_factory, sess):
    out = []
    for i, s in enumerate(sess):
        eng = engine_factory()
        first_alert, blocked = None, False
        for j, e in enumerate(s.events):
            a = eng.observe(f"u{i}", e)
            if a.action in ("alert", "block") and first_alert is None:
                first_alert = j + 1
            blocked |= a.action == "block"
        out.append((s, first_alert, blocked))
    return out


def summarize(results):
    rep = {}
    for kind in ["benign"] + ATTACKS:
        rows = [(s, fa, b) for s, fa, b in results if (s.kind.startswith("benign") if kind == "benign" else s.kind == kind)]
        alerted = [fa for _, fa, _ in rows if fa]
        rep[kind] = {"sessions": len(rows), "alerted": round(len(alerted) / len(rows), 3),
                     "blocked": round(sum(b for *_, b in rows) / len(rows), 3),
                     "median_queries_to_alert": statistics.median(alerted) if alerted else None}
    return rep


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", action="store_true")
    ap.add_argument("--out")
    args = ap.parse_args()
    app = build_app()
    if args.train or not os.path.exists(TRAIN_PATH):
        train(app)
    model = AnomalyModel.load()
    test = sessions(app, seed=2002, n_benign=200, n_per_attack=40)
    cfg = app.gateway.policy.get("threat") or {}
    detectors = {"rules only": lambda: ThreatEngine(cfg, None, use_rules=True),
                 "ML only": lambda: ThreatEngine(cfg, model, use_rules=False),
                 "rules + ML": lambda: ThreatEngine(cfg, model, use_rules=True)}
    report = {}
    print(f"{'detector':12} {'normal: alert/block':>20} " + " ".join(f"{a[:13]:>14}" for a in ATTACKS))
    for name, fac in detectors.items():
        rep = summarize(run(fac, test))
        report[name] = rep
        print(f"{name:12} {rep['benign']['alerted']:>9.1%} / {rep['benign']['blocked']:<8.1%} "
              + " ".join(f"{rep[a]['alerted']:>6.0%} ({rep[a]['median_queries_to_alert'] or '-':>3})" for a in ATTACKS))
    print("cells: share of attack sessions alerted (median queries until first alert)")
    if args.out:
        json.dump(report, open(args.out, "w"), indent=2)


if __name__ == "__main__":
    main()
