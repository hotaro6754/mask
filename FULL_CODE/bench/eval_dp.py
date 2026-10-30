"""Differential-privacy aggregates: utility for analysts vs protection against a differencing attack.

    uv run python bench/eval_dp.py [--out docs/eval/dp.json]

Utility: AVG(balance) over groups of n customers, analyst view vs the true value, median relative error.
Privacy: an analyst tries to learn one customer's balance with SUM over a group minus SUM over the same group
without that customer. Without noise this gives the exact balance. We report the median error of that estimate,
how often it lands within 10% of the truth, and the best an attacker can do by averaging every attempt their
daily budget allows.
"""

import argparse
import copy
import json
import os
import random
import statistics
import tempfile
from pathlib import Path

os.environ.setdefault("MASKGUARD_HMAC_KEY", "dp-eval-key")
from maskguard import config
from maskguard.gateway import Gateway


def gateway(app, eps, budget=1e9):
    pol = copy.deepcopy(app.gateway.policy)
    pol["dp"]["epsilon_per_query"], pol["dp"]["daily_budget"] = eps, budget
    pol["threat"] = {"enabled": False}
    return Gateway(app.backend, app.gateway.registry, pol, app.auth, os.path.join(tempfile.mkdtemp(), "a.jsonl"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    args = ap.parse_args()
    tmp = tempfile.mkdtemp()
    app = config.build(
        config.Settings(db=f"sqlite:///{tmp}/dp.db", audit=f"{tmp}/a.jsonl", registry_out=f"{tmp}/r.yaml")
    )
    analyst = app.auth.login("analyst.ali", "analyst123")

    def truth(sql):
        return app.backend.admin_query(sql)[1][0][0]

    report = {"utility": {}, "differencing_attack": {}}
    r = random.Random(1)
    print("AVG(balance) median relative error, by group size n and epsilon per query")
    for eps in (0.1, 0.5, 1.0, 2.0):
        gw = gateway(app, eps)
        row = {}
        for n in (25, 50, 150, 300):
            q = f"SELECT avg(balance) FROM accounts WHERE id <= {n}"
            true = float(truth(q))
            errs = [abs(gw.query(analyst, q, observe=False).rows[0][0] - true) / true for _ in range(200)]
            row[n] = round(statistics.median(errs), 4)
        report["utility"][eps] = row
        print(f"  eps={eps:<4} " + "  ".join(f"n={n}: {e:6.1%}" for n, e in row.items()))
    print("\nDifferencing attack on one customer's balance (SUM with minus SUM without)")
    budget = app.gateway.policy["dp"]["daily_budget"]
    for eps in (0.1, 0.5, 1.0, 2.0):
        gw = gateway(app, eps)
        errs, close = [], 0
        for _ in range(200):
            target = r.randint(1, 100)
            true = float(truth(f"SELECT balance FROM accounts WHERE id = {target}"))
            a = gw.query(analyst, "SELECT sum(balance) FROM accounts WHERE id <= 100", observe=False).rows[0][0]
            b = gw.query(
                analyst, f"SELECT sum(balance) FROM accounts WHERE id <= 100 AND id <> {target}", observe=False
            ).rows[0][0]
            err = abs((a - b) - true)
            errs.append(err)
            close += err <= 0.1 * max(true, 1.0)
        pairs = int(budget // (2 * eps))  # query pairs one user can afford per day
        report["differencing_attack"][eps] = {
            "median_abs_error": round(statistics.median(errs)),
            "within_10pct": round(close / 200, 3),
            "pairs_per_day": pairs,
            "median_abs_error_averaging_a_days_budget": round(statistics.median(errs) / max(pairs, 1) ** 0.5),
        }
        d = report["differencing_attack"][eps]
        print(
            f"  eps={eps:<4} median error ₹{d['median_abs_error']:,}  within 10%: {d['within_10pct']:.1%}  "
            f"averaging {pairs} pairs/day: ₹{d['median_abs_error_averaging_a_days_budget']:,}"
        )
    mean_balance = float(truth("SELECT avg(balance) FROM accounts"))
    report["mean_balance"] = round(mean_balance)
    print(f"\n(mean balance ₹{mean_balance:,.0f}; without DP the differencing attack recovers it exactly)")
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
