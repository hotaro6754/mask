"""Differential privacy for aggregates over protected numeric columns (policy action `aggregate`).

An analyst may use such a column only as SUM(col), AVG(col) or COUNT(col) directly in the SELECT list of a simple
query. Values are clipped to policy bounds [lo, hi] inside the masked view, so one person can change a SUM by at
most max(|lo|, |hi|) and a COUNT by 1. Each protected aggregate gets Laplace noise with scale sensitivity / epsilon;
AVG is a noisy SUM over a noisy COUNT, each with epsilon / 2. Groups in a GROUP BY are disjoint, so a query costs
epsilon per protected output column (parallel composition across groups, sequential across columns).

Each user has a daily budget; once spent, protected aggregates are refused until the next day.
Noise comes from the OS random source, so it can't be replayed or predicted.
"""

import math
import random
import threading
import time
from collections import defaultdict

_rng = random.SystemRandom()


def laplace(scale):
    u = _rng.random() - 0.5
    return -scale * math.copysign(1.0, u) * math.log(1 - 2 * abs(u))


class BudgetExceeded(Exception):
    pass


class PrivacyLedger:
    def __init__(self, daily_budget=10.0):
        self.daily_budget = float(daily_budget)
        self.spent = defaultdict(float)
        self.lock = threading.Lock()

    @classmethod
    def from_policy(cls, policy):
        return cls((policy.get("dp") or {}).get("daily_budget", 10.0))

    @staticmethod
    def _key(user, now):
        return user, time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))

    def remaining(self, user, now=None):
        return round(self.daily_budget - self.spent[self._key(user, now)], 4)

    def spend(self, user, cost, now=None):
        with self.lock:
            k = self._key(user, now)
            if self.spent[k] + cost > self.daily_budget + 1e-9:
                raise BudgetExceeded(
                    f"privacy budget exhausted: {self.daily_budget - self.spent[k]:.2f} of "
                    f"{self.daily_budget:.2f} left today, query needs {cost:.2f}"
                )
            self.spent[k] += cost
            return round(self.daily_budget - self.spent[k], 4)


def apply_noise(columns, rows, plan):
    """plan: {"ops": [...], "n_visible": int}. Returns (columns, rows) with noise added and helper columns removed."""
    nv = plan["n_visible"]
    out = []
    for row in rows:
        row = list(row)
        for op in plan["ops"]:
            i, eps = op["index"], op["epsilon"]
            if op["type"] == "count":
                v = None if row[i] is None else max(0, round(float(row[i]) + laplace(1 / eps)))
            elif op["type"] == "sum":
                v = None if row[i] is None else round(float(row[i]) + laplace(op["sensitivity"] / eps), 2)
            else:  # avg = noisy sum / noisy count
                s, c = row[i], row[op["count_index"]]
                if s is None or c is None:
                    v = None
                else:
                    ns = float(s) + laplace(op["sensitivity"] / (eps / 2))
                    nc = max(1.0, float(c) + laplace(1 / (eps / 2)))
                    v = round(min(max(ns / nc, op["lo"]), op["hi"]), 2)
            row[i] = v
        out.append(tuple(row[:nv]))
    return list(columns[:nv]), out
