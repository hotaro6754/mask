"""Known gaps in the analyst noisy-aggregate mechanism (docs/design/PRIVACY_ACCOUNTING.md §1.2), as executable checks.

Each test asserts what the design requires. Where today's code does not meet it, the test is a strict xfail: it
documents the gap now and fails the moment the gap is fixed, so the marker has to be removed deliberately.
Passing these tests is not evidence of differential privacy (design §13); failing ones are evidence against it.
"""
import copy, os, re, threading

import pytest
import yaml

from maskguard.backends import SQLiteBackend
from maskguard.dp import BudgetExceeded, PrivacyLedger
from maskguard.rewriter import rewrite

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESIGN = "docs/design/PRIVACY_ACCOUNTING.md"
BOUND = 1_000_000.0  # default dp.bounds for balance: [0, 10 lakh]

REGISTRY = {
    "accounts": {"id": {"type": "num"}, "user_id": {"type": "num"}, "status": {"type": "text"},
                 "balance": {"type": "num", "tag": "FINANCIAL_CONFIDENTIAL", "kind": "amount"}},
    "tickets": {"id": {"type": "num"}, "user_id": {"type": "num"}},
}


def _policy():
    with open(os.path.join(ROOT, "policies", "default.yaml")) as f:
        p = copy.deepcopy(yaml.safe_load(f))
    p["min_group_size"] = {}  # the group floor would hide these tiny datasets; it is not what is measured here
    return p


def _db(accounts, tickets=()):
    b = SQLiteBackend(":memory:")
    b.admin_script("CREATE TABLE accounts (id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT, balance REAL);"
                   "CREATE TABLE tickets (id INTEGER PRIMARY KEY, user_id INTEGER);")
    b.insert_many("accounts", list(accounts))
    b.insert_many("tickets", list(tickets))
    return b


def _shift(sql, d, d_prime):
    """Exact (noise-free) change in the released aggregate between neighbouring datasets, and the sensitivity the
    mechanism declares for it. The Laplace noise is calibrated to the declared value, so shift > declared means the
    release leaks more than the epsilon charged."""
    res = rewrite(sql, "analyst", REGISTRY, _policy(), "sqlite")
    assert res.dp, "expected a noisy release for this query"
    f = lambda b: float(b.execute(res.sql)[1][0][0] or 0)
    return abs(f(d) - f(d_prime)), res.dp["ops"][0]["sensitivity"]


# ---------------------------------------------------------------- sensitivity under replace-one-customer (D2)

def test_control_single_account_customers_stay_within_the_declared_sensitivity():
    """Guards the harness itself: when each customer has one row, the declared sensitivity holds."""
    d = _db([(1, 1, "active", 0.0), (2, 2, "active", 500.0)])
    d2 = _db([(1, 1, "active", BOUND), (2, 2, "active", 500.0)])
    shift, declared = _shift("SELECT SUM(balance) AS s FROM accounts", d, d2)
    assert shift <= declared


@pytest.mark.xfail(strict=True, reason=f"F6: clipping is per row, not per customer ({DESIGN} §6.1)")
def test_a_customer_with_several_accounts_moves_a_sum_by_at_most_the_declared_sensitivity():
    d = _db([(1, 1, "active", 0.0), (2, 1, "active", 0.0), (3, 2, "active", 500.0)])
    d2 = _db([(1, 1, "active", BOUND), (2, 1, "active", BOUND), (3, 2, "active", 500.0)])  # customer 1 replaced
    shift, declared = _shift("SELECT SUM(balance) AS s FROM accounts", d, d2)
    assert shift <= declared, f"one customer moved the SUM by {shift:,.0f}; noise is calibrated to {declared:,.0f}"


@pytest.mark.xfail(strict=True, reason=f"F1: joins that duplicate protected rows are accepted ({DESIGN} §6.2)")
def test_a_join_cannot_multiply_one_customers_influence_on_a_sum():
    tickets = [(10, 1), (11, 1), (12, 1), (13, 1), (14, 2)]  # customer 1 has four tickets
    d = _db([(1, 1, "active", 0.0), (2, 2, "active", 500.0)], tickets)
    d2 = _db([(1, 1, "active", BOUND), (2, 2, "active", 500.0)], tickets)
    shift, declared = _shift("SELECT SUM(a.balance) AS s FROM accounts a JOIN tickets t ON t.user_id = a.user_id",
                             d, d2)
    assert shift <= declared, f"one customer moved the SUM by {shift:,.0f}; noise is calibrated to {declared:,.0f}"


# ---------------------------------------------------------------- ordering on protected outputs (F2)

def test_ordering_by_the_aggregate_expression_gets_no_noisy_release():
    res = rewrite("SELECT status, SUM(balance) AS s FROM accounts GROUP BY status ORDER BY SUM(balance) DESC",
                  "analyst", REGISTRY, _policy(), "sqlite")
    assert res.dp is None


@pytest.mark.xfail(strict=True, reason=f"F2: the database sorts on true sums before noise is added ({DESIGN} §6.3)")
@pytest.mark.parametrize("order", ["ORDER BY s DESC", "ORDER BY 2 DESC", "ORDER BY 2 DESC LIMIT 1"])
def test_a_noisy_release_is_never_ordered_or_limited_on_true_values(order):
    res = rewrite(f"SELECT status, SUM(balance) AS s FROM accounts GROUP BY status {order}",
                  "analyst", REGISTRY, _policy(), "sqlite")
    assert not (res.dp and re.search(r"\bORDER\s+BY\b", res.sql, re.IGNORECASE)), res.sql[-80:]


# ---------------------------------------------------------------- budget accounting

@pytest.mark.xfail(strict=True, reason=f"F4: the budget is per analyst account, not per dataset ({DESIGN} §4)")
def test_the_budget_is_shared_by_every_analyst():
    ledger = PrivacyLedger(daily_budget=10.0)
    ledger.spend("analyst.ali", 6.0)
    assert ledger.remaining("analyst.two") == 4.0


def test_concurrent_spends_never_exceed_the_budget():
    """The current in-memory ledger is atomic within one process. Cross-process and cross-server enforcement
    needs the persistent accountant (design §9) and its own tests."""
    ledger, ok, barrier = PrivacyLedger(daily_budget=10.0), [], threading.Barrier(64)

    def spend():
        barrier.wait()
        try:
            ledger.spend("analyst.ali", 0.5)
            ok.append(1)
        except BudgetExceeded:
            pass
    threads = [threading.Thread(target=spend) for _ in range(64)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ok) == 20 and ledger.remaining("analyst.ali") == 0.0
