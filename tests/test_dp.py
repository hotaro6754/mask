"""Differential-privacy aggregates: noise only where allowed, fail closed elsewhere, budget enforced."""
import statistics

import pytest

from maskguard.dp import PrivacyLedger, laplace
from maskguard.rewriter import Rejected


def true_avg(env, where="1=1"):
    return float(env.backend.admin_query(f"SELECT avg(balance) FROM accounts WHERE {where}")[1][0][0])


def test_laplace_scale():
    xs = [abs(laplace(2.0)) for _ in range(20000)]
    assert 1.8 < statistics.mean(xs) < 2.2  # E|Lap(b)| = b


def test_analyst_gets_noisy_but_useful_average_and_pays_budget(env):
    s = env.login("analyst")
    r = env.gw.query(s, "SELECT status, avg(balance) AS avg_balance, count(*) AS n FROM accounts GROUP BY status ORDER BY status")
    assert r.columns == ["status", "avg_balance", "n"] and len(r.rows) == 2
    assert r.dp == {"epsilon": 0.5, "remaining": 9.5, "columns": ["balance"]}
    for status, avg, n in r.rows:
        true = true_avg(env, f"status = '{status}'")
        assert avg != round(true, 2) and abs(avg - true) / true < 0.5  # noisy, but in the right ballpark
        assert int(n) >= 5


def test_sum_and_count_are_noised_and_cost_epsilon_each(env):
    r = env.gw.query(env.login("analyst"), "SELECT sum(balance), count(balance) FROM accounts")
    assert r.dp["epsilon"] == 1.0 and len(r.rows[0]) == 2


@pytest.mark.parametrize("sql", [
    "SELECT balance FROM accounts",
    "SELECT max(balance), min(balance) FROM accounts",
    "SELECT id FROM accounts WHERE balance > 500000",
    "SELECT id FROM accounts ORDER BY balance DESC LIMIT 5",
    "SELECT * FROM accounts",
    "SELECT avg(b) FROM (SELECT balance AS b FROM accounts) t",
    "WITH x AS (SELECT balance FROM accounts) SELECT avg(balance) FROM x",
    "SELECT round(avg(balance)) FROM accounts",
    "SELECT status, count(*) FROM accounts GROUP BY status HAVING avg(balance) > 1",
])
def test_any_other_use_of_a_protected_number_fails_closed(env, sql):
    s = env.login("analyst")
    before = env.gw.dp_ledger.remaining(s.user)
    cols, rows = env.gw.execute(s, sql)
    raw = {str(r[0]) for r in env.backend.admin_query("SELECT balance FROM accounts")[1]}
    assert not ({str(c) for row in rows for c in row} & raw)
    assert env.gw.dp_ledger.remaining(s.user) == before  # no budget spent, no noise path taken


def test_budget_is_enforced(env):
    s = env.login("analyst")
    env.gw.dp_ledger.daily_budget = 1.0
    env.gw.query(s, "SELECT avg(balance) FROM accounts")
    env.gw.query(s, "SELECT avg(balance) FROM accounts")
    with pytest.raises(Rejected, match="privacy budget exhausted"):
        env.gw.query(s, "SELECT avg(balance) FROM accounts")
    assert '"dp_epsilon": 0.5' in open(env.gw.audit.path).read()


def test_admin_and_support_unchanged(env):
    assert env.gw.query(env.login("admin"), "SELECT avg(balance) FROM accounts").dp is None
    assert env.gw.query(env.login("support"), "SELECT avg(balance) FROM accounts").dp is None


def test_ledger_resets_daily():
    led = PrivacyLedger(1.0)
    led.spend("u", 1.0, now=1_760_000_000)
    assert led.remaining("u", now=1_760_000_000 + 86400) == 1.0
