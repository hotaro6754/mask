"""Concurrent mixed-role queries share one gateway and one database connection per backend. A request must never
receive another role's view: every concurrent result has to equal the same role's result computed alone."""

import random
from concurrent.futures import ThreadPoolExecutor

import pytest

QUERIES = [
    "SELECT id, name, email, phone, ssn FROM users ORDER BY id LIMIT 5",
    "SELECT u.id, u.pan, a.credit_card, a.balance FROM users u JOIN accounts a ON a.user_id = u.id ORDER BY u.id LIMIT 5",
    "SELECT id, contact, payment_ref FROM support_tickets ORDER BY id LIMIT 5",
    "SELECT count(*) FROM users WHERE ssn LIKE '5%'",
    "WITH t AS (SELECT id, aadhaar FROM users) SELECT id, aadhaar FROM t ORDER BY id LIMIT 3",
]
ROLES = ["admin", "support", "analyst"]


@pytest.mark.parametrize("workers", [12])
def test_concurrent_mixed_roles_never_see_each_others_view(env, workers):
    sessions = {r: env.login(r) for r in ROLES}

    def run(role, sql):
        return [tuple(row) for row in env.gw.query(sessions[role], sql, observe=False).rows]

    expected = {(r, q): run(r, q) for r in ROLES for q in QUERIES}
    assert expected[("admin", QUERIES[0])] != expected[("support", QUERIES[0])] != expected[("analyst", QUERIES[0])]
    jobs = [(r, q) for r in ROLES for q in QUERIES] * 8
    random.Random(7).shuffle(jobs)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda job: (job, run(*job)), jobs))
    wrong = [job for job, rows in results if rows != expected[job]]
    assert not wrong, f"{len(wrong)} of {len(jobs)} concurrent results differ from the same role run alone: {wrong[:3]}"
