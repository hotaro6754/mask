"""Simulated user sessions for training and evaluating the threat engine.

Normal personas: support agents doing customer lookups, analysts running aggregates and token joins, with
occasional paging, typos and off-hours work. Attackers: equality enumeration, range/prefix binary search,
ORDER BY probing, bulk paging, firewall probing, and a slow attacker that hides probes among normal queries.
Every query runs through the real rewriter and database, so event features match production exactly.
"""
import random, time
from dataclasses import dataclass

from .audit import fingerprint
from .rewriter import Rejected, rewrite
from .threat import Event

ATTACKS = ["enumeration", "binary_search", "order_probe", "bulk_paging", "firewall_probe", "slow_and_low"]


@dataclass
class Session:
    kind: str          # benign persona or attack name
    role: str
    events: list
    malicious: bool


def _support_query(r, n_users):
    i = r.randint(1, n_users)
    return r.choice([
        f"SELECT * FROM support_tickets WHERE id = {i}",
        f"SELECT name, city FROM users WHERE id = {i}",
        "SELECT id, status, notes FROM support_tickets WHERE status = 'open' LIMIT 20",
        f"SELECT u.name, a.status FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.id = {i}",
        f"SELECT id, name, city FROM users WHERE name LIKE '{r.choice('ABCDEGHKMNPRSV')}%' LIMIT 10",
        f"SELECT message FROM support_tickets WHERE user_id = {i}",
        f"SELECT credit_card, status FROM accounts WHERE user_id = {i}",
    ])


def _analyst_query(r):
    return r.choice([
        "SELECT city, count(*) FROM users GROUP BY city",
        "SELECT status, avg(balance) FROM accounts GROUP BY status",
        "SELECT count(*) FROM support_tickets WHERE status = 'open'",
        "SELECT u.city, count(*) FROM users u JOIN accounts a ON a.user_id = u.id GROUP BY u.city",
        "SELECT count(*) FROM users u JOIN accounts a ON a.user_id = u.id WHERE a.status = 'frozen'",
        "SELECT notes, count(*) FROM support_tickets GROUP BY notes",
        "SELECT * FROM users LIMIT 20",
        "SELECT email, count(*) FROM users GROUP BY email HAVING count(*) > 1",
    ])


def _attack_query(r, kind, k):
    if kind in ("enumeration", "slow_and_low"):
        return f"SELECT id FROM users WHERE email = '{r.choice('abcdefghijk')}{r.randint(1, 99999)}@example.com'"
    if kind == "binary_search":
        if r.random() < 0.5:
            lo = r.randint(0, 900000)
            return f"SELECT count(*) FROM accounts WHERE balance BETWEEN {lo} AND {lo + r.randint(100, 50000)}"
        return f"SELECT count(*) FROM users WHERE ssn LIKE '{r.randint(100, 899)}-{r.randint(10, 99)}%'"
    if kind == "order_probe":
        return f"SELECT id FROM users ORDER BY ssn LIMIT 1 OFFSET {k}"
    if kind == "bulk_paging":
        return f"SELECT * FROM {r.choice(['users', 'accounts', 'support_tickets'])} LIMIT 100 OFFSET {k * 100}"
    if kind == "firewall_probe":
        return r.choice(["SELECT * FROM sqlite_master", "SELECT 1; DROP TABLE users", "SELECT load_extension('x')",
                         "UPDATE users SET ssn = '0'", "SELECT * FROM pg_catalog.pg_user",
                         "SELECT pg_read_file('/etc/passwd')", "SELECT email FROM users INTO OUTFILE '/tmp/x'"])
    raise ValueError(kind)


def _run(app, role, sql, ts):
    try:
        res = rewrite(sql, role, app.gateway.registry, app.gateway.policy, app.backend.dialect)
    except Rejected:
        return Event(ts, "reject", fingerprint(sql, app.backend.dialect), 0, {})
    try:
        _, rows = app.backend.execute(res.sql)
    except Exception:
        return Event(ts, "reject", fingerprint(sql, app.backend.dialect), 0, res.shape)
    return Event(ts, "allow", fingerprint(sql, app.backend.dialect), len(rows), res.shape)


def _start(r, offhours_p=0.1):
    day = 1_760_000_000 + r.randint(0, 200) * 86400
    hour = r.choice([22, 23, 1, 5]) if r.random() < offhours_p else r.randint(9, 18)
    return time.mktime(time.localtime(day)[:3] + (hour, r.randint(0, 59), 0, 0, 0, -1))


def benign_session(app, r, n_users=300):
    role = r.choice(["support", "support", "analyst"])
    ts, events = _start(r), []
    for _ in range(r.randint(10, 45)):
        ts += r.uniform(15, 150)
        if r.random() < 0.03:
            sql = "SELEC * FROM users"  # typo
        elif role == "support" and r.random() < 0.08:  # paging through open tickets, a few pages
            sql = f"SELECT id, status FROM support_tickets WHERE status = 'open' LIMIT 20 OFFSET {20 * r.randint(1, 3)}"
        else:
            sql = _support_query(r, n_users) if role == "support" else _analyst_query(r)
        events.append(_run(app, role, sql, ts))
    return Session(f"benign_{role}", role, events, False)


def attack_session(app, r, kind, n_users=300):
    role = r.choice(["support", "analyst"])
    ts, events = _start(r, offhours_p=0.3), []
    n = r.randint(25, 60) if kind != "slow_and_low" else r.randint(50, 90)
    k = 0
    for _ in range(n):
        if kind == "slow_and_low":
            ts += r.uniform(30, 120)
            malicious = r.random() < 0.4
        elif kind == "firewall_probe":
            ts += r.uniform(5, 60)
            malicious = r.random() < 0.35
        else:
            ts += r.uniform(2, 15)
            malicious = r.random() < 0.9
        if malicious:
            sql = _attack_query(r, kind, k)
            k += 1
        else:
            sql = _support_query(r, n_users) if role == "support" else _analyst_query(r)
        events.append(_run(app, role, sql, ts))
    return Session(kind, role, events, True)


def sessions(app, seed, n_benign=200, n_per_attack=40):
    r = random.Random(seed)
    out = [benign_session(app, r) for _ in range(n_benign)]
    out += [attack_session(app, r, a) for a in ATTACKS for _ in range(n_per_attack)]
    return out


def live_attack(gateway, session, kind="enumeration", n=30, start=None, step=4.0, seed=0):
    """Run an attack through the real gateway as `session`, one query every `step` simulated seconds.
    Returns [(query_no, sql, risk, action, reasons, outcome)] and stops at the block (dashboard / CLI demo)."""
    r = random.Random(seed)
    t = start or time.time()
    out = []
    for i in range(n):
        sql = _attack_query(r, kind, i)
        t += step
        try:
            res = gateway.query(session, sql, now=t)
            outcome = f"{len(res.rows)} rows"
        except Rejected as e:
            outcome = str(e)[:120]
        snap = gateway.threat.latest.get(session.user) if gateway.threat else None
        a = snap[1] if snap else None
        out.append((i + 1, sql, a.risk if a else 0, a.action if a else "none", a.reasons if a else [], outcome))
        if "blocked" in outcome:
            break
    return out
