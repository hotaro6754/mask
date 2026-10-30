"""Insider-threat engine: rules, ML calibration, gateway blocking, unblocking, and no harm to normal users."""

import random
from pathlib import Path

import numpy as np
import pytest

from maskguard.rewriter import Rejected
from maskguard.threat import AnomalyModel, Event, ThreatEngine, rule_risk
from maskguard.threat_sim import benign_session, live_attack


def ev(i, fp="SELECT id FROM users WHERE email = ?", masked=1, decision="allow", rows=0, **shape):
    return Event(1_760_000_000 + 4 * i, decision, fp, rows, {"pred_masked": masked, "literal_hash": i, **shape})


def test_enumeration_rule_fires_with_reason():
    risk, reasons = rule_risk([ev(i) for i in range(20)])
    assert risk >= 70 and any("enumeration" in r for r in reasons)


def test_repeating_the_same_lookup_is_not_enumeration():
    same = [
        Event(1_760_000_000 + 4 * i, "allow", "SELECT * FROM t WHERE id = ?", 1, {"literal_hash": 7}) for i in range(30)
    ]
    assert rule_risk(same)[0] < 70


def test_firewall_burst_rule():
    risk, reasons = rule_risk([ev(i, fp=f"bad{i}", decision="reject", masked=0) for i in range(6)])
    assert risk >= 70 and any("firewall" in r for r in reasons)


def test_ml_alone_alerts_but_cannot_block():
    X = np.random.default_rng(0).normal(0, 1, (500, 19)).astype(np.float32)
    model = AnomalyModel(X)
    eng = ThreatEngine({}, model, use_rules=False)
    model.risk = lambda x: 99  # pretend the anomaly score is extreme
    a = None
    for i in range(10):
        a = eng.observe("u", Event(1_760_000_000 + i, "allow", f"q{i}", 1, {}))
    assert a.action == "alert" and a.risk == eng.block - 1


@pytest.mark.parametrize("kind", ["enumeration", "order_probe", "bulk_paging", "firewall_probe"])
def test_gateway_blocks_simulated_insider_and_admin_can_unblock(sqlite_env, kind):
    env = sqlite_env
    intruder = env.auth.login("intruder.ian", "intruder123")
    steps = live_attack(env.gw, intruder, kind, n=60)
    assert steps[-1][3] == "block", steps[-1]
    with pytest.raises(Rejected, match="blocked"):
        env.gw.query(intruder, "SELECT id FROM users LIMIT 1")
    assert '"decision": "blocked"' in Path(env.gw.audit.path).read_text(encoding="utf-8")
    env.gw.threat.unblock("intruder.ian")
    assert env.gw.query(intruder, "SELECT id FROM users LIMIT 1").rows


def test_normal_sessions_are_not_blocked(sqlite_env):
    r = random.Random(77)
    eng = ThreatEngine({}, AnomalyModel.load())
    for i in range(25):
        s = benign_session(sqlite_env.app, r)
        for e in s.events:
            assert eng.observe(f"n{i}", e).action != "block"


def test_attack_self_test_does_not_feed_the_threat_engine(sqlite_env):
    from maskguard.attacks import run_suite

    s = sqlite_env.login("support")
    run_suite(sqlite_env.gw, s)
    assert "support.sam" not in sqlite_env.gw.threat.latest


def test_threat_endpoints(sqlite_env):
    from fastapi.testclient import TestClient

    from maskguard import api

    api.state["app"] = sqlite_env.app
    try:
        c = TestClient(api.app)
        tok = c.post("/auth/login", json={"username": "admin.ann", "password": "admin123"}).json()["token"]
        h = {"Authorization": f"Bearer {tok}"}
        intruder = sqlite_env.auth.login("intruder.ian", "intruder123")
        live_attack(sqlite_env.gw, intruder, "enumeration", n=40)
        assert c.get("/threats", headers=h).json()["users"]["intruder.ian"]["blocked"] is True
        assert c.post("/threats/intruder.ian/unblock", headers=h).status_code == 200
        assert not sqlite_env.gw.threat.is_blocked("intruder.ian")
    finally:
        api.state.clear()


def test_fast_scorer_matches_sklearn():
    m = AnomalyModel.load()
    assert m._trees is not None
    X = np.load("src/maskguard/ml/threat_benign_windows.npz")["X"]
    rng = np.random.default_rng(1)
    test = np.vstack([X[rng.integers(0, len(X), 100)], rng.normal(0, 3, (50, X.shape[1])).astype(np.float32)])
    assert np.allclose([m.score(x) for x in test], -m.forest.score_samples(test), atol=1e-12)
