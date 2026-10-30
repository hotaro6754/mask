"""Python SDK against a real HTTP server (uvicorn in a thread)."""

import socket
import threading
import time

import pytest
import uvicorn

from maskguard import api
from maskguard.client import MaskGuardClient, MaskGuardError


@pytest.fixture
def server(sqlite_env):
    api.state["app"] = sqlite_env.app
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    srv = uvicorn.Server(uvicorn.Config(api.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    srv.should_exit = True
    t.join(5)
    api.state.clear()


def test_sdk_roles_and_admin(server):
    sup = MaskGuardClient(server, "support.sam", "support123")
    row = sup.query("SELECT ssn, email FROM users ORDER BY id LIMIT 1")[0]
    assert row["ssn"].startswith("XXX-XX-") and "***@" in row["email"]
    assert {k: sup.me()[k] for k in ("user", "role")} == {"user": "support.sam", "role": "support"}
    ana = MaskGuardClient(server, "analyst.ali", "analyst123")
    r = ana.query_raw("SELECT status, avg(balance) FROM accounts GROUP BY status")
    assert r["dp"]["epsilon"] > 0 and r["dp"]["remaining"] < 10
    assert ana.query_df("SELECT count(*) AS n FROM users").iloc[0]["n"] == 300
    adm = MaskGuardClient(server, "admin.ann", "admin123")
    assert len(adm.registry()) >= 10 and adm.audit()["chain_valid"]
    assert isinstance(adm.threats(), dict)


def test_sdk_errors(server):
    with pytest.raises(MaskGuardError) as e:
        MaskGuardClient(server, "support.sam", "wrong")
    assert e.value.status == 401
    sup = MaskGuardClient(server, "support.sam", "support123")
    with pytest.raises(MaskGuardError, match="400"):
        sup.query("DROP TABLE users")
    with pytest.raises(MaskGuardError, match="403"):
        sup.registry()
