"""Control Room web dashboard: assets, CSP, and (when Node + Playwright are available) a full browser walkthrough."""
import os, shutil, socket, subprocess, threading, time

import pytest
from fastapi.testclient import TestClient

from maskguard import api

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_assets_served_without_inline_code(sqlite_env):
    api.state["app"] = sqlite_env.app
    c = TestClient(api.app)
    try:
        html = c.get("/ui/").text
        assert "<script src=\"app.js\"></script>" in html and "onclick=" not in html and "<style" not in html
        js = c.get("/ui/app.js")
        assert js.status_code == 200 and "innerHTML" not in js.text  # values are always inserted as text
        assert c.get("/ui/app.css").status_code == 200
        assert c.get("/").status_code in (200, 307) and c.get("/postman").status_code == 200
    finally:
        api.state.clear()


@pytest.mark.skipif(not shutil.which("node") or not os.path.isdir("/opt/node22/lib/node_modules/playwright"),
                    reason="node + playwright not installed")
def test_browser_walkthrough(sqlite_env, tmp_path):
    import uvicorn
    api.state["app"] = sqlite_env.app
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(api.app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True); t.start()
    while not server.started:
        time.sleep(0.05)
    try:
        r = subprocess.run(["node", os.path.join(ROOT, "scripts", "ui_smoke.js"), f"http://127.0.0.1:{port}", str(tmp_path)],
                           capture_output=True, text=True, timeout=300,
                           env={**os.environ, "NODE_PATH": "/opt/node22/lib/node_modules"})
        assert r.returncode == 0, r.stdout + r.stderr
        assert "no console errors" in r.stdout and "overflow px: 0" in r.stdout
    finally:
        server.should_exit = True; t.join(5); api.state.clear()
