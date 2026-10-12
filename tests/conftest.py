import os, sqlite3, sys, pathlib, yaml, pytest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
os.environ.setdefault("MASKGUARD_HMAC_KEY", "test-key-not-for-prod")
from maskguard import masks
from maskguard.scanner import scan_sqlite
from maskguard.gateway import Authenticator, Gateway
from seed.make_data import make_db

@pytest.fixture()
def env(tmp_path):
    conn = sqlite3.connect(":memory:")
    masks.register_sqlite(conn)
    make_db(conn)
    registry = {t: scan_sqlite(conn, t) for t in ("users", "accounts")}
    policy = yaml.safe_load((ROOT / "policies" / "default.yaml").read_text())
    auth = Authenticator({"ann": ("pw", "admin"), "sam": ("pw", "support"), "ali": ("pw", "analyst"),
                          "eve": ("pw", "intern")})
    gw = Gateway(conn, registry, policy, auth, str(tmp_path / "audit.jsonl"))
    names = {r[0] for r in conn.execute("SELECT name FROM users")}
    raw = set()
    for t, cols in (("users", ["email", "phone", "aadhaar", "pan", "ssn"]), ("accounts", ["credit_card", "iban", "balance"])):
        for c in cols:
            raw |= {str(r[0]) for r in conn.execute(f"SELECT {c} FROM {t}")}
    return type("Env", (), dict(conn=conn, gw=gw, auth=auth, raw=raw, names=names, registry=registry, policy=policy))
