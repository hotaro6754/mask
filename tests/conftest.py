import os
import pytest

os.environ.setdefault("MASKGUARD_HMAC_KEY", "test-key-not-for-prod")
os.environ.setdefault("MASKGUARD_JWT_SECRET", "test-jwt-secret-not-for-prod-0123456789")

from maskguard import config  # noqa: E402

PG_URL = os.environ.get("MASKGUARD_TEST_PG")  # e.g. postgresql://postgres@127.0.0.1:5432/bank
BACKENDS = ["sqlite", pytest.param("postgres", marks=pytest.mark.skipif(not PG_URL, reason="MASKGUARD_TEST_PG not set"))]


def make_settings(tmp_path, backend):
    return config.Settings(db=PG_URL if backend == "postgres" else f"sqlite:///{tmp_path}/bank.db",
                           audit=str(tmp_path / "audit.jsonl"), registry_out=str(tmp_path / "registry.yaml"),
                           seed_if_empty=True)


class Env:
    def __init__(self, app):
        self.app, self.gw, self.auth, self.backend = app, app.gateway, app.auth, app.backend
        q = lambda sql: self.backend.admin_query(sql)[1]
        self.names = {str(r[0]) for r in q("SELECT name FROM users")}
        self.raw = set()
        for t, cols in (("users", ["email", "phone", "aadhaar", "pan", "ssn"]),
                        ("accounts", ["credit_card", "iban", "balance"]),
                        ("support_tickets", ["contact", "payment_ref"])):
            for c in cols:
                self.raw |= {str(r[0]) for r in q(f"SELECT {c} FROM {t}")}

    def login(self, role):
        return self.auth.login(*config.DEMO_ACCOUNTS[role])

    def run(self, role, sql):
        return self.gw.execute(self.login(role), sql)

    def real(self, col, table="users"):
        return self.backend.admin_query(f"SELECT {col} FROM {table} ORDER BY id LIMIT 1")[1][0][0]


@pytest.fixture(params=BACKENDS)
def env(request, tmp_path):
    from maskguard.seed import make_db
    app = config.build(make_settings(tmp_path, request.param))
    make_db(app.backend)  # fresh, deterministic data for every test (also resets a shared Postgres DB)
    return Env(app)


@pytest.fixture
def sqlite_env(tmp_path):
    return Env(config.build(make_settings(tmp_path, "sqlite")))
