"""Builds a running MaskGuard (backend, scanner, gateway, auth) from environment settings."""
import ipaddress, os, time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

from .auth import Authenticator
from .backends import connect
from .gateway import Gateway
from .integrity import IntegrityStore
from .policy import PolicyStore
from .scanner import ScanWorker, save_registry, scan
from .seed import make_db


# Demo identities for the role toggle, `maskguard compare` and the dashboard playground. They are ordinary users from
# policies/users.demo.yaml (real login, real tokens); demo mode only lets evaluators switch between them without
# typing passwords. It is on by default in development, off by default when MASKGUARD_ENV=production, and refused
# outright if someone turns it on in production.
DEMO_ACCOUNTS = {"admin": ("admin.ann", "admin123"), "support": ("support.sam", "support123"),
                 "analyst": ("analyst.ali", "analyst123"), "auditor": ("auditor.aud", "auditor123")}


ENVIRONMENTS = ("development", "production")


class UnsafeConfiguration(RuntimeError):
    """Settings that would weaken a guarantee. Startup stops and the message lists every problem at once."""

    def __init__(self, problems):
        self.problems = list(problems)
        super().__init__("unsafe configuration, refusing to start:\n" + "\n".join(f"  - {p}" for p in self.problems))


def environment():
    env = os.environ.get("MASKGUARD_ENV", "development").strip().lower()
    if env not in ENVIRONMENTS:  # a typo such as "prod" must not quietly mean development (demo identities on)
        raise UnsafeConfiguration([f"MASKGUARD_ENV={env!r} is not one of: {', '.join(ENVIRONMENTS)}"])
    return env


def demo_enabled():
    default = "0" if environment() == "production" else "1"
    on = os.environ.get("MASKGUARD_DEMO", default) == "1"
    if on and environment() == "production":
        raise RuntimeError("MASKGUARD_DEMO=1 is not allowed when MASKGUARD_ENV=production")
    return on


def demo_accounts():
    return dict(DEMO_ACCOUNTS) if demo_enabled() else {}


def check_production_identity(auth):
    """Production must not accept the shipped demo identities through /auth/login. Turning demo mode off only
    removes /auth/demo; the demo users would still log in from a copy of the demo user store."""
    if environment() != "production":
        return
    demo = sorted(u for u, _ in DEMO_ACCOUNTS.values() if u in auth.users)
    if demo:
        raise UnsafeConfiguration([(f"the user store contains demo identities ({', '.join(demo)}): "
                                    "set MASKGUARD_USERS to a production user file")])
    if not auth.users:
        raise UnsafeConfiguration(["the user store has no users"])


# Secrets copied from the examples or docs are as good as public.
PLACEHOLDER_MARKERS = ("change-me", "changeme", "dev-only", "not-for-prod", "example", "placeholder")
MIN_SECRET_LEN = 32
PRODUCTION_DB_SCHEMES = ("postgres", "postgresql", "mysql", "mysql+pymysql")


def _secret_problem(name):
    v = os.environ.get(name, "")
    if not v:
        return f"{name} is not set (no generated or default secret is used in production)"
    if len(v) < MIN_SECRET_LEN:
        return f"{name} is shorter than {MIN_SECRET_LEN} characters"
    if any(m in v.lower() for m in PLACEHOLDER_MARKERS):
        return f"{name} looks like a placeholder from the examples"
    return None


def _same_file(a, b):
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.realpath(a) == os.path.realpath(b)


def production_problems(settings):
    """Everything that must hold before a production gateway touches a database. Empty list = OK."""
    problems = []
    if os.environ.get("MASKGUARD_DEMO", "0") != "0":
        problems.append("MASKGUARD_DEMO must be 0: demo identities and /auth/demo stay off in production")
    if any(_same_file(settings.users, f) for f in DEMO_USERS_FILES):
        problems.append("MASKGUARD_USERS is unset or points at the demo user store: production needs its own user file")
    elif not os.path.isfile(settings.users):
        problems.append(f"MASKGUARD_USERS file not found: {settings.users}")
    for name in ("MASKGUARD_JWT_SECRET", "MASKGUARD_HMAC_KEY"):
        msg = _secret_problem(name)
        if msg:
            problems.append(msg)
    if urlparse(settings.db).scheme not in PRODUCTION_DB_SCHEMES:
        problems.append("MASKGUARD_DB must be a PostgreSQL or MySQL URL for a least-privilege account: production never "
                        "falls back to the bundled SQLite demo database")
    if settings.seed_if_empty:
        problems.append("MASKGUARD_SEED_IF_EMPTY must be 0: production never writes demo data into a database")
    return problems


def is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def listen_problems(service, host, tls=False):
    """Network exposure rules. Development: anything goes. Production: off-loopback only with verified TLS."""
    if environment() != "production" or is_loopback(host):
        return []
    if service == "api":
        return [] if tls else [
            (f"the API would listen on {host!r} without TLS: pass --ssl-certfile and --ssl-keyfile "
             "(MASKGUARD_TLS_CERT / MASKGUARD_TLS_KEY), or bind 127.0.0.1")]
    if service == "proxy":
        return [(f"the PostgreSQL proxy would listen on {host!r}: it has no TLS (it declines SSLRequest and takes "
                 "cleartext passwords), so production allows it on loopback only")]
    return [f"the {service} would listen on {host!r}: production allows it on loopback only (its TLS is untested)"]


def _env(name, default):
    return os.environ.get(name, default)


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))  # pip installs ship policies/ inside the package
DEMO_USERS_FILE = os.path.join(ROOT, "policies", "users.demo.yaml")
# Every copy of the demo user store: the source tree's and the one bundled in an installed package.
DEMO_USERS_FILES = (DEMO_USERS_FILE, os.path.join(PACKAGE_DIR, "policies", "users.demo.yaml"))


def _cfg(name, default):
    """Config file path: env var, else ./default, else the copy in the source tree, else the copy in the package."""
    v = os.environ.get(name)
    if v:
        return v
    for path in (default, os.path.join(ROOT, default), os.path.join(PACKAGE_DIR, default)):
        if os.path.exists(path):
            return path
    return default


@dataclass
class Settings:
    db: str = field(default_factory=lambda: _env("MASKGUARD_DB", "sqlite:///data/bank.db"))
    policy: str = field(default_factory=lambda: _cfg("MASKGUARD_POLICY", "policies/default.yaml"))
    users: str = field(default_factory=lambda: _cfg("MASKGUARD_USERS", "policies/users.demo.yaml"))
    overrides: str = field(default_factory=lambda: _cfg("MASKGUARD_OVERRIDES", "policies/overrides.yaml"))
    registry_out: str = field(default_factory=lambda: _env("MASKGUARD_REGISTRY", "data/registry.yaml"))
    audit: str = field(default_factory=lambda: _env("MASKGUARD_AUDIT", "data/audit.jsonl"))
    scan_interval: int = field(default_factory=lambda: int(_env("MASKGUARD_SCAN_INTERVAL", "300")))
    seed_if_empty: bool = field(  # never on by default in production
        default_factory=lambda: _env("MASKGUARD_SEED_IF_EMPTY", "0" if environment() == "production" else "1") == "1")
    state_dir: str = field(default_factory=lambda: _env("MASKGUARD_STATE_DIR", ""))  # default: next to the audit log

    def state(self, name):
        return os.path.join(self.state_dir or os.path.dirname(self.audit) or ".", name)


@dataclass
class App:
    settings: Settings
    backend: object
    gateway: Gateway
    auth: Authenticator
    policy: PolicyStore = None
    integrity: IntegrityStore = None
    worker: ScanWorker = None
    started: float = field(default_factory=time.time)


def _load_yaml(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def build(settings=None, start_worker=False):
    s = settings or Settings()
    production = environment() == "production"
    if production:  # before touching the database: nothing below runs on an unsafe configuration
        problems = production_problems(s)
        if problems:
            raise UnsafeConfiguration(problems)
    for p in (s.audit, s.registry_out):
        if p and os.path.dirname(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
    if s.db.startswith("sqlite:///") and s.db != "sqlite:///:memory:" and os.path.dirname(s.db[10:]):
        os.makedirs(os.path.dirname(s.db[10:]), exist_ok=True)
    try:  # production runs on a read-only account: the masking functions come from `maskguard db-install`
        backend = connect(s.db, install=not production)
    except RuntimeError as e:
        raise UnsafeConfiguration([str(e)]) if production else e
    demo_enabled()  # refuse demo identities in production before anything starts
    if production:
        problems = backend.privilege_problems()
        if problems:
            raise UnsafeConfiguration(problems)
    if s.seed_if_empty and not backend.tables():
        make_db(backend)
    policy, overrides = _load_yaml(s.policy), _load_yaml(s.overrides)
    store = PolicyStore(policy, s.state("policy_history.jsonl"))  # validates; refuses an unsafe policy
    auth = Authenticator.from_file(s.users)
    check_production_identity(auth)
    registry = scan(backend, overrides=overrides)
    if s.registry_out:
        save_registry(registry, s.registry_out)
    gateway = Gateway(backend, registry, policy, auth, s.audit, allow_dp=not production, allow_self_test=not production)
    integrity = IntegrityStore(backend, s.db, s.state("integrity_baseline.json"), s.state("integrity_history.jsonl"))
    integrity.ensure_baseline()
    app = App(s, backend, gateway, auth, store, integrity)
    if start_worker:
        def on_update(reg):
            gateway.update_registry(reg)
            if s.registry_out:
                save_registry(reg, s.registry_out)
        app.worker = ScanWorker(backend, on_update, s.scan_interval, overrides)
        app.worker.start()
    return app
