"""Builds a running MaskGuard (backend, scanner, gateway, auth) from environment settings."""
import ipaddress, os, secrets, time
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
    env = _env("MASKGUARD_ENV", "development").strip().lower()
    if env not in ENVIRONMENTS:  # a typo such as "prod" must not quietly mean development (demo identities on)
        raise UnsafeConfiguration([f"MASKGUARD_ENV={env!r} is not one of: {', '.join(ENVIRONMENTS)}"])
    return env


def demo_enabled():
    default = "0" if environment() == "production" else "1"
    on = _env("MASKGUARD_DEMO", default) == "1"
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


# Settings saved by `maskguard connect` (or written by hand): MASKGUARD_* names and values, in the folder you run
# MaskGuard from. Environment variables win over it. Secrets never go in it.
SETTINGS_FILE = "maskguard.yaml"
SECRET_NAMES = ("MASKGUARD_HMAC_KEY", "MASKGUARD_JWT_SECRET")


def settings_file():
    return os.environ.get("MASKGUARD_CONFIG") or SETTINGS_FILE


def file_settings():
    try:
        with open(settings_file()) as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}
    return {k: str(v) for k, v in data.items() if k.startswith("MASKGUARD_") and k not in SECRET_NAMES}


def save_settings(values):
    """Merge MASKGUARD_* values into the settings file (None removes one). Readable only by you: it can hold a
    database URL with a password."""
    data = {**file_settings(), **values}
    data = {k: v for k, v in data.items() if v is not None}
    fd = os.open(settings_file(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("# MaskGuard settings for this folder (written by `maskguard connect`). Environment variables win.\n")
        yaml.safe_dump(data, f, sort_keys=True)
    return settings_file()


def _env(name, default):
    v = os.environ.get(name)
    return v if v is not None else file_settings().get(name, default)


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))  # pip installs ship policies/ inside the package
DEMO_USERS_FILE = os.path.join(ROOT, "policies", "users.demo.yaml")
# Every copy of the demo user store: the source tree's and the one bundled in an installed package.
DEMO_USERS_FILES = (DEMO_USERS_FILE, os.path.join(PACKAGE_DIR, "policies", "users.demo.yaml"))


def _cfg(name, default):
    """Config file path: env var (or settings file), else ./default, else the source tree's copy, else the package's."""
    v = os.environ.get(name) or (file_settings().get(name) if name else None)
    if v:
        return v
    for path in (default, os.path.join(ROOT, default), os.path.join(PACKAGE_DIR, default)):
        if os.path.exists(path):
            return path
    return default


# The bundled demo schema's non-personal columns (ids, status, city, ...), reviewed and approved as PUBLIC.
DEMO_PUBLIC_FILE = "policies/public.demo.yaml"
# The demo bank's row filters (support never sees frozen accounts): demo data only.
DEMO_ROW_FILTERS_FILE = "policies/row_filters.demo.yaml"


def load_policy(settings):
    """The policy file, plus the demo bank's row filters when running on the demo data. A filter written for the demo
    schema would refuse every query on another database's table of the same name (its column isn't there)."""
    policy = _load_yaml(settings.policy)
    if demo_enabled() and settings.seed_if_empty:
        for role, tables in (_load_yaml(_cfg("", DEMO_ROW_FILTERS_FILE)) or {}).items():
            rf = policy.setdefault("row_filters", {}) or {}
            policy["row_filters"] = rf
            for table, cond in (tables or {}).items():
                rf.setdefault(role, {}).setdefault(table, cond)
    return policy


def load_overrides(settings):
    """Manual tags from the overrides file. With demo data (demo mode, and a database MaskGuard may seed) the demo
    schema's approved-public columns are added too, but only where the scanner found nothing (an approval never hides
    a detection). Your own database and production never get them."""
    overrides = {t: dict(c or {}) for t, c in (_load_yaml(settings.overrides) or {}).items()}
    if demo_enabled() and settings.seed_if_empty:
        for table, cols in (_load_yaml(_cfg("", DEMO_PUBLIC_FILE)) or {}).items():
            for col in cols or []:
                overrides.setdefault(table, {}).setdefault(col, {
                    "tag": "PUBLIC", "if_untagged": True, "source": "approval",
                    "evidence": "demo schema: reviewed and approved as non-personal (policies/public.demo.yaml)"})
    return overrides


@dataclass
class Settings:
    db: str = field(default_factory=lambda: _env("MASKGUARD_DB", "sqlite:///data/bank.db"))
    policy: str = field(default_factory=lambda: _cfg("MASKGUARD_POLICY", "policies/default.yaml"))
    users: str = field(default_factory=lambda: _cfg("MASKGUARD_USERS", "policies/users.demo.yaml"))
    overrides: str = field(default_factory=lambda: _cfg("MASKGUARD_OVERRIDES", "policies/overrides.yaml"))
    registry_out: str = field(default_factory=lambda: _env("MASKGUARD_REGISTRY", "data/registry.yaml"))
    audit: str = field(default_factory=lambda: _env("MASKGUARD_AUDIT", "data/audit.jsonl"))
    scan_interval: int = field(default_factory=lambda: int(_env("MASKGUARD_SCAN_INTERVAL", "300")))
    # Demo data goes only into the bundled demo database by default: never into a database you point MaskGuard at
    # (set MASKGUARD_SEED_IF_EMPTY=1 to seed one on purpose), and never in production.
    seed_if_empty: bool = field(default_factory=lambda: _env(
        "MASKGUARD_SEED_IF_EMPTY", "1" if environment() != "production" and not _env("MASKGUARD_DB", "") else "0") == "1")
    state_dir: str = field(default_factory=lambda: _env("MASKGUARD_STATE_DIR", ""))  # default: next to the audit log

    def state(self, name):
        return os.path.join(self.state_dir or os.path.dirname(self.audit) or ".", name)


GENERATED = {}  # secret name -> file it was generated into, this process (development only)


def ensure_dev_secrets(settings):
    """Development only: a random HMAC key and JWT secret, made once for this machine and kept in the state folder
    (readable only by you), so tokens and logins survive restarts. Production never generates secrets."""
    if environment() == "production":
        return
    missing = [n for n in SECRET_NAMES if not os.environ.get(n)]
    if not missing:
        return
    path = _env("MASKGUARD_SECRETS_FILE", os.path.join("data", "secrets.yaml"))  # one per folder, whatever the database
    stored = _load_yaml(path)
    new = {n: secrets.token_hex(32) for n in missing if not stored.get(n)}
    if new:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("# Generated by MaskGuard for development on this machine. Keep it private; never commit it.\n"
                    "# Production needs its own secrets (MASKGUARD_HMAC_KEY, MASKGUARD_JWT_SECRET).\n")
            yaml.safe_dump({**stored, **new}, f, sort_keys=True)
    for n in missing:
        os.environ[n] = stored.get(n) or new[n]
        GENERATED[n] = path


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
    ensure_dev_secrets(s)  # before anything that issues tokens or computes them
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
    policy, overrides = load_policy(s), load_overrides(s)
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
        app.worker = ScanWorker(backend, on_update, s.scan_interval, lambda: load_overrides(s))
        app.worker.start()
    return app
