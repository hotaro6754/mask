"""Builds a running MaskGuard (backend, scanner, gateway, auth) from environment settings."""
import os, time
from dataclasses import dataclass, field

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


def environment():
    return os.environ.get("MASKGUARD_ENV", "development").lower()


def demo_enabled():
    default = "0" if environment() == "production" else "1"
    on = os.environ.get("MASKGUARD_DEMO", default) == "1"
    if on and environment() == "production":
        raise RuntimeError("MASKGUARD_DEMO=1 is not allowed when MASKGUARD_ENV=production")
    return on


def demo_accounts():
    return dict(DEMO_ACCOUNTS) if demo_enabled() else {}


DEMO_ENABLED = os.environ.get("MASKGUARD_DEMO", "0" if environment() == "production" else "1") == "1"


def _env(name, default):
    return os.environ.get(name, default)


@dataclass
class Settings:
    db: str = field(default_factory=lambda: _env("MASKGUARD_DB", "sqlite:///data/bank.db"))
    policy: str = field(default_factory=lambda: _env("MASKGUARD_POLICY", "policies/default.yaml"))
    users: str = field(default_factory=lambda: _env("MASKGUARD_USERS", "policies/users.demo.yaml"))
    overrides: str = field(default_factory=lambda: _env("MASKGUARD_OVERRIDES", "policies/overrides.yaml"))
    registry_out: str = field(default_factory=lambda: _env("MASKGUARD_REGISTRY", "data/registry.yaml"))
    audit: str = field(default_factory=lambda: _env("MASKGUARD_AUDIT", "data/audit.jsonl"))
    scan_interval: int = field(default_factory=lambda: int(_env("MASKGUARD_SCAN_INTERVAL", "300")))
    seed_if_empty: bool = field(default_factory=lambda: _env("MASKGUARD_SEED_IF_EMPTY", "1") == "1")
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
    for p in (s.audit, s.registry_out):
        if p and os.path.dirname(p):
            os.makedirs(os.path.dirname(p), exist_ok=True)
    if s.db.startswith("sqlite:///") and s.db != "sqlite:///:memory:" and os.path.dirname(s.db[10:]):
        os.makedirs(os.path.dirname(s.db[10:]), exist_ok=True)
    backend = connect(s.db)
    demo_enabled()  # refuse demo identities in production before anything starts
    if s.seed_if_empty and not backend.tables():
        make_db(backend)
    policy, overrides = _load_yaml(s.policy), _load_yaml(s.overrides)
    store = PolicyStore(policy, s.state("policy_history.jsonl"))  # validates; refuses an unsafe policy
    registry = scan(backend, overrides=overrides)
    if s.registry_out:
        save_registry(registry, s.registry_out)
    auth = Authenticator.from_file(s.users)
    gateway = Gateway(backend, registry, policy, auth, s.audit)
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
