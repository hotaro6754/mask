"""Builds a running MaskGuard (backend, scanner, gateway, auth) from environment settings."""
import os
from dataclasses import dataclass, field

import yaml

from .auth import Authenticator
from .backends import connect
from .gateway import Gateway
from .scanner import ScanWorker, save_registry, scan
from .seed import make_db


# Demo accounts for the role toggle and `maskguard roles`. Set MASKGUARD_DEMO=0 in any real deployment.
DEMO_ENABLED = os.environ.get("MASKGUARD_DEMO", "1") == "1"
DEMO_ACCOUNTS = {"admin": ("admin.ann", "admin123"), "support": ("support.sam", "support123"),
                 "analyst": ("analyst.ali", "analyst123")}


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


@dataclass
class App:
    settings: Settings
    backend: object
    gateway: Gateway
    auth: Authenticator
    worker: ScanWorker = None


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
    if s.seed_if_empty and not backend.tables():
        make_db(backend)
    policy, overrides = _load_yaml(s.policy), _load_yaml(s.overrides)
    registry = scan(backend, overrides=overrides)
    if s.registry_out:
        save_registry(registry, s.registry_out)
    auth = Authenticator.from_file(s.users)
    gateway = Gateway(backend, registry, policy, auth, s.audit)
    app = App(s, backend, gateway, auth)
    if start_worker:
        def on_update(reg):
            gateway.update_registry(reg)
            if s.registry_out:
                save_registry(reg, s.registry_out)
        app.worker = ScanWorker(backend, on_update, s.scan_interval, overrides)
        app.worker.start()
    return app
