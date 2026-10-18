"""Service layer behind the CLI: one interface, two transports.

LocalService  runs the engine in-process (config.build): the same Gateway, rewriter and policy the API uses.
              The operator holds the database URL and config files, so operator commands (scan, integrity,
              audit) run with that authority; data queries still go through Gateway.query under a real user
              session (a demo identity in demo mode, or --user/--password).
RemoteService talks to a running API (`--api URL` or MASKGUARD_API) through the Python SDK. Every call then
              carries a token and is checked against that identity's capabilities on the server.

Both return plain dicts shaped like the REST responses, so the CLI renders them the same way.
"""
import datetime, decimal, os, time

from . import config, policy as P
from .rewriter import Rejected, tag_of


class Denied(Exception):
    """Authorization or policy refusal (exit code 3)."""


class Unavailable(Exception):
    """Backend, database or API not reachable (exit code 4)."""


def _jsonable(v):
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    return v


class LocalService:
    mode = "local"

    def __init__(self, app=None):
        try:
            self.app = app or config.build()
        except config.UnsafeConfiguration as e:  # lists configuration problems only, never data: show all of them
            raise Unavailable(f"cannot start the engine: {e}") from None
        except Exception as e:
            raise Unavailable(f"cannot start the engine: {type(e).__name__}: {str(e)[:160]}") from None
        self.gw = self.app.gateway

    # ---- identity ----
    def session(self, role=None, user=None, password=None):
        try:
            if user:
                return self.app.auth.login(user, password or "")
            accounts = config.demo_accounts()
            if role not in accounts:
                raise Denied(f"no demo identity for role '{role}'" if accounts else
                             "demo mode is off: use --user/--password")
            return self.app.auth.login(*accounts[role])
        except PermissionError:
            raise Denied("bad credentials") from None

    # ---- status ----
    def status(self):
        a, gw = self.app, self.gw
        checks = []
        try:
            n = len(a.backend.tables())
            checks.append(("Database", True, f"{a.backend.dialect} · {n} tables"))
        except Exception as e:
            checks.append(("Database", False, type(e).__name__))
        from .scanner import ML_HINT, ml_available, summary, unreviewed
        tagged, pending, ml = summary(gw.registry), unreviewed(gw.registry), ml_available()
        checks.append(("PII scanner", True, f"{len(tagged)} sensitive columns · "
                                            + (f"{len(pending)} unreviewed (masked) · " if pending else "")
                                            + ("LightGBM + checksums" if ml else f"rules only: {ML_HINT}")))
        warn = set() if ml else {"PII scanner"}  # works, but finds less: unrecognised columns stay masked
        errs = P.validate(gw.policy)
        checks.append(("Policy engine", not errs, f"{P.version(gw.policy)} · default {gw.policy.get('default_action', 'deny')}"
                                                  + (f" · {errs[0]}" if errs else "")))
        checks.append(("Audit trail", gw.audit.verify(), "hash chain intact" if gw.audit.verify() else "CHAIN BROKEN"))
        base = a.integrity.baseline()
        checks.append(("Integrity baseline", base is not None, base["taken_at"] if base else "none recorded"))
        gen = config.GENERATED.get("MASKGUARD_HMAC_KEY")
        checks.append(("HMAC key", bool(os.environ.get("MASKGUARD_HMAC_KEY")),
                       f"generated for this machine ({gen})" if gen else "set" if os.environ.get("MASKGUARD_HMAC_KEY") else "MISSING"))
        checks.append(("Threat engine", gw.threat is not None, "rules + IsolationForest" if gw.threat else "off"))
        checks.append(("Noisy aggregates", True, "enabled (development only; not a formal DP guarantee)" if gw.allow_dp
                       else "disabled in production (design review pending)"))
        return {"mode": self.mode, "environment": config.environment(), "demo_mode": config.demo_enabled(),
                "backend": a.backend.dialect, "policy_version": P.version(gw.policy),
                "checks": [{"name": n, "ok": ok, "detail": d, **({"warn": True} if n in warn else {})}
                           for n, ok, d in checks]}

    # ---- schema & scanner ----
    def inventory(self):
        out = []
        for t, cols in sorted(self.gw.registry.items()):
            for c, m in cols.items():
                out.append({"table": t, "column": c, "sql_type": m.get("sql_type"), "tag": tag_of(m),
                            "kind": m.get("kind"), "confidence": m.get("confidence"), "source": m.get("source"),
                            "evidence": m.get("evidence"), **({"suggest": "PUBLIC"} if not m.get("tag") and m.get("suggest") else {})})
        return out

    def tables(self):
        b = self.app.backend
        return [{"table": t, "columns": len(b.columns(t)), "rows": b.admin_query(f"SELECT count(*) FROM {b._qualified(t)}")[1][0][0],
                 "scanned": t in self.gw.registry} for t in b.tables()]

    def review(self, columns, tag="PUBLIC", kind=None):
        """Record a person's decision for columns (PUBLIC = not personal data, or a classification) in the overrides
        file, then rescan so it applies at once. Writes MASKGUARD_OVERRIDES if set, else ./policies/overrides.yaml."""
        import yaml
        from .scanner import save_registry, scan
        tag = tag.upper()
        known = set(P.known_tags(self.gw.policy, self.gw.registry)) | {"PUBLIC"}
        if tag not in known or tag == "UNREVIEWED":
            raise Denied(f"unknown classification {tag}; use PUBLIC or one of: {', '.join(sorted(known - {'PUBLIC', 'UNREVIEWED'}))}")
        reg = {t.lower(): (t, {c.lower(): c for c in cols}) for t, cols in self.gw.registry.items()}
        picked = []
        for name in columns:
            t, _, c = name.partition(".")
            if t.lower() not in reg or c.lower() not in reg[t.lower()][1]:
                raise Denied(f"unknown column {name}: use TABLE.COLUMN as `maskguard pii list` shows it")
            picked.append((reg[t.lower()][0], reg[t.lower()][1][c.lower()]))
        target = config._env("MASKGUARD_OVERRIDES", "") or os.path.join("policies", "overrides.yaml")
        current = config._load_yaml(target if os.path.exists(target) else self.app.settings.overrides) or {}
        for t, c in picked:
            current.setdefault(t, {})[c] = {"tag": tag, **({"kind": kind} if kind else {})}
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        with open(target, "w") as f:
            f.write("# Reviewed classifications (maskguard pii approve / pii tag). They win over the scanner.\n"
                    "# PUBLIC = a person checked the column and it is not personal data: every role sees it.\n")
            yaml.safe_dump(current, f, sort_keys=True)
        os.environ.setdefault("MASKGUARD_OVERRIDES", target)  # this process rescans with it; later runs find it in ./
        self.app.settings.overrides = target
        new = scan(self.app.backend, overrides=config.load_overrides(self.app.settings))
        self.gw.update_registry(new)
        if self.app.settings.registry_out:
            save_registry(new, self.app.settings.registry_out)
        self.gw.audit.append(user="cli-operator", role="operator", decision="pii_review", channel="cli",
                             target=",".join(f"{t}.{c}" for t, c in picked), reason=f"tag={tag}")
        return {"file": target, "tag": tag, "columns": [f"{t}.{c}" for t, c in picked]}

    def scan(self, tables=None, sample_limit=200, dry_run=False):
        from .scanner import save_registry, scan, summary
        known = set(self.app.backend.tables())
        if tables and not set(tables) <= known:
            raise Denied(f"unknown table(s): {', '.join(sorted(set(tables) - known))}")
        t0 = time.perf_counter()
        reg = scan(self.app.backend, tables=tables, overrides=config.load_overrides(self.app.settings),
                   sample_size=sample_limit)
        if not dry_run:
            merged = dict(self.gw.registry); merged.update(reg)
            self.gw.update_registry(merged)
            if self.app.settings.registry_out:
                save_registry(merged, self.app.settings.registry_out)
        self.gw.audit.append(user="cli-operator", role="operator", decision="scan", channel="cli",
                             target=",".join(tables or ["*"]), dry_run=dry_run, sample_limit=sample_limit)
        return {"scanned_at": datetime.datetime.now().isoformat(timespec="seconds"), "dry_run": dry_run,
                "applied": not dry_run, "sample_limit": sample_limit, "tables": sorted(reg),
                "ms": round((time.perf_counter() - t0) * 1000, 1), "tagged": summary(reg),
                "registry_file": None if dry_run else self.app.settings.registry_out}

    # ---- policy ----
    def roles(self):
        return P.roles(self.gw.policy)

    def explain(self, role, table):
        try:
            return P.explain(role, table, self.gw.registry, self.gw.policy)
        except KeyError as e:
            raise Denied(str(e).strip("'\"")) from None

    def matrix(self):
        return P.matrix(self.gw.registry, self.gw.policy)

    def set_rule(self, role, tag, action, reason="", confirm=False):
        try:
            r = self.app.policy.set_rule(role, tag, action, "cli-operator", reason, confirm)
        except P.PolicyError as e:
            raise Denied(str(e)) from None
        if r["changed"]:
            self.gw.audit.append(user="cli-operator", role="operator", decision="policy_change", channel="cli",
                                 target=f"{role}/{tag}", change=f"{r['entry']['from']} -> {action}", reason=reason[:160])
        return r

    def policy_history(self):
        return self.app.policy.history()

    # ---- data ----
    def query(self, sql, role=None, user=None, password=None):
        s = self.session(role, user, password)
        try:
            r = self.gw.query(s, sql, channel="cli")
        except Rejected as e:
            raise Denied(f"rejected: {e} [{getattr(e, 'request_id', '')}]") from None
        except Exception as e:  # never echo database errors (they can quote values)
            from .gateway import safe_error
            raise Denied(safe_error(e)) from None
        return {"role": s.role, "user": s.user, "columns": r.columns,
                "rows": [[_jsonable(v) for v in row] for row in r.rows], "row_count": len(r.rows), "masked": r.masked,
                "rewritten_sql": r.rewritten_sql, "ms": round(r.ms, 2), "risk": r.risk, "dp": r.dp,
                "request_id": r.request_id, "policy_version": r.policy_version}

    def query_table(self, table, columns=None, limit=10, role=None, user=None, password=None):
        sql = self._table_sql(table, columns, limit)
        return {"sql": sql, **self.query(sql, role, user, password)}

    def _table_sql(self, table, columns=None, limit=10):
        from sqlglot import exp
        reg = {t.lower(): c for t, c in self.gw.registry.items()}
        if table.lower() not in reg:
            raise Denied(f"unknown table: {table}")
        known = {c.lower(): c for c in reg[table.lower()]}
        picked = columns or list(reg[table.lower()])
        bad = [c for c in picked if c.lower() not in known]
        if bad:
            raise Denied(f"unknown column(s): {', '.join(bad)}")
        return exp.select(*[exp.column(known[c.lower()], quoted=True) for c in picked]).from_(
            exp.table_(table.lower(), quoted=True)).limit(int(limit)).sql(dialect=self.app.backend.dialect)

    def compare(self, sql, roles):
        out = {}
        for r in roles:
            try:
                out[r] = self.query(sql, role=r)
            except Denied as e:
                out[r] = {"role": r, "error": str(e)}
        return out

    # ---- audit & integrity ----
    def audit(self, n=20, **filters):
        return {"chain_valid": self.gw.audit.verify(),
                "entries": self.gw.audit.search(limit=n, **{k: v for k, v in filters.items() if v})[::-1]}

    def audit_verify(self):
        return self.gw.audit.verify()

    def integrity_verify(self):
        return self.app.integrity.verify("cli-operator")

    def integrity_baseline(self, reason=""):
        snap = self.app.integrity.record_baseline("cli-operator", reason)
        self.gw.audit.append(user="cli-operator", role="operator", decision="integrity_baseline", channel="cli",
                             reason=reason[:160])
        return snap

    def integrity_proof(self, sql=None, user=None, password=None):
        """As every demo identity in demo mode; otherwise as the account given, which needs integrity.verify."""
        from .integrity import proof
        if user:
            s = self.session(None, user, password)
            if not P.can(s.role, "integrity.verify", self.gw.policy):
                raise Denied(f"role '{s.role}' lacks capability 'integrity.verify'")
            sessions, actor = {s.role: s}, s.user
        else:
            sessions, actor = {r: self.app.auth.login(u, p) for r, (u, p) in config.demo_accounts().items()}, "cli-operator"
            if not sessions:
                raise Denied("outside demo mode, run the proof as an account with integrity.verify: --user and --password")
        if not sql:
            first = sorted(self.gw.registry)[0] if self.gw.registry else "users"
            sql = f"SELECT * FROM {first} LIMIT 5"
        return proof(self.app, sql, sessions, actor=actor)

    def integrity_history(self):
        return self.app.integrity.history()

    def attacks(self, role=None, user=None, password=None):
        from .attacks import SelfTestDisabled, require_self_test, run_suite, score
        try:
            require_self_test(self.gw, channel="cli")  # before resolving identities (production has no demo ones)
            s = self.session(role, user, password)
            results = run_suite(self.gw, s, channel="cli")
        except SelfTestDisabled as e:
            raise Denied(str(e)) from None
        return {"role": s.role, "score": score(results), "results": results}


class RemoteService:
    """Same interface over the REST API. Operator calls authenticate as --user/--password, else the demo admin."""
    mode = "remote"

    def __init__(self, url, user=None, password=None, role="admin"):
        from .client import MaskGuardClient, MaskGuardError
        self.url, self.Err, self.Client = url.rstrip("/"), MaskGuardError, MaskGuardClient
        self._cache = {}
        try:
            self.anon = MaskGuardClient(self.url)
            self.anon.health()
        except Exception as e:
            if isinstance(e, MaskGuardError):
                raise Unavailable(f"API at {self.url} answered {e.status}") from None
            raise Unavailable(f"API at {self.url} is not reachable ({type(e).__name__})") from None
        self.operator = (user, password) if user else ("role", role)

    def _client(self, role=None, user=None, password=None):
        key = (user, role)
        if key not in self._cache:
            try:
                self._cache[key] = (self.Client(self.url, user, password) if user else self.Client.demo(self.url, role))
            except self.Err as e:
                raise Denied(f"cannot sign in: {e.detail}") from None
        return self._cache[key]

    def _op(self):
        a, b = self.operator
        return self._client(role=b) if a == "role" else self._client(user=a, password=b)

    def _call(self, fn, *a, **kw):
        try:
            return fn(*a, **kw)
        except self.Err as e:
            if e.status in (401, 403, 404, 409, 400):
                raise Denied(f"{e.status}: {e.detail}") from None
            raise Unavailable(f"{e.status}: {e.detail}") from None

    def status(self):
        meta = self.anon.meta()
        ready = self.anon.ready()
        checks = [{"name": k.replace("_", " ").title(), "ok": v.get("ok"),
                   "detail": ", ".join(f"{x}={y}" for x, y in v.items() if x != "ok")}
                  for k, v in (ready.get("checks") or {}).items()]
        return {"mode": self.mode, "environment": meta["environment"], "demo_mode": meta["demo_mode"],
                "backend": meta["backend"], "policy_version": meta["policy_version"], "api": self.url, "checks": checks}

    def inventory(self):
        return [{"sql_type": None, "source": None, **r} for r in self._call(self._op().registry)]

    def tables(self):
        return [{"table": t["table"], "columns": len(t["columns"]), "rows": None, "scanned": True}
                for t in self._call(self._op().tables)]

    def review(self, columns, tag="PUBLIC", kind=None):
        raise Denied("reviews are saved to the overrides file on the MaskGuard host: run this command there, without --api")

    def scan(self, tables=None, sample_limit=200, dry_run=False):
        return self._call(self._op()._call, "POST", "/scan", {"tables": tables, "sample_limit": sample_limit, "dry_run": dry_run})

    def roles(self):
        return self._call(self._op().roles)

    def explain(self, role, table):
        return self._call(self._op().explain, table, role)

    def matrix(self):
        return self._call(self._op().matrix)

    def set_rule(self, role, tag, action, reason="", confirm=False):
        return self._call(self._op()._call, "PUT", "/policy/rules",
                          {"role": role, "tag": tag, "action": action, "reason": reason, "confirm": confirm})

    def policy_history(self):
        return self._call(self._op()._call, "GET", "/policy/history")["history"]

    def query(self, sql, role=None, user=None, password=None):
        return self._call(self._client(role, user, password).query_raw, sql)

    def query_table(self, table, columns=None, limit=10, role=None, user=None, password=None):
        return self._call(self._client(role, user, password).query_table, table, columns, limit)

    def compare(self, sql, roles):
        return self._call(self._op().compare, sql, roles)

    def audit(self, n=20, **filters):
        return self._call(self._op().audit, n, **filters)

    def audit_verify(self):
        return self.audit(1)["chain_valid"]

    def integrity_verify(self):
        return self._call(self._op().verify_integrity)

    def integrity_baseline(self, reason=""):
        return self._call(self._op()._call, "POST", "/integrity/baseline", {"reason": reason})

    def integrity_proof(self, sql=None, user=None, password=None):
        return self._call(self._op().integrity_proof, sql)

    def integrity_history(self):
        return self._call(self._op()._call, "GET", "/integrity/history")["history"]

    def attacks(self, role=None, user=None, password=None):
        return self._call(self._client(role, user, password).attacks)


def connect(api=None, user=None, password=None):
    api = api or os.environ.get("MASKGUARD_API")
    return RemoteService(api, user, password) if api else LocalService()
