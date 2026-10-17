"""REST API. Run: maskguard serve  (OpenAPI at /docs, dashboard at /ui/)

Every data path goes through Gateway.query (authenticate -> threat check -> rewrite -> read-only execute -> audit).
The role always comes from the signed token, never from the request body. Non-query endpoints are gated by
capabilities from the policy (role_info.<role>.capabilities), not by role names.

Public       GET  /health   GET /ready   GET /meta   POST /auth/login   POST /auth/demo (demo mode only)
Any role     GET  /me   GET /tables   POST /query   POST /query/table   GET /policy   GET /roles   GET /attacks
             GET  /policy/explain?table=T            (own role; other roles need policy.read)
policy.read  GET  /policy/matrix   GET /policy/history   GET /diagnostics
policy.write POST /policy/check   PUT /policy/rules   POST /policy/reset
registry.read GET /registry        scan.run POST /scan
audit.read   GET  /audit   GET /audit/stats
integrity.*  GET  /integrity   GET /integrity/status   POST /integrity/verify   POST /integrity/baseline
             POST /integrity/proof   GET /integrity/history
threats.manage GET /threats   POST /threats/{user}/unblock      pia.read GET /pia
Demo mode    POST /demo/compare  (same SQL as each demo identity; every run is a real, audited query)
"""
import datetime, decimal, os, time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlglot import exp

from . import config, policy as P
from .attacks import run_suite, score
from .gateway import safe_error
from .rewriter import Rejected
from .scanner import scan, summary

VERSION = "1.0.0"
state = {}
bearer = HTTPBearer(auto_error=False)
WEB = os.path.join(os.path.dirname(__file__), "web")
POSTMAN = os.path.join(os.path.dirname(__file__), "..", "..", "postman")


def get_app():
    if "app" not in state:
        state["app"] = config.build(start_worker=True)
    return state["app"]


@asynccontextmanager
async def lifespan(_):
    try:
        get_app()  # build at startup: an unsafe production configuration stops the server instead of failing requests
    except config.UnsafeConfiguration as e:
        import logging
        logging.getLogger("uvicorn.error").error("%s", e)
        raise
    if config.demo_enabled():
        import logging
        logging.getLogger("uvicorn.error").warning(
            "DEMO MODE: demo identities (including admin) can be used without a password from this machine%s. "
            "Synthetic data only; set MASKGUARD_DEMO=0 or MASKGUARD_ENV=production for anything else.",
            " and from any client (MASKGUARD_DEMO=1)" if os.environ.get("MASKGUARD_DEMO") == "1" else "")
    yield
    if state.get("app") and state["app"].worker:
        state["app"].worker.stop()


app = FastAPI(title="MaskGuard", version=VERSION, lifespan=lifespan,
              description="Query-time, role-based PII masking. Authenticate with /auth/login (or /auth/demo in demo "
                          "mode), then send the token as `Authorization: Bearer <token>`.")

UI_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
          "font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-Frame-Options"] = "DENY"
    if request.url.path.startswith("/ui"):
        resp.headers["Content-Security-Policy"] = UI_CSP
    else:
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


if os.path.isdir(WEB):
    app.mount("/ui", StaticFiles(directory=WEB, html=True), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui/")


# ---------- models ----------

class Login(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=256)


class DemoLogin(BaseModel):
    role: str = Field(max_length=64)


class Query(BaseModel):
    sql: str = Field(max_length=20000)


class TableQuery(BaseModel):
    table: str = Field(max_length=128)
    columns: Optional[list[str]] = None
    limit: int = Field(10, ge=1, le=1000)
    order_by: Optional[str] = None


class Compare(BaseModel):
    sql: str = Field(max_length=20000)
    roles: Optional[list[str]] = None


class Rule(BaseModel):
    role: str
    tag: str
    action: str
    reason: str = ""
    confirm: bool = False


class Reason(BaseModel):
    reason: str = ""


class ScanRequest(BaseModel):
    tables: Optional[list[str]] = None
    sample_limit: int = Field(200, ge=10, le=5000)
    dry_run: bool = False


class ProofRequest(BaseModel):
    sql: str = Field("SELECT * FROM users ORDER BY id LIMIT 5", max_length=20000)


# ---------- helpers ----------

def _json(v):
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v).hex()
    return v


def session(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "missing bearer token")
    try:
        return get_app().auth.session_from_token(creds.credentials)
    except PermissionError:
        raise HTTPException(401, "invalid or expired token")


def require(capability):
    def dep(s=Depends(session)):
        if not P.can(s.role, capability, get_app().gateway.policy):
            _audit(s, "denied", target=capability, reason="missing capability")
            raise HTTPException(403, f"role '{s.role}' lacks capability '{capability}'")
        return s
    return dep


def _audit(s, decision, **kw):
    get_app().gateway.audit.append(user=s.user, role=s.role, decision=decision, channel="rest",
                                   policy_version=P.version(get_app().gateway.policy), **kw)


def _run(s, sql, channel="rest"):
    try:
        r = get_app().gateway.query(s, sql, channel=channel)
    except Rejected as e:
        raise HTTPException(400, f"rejected: {e}", headers={"X-Request-ID": getattr(e, "request_id", "")})
    except PermissionError:
        raise HTTPException(401, "not authenticated")
    except Exception as e:  # never echo database errors: they can contain values
        raise HTTPException(400, safe_error(e))
    return {"role": s.role, "user": s.user, "columns": r.columns, "rows": [[_json(v) for v in row] for row in r.rows],
            "row_count": len(r.rows), "masked": r.masked, "rewritten_sql": r.rewritten_sql, "ms": round(r.ms, 2),
            "risk": r.risk, "dp": r.dp, "request_id": r.request_id, "policy_version": r.policy_version}


LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def _demo_allowed(request):
    """Demo identities need demo mode, and either a client on this machine or an explicit MASKGUARD_DEMO=1."""
    if not config.demo_enabled():
        raise HTTPException(404, "demo mode is disabled")
    host = request.client.host if request.client else ""
    if host not in LOOPBACK and os.environ.get("MASKGUARD_DEMO") != "1":
        raise HTTPException(403, "demo identities are only available from this machine; set MASKGUARD_DEMO=1 to allow remote demo logins")


def _demo_session(role):
    accounts = config.demo_accounts()
    if role not in accounts:
        raise HTTPException(404, f"no demo identity for role '{role}'")
    return get_app().auth.login(*accounts[role])


# ---------- public ----------

@app.get("/health", tags=["service"])
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/ready", tags=["service"])
def ready():
    a = get_app()
    checks = {}
    try:
        checks["database"] = {"ok": True, "backend": a.backend.dialect, "tables": len(a.backend.tables())}
    except Exception as e:
        checks["database"] = {"ok": False, "error": type(e).__name__}
    w = a.worker
    checks["scanner"] = {"ok": not (w and w.last_error), "tagged_columns": len(summary(a.gateway.registry)),
                         "background": bool(w and w.is_alive()), "last_run": w.last_run if w else None}
    checks["policy"] = {"ok": not P.validate(a.gateway.policy), "version": P.version(a.gateway.policy),
                        "default_action": a.gateway.policy.get("default_action", "deny")}
    checks["audit"] = {"ok": a.gateway.audit.verify()}
    checks["hmac_key"] = {"ok": bool(os.environ.get("MASKGUARD_HMAC_KEY"))}
    checks["integrity_baseline"] = {"ok": a.integrity.baseline() is not None}
    ok = all(c["ok"] for c in checks.values())
    return JSONResponse({"ready": ok, "checks": checks}, status_code=200 if ok else 503)


@app.get("/meta", tags=["service"])
def meta():
    a = get_app()
    return {"name": "MaskGuard", "version": VERSION, "environment": config.environment(),
            "demo_mode": config.demo_enabled(), "backend": a.backend.dialect,
            "demo_identities": [{"role": r, "user": u} for r, (u, _) in config.demo_accounts().items()],
            "policy_version": P.version(a.gateway.policy), "uptime_s": round(time.time() - a.started)}


@app.post("/auth/login", tags=["auth"])
def login(body: Login):
    a = get_app().auth
    try:
        s = a.login(body.username, body.password)
    except PermissionError:
        raise HTTPException(401, "bad credentials")
    return {"token": a.issue_token(s), "role": s.role, "user": s.user}


@app.post("/auth/demo", tags=["auth"])
def demo_login(body: DemoLogin, request: Request):
    """Demo mode only: sign in as the synthetic demo identity for a role (a normal user with a normal token)."""
    _demo_allowed(request)
    s = _demo_session(body.role)
    return {"token": get_app().auth.issue_token(s), "role": s.role, "user": s.user, "demo": True}


# ---------- any authenticated role ----------

@app.get("/me", tags=["auth"])
def me(s=Depends(session)):
    pol = get_app().gateway.policy
    return {"user": s.user, "role": s.role, "capabilities": P.capabilities(s.role, pol),
            "policy_version": P.version(pol)}


@app.get("/tables", tags=["data"])
def tables(s=Depends(session)):
    """Tables you may query, with each column's classification and the action applied for your role."""
    from .rewriter import action_for
    a = get_app()
    pol = a.gateway.policy
    out = []
    for t, cols in sorted(a.gateway.registry.items()):
        out.append({"table": t, "row_filter": ((pol.get("row_filters") or {}).get(s.role) or {}).get(t),
                    "columns": [{"column": c, "sql_type": m.get("sql_type"), "tag": m.get("tag") or "PUBLIC",
                                 "kind": m.get("kind"), "action": action_for(m, s.role, pol)} for c, m in cols.items()]})
    return {"role": s.role, "backend": a.backend.dialect, "tables": out}


@app.post("/query", tags=["data"])
def query(body: Query, s=Depends(session)):
    return _run(s, body.sql)


@app.post("/query/table", tags=["data"])
def query_table(body: TableQuery, s=Depends(session)):
    """Query builder: table + columns + limit. Identifiers are checked against the scanned schema, then the
    generated SELECT goes through the same gateway as /query."""
    reg = {t.lower(): cols for t, cols in get_app().gateway.registry.items()}
    cols = reg.get(body.table.lower())
    if cols is None:
        raise HTTPException(404, f"unknown table: {body.table}")
    known = {c.lower(): c for c in cols}
    picked = body.columns or list(cols)
    bad = [c for c in picked + ([body.order_by] if body.order_by else []) if c.lower() not in known]
    if bad:
        raise HTTPException(400, f"unknown column(s): {', '.join(bad)}")
    q = exp.select(*[exp.column(known[c.lower()], quoted=True) for c in picked]).from_(
        exp.table_(body.table.lower(), quoted=True))
    if body.order_by:
        q = q.order_by(exp.column(known[body.order_by.lower()], quoted=True))
    sql = q.limit(body.limit).sql(dialect=get_app().backend.dialect)
    return {"sql": sql, **_run(s, sql)}


@app.get("/policy", tags=["policy"])
def my_policy(s=Depends(session)):
    pol = get_app().gateway.policy
    return {"role": s.role, "policy_version": P.version(pol), "default_action": pol.get("default_action", "deny"),
            "rules": pol["roles"][s.role], "row_filters": ((pol.get("row_filters") or {}).get(s.role) or {}),
            "max_rows": (pol.get("max_rows") or {}).get(s.role), "capabilities": P.capabilities(s.role, pol),
            "actions": {k: {"strictness": v[0], "label": v[1], "detail": v[2]} for k, v in P.ACTIONS.items()}}


@app.get("/roles", tags=["policy"])
def roles(s=Depends(session)):
    pol = get_app().gateway.policy
    full = P.can(s.role, "policy.read", pol)
    out = []
    for r in P.roles(pol):
        if not full and r["role"] != s.role:
            r = {k: r[k] for k in ("role", "label", "description")}
        out.append(r)
    return {"roles": out, "capability_catalog": P.CAPABILITIES}


@app.get("/policy/explain", tags=["policy"])
def explain(table: str, role: Optional[str] = None, s=Depends(session)):
    pol = get_app().gateway.policy
    role = role or s.role
    if role != s.role and not P.can(s.role, "policy.read", pol):
        raise HTTPException(403, "explaining another role's policy needs capability 'policy.read'")
    try:
        return P.explain(role, table, get_app().gateway.registry, pol)
    except KeyError as e:
        raise HTTPException(404, str(e).strip("'\""))


@app.get("/policy/matrix", tags=["policy"])
def policy_matrix(_=Depends(require("policy.read"))):
    return P.matrix(get_app().gateway.registry, get_app().gateway.policy)


@app.get("/policy/history", tags=["policy"])
def policy_history(n: int = 50, _=Depends(require("policy.read"))):
    return {"version": P.version(get_app().gateway.policy), "history": get_app().policy.history(n)}


@app.post("/policy/check", tags=["policy"])
def policy_check(body: Rule, _=Depends(require("policy.write"))):
    try:
        current, warnings, weaker = get_app().policy.check_rule(body.role, body.tag, body.action)
    except P.PolicyError as e:
        raise HTTPException(400, str(e))
    return {"current": current, "proposed": body.action, "weakening": weaker, "warnings": warnings,
            "needs_confirmation": weaker}


@app.put("/policy/rules", tags=["policy"])
def policy_set(body: Rule, s=Depends(require("policy.write"))):
    try:
        r = get_app().policy.set_rule(body.role, body.tag, body.action, s.user, body.reason, body.confirm)
    except P.PolicyError as e:
        _audit(s, "policy_denied", target=f"{body.role}/{body.tag}", reason=str(e)[:160])
        raise HTTPException(409 if "weakens" in str(e) else 400, str(e))
    if r["changed"]:
        _audit(s, "policy_change", target=f"{body.role}/{body.tag}", reason=body.reason[:160],
               change=f"{r['entry']['from']} -> {r['entry']['to']}", version_after=r["version"])
    return r


@app.post("/policy/reset", tags=["policy"])
def policy_reset(s=Depends(require("policy.write"))):
    e = get_app().policy.reset(s.user)
    _audit(s, "policy_change", target="*", change="reset to file baseline", version_after=e["version_after"])
    return e


@app.get("/diagnostics", tags=["service"])
def diagnostics(_=Depends(require("policy.read"))):
    """Safe configuration summary: no URLs with credentials, no keys, no paths outside the app's own state."""
    a = get_app()
    st = a.settings
    return {"environment": config.environment(), "demo_mode": config.demo_enabled(), "backend": a.backend.dialect,
            "database": st.db.split("@")[-1].split("?")[0] if "@" in st.db else st.db.split("://")[0] + "://…",
            "hmac_key": "set" if os.environ.get("MASKGUARD_HMAC_KEY") else "MISSING",
            "jwt_secret": "set" if os.environ.get("MASKGUARD_JWT_SECRET") else "ephemeral (tokens reset on restart)",
            "scan_interval_s": st.scan_interval, "policy_file": os.path.basename(st.policy),
            "users_file": os.path.basename(st.users), "threat_engine": a.gateway.threat is not None,
            "dp": a.gateway.policy.get("dp"), "version": VERSION}


# ---------- scanner ----------

@app.get("/registry", tags=["scanner"])
def registry(_=Depends(require("registry.read"))):
    return {"tagged": summary(get_app().gateway.registry)}


@app.post("/scan", tags=["scanner"])
def rescan(body: Optional[ScanRequest] = None, s=Depends(require("scan.run"))):
    body = body or ScanRequest()
    a = get_app()
    known = set(a.backend.tables())
    if body.tables and not set(body.tables) <= known:
        raise HTTPException(404, f"unknown table(s): {', '.join(sorted(set(body.tables) - known))}")
    t0 = time.perf_counter()
    reg = scan(a.backend, tables=body.tables, overrides=config._load_yaml(a.settings.overrides),
               sample_size=body.sample_limit)
    if not body.dry_run:
        merged = dict(a.gateway.registry); merged.update(reg)
        a.gateway.update_registry(merged)
    _audit(s, "scan", target=",".join(body.tables or ["*"]), dry_run=body.dry_run, sample_limit=body.sample_limit)
    return {"scanned_at": datetime.datetime.now().isoformat(timespec="seconds"), "dry_run": body.dry_run,
            "applied": not body.dry_run, "sample_limit": body.sample_limit, "tables": sorted(reg),
            "ms": round((time.perf_counter() - t0) * 1000, 1), "tagged": summary(reg if body.dry_run else a.gateway.registry),
            "limitations": "Classification is inferred from up to sample_limit values per column plus the header. "
                           "A column with no PII in the sample is not proven clean; use overrides.yaml to force a tag."}


# ---------- audit ----------

@app.get("/audit", tags=["audit"])
def audit(n: int = 20, user: Optional[str] = None, role: Optional[str] = None, decision: Optional[str] = None,
          q: Optional[str] = None, request_id: Optional[str] = None, _=Depends(require("audit.read"))):
    log = get_app().gateway.audit
    return {"chain_valid": log.verify(),
            "entries": log.search(user, role, decision, q, request_id, limit=max(1, min(n, 1000)))[::-1]}


@app.get("/audit/stats", tags=["audit"])
def audit_stats(hours: int = 24, _=Depends(require("audit.read"))):
    return get_app().gateway.audit.stats(max(1, min(hours, 24 * 30)))


# ---------- integrity ----------

@app.get("/integrity", tags=["integrity"])
def integrity(_=Depends(require("integrity.verify"))):
    """Legacy view: SHA-256 per table."""
    b = get_app().backend
    return {t: b.checksum(t) for t in b.tables()}


@app.get("/integrity/status", tags=["integrity"])
def integrity_status(_=Depends(require("integrity.verify"))):
    a = get_app()
    base = a.integrity.baseline()
    hist = a.integrity.history(1)
    return {"baseline": None if base is None else {k: base.get(k) for k in ("taken_at", "recorded_by", "reason",
                                                                              "combined_sha256", "tables")},
            "last_verification": hist[-1] if hist else None}


@app.post("/integrity/verify", tags=["integrity"])
def integrity_verify(s=Depends(require("integrity.verify"))):
    r = get_app().integrity.verify(s.user)
    _audit(s, "integrity_verify", result=r["status"])
    return r


@app.post("/integrity/baseline", tags=["integrity"])
def integrity_baseline(body: Optional[Reason] = None, s=Depends(require("integrity.baseline"))):
    snap = get_app().integrity.record_baseline(s.user, (body.reason if body else "")[:200])
    _audit(s, "integrity_baseline", reason=(body.reason if body else "")[:160])
    return {"taken_at": snap["taken_at"], "combined_sha256": snap["combined_sha256"], "tables": snap["tables"]}


@app.post("/integrity/proof", tags=["integrity"])
def integrity_proof(body: Optional[ProofRequest] = None, s=Depends(require("integrity.verify"))):
    """Digest -> the same query as every demo identity (or only you, outside demo mode) -> write attempts -> digest."""
    from .integrity import proof
    a = get_app()
    sessions = {r: a.auth.login(u, p) for r, (u, p) in config.demo_accounts().items()} or {s.role: s}
    r = proof(a, (body or ProofRequest()).sql, sessions, actor=s.user)
    _audit(s, "integrity_proof", result=r["status"])
    return r


@app.get("/integrity/history", tags=["integrity"])
def integrity_history(n: int = 20, _=Depends(require("integrity.verify"))):
    return {"history": get_app().integrity.history(n)}


# ---------- demo ----------

@app.post("/demo/compare", tags=["demo"])
def demo_compare(body: Compare, request: Request, s=Depends(session)):
    """Demo mode only: run the same SQL as each demo identity. Each run is a separate, audited gateway query under
    that identity's own session; nothing is computed client-side. A caller may only include roles whose view is no
    more revealing than its own (an admin may compare all), so compare can't be used to borrow a stronger role."""
    _demo_allowed(request)
    pol = get_app().gateway.policy
    roles = body.roles or [r for r in config.demo_accounts() if r in pol["roles"] and P.view_within(r, s.role, pol)]
    stronger = [r for r in roles if r in pol["roles"] and not P.view_within(r, s.role, pol)]
    if stronger:
        _audit(s, "denied", target="demo/compare:" + ",".join(stronger), reason="role sees more than the caller")
        raise HTTPException(403, f"your role ({s.role}) may not view data as {', '.join(stronger)}: those roles see more than you")
    out = {}
    for role in roles:
        try:
            out[role] = _run(_demo_session(role), body.sql, channel="rest-demo")
        except HTTPException as e:
            if e.status_code == 404:
                raise
            out[role] = {"role": role, "error": e.detail, "request_id": (e.headers or {}).get("X-Request-ID")}
    return {"sql": body.sql, "requested_by": s.user, "results": out}


# ---------- threats, PIA, attacks, downloads ----------

@app.get("/threats", tags=["threats"])
def threats(_=Depends(require("threats.manage"))):
    t = get_app().gateway.threat
    return {"enabled": t is not None, "users": t.snapshot() if t else {}}


@app.post("/threats/{user}/unblock", tags=["threats"])
def unblock(user: str, s=Depends(require("threats.manage"))):
    a = get_app()
    if a.gateway.threat:
        a.gateway.threat.unblock(user)
    _audit(s, "unblock", target=user)
    return {"unblocked": user}


@app.get("/pia", tags=["compliance"])
def pia(days: int = 30, fmt: str = "json", _=Depends(require("pia.read"))):
    from .pia import build, to_markdown
    r = build(get_app(), days)
    return PlainTextResponse(to_markdown(r), media_type="text/markdown") if fmt == "md" else r


@app.get("/attacks", tags=["security"])
def attacks(s=Depends(session)):
    results = run_suite(get_app().gateway, s)
    return {"role": s.role, "score": score(results), "results": results}


@app.get("/postman", tags=["service"], include_in_schema=False)
def postman_collection():
    p = os.path.join(POSTMAN, "Smart-Data-Masking.postman_collection.json")
    if not os.path.exists(p):
        raise HTTPException(404, "collection not bundled with this install")
    return FileResponse(p, filename="Smart-Data-Masking.postman_collection.json", media_type="application/json")
