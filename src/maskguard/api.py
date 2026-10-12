"""REST API. Run: maskguard serve  (or uvicorn maskguard.api:app)

POST /auth/login {username, password}      -> {token, role}
POST /query      {sql}   Bearer token      -> masked rows, rewritten SQL, masked columns
GET  /me                                    -> user and role from the token
GET  /registry   (admin)                    -> scanner tags with evidence
POST /scan       (admin)                    -> rescan now
GET  /integrity  (admin)                    -> SHA-256 checksum per table (proves data is untouched)
GET  /audit      (admin)                    -> last entries + chain verification
GET  /attacks                               -> attack suite for the caller's role
GET  /threats    (admin)                    -> per-user risk, alerts and blocks from the threat engine
POST /threats/{user}/unblock (admin)        -> lift a block
"""
import datetime, decimal
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from . import config
from .attacks import run_suite, score
from .rewriter import Rejected
from .scanner import scan, summary

state = {}
bearer = HTTPBearer(auto_error=False)


def get_app():
    if "app" not in state:
        state["app"] = config.build(start_worker=True)
    return state["app"]


@asynccontextmanager
async def lifespan(_):
    get_app()
    yield
    if state.get("app") and state["app"].worker:
        state["app"].worker.stop()


app = FastAPI(title="MaskGuard", version="0.1.0", lifespan=lifespan)


class Login(BaseModel):
    username: str
    password: str


class Query(BaseModel):
    sql: str


def _json(v):
    if isinstance(v, decimal.Decimal):
        return float(v)
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat()
    return v


def session(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "missing bearer token")
    try:
        return get_app().auth.session_from_token(creds.credentials)
    except PermissionError as e:
        raise HTTPException(401, str(e))


def admin(s=Depends(session)):
    if s.role != "admin":
        raise HTTPException(403, "admin only")
    return s


@app.post("/auth/login")
def login(body: Login):
    a = get_app().auth
    try:
        s = a.login(body.username, body.password)
    except PermissionError:
        raise HTTPException(401, "bad credentials")
    return {"token": a.issue_token(s), "role": s.role}


@app.get("/me")
def me(s=Depends(session)):
    return {"user": s.user, "role": s.role}


@app.post("/query")
def query(body: Query, s=Depends(session)):
    try:
        r = get_app().gateway.query(s, body.sql)
    except Rejected as e:
        raise HTTPException(400, f"rejected: {e}")
    except Exception as e:
        raise HTTPException(400, f"query failed: {type(e).__name__}")
    return {"role": s.role, "columns": r.columns, "rows": [[_json(v) for v in row] for row in r.rows],
            "row_count": len(r.rows), "masked": r.masked, "rewritten_sql": r.rewritten_sql, "ms": round(r.ms, 2)}


@app.get("/registry")
def registry(_=Depends(admin)):
    return {"tagged": summary(get_app().gateway.registry)}


@app.post("/scan")
def rescan(_=Depends(admin)):
    a = get_app()
    a.gateway.update_registry(scan(a.backend, overrides=config._load_yaml(a.settings.overrides)))
    return {"tagged": summary(a.gateway.registry)}


@app.get("/integrity")
def integrity(_=Depends(admin)):
    b = get_app().backend
    return {t: b.checksum(t) for t in b.tables()}


@app.get("/audit")
def audit(n: int = 20, _=Depends(admin)):
    log = get_app().gateway.audit
    return {"chain_valid": log.verify(), "entries": log.tail(n)}


@app.get("/threats")
def threats(_=Depends(admin)):
    t = get_app().gateway.threat
    return {"enabled": t is not None, "users": t.snapshot() if t else {}}


@app.post("/threats/{user}/unblock")
def unblock(user: str, s=Depends(admin)):
    a = get_app()
    if a.gateway.threat:
        a.gateway.threat.unblock(user)
    a.gateway.audit.append(user=s.user, role=s.role, decision="unblock", target=user)
    return {"unblocked": user}


@app.get("/attacks")
def attacks(s=Depends(session)):
    results = run_suite(get_app().gateway, s)
    return {"role": s.role, "score": score(results), "results": results}
