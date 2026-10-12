"""Users, password hashing and signed session tokens. The role always comes from here, never from the query."""
import base64, hashlib, hmac, os, secrets, time
from dataclasses import dataclass

import jwt
import yaml

ITERATIONS = 200_000


def hash_password(password, salt=None, iterations=ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    b64 = lambda b: base64.b64encode(b).decode()
    return f"pbkdf2_sha256${iterations}${b64(salt)}${b64(dk)}"


def check_password(password, stored):
    try:
        algo, iters, salt, dk = stored.split("$")
        assert algo == "pbkdf2_sha256"
        cand = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(cand, base64.b64decode(dk))
    except Exception:
        return False


@dataclass(frozen=True)
class Session:
    user: str
    role: str
    _minted_by: object = None


class Authenticator:
    """users: {name: {"role": ..., "password_hash": ...}}. Sessions are only valid if minted by this instance."""

    def __init__(self, users, jwt_secret=None, token_ttl=8 * 3600):
        self.users = users
        self.jwt_secret = jwt_secret or os.environ.get("MASKGUARD_JWT_SECRET") or secrets.token_hex(32)
        self.token_ttl = token_ttl
        self._mint = object()

    @classmethod
    def from_file(cls, path, **kw):
        with open(path) as f:
            return cls((yaml.safe_load(f) or {}).get("users", {}), **kw)

    def login(self, user, password):
        rec = self.users.get(user)
        if not rec or not check_password(password, rec.get("password_hash", "")):
            raise PermissionError("bad credentials")
        return Session(user, rec["role"], self._mint)

    def valid(self, s):
        # also re-check the user store, so a deleted user or changed role takes effect immediately
        return (isinstance(s, Session) and s._minted_by is self._mint
                and self.users.get(s.user, {}).get("role") == s.role)

    def issue_token(self, session):
        if not self.valid(session):
            raise PermissionError("not authenticated")
        now = int(time.time())
        return jwt.encode({"sub": session.user, "role": session.role, "iat": now, "exp": now + self.token_ttl},
                          self.jwt_secret, algorithm="HS256")

    def session_from_token(self, token):
        try:
            claims = jwt.decode(token, self.jwt_secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
        except jwt.PyJWTError as e:
            raise PermissionError(f"invalid token: {e}") from None
        s = Session(claims["sub"], claims.get("role"), self._mint)
        if not self.valid(s):
            raise PermissionError("user or role no longer valid")
        return s
