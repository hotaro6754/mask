import hashlib, hmac, os

# Characters kept as-is by partial masking so formats stay readable (4111-XXXX-XXXX-1111). Everything else, in any
# script, is maskable. One explicit set keeps SQLite, PostgreSQL and MySQL byte-identical (no locale-dependent
# "is this a letter" checks).
SEPARATORS = " \t\n\r-/.,:()+_@#"


def partial(value, prefix=0, suffix=4, mask_char="X"):
    if value is None:
        return None
    s = str(value)
    total = sum(c not in SEPARATORS for c in s)
    if prefix + suffix >= total:
        prefix = suffix = 0
    seen, out = 0, []
    for c in s:
        if c not in SEPARATORS:
            seen += 1
            out.append(c if (seen <= prefix or seen > total - suffix) else mask_char)
        else:
            out.append(c)
    return "".join(out)

def email(value):
    if value is None:
        return None
    local, _, domain = str(value).partition("@")
    return (local[:1] + "***@" + domain) if domain else "***"

def _key():
    k = os.environ.get("MASKGUARD_HMAC_KEY")
    if not k:
        raise RuntimeError("MASKGUARD_HMAC_KEY is not set")  # fail closed, no default key
    return k.encode()

def token(value, length=16):
    if value is None:
        return None
    return hmac.new(_key(), str(value).encode(), hashlib.sha256).hexdigest()[:length]

def bucket(value, size=10000):
    return None if value is None else int(value // size) * size

def register_sqlite(conn):
    conn.create_function("mg_partial", 3, partial, deterministic=True)
    conn.create_function("mg_email", 1, email, deterministic=True)
    conn.create_function("mg_hmac", 1, token, deterministic=True)
    conn.create_function("mg_bucket", 2, bucket, deterministic=True)
    from .textpii import redact
    conn.create_function("mg_redact_text", 1, redact, deterministic=True)
