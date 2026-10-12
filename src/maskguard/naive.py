"""Baseline for comparison: 'display masking' that masks result columns by their output name.

It runs the user's SQL as written and masks a result column only if its name matches a tagged column,
the way a simple output filter does. Predicates, aliases and expressions all see real values.
"""
from . import masks
from .rewriter import action_for


def _mask_value(v, meta, action, policy):
    if v is None or action == "allow":
        return v
    if action == "partial":
        if meta.get("type") == "num":
            return masks.bucket(float(v), policy.get("bucket_size", 10000))
        if meta.get("kind") == "email":
            return masks.email(v)
        p = policy["partial"].get(meta.get("kind"), policy["partial"]["default"])
        return masks.partial(v, p["prefix"], p["suffix"])
    if action == "hmac":
        return masks.token(v)
    if action == "redact":
        return None if meta.get("type") == "num" else "REDACTED"
    return None


def naive_query(backend, sql, role, registry, policy):
    by_name = {}
    for cols in registry.values():
        for c, meta in cols.items():
            if meta.get("tag"):
                by_name[c.lower()] = meta
    cols, rows = backend.execute(sql)
    plan = [(by_name.get(c.lower()), action_for(by_name[c.lower()], role, policy) if c.lower() in by_name else "allow")
            for c in cols]
    return cols, [tuple(_mask_value(v, m, a, policy) if m else v for v, (m, a) in zip(r, plan)) for r in rows]
