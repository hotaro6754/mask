import re
from stdnum import iban as _iban, luhn as _luhn
from stdnum.in_ import aadhaar as _aadhaar, pan as _pan

KIND_TAG = {"email": "PII_HIGH", "phone": "PII_HIGH", "ssn": "PII_HIGH", "aadhaar": "PII_HIGH", "pan": "PII_HIGH",
            "card": "FINANCIAL_CONFIDENTIAL", "iban": "FINANCIAL_CONFIDENTIAL", "balance": "FINANCIAL_CONFIDENTIAL",
            "name": "PII_MEDIUM", "address": "PII_MEDIUM", "dob": "PII_MEDIUM"}
HEADER_WORDS = {"email": "email", "mail": "email", "phone": "phone", "mobile": "phone", "msisdn": "phone",
                "ssn": "ssn", "aadhaar": "aadhaar", "aadhar": "aadhaar", "pan": "pan", "card": "card", "cc": "card",
                "iban": "iban", "balance": "balance", "name": "name", "address": "address", "dob": "dob", "birth": "dob"}

def _digits(v):
    return re.sub(r"[\s-]", "", str(v))

def _is_card(v):
    d = _digits(v)
    return d.isdigit() and 13 <= len(d) <= 19 and _luhn.is_valid(d)

VALIDATORS = {
    "card": _is_card,
    "aadhaar": lambda v: _aadhaar.is_valid(_digits(v)),
    "pan": lambda v: _pan.is_valid(str(v).strip().upper()),
    "iban": lambda v: _iban.is_valid(str(v).replace(" ", "")),
    "email": lambda v: re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", str(v)) is not None,
    "phone": lambda v: re.fullmatch(r"(?:\+?91)?[6-9]\d{9}", _digits(v)) is not None,
    "ssn": lambda v: re.fullmatch(r"\d{3}-?\d{2}-?\d{4}", str(v)) is not None,
}

def header_kind(column):
    tokens = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", column).lower())
    return next((HEADER_WORDS[t] for t in tokens if t in HEADER_WORDS), None)

def _safe(fn, v):
    try:
        return bool(fn(v))
    except Exception:
        return False

def _out(kind, conf, evidence):
    return {"kind": kind, "tag": KIND_TAG[kind], "confidence": conf, "evidence": evidence}

def classify_column(column, values, hi=0.8, lo=0.3):
    sample = [v for v in values if v is not None][:200]
    hk = header_kind(column)
    best_kind, best_ratio = None, 0.0
    for kind, fn in VALIDATORS.items():
        if not sample:
            break
        ratio = sum(1 for v in sample if _safe(fn, v)) / len(sample)
        if ratio > best_ratio:
            best_kind, best_ratio = kind, ratio
    if best_kind and best_ratio >= hi:
        return _out(best_kind, "high", f"{best_ratio:.0%} pass {best_kind} validator; header={hk}")
    if best_kind and best_ratio >= lo:
        return _out(best_kind, "review", f"only {best_ratio:.0%} pass {best_kind} validator; header={hk}")
    if hk:  # header-only evidence: tag anyway (fail closed)
        return _out(hk, "medium", f"header token matched {hk}; no validator match")
    return None

def scan_sqlite(conn, table):
    entry = {}
    for _, name, ctype, *_ in conn.execute(f'PRAGMA table_info("{table}")').fetchall():
        vals = [r[0] for r in conn.execute(f'SELECT "{name}" FROM "{table}" LIMIT 200')]
        numeric = (ctype or "").upper() in ("INTEGER", "REAL", "NUMERIC", "FLOAT", "DOUBLE", "DECIMAL")
        entry[name] = {"type": "num" if numeric else "text", **(classify_column(name, vals) or {})}
    return entry
