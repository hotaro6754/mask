"""Column -> fixed-length feature vector for the PII classifier (Sherlock-style, plus checksum pass rates)."""
import math, re
from collections import Counter
from datetime import date

import numpy as np
from stdnum import iban as _iban, luhn as _luhn, verhoeff as _verhoeff
from stdnum.in_ import epic as _epic, gstin as _gstin, pan as _pan

from .synth import KINDS

DEVANAGARI = re.compile(r"[ऀ-ॿ]")
HINDI_MONTHS = ["जनवरी", "फ़रवरी", "फरवरी", "मार्च", "अप्रैल", "मई", "जून", "जुलाई", "अगस्त", "सितंबर", "अक्टूबर", "नवंबर", "दिसंबर"]
EN_MONTHS = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}
HI_MONTHS = {"जनवरी": 1, "फ़रवरी": 2, "फरवरी": 2, "मार्च": 3, "अप्रैल": 4, "मई": 5, "जून": 6, "जुलाई": 7, "अगस्त": 8,
             "सितंबर": 9, "अक्टूबर": 10, "नवंबर": 11, "दिसंबर": 12}

# header vocabulary -> kind (a weak hint only; training headers lie ~60% of the time)
HEADER_WORDS = {
    "aadhaar": "aadhaar", "aadhar": "aadhaar", "uid": "aadhaar", "uidai": "aadhaar", "pan": "pan", "gstin": "gstin",
    "gst": "gstin", "upi": "upi", "vpa": "upi", "phone": "phone", "mobile": "phone", "msisdn": "phone",
    "contact": "phone", "cell": "phone", "pincode": "pincode", "pin": "pincode", "zip": "pincode", "postcode": "pincode",
    "passport": "passport", "voter": "voter_id", "epic": "voter_id", "ifsc": "ifsc", "vehicle": "vehicle_reg",
    "registration": "vehicle_reg", "account": "bank_account", "acct": "bank_account", "name": "name",
    "holder": "name", "address": "address", "addr": "address", "email": "email", "mail": "email", "dob": "dob",
    "birth": "dob", "card": "card", "cc": "card", "iban": "iban", "ssn": "ssn", "balance": "amount",
    "salary": "amount", "amount": "amount", "income": "amount", "notes": "free_text", "remarks": "free_text",
    "comment": "free_text", "comments": "free_text", "description": "free_text",
}
GENERIC_HEADER = re.compile(r"^(col|column|field|attr|f|c|x|v|var)_?\d*[a-z]?$")

_PATTERNS = {
    "aadhaar_masked": re.compile(r"^[Xx*]{4}[\s-]?[Xx*]{4}[\s-]?\d{4}$"),
    "pan_shape": re.compile(r"^[A-Z]{5}\d{4}[A-Z]$"),
    "gstin_shape": re.compile(r"^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]$"),
    "upi": re.compile(r"^[\w.\-]{2,}@[A-Za-z]{2,}$"),
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$"),
    "phone": re.compile(r"^(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}$"),
    "pincode": re.compile(r"^[1-9]\d{5}$"),
    "six_digit": re.compile(r"^\d{6}$"),
    "passport": re.compile(r"^[A-Z]\d{7}$"),
    "voter_shape": re.compile(r"^[A-Z]{3}\d{7}$"),
    "ifsc": re.compile(r"^[A-Z]{4}0[A-Z0-9]{6}$"),
    "vehicle": re.compile(r"^(?:[A-Z]{2}[\s-]?\d{1,2}[\s-]?[A-Z]{1,3}[\s-]?\d{4}|\d{2}\s?BH\s?\d{4}\s?[A-Z]{1,2})$"),
    "bank_account": re.compile(r"^\d{9,18}$"),
    "ssn": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "latin_name": re.compile(r"^[A-Za-z][A-Za-z.']*(?:\s+[A-Za-z][A-Za-z.']*){1,4}$"),
    "deva_words": re.compile(r"^[ऀ-ॿ]+(?:\s+[ऀ-ॿ]+){0,4}$"),
    "amount": re.compile(r"^(?:₹|Rs\.?\s?|INR\s?)?-?[\d,]+(?:\.\d{1,2})?$"),
    "time": re.compile(r"\d{1,2}:\d{2}"),
    "ipv4": re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$"),
    "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I),
    "hex": re.compile(r"^[0-9a-f]{16,}$", re.I),
    "url": re.compile(r"^https?://", re.I),
}


def _compact(v):
    return re.sub(r"[\s-]", "", v)


def _safe(fn, v):
    try:
        return bool(fn(v))
    except Exception:
        return False


def _aadhaar(v):
    d = _compact(v)
    return len(d) == 12 and d.isdigit() and d[0] not in "01" and _verhoeff.is_valid(d)


def _card(v):
    d = _compact(v)
    return d.isdigit() and 13 <= len(d) <= 19 and _luhn.is_valid(d)


VALIDATORS = {
    "aadhaar": _aadhaar,
    "pan": lambda v: _pan.is_valid(v.strip().upper()) and bool(_PATTERNS["pan_shape"].match(v.strip())),
    "gstin": lambda v: _gstin.is_valid(v.strip()),
    "voter_epic": lambda v: _epic.is_valid(v.strip()),
    "card": _card,
    "iban": lambda v: _iban.is_valid(v.replace(" ", "")),
}


def parse_date(v):
    v = v.strip()
    m = re.match(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$", v)
    try:
        if m:
            return date(int(m[3]), int(m[2]), int(m[1]))
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})(?:[ T].*)?$", v)
        if m:
            return date(int(m[1]), int(m[2]), int(m[3]))
        m = re.match(r"^(\d{1,2})\s+(\S+)\s+(\d{4})$", v)
        if m:
            mon = EN_MONTHS.get(m[2][:3].lower()) or HI_MONTHS.get(m[2])
            if mon:
                return date(int(m[3]), mon, int(m[1]))
    except ValueError:
        return None
    return None


def header_kind(column):
    tokens = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", column or "").lower())
    return next((HEADER_WORDS[t] for t in tokens if t in HEADER_WORDS), None)


def _shape(v):
    s = re.sub(r"[A-Z]", "A", v)
    s = re.sub(r"[a-z]", "a", s)
    s = re.sub(r"\d", "9", s)
    s = DEVANAGARI.sub("d", s)
    return re.sub(r"(.)\1+", r"\1+", s)


def _stats(xs):
    if not xs:
        return [0.0, 0.0, 0.0, 0.0]
    a = np.asarray(xs, dtype=float)
    return [float(a.mean()), float(a.std()), float(a.min()), float(a.max())]


PATTERN_KEYS = list(_PATTERNS)
VALIDATOR_KEYS = list(VALIDATORS)
HEADER_KINDS = [k for k in KINDS if k != "none"]

FEATURE_NAMES = (
    ["n_values", "null_frac", "unique_ratio"]
    + [f"len_{s}" for s in ("mean", "std", "min", "max")]
    + [f"words_{s}" for s in ("mean", "std", "min", "max")]
    + [f"digits_{s}" for s in ("mean", "std", "min", "max")]
    + [f"maxdigitrun_{s}" for s in ("mean", "std", "min", "max")]
    + ["frac_digit_chars", "frac_upper_chars", "frac_lower_chars", "frac_space_chars", "frac_punct_chars",
       "frac_deva_chars", "frac_X_chars", "char_entropy", "frac_all_digits", "frac_alnum_mixed",
       "frac_has_at", "frac_has_comma", "frac_has_dot", "frac_has_dash", "frac_has_slash", "frac_has_plus",
       "frac_leading_zero", "frac_starts_digit", "frac_titlecase", "frac_all_upper", "commas_mean",
       "top_shape_frac", "distinct_shapes_ratio", "len_cv"]
    + [f"pat_{k}" for k in PATTERN_KEYS]
    + [f"val_{k}" for k in VALIDATOR_KEYS]
    + ["date_frac", "date_year_mean", "date_year_std", "date_year_min", "date_year_max", "date_hindi_month_frac"]
    + [f"hdr_{k}" for k in HEADER_KINDS] + ["hdr_generic", "hdr_none"]
)


def column_features(header, values, max_values=200):
    raw = list(values)[:max_values]
    vals = [str(v) for v in raw if v is not None and str(v).strip() != ""]
    n_raw, n = len(raw), len(vals)
    f = [float(n), (n_raw - n) / n_raw if n_raw else 1.0, len(set(vals)) / n if n else 0.0]
    lens = [len(v) for v in vals]
    f += _stats(lens)
    f += _stats([len(v.split()) for v in vals])
    f += _stats([sum(c.isdigit() for c in v) for v in vals])
    f += _stats([max((len(m) for m in re.findall(r"\d+", v)), default=0) for v in vals])
    allc = "".join(vals)
    tot = len(allc) or 1
    cnt = Counter(allc)
    ent = -sum((c / tot) * math.log2(c / tot) for c in cnt.values()) if allc else 0.0
    frac = lambda pred: (sum(1 for v in vals if pred(v)) / n) if n else 0.0
    f += [sum(c.isdigit() for c in allc) / tot, sum(c.isupper() for c in allc) / tot,
          sum(c.islower() for c in allc) / tot, allc.count(" ") / tot,
          sum((not c.isalnum()) and c != " " for c in allc) / tot, len(DEVANAGARI.findall(allc)) / tot,
          (allc.count("X") + allc.count("x")) / tot, ent,
          frac(str.isdigit), frac(lambda v: any(c.isdigit() for c in v) and any(c.isalpha() for c in v)),
          frac(lambda v: "@" in v), frac(lambda v: "," in v), frac(lambda v: "." in v), frac(lambda v: "-" in v),
          frac(lambda v: "/" in v), frac(lambda v: "+" in v), frac(lambda v: v[:1] == "0"),
          frac(lambda v: v[:1].isdigit()), frac(lambda v: v.istitle()), frac(lambda v: v.isupper()),
          (sum(v.count(",") for v in vals) / n) if n else 0.0]
    shapes = Counter(_shape(v) for v in vals)
    f += [(shapes.most_common(1)[0][1] / n) if n else 0.0, (len(shapes) / n) if n else 0.0,
          (float(np.std(lens)) / (float(np.mean(lens)) or 1.0)) if lens else 0.0]
    f += [frac(lambda v, p=p: bool(p.search(v.strip()))) for p in _PATTERNS.values()]
    f += [frac(lambda v, fn=fn: _safe(fn, v)) for fn in VALIDATORS.values()]
    dates = [d for d in (parse_date(v) for v in vals) if d]
    years = [d.year for d in dates]
    f += [len(dates) / n if n else 0.0] + (_stats(years) if years else [0.0, 0.0, 0.0, 0.0])
    f += [frac(lambda v: any(m in v for m in HINDI_MONTHS))]
    hk = header_kind(header)
    f += [1.0 if hk == k else 0.0 for k in HEADER_KINDS]
    f += [1.0 if GENERIC_HEADER.match((header or "").lower()) else 0.0, 1.0 if hk is None else 0.0]
    assert len(f) == len(FEATURE_NAMES)
    return np.asarray(f, dtype=np.float32)
