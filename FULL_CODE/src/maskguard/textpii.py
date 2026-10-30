"""Redact identifiers inside free text (notes, comments, chat logs), at query time.

The pattern list is the single source of truth for both engines: SQLite runs it through Python `re`, PostgreSQL
through a generated PL/pgSQL function (see backends.PG_FUNCTIONS). The patterns only use syntax both engines
interpret the same way (ASCII classes, bounded repeats, look-around; no \\b, \\d or \\w), are applied one after
another in a fixed order, and every placeholder is digit-free so a later pattern can never match inside it.
Tests assert byte-identical output from both engines.

Redaction is deliberately broad: any 9-18 digit run, 6-digit PIN-like number or date is removed. In free text an
over-redacted reference number costs little; a missed Aadhaar costs a lot.
"""

import re

L = "(?<![A-Za-z0-9])"  # left boundary (ASCII), same meaning in Python and PostgreSQL ARE
R_ = "(?![A-Za-z0-9])"  # right boundary

EN_MONTHS = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec"
HI_MONTHS = "जनवरी|फ़रवरी|फरवरी|मार्च|अप्रैल|मई|जून|जुलाई|अगस्त|सितंबर|अक्टूबर|नवंबर|दिसंबर"

# (label, pattern) - applied in this order
PATTERNS = [
    ("EMAIL", "[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)*[.][A-Za-z]{2,}"),
    ("UPI", "[A-Za-z0-9._-]{2,}@[A-Za-z]{2,}(?![A-Za-z0-9.])"),
    ("IBAN", L + "[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}" + R_),
    ("GSTIN", L + "[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z]Z[0-9A-Z]" + R_),
    ("PAN", L + "[A-Z]{5}[0-9]{4}[A-Z]" + R_),
    ("IFSC", L + "[A-Z]{4}0[A-Z0-9]{6}" + R_),
    ("VOTER_ID", L + "[A-Z]{3}[0-9]{7}" + R_),
    ("PASSPORT", L + "[A-Z][0-9]{7}" + R_),
    ("VEHICLE", L + "[A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}" + R_),
    ("VEHICLE", L + "[0-9]{2} ?BH ?[0-9]{4} ?[A-Z]{1,2}" + R_),
    ("DATE", L + "[0-9]{1,2}[/-][0-9]{1,2}[/-][0-9]{4}" + R_),
    ("DATE", L + "[0-9]{4}-[0-9]{2}-[0-9]{2}" + R_),
    ("DATE", L + "[0-9]{1,2} (?:" + EN_MONTHS + ")[a-z]* [0-9]{4}" + R_),
    ("DATE", L + "[0-9]{1,2} (?:" + HI_MONTHS + ") [0-9]{4}" + R_),
    ("SSN", L + "[0-9]{3}-[0-9]{2}-[0-9]{4}" + R_),
    ("CARD", L + "[0-9](?:[ -]?[0-9]){12,18}" + R_),
    ("AADHAAR", L + "[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{4}" + R_),
    ("AADHAAR", L + "[Xx*]{4}[ -]?[Xx*]{4}[ -]?[0-9]{4}" + R_),
    ("PHONE", L + "(?:[+]91[ -]?|0)?[6-9][0-9]{4}[ -]?[0-9]{5}" + R_),
    ("NUMBER", L + "[0-9]{9,18}" + R_),
    ("PIN", L + "[1-9][0-9]{5}" + R_),
]
_COMPILED = [(label, re.compile(p)) for label, p in PATTERNS]


def redact(text):
    if text is None:
        return None
    s = str(text)
    for label, rx in _COMPILED:
        s = rx.sub(f"[{label}]", s)
    return s


def find(text):
    """Spans (label, start, end, value) in the ORIGINAL text, using the same ordered rules as redact()."""
    if text is None:
        return []
    s, taken, spans = str(text), [], []
    for label, rx in _COMPILED:
        for m in rx.finditer(s):
            a, b = m.span()
            if not any(a < tb and ta < b for ta, tb in taken):
                taken.append((a, b))
                spans.append((label, a, b, m.group()))
    return sorted(spans, key=lambda x: x[1])


def pg_function_sql():
    """PL/pgSQL version of redact(), generated from PATTERNS so the two can never drift apart."""
    steps = "\n".join(
        f"  s := regexp_replace(s, {_pg_literal(p)}, {_pg_literal('[' + label + ']')}, 'g');" for label, p in PATTERNS
    )
    return (
        "CREATE OR REPLACE FUNCTION mg_redact_text(v text) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $f$\n"
        "DECLARE s text := v;\nBEGIN\n  IF v IS NULL THEN RETURN NULL; END IF;\n" + steps + "\n  RETURN s;\nEND $f$;\n"
    )


def _pg_literal(s):
    return "'" + s.replace("'", "''") + "'"


def scan_values(values, min_rows=2, min_frac=0.03):
    """Scanner helper: does this text column carry identifiers? Returns (has_pii, evidence)."""
    vals = [str(v) for v in values if v is not None and str(v).strip()]
    if not vals:
        return False, "empty"
    hits, kinds = 0, {}
    for v in vals:
        sp = find(v)
        if sp:
            hits += 1
            for label, *_ in sp:
                kinds[label] = kinds.get(label, 0) + 1
    frac = hits / len(vals)
    ev = (
        f"{frac:.0%} of sampled rows contain identifiers ({', '.join(sorted(kinds))})"
        if hits
        else "no identifiers in sample"
    )
    return (hits >= min_rows or (hits and frac >= min_frac)), ev
