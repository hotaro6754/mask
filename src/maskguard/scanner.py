"""PII discovery: hybrid LightGBM column classifier + checksum rules (see maskguard.ml.model.decide).

classify_column() is the scanner used everywhere. classify_column_rules() is the v1 rules-only scanner, kept as a
fallback when LightGBM is unavailable and as a baseline for bench/eval_scanner.py.
"""
import logging, re, threading, time
import yaml
from stdnum import iban as _iban, luhn as _luhn
from stdnum.in_ import aadhaar as _aadhaar, pan as _pan

log = logging.getLogger("maskguard.scanner")

KIND_TAG = {
    # direct identifiers
    "aadhaar": "PII_HIGH", "pan": "PII_HIGH", "passport": "PII_HIGH", "voter_id": "PII_HIGH", "ssn": "PII_HIGH",
    "phone": "PII_HIGH", "email": "PII_HIGH", "upi": "PII_HIGH",
    # financial
    "card": "FINANCIAL_CONFIDENTIAL", "iban": "FINANCIAL_CONFIDENTIAL", "bank_account": "FINANCIAL_CONFIDENTIAL",
    "amount": "FINANCIAL_CONFIDENTIAL", "balance": "FINANCIAL_CONFIDENTIAL", "gstin": "FINANCIAL_CONFIDENTIAL",
    # quasi-identifiers
    "name": "PII_MEDIUM", "address": "PII_MEDIUM", "dob": "PII_MEDIUM", "pincode": "PII_MEDIUM",
    "vehicle_reg": "PII_MEDIUM", "ifsc": "PII_MEDIUM",
    # identifiers embedded in free text (notes, comments)
    "free_text_pii": "PII_IN_TEXT",
    # health data: a special category (GDPR art. 9, DPDP), sensitive even without a name next to it
    "health": "HEALTH",
    # personal attributes that look harmless as values (M/F, a short list): masked from the header alone
    "demographic": "PII_MEDIUM",
}
HEADER_WORDS = {"email": "email", "mail": "email", "phone": "phone", "mobile": "phone", "msisdn": "phone",
                "ssn": "ssn", "aadhaar": "aadhaar", "aadhar": "aadhaar", "pan": "pan", "card": "card", "cc": "card",
                "iban": "iban", "balance": "balance", "name": "name", "address": "address", "dob": "dob", "birth": "dob",
                "amount": "amount", "fee": "amount", "fees": "amount", "salary": "amount",
                "premium": "amount", "wage": "amount", "refund": "amount",
                "doctor": "name", "physician": "name", "nurse": "name", "surgeon": "name",
                "diagnosis": "health", "icd": "health", "blood": "health", "allergy": "health", "allergies": "health",
                "medication": "health", "medicine": "health", "prescription": "health", "disease": "health",
                "symptom": "health", "symptoms": "health", "treatment": "health", "therapy": "health",
                "illness": "health", "disability": "health", "medical": "health", "clinical": "health",
                "gender": "demographic", "sex": "demographic", "religion": "demographic", "caste": "demographic",
                "ethnicity": "demographic", "marital": "demographic", "nationality": "demographic"}
# Kinds whose header alone is enough to mask a non-numeric column, even when the values look harmless
STRONG_HEADER_KINDS = {"health", "demographic"}
TEXT_ONLY_HEADER_KINDS = {"name", "health", "demographic"}  # a header like these on whole numbers is a key, not the data
KEY_WORDS = {"id", "no", "num", "number", "key", "ref", "seq"}

ICD10 = re.compile(r"[A-TV-Z][0-9][0-9A-Z](?:\.[0-9A-Z]{1,4})?")
BLOOD_GROUP = re.compile(r"(?:A|B|AB|O)\s?(?:\+|-|POS(?:ITIVE)?|NEG(?:ATIVE)?)")
HONORIFIC_NAME = re.compile(r"(?:Dr|Mr|Mrs|Ms|Miss|Prof|Shri|Smt|Sri|Kumari)\.?\s+[A-Z][\w'.-]+(?:\s+[A-Z][\w'.-]+)*")


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


def _numeric(sample):
    return bool(sample) and all(isinstance(v, (int, float)) or re.fullmatch(r"-?\d+(?:\.\d+)?", str(v).strip())
                                for v in sample[:50])


def value_kind(sample):
    """Kinds recognised from the values alone that the classifier wasn't trained on: diagnosis codes (ICD-10), blood
    groups, and names with a title (Dr., Mrs., Shri …). Returns (kind, evidence) or (None, None)."""
    vals = [str(v).strip() for v in sample[:200] if v is not None and str(v).strip()]
    if len(vals) < 3:
        return None, None
    for kind, rx, what, need in (("health", ICD10, "ICD-10 diagnosis codes", 0.9),
                                 ("health", BLOOD_GROUP, "blood groups", 0.9),
                                 ("name", HONORIFIC_NAME, "names with a title (Dr., Mrs. …)", 0.8)):
        hits = [v for v in vals if rx.fullmatch(v if kind == "name" else v.upper())]
        if len(hits) / len(vals) >= need and len(set(hits)) >= 2:
            return kind, f"{len(hits) / len(vals):.0%} of values look like {what}"
    return None, None


# Identifiers whose format is strict enough that even one value is evidence: an order-id or reference column almost
# never contains an email address, a PAN or a valid IBAN by accident. (Aadhaar, cards and phone numbers are left out:
# about one random 12- or 16-digit number in ten passes their checksum, and any 10-digit number can look like a phone.)
SPARSE_KINDS = ("email", "pan", "iban")


def sparse_identifiers(sample):
    """A few strong-format identifiers in an otherwise ordinary column (a reference field someone typed an email
    into). Returns (kind, evidence) or (None, None); the caller tags the column for review, so it stays masked."""
    vals = [v for v in sample if v is not None and str(v).strip()]
    for kind in SPARSE_KINDS:
        hits = {str(v).strip() for v in vals if _safe(VALIDATORS[kind], str(v).strip())}
        if hits:
            return kind, (f"{len(hits)} distinct value(s) of {len(vals)} sampled look like {kind}: "
                          "a sparse identifier, needs review")
    return None, None


def suggest_public(column, sample):
    """For a column the scanner found nothing in: why it probably isn't personal data, or None. Only a suggestion:
    nothing is approved until a person runs `maskguard pii approve` (--suggested takes these)."""
    vals = [v for v in sample if v is not None]
    if len(vals) < 5:
        return None
    tokens = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", column).lower())
    if tokens[-1] in KEY_WORDS and all(isinstance(v, int) or re.fullmatch(r"\d+", str(v).strip()) for v in vals):
        return "looks like an id or key (whole numbers)"
    distinct = {str(v).strip().lower() for v in vals}
    if len(vals) >= 20 and len(distinct) <= 12 and all(len(d) <= 20 for d in distinct) and not _numeric(vals):
        return f"short list of values ({len(distinct)} distinct), like a status or type"
    return None


def header_kind(column):
    tokens = re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", column).lower())
    return next((HEADER_WORDS[t] for t in tokens if t in HEADER_WORDS), None)


def _safe(fn, v):
    try:
        return bool(fn(v))
    except Exception:
        return False


def _out(kind, conf, evidence, **extra):
    return {"kind": kind, "tag": KIND_TAG[kind], "confidence": conf, "evidence": evidence, **extra}


def classify_column_rules(column, values, hi=0.8, lo=0.3):
    """v1 scanner: validators + header keywords."""
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
        return _out(best_kind, "high", f"{best_ratio:.0%} pass {best_kind} validator; header={hk}", source="rules")
    if best_kind and best_ratio >= lo:
        return _out(best_kind, "review", f"only {best_ratio:.0%} pass {best_kind} validator; header={hk}", source="rules")
    vk, vev = value_kind(sample)
    if vk:
        return _out(vk, "high", vev, source="patterns")
    if _texty(sample):  # identifiers inside free text, as the ML path does
        from .textpii import scan_values
        has, ev = scan_values(sample)
        if has:
            return _out("free_text_pii", "high", f"free text; {ev}", source="rules+patterns")
    sk, sev = sparse_identifiers(sample)
    if sk:
        return _out(sk, "review", sev, source="sparse")
    if hk and not (hk in TEXT_ONLY_HEADER_KINDS and _numeric(sample)):  # header-only evidence: tag anyway (fail closed)
        return _out(hk, "medium", f"header token matched {hk}; no validator match", source="rules")
    return None


_ML = {"ok": None, "error": None}
# LightGBM needs the OpenMP runtime, which minimal systems (slim Docker images, fresh macOS) don't ship
ML_HINT = "install the OpenMP runtime for the ML scanner: libgomp1 (Debian/Ubuntu), libgomp (Fedora), libomp (macOS: brew)"


def ml_available():
    if _ML["ok"] is None:
        try:
            from .ml.model import Classifier
            Classifier.get()
            _ML["ok"] = True
        except Exception as e:  # missing lightgbm, its OpenMP runtime, or the model file -> rules only
            log.warning("ML scanner unavailable (%s); using rules only; %s", e, ML_HINT)
            _ML["ok"], _ML["error"] = False, f"{type(e).__name__}: {str(e)[:120]}"
    return _ML["ok"]


def _texty(sample):
    """Mostly multi-word values: worth checking for identifiers inside the text."""
    vals = [str(v) for v in sample[:50] if v is not None]
    return bool(vals) and sum(len(v.split()) >= 4 for v in vals) / len(vals) >= 0.5


def classify_column(column, values):
    """Hybrid scanner. Returns {kind, tag, confidence, evidence, source, probs} or None for non-PII columns."""
    if not ml_available():
        return classify_column_rules(column, values)
    from .ml.model import decide
    sample = [v for v in values if v is not None][:200]
    d = decide(column, sample)
    kind = d["kind"]
    if kind in KIND_TAG:
        return _out(kind, d["confidence"], d["evidence"], source=d["source"], probs=d["probs"])
    vk, vev = value_kind(sample)
    if vk:
        return _out(vk, "high", vev, source="patterns", probs=d["probs"])
    if kind == "free_text" or _texty(sample):
        from .textpii import scan_values
        has, ev = scan_values(sample)
        if has:
            return _out("free_text_pii", "high", f"free text; {ev}", source="ml+patterns", probs=d["probs"])
        if kind == "free_text":
            return None
    sk, sev = sparse_identifiers(sample)
    if sk:
        return _out(sk, "review", sev, source="sparse", probs=d["probs"])
    hk = header_kind(column)  # ML says not PII; a PII header with a non-confident model still masks (fail closed)
    if hk in TEXT_ONLY_HEADER_KINDS and _numeric(sample):  # doctor_id, blood_test_no: numbers, not names or health
        return None
    if hk in STRONG_HEADER_KINDS:
        return _out(hk, "medium", f"header says {hk} data; {d['evidence']}", source="header", probs=d["probs"])
    if hk and d["confidence"] != "high":
        return _out(hk, "review", f"header says {hk}; {d['evidence']}", source="header", probs=d["probs"])
    return None


def scan_table(backend, table, sample_size=200):
    from .backends import is_numeric
    entry = {}
    for name, sql_type in backend.columns(table):
        vals = backend.sample(table, name, sample_size)
        found = classify_column(name, vals)
        entry[name] = {"type": "num" if is_numeric(sql_type) else "text", "sql_type": sql_type, **(found or {})}
        hint = None if found else suggest_public(name, vals)
        if hint:
            entry[name].update(suggest="PUBLIC", evidence=f"{hint}: suggested PUBLIC")
    return entry


def scan(backend, tables=None, overrides=None, sample_size=200):
    """Scan every table (or the given ones) and return {table: {column: meta}}. Overrides win over the scanner."""
    registry = {t: scan_table(backend, t, sample_size) for t in (tables or backend.tables())}
    for table, cols in (overrides or {}).items():
        for col, meta in (cols or {}).items():
            if table in registry and col in registry[table]:
                meta = dict(meta)
                if meta.pop("if_untagged", False) and registry[table][col].get("tag"):
                    continue  # a conditional approval never hides something the scanner found
                registry[table][col].update({"confidence": "override", "evidence": "manual override", **meta})
    return registry


def save_registry(registry, path):
    with open(path, "w") as f:
        yaml.safe_dump(registry, f, sort_keys=True)


def load_registry(path):
    with open(path) as f:
        return yaml.safe_load(f) or {}


def summary(registry):
    """Flat list of sensitive columns for display (not the approved-public or unreviewed ones)."""
    return [{"table": t, "column": c, "tag": m.get("tag"), "kind": m.get("kind"), "source": m.get("source"),
             "confidence": m.get("confidence"), "evidence": m.get("evidence")}
            for t, cols in registry.items() for c, m in cols.items() if m.get("tag") not in (None, "PUBLIC")]


def unreviewed(registry):
    """Columns the scanner found nothing in and no person has approved: masked for non-admin roles until reviewed."""
    return [(t, c) for t, cols in registry.items() for c, m in cols.items() if not m.get("tag")]


class ScanWorker(threading.Thread):
    """Background worker: rescans on an interval and hands the new registry to on_update (e.g. the gateway).
    New tables become queryable only after they've been scanned, so unscanned data stays rejected (fail closed)."""

    def __init__(self, backend, on_update, interval=300, overrides=None):
        super().__init__(daemon=True, name="maskguard-scanner")
        self.backend, self.on_update, self.interval, self.overrides = backend, on_update, interval, overrides
        self.stop_event = threading.Event()
        self.last_run, self.last_error = None, None

    def run_once(self):
        try:
            overrides = self.overrides() if callable(self.overrides) else self.overrides  # re-read: reviews apply
            self.on_update(scan(self.backend, overrides=overrides))
            self.last_run, self.last_error = time.time(), None
        except Exception as e:  # keep the old registry; a failed scan must not unmask anything
            self.last_error = repr(e)

    def run(self):
        while not self.stop_event.wait(self.interval):  # the caller already ran the first scan
            self.run_once()

    def stop(self):
        self.stop_event.set()
