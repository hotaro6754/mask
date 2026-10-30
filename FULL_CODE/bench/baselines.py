"""The detectors compared in bench/evaluate.py. Each maps one column (header, values) to a PII kind, or None for "not
personal". They see exactly the information their name says, so the comparison is fair:

    A  header_only      the column name, nothing else (the vocabulary the model's header features use)
    B  rules_only       regular expressions and check digits on the values; the column name is not read
    C  lightgbm_only    the LightGBM classifier's most probable kind, threshold 0.5; no checksum override
    D  rules_lightgbm   maskguard.ml.model.decide: check digits first, then the classifier, then the review band
    E  full_scanner     maskguard.scanner.classify_column: D plus reading values as a person would, value patterns,
                        free text, the sparse-identifier band and the column-name rules (what production runs)
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Sequence

from maskguard import scanner
from maskguard.ml import model
from maskguard.ml.features import _PATTERNS, VALIDATORS, header_kind

NOT_PII = {None, "none", "free_text", "amount"}
RULE_THRESHOLD = 0.6  # the share of values that must match, as in maskguard.ml.model.rule_kind

# Check-digit rules first (a pass is strong evidence), then shapes from most to least specific. A bare 9-18 digit
# number (bank account) and a 6-digit number (PIN) come last: they match many things that are not personal.
CHECKSUM_RULES: dict[str, Callable[[str], bool]] = {
    "aadhaar": VALIDATORS["aadhaar"],
    "gstin": VALIDATORS["gstin"],
    "card": VALIDATORS["card"],
    "iban": VALIDATORS["iban"],
    "pan": VALIDATORS["pan"],
    "voter_id": VALIDATORS["voter_epic"],
}
SHAPE_RULES: dict[str, Callable[[str], bool]] = {
    "email": _PATTERNS["email"].match,
    "upi": _PATTERNS["upi"].match,
    "ifsc": _PATTERNS["ifsc"].match,
    "ssn": _PATTERNS["ssn"].match,
    "passport": _PATTERNS["passport"].match,
    "vehicle_reg": _PATTERNS["vehicle"].match,
    "phone": _PATTERNS["phone"].match,
    "pincode": _PATTERNS["pincode"].match,
    "bank_account": _PATTERNS["bank_account"].match,
}


def _share(rule: Callable[[str], object], values: Sequence[str]) -> float:
    hits = 0
    for v in values:
        with contextlib.suppress(ValueError, TypeError, AttributeError):  # a validator rejecting a value: a miss
            hits += bool(rule(v))
    return hits / len(values)


def _strings(values: Sequence) -> list[str]:
    return [str(v).strip() for v in values if v is not None and str(v).strip()]


def header_only(header: str, values: Sequence) -> str | None:
    kind = header_kind(header)
    return None if kind in NOT_PII else kind


def rules_only(header: str, values: Sequence) -> str | None:
    vals = _strings(values)
    if not vals:
        return None
    for rules in (CHECKSUM_RULES, SHAPE_RULES):
        best = max(rules, key=lambda k: _share(rules[k], vals))
        if _share(rules[best], vals) >= RULE_THRESHOLD:
            return best
    return None


def lightgbm_only(header: str, values: Sequence) -> str | None:
    probs = model.Classifier.get().proba(header, list(values))
    i = int(probs.argmax())
    kind = model.KINDS[i]
    return None if kind in NOT_PII or probs[i] < 0.5 else kind


def rules_lightgbm(header: str, values: Sequence) -> str | None:
    kind = model.decide(header, list(values))["kind"]
    return None if kind in NOT_PII else kind


def full_scanner(header: str, values: Sequence) -> str | None:
    found = scanner.classify_column(header, list(values))
    return found["kind"] if found else None


DETECTORS: dict[str, Callable[[str, Sequence], str | None]] = {
    "A_header_only": header_only,
    "B_rules_only": rules_only,
    "C_lightgbm_only": lightgbm_only,
    "D_rules_lightgbm": rules_lightgbm,
    "E_full_scanner": full_scanner,
}
