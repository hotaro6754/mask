"""Free-text redaction: patterns, SQLite/PostgreSQL parity, predicates, scanner tagging."""

import random

import pytest

from maskguard import textpii
from maskguard.ml import synth
from tests.conftest import PG_URL

CASES = [
    ("Call me on 98765 43210 tomorrow", "Call me on [PHONE] tomorrow"),
    ("Mobile +91-9876543210 / 09876543210", "Mobile [PHONE] / [PHONE]"),
    ("mail ravi.k@bank.co.in please", "mail [EMAIL] please"),
    ("pay to ravi.k@okaxis now", "pay to [UPI] now"),
    ("Aadhaar 2345 6789 0124 verified", "Aadhaar [AADHAAR] verified"),
    ("masked XXXX XXXX 1234 ok", "masked [AADHAAR] ok"),
    ("PAN ABCPK1234L on file", "PAN [PAN] on file"),
    ("GSTIN 27ABCPK1234L1Z5 issued", "GSTIN [GSTIN] issued"),
    ("IFSC SBIN0001234 branch", "IFSC [IFSC] branch"),
    ("card 4111-1111-1111-1111 blocked", "card [CARD] blocked"),
    ("acct 1234567890 credited", "acct [NUMBER] credited"),
    ("acct 123456789012345 credited", "acct [CARD] credited"),  # 13-19 digits: card-shaped, still removed
    ("born 12/03/1985, लिखा 12 जनवरी 1961", "born [DATE], लिखा [DATE]"),
    ("pin 560001 area", "pin [PIN] area"),
    ("vehicle MH 12 AB 1234 parked", "vehicle [VEHICLE] parked"),
    ("Order ORD-77 shipped in 3 days, 2 items", "Order ORD-77 shipped in 3 days, 2 items"),  # nothing to remove
]


@pytest.mark.parametrize("text,expected", CASES)
def test_redact(text, expected):
    assert textpii.redact(text) == expected


def test_find_reports_original_values():
    spans = textpii.find("Call 98765 43210 or mail a@b.co")
    assert [(s[0], s[3]) for s in spans] == [("PHONE", "98765 43210"), ("EMAIL", "a@b.co")]


def _corpus(n=400):
    r = random.Random(9)
    texts = [synth.free_text(r) for _ in range(n)]
    for kind in (
        "aadhaar",
        "pan",
        "gstin",
        "upi",
        "phone",
        "passport",
        "voter_id",
        "ifsc",
        "vehicle_reg",
        "bank_account",
        "email",
        "dob",
        "card",
        "pincode",
    ):
        for _ in range(20):
            v = synth.GENERATORS[kind](r)
            texts += [f"The recorded value is {v} for this file.", f"दर्ज मूल्य {v} है।", f"record me {v} save karo."]
    return texts + [c for c, _ in CASES]


@pytest.mark.skipif(not PG_URL, reason="MASKGUARD_TEST_PG not set")
def test_postgres_redaction_is_byte_identical_to_python():
    from maskguard.backends import PostgresBackend

    b = PostgresBackend(PG_URL)
    texts = _corpus()
    got = [
        r[0]
        for r in b.admin_query(
            "SELECT mg_redact_text(t) FROM unnest(%s::text[]) WITH ORDINALITY AS u(t, i) ORDER BY i", (texts,)
        )[1]
    ]
    mismatches = [(t, p, g) for t, p, g in zip(texts, map(textpii.redact, texts), got, strict=False) if p != g]
    assert not mismatches, mismatches[:5]


def test_scanner_tags_free_text_with_identifiers_only(env):
    reg = env.gw.registry["support_tickets"]
    assert reg["message"]["tag"] == "PII_IN_TEXT" and "PHONE" in reg["message"]["evidence"]
    assert reg["notes"]["source"] == "approval"  # short category labels, no identifiers: only the demo approval applies


def test_roles_see_free_text_correctly_and_filters_see_redacted_text(env):
    raw = [r[0] for r in env.backend.admin_query("SELECT message FROM support_tickets ORDER BY id")[1]]
    phone_msg = next(m for m in raw if "called from" in m)
    digits = textpii.find(phone_msg)[0][3]
    sup = [r[0] for r in env.run("support", "SELECT message FROM support_tickets ORDER BY id")[1]]
    assert all(textpii.find(m) == [] or all(s[0] in ("PIN",) for s in textpii.find(m)) for m in sup)
    assert any("[PHONE]" in m for m in sup)
    assert env.run("support", f"SELECT id FROM support_tickets WHERE message LIKE '%{digits}%'")[1] == []
    assert {r[0] for r in env.run("analyst", "SELECT message FROM support_tickets LIMIT 5")[1]} == {"REDACTED"}
    assert env.run("admin", f"SELECT id FROM support_tickets WHERE message LIKE '%{digits}%'")[1]
