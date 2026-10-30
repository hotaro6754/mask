"""Scanner edge cases: mostly-empty columns, a few identifiers in an ordinary column, mixed and tiny samples."""
import pytest

from maskguard import scanner
from maskguard.scanner import classify_column, classify_column_rules, scan_table

REFS = [f"ORD-{20240000 + i}" for i in range(200)]
HARD_NEGATIVES = {  # ordinary columns that must not be pulled into review by the sparse band
    "order_ref": [f"ORD-{20240000 + i}" for i in range(200)],
    "utr": [f"UTR{3000000000 + 7919 * i}" for i in range(200)],
    "sku": [f"SKU-{chr(65 + i % 26)}{i:05d}" for i in range(200)],
    "uuid": [f"{i:08x}-1f2e-4c3d-9a8b-{i * 7919:012x}" for i in range(200)],
    "bad_pan": [f"ABCD{c}1234F" for c in "DIMNOQRSUVWXYZ"] * 10,  # PAN-shaped, impossible holder type
    # PAN-shaped product codes, a few of which pass the PAN check by chance (bharat-pii-bench's pan_sku decoy)
    "pan_sku": [f"XKQ{'D' if i % 15 else 'P'}R{i:04d}Z" for i in range(200)],
    "ip": [f"10.0.{i // 250}.{i % 250}" for i in range(200)],
}


@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
@pytest.mark.parametrize("kind,odd", [("email", "ravi.k@example.in"), ("pan", "AFZPK7190K"),
                                      ("iban", "GB82 WEST 1234 5698 7654 32")])
def test_a_few_strong_identifiers_in_a_reference_column_go_to_review(classify, kind, odd):
    r = classify("ref_code", REFS[:197] + [odd] * 3)
    assert r and r["kind"] == kind and r["tag"] == scanner.KIND_TAG[kind], r  # masked either way
    assert r["source"] in ("ml", "sparse") and (r["source"] == "ml" or r["confidence"] == "review")
    assert odd not in r["evidence"]  # evidence describes the column, never quotes a value


def test_the_sparse_band_catches_what_the_model_misses():
    r = classify_column("ref_code", REFS[:199] + ["AFZPK7190K"])  # one PAN in 200 references: the model says "none"
    assert r["source"] == "sparse" and r["confidence"] == "review" and r["tag"] == "PII_HIGH"
    assert classify_column("ref_code", REFS) is None


@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
@pytest.mark.parametrize("name", sorted(HARD_NEGATIVES))
def test_ordinary_codes_are_not_flagged(classify, name):
    r = classify(name, HARD_NEGATIVES[name])
    assert r is None or r["source"] != "sparse", r


@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
def test_mixed_contact_column_is_masked(classify):
    vals = [f"user{i}@mail.example.in" if i % 2 else f"98{i:08d}" for i in range(100)]
    r = classify("contact", vals)
    assert r and r["tag"] == "PII_HIGH", r


@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
def test_a_single_sampled_email_is_enough(classify):
    assert classify("col_3", ["priya@example.in"])["kind"] == "email"
    assert classify("col_4", []) is None  # an empty column: nothing to tag (and it stays UNREVIEWED, so masked)


def test_mostly_empty_column_is_sampled_past_the_nulls(env):
    """300 NULLs, then a handful of emails: sampling skips NULLs, so the emails are found on every backend."""
    b = env.backend
    b.admin_script("DROP TABLE IF EXISTS sparse_contacts")
    b.admin_script("CREATE TABLE sparse_contacts (id INTEGER, alt_contact VARCHAR(80))")
    rows = [f"({i}, NULL)" for i in range(300)] + [f"({300 + i}, 'person{i}@example.in')" for i in range(5)]
    b.admin_script("INSERT INTO sparse_contacts VALUES " + ", ".join(rows))
    assert len(b.sample("sparse_contacts", "alt_contact")) == 5
    entry = scan_table(b, "sparse_contacts")
    assert entry["alt_contact"]["kind"] == "email" and entry["alt_contact"]["tag"] == "PII_HIGH"
    b.admin_script("DROP TABLE sparse_contacts")


# Patterns from the organisers' Saffron Bank pack (TalentAP 2026). The values below are made up in the same formats.
@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
def test_pan_shape_counts_even_when_the_check_digits_fail(classify):
    pans = ["TZPPG0000O", "ZFSPV0000G", "OOHPJ0000H", "UXAPH0000R", "GYNPT0000T", "VRQPK0000Z"] * 4
    assert classify("pan_no", pans)["kind"] == "pan"   # 0000 is never issued, so stdnum rejects them; shape + name agree
    assert classify("col_7", pans)["kind"] == "pan"    # no name at all: the shape (with a valid holder letter) is enough


@pytest.mark.parametrize("classify", [classify_column, classify_column_rules], ids=["hybrid", "rules"])
def test_banking_abbreviations_name_money_and_accounts(classify):
    money = [11132.85, 85000.0, 360567.13, 4200.5, 99000.0]
    for col in ("curr_bal", "bal_after", "amt_requested_inr", "od_limit_inr", "CREDIT_LIMIT"):
        r = classify(col, money)
        assert r and r["kind"] == "amount" and r["tag"] == "FINANCIAL_CONFIDENTIAL", (col, r)
    assert classify("credit_score", [712, 688, 801, 640, 755])["kind"] == "credit_score"
    assert classify("int_rate_pct", [3.5, 6.75, 7.1, 4.0, 5.25]) is None  # a rate is not personal money
    accts = ["51145972248884", "46775843622712", "56690643833469", "00381255117509", "73400918812345"]
    for col in ("account_no", "LINKED_ACCT"):
        assert classify(col, accts)["kind"] == "bank_account", col


def test_a_column_named_like_personal_data_is_never_suggested_public():
    from maskguard.scanner import suggest_public
    accts = ["51145972248884", "46775843622712", "56690643833469", "00381255117509", "73400918812345"]
    assert suggest_public("account_no", accts) is None   # whole numbers ending in _no, but the name says account
    assert suggest_public("txn_id", accts) is not None   # an ordinary key is still suggested
