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
