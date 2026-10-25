"""Hybrid ML scanner: model loads, finds PII the v1 rules could not, stays quiet on look-alikes, fails closed."""
import random

import pytest

from maskguard import scanner
from maskguard.ml import synth
from maskguard.ml.features import FEATURE_NAMES, column_features
from maskguard.ml.model import Classifier, decide, rule_kind


def col(kind, n=30, seed=1, header="col_07"):
    r = random.Random(seed)
    if kind == "none":
        return header, [synth.negative(r, "order12") for _ in range(n)]
    return header, [synth.GENERATORS[kind](r) for _ in range(n)]


def test_feature_vector_is_fixed_length():
    assert column_features("x", ["a", None, "123"]).shape == (len(FEATURE_NAMES),)
    assert column_features("x", []).shape == (len(FEATURE_NAMES),)


@pytest.mark.parametrize("kind", ["name", "address", "dob", "bank_account", "upi", "ifsc", "passport",
                                  "vehicle_reg", "pincode", "phone", "email"])
def test_ml_finds_pii_that_has_no_checksum_under_a_meaningless_header(kind):
    h, values = col(kind, seed=11)
    d = decide(h, values)
    assert d["kind"] == kind and d["source"] == "ml", d


@pytest.mark.parametrize("kind", ["aadhaar", "pan", "gstin", "card", "iban", "voter_id"])
def test_checksums_win_and_are_reported_as_such(kind):
    h, values = col(kind, seed=12)
    d = decide(h, values)
    assert d["kind"] == kind and d["source"] == "checksum"


@pytest.mark.parametrize("sub", ["order12", "otp", "pan_sku", "invoice", "ipv4", "timestamp", "gstin_bad", "uuid",
                                 "category", "city_set", "status", "sku"])
def test_look_alikes_are_not_tagged(sub):
    r = random.Random(5)
    synth._COLUMN_CHOICES.clear()
    values = [synth.negative(r, sub, "k") for _ in range(30)]
    if sub == "otp":  # random 6-digit columns overlap pincodes unless a leading 0 appears; make it unambiguous
        values[0] = "012345"
    assert decide("field_c", values)["kind"] is None


def test_amount_is_financial_only_with_a_personal_header():
    r = random.Random(3)
    values = [synth.amount(r, 0.1, (3, 2)) for _ in range(30)]
    assert scanner.classify_column("balance", values)["tag"] == "FINANCIAL_CONFIDENTIAL"
    assert scanner.classify_column("unit_price", values) is None


def test_low_confidence_pii_still_masks_review_band():
    h, values = col("name", n=4, seed=2)
    d = scanner.classify_column("ssn", values[:1] + ["???"])
    assert d is not None and d.get("tag")  # header says PII, model unsure -> tagged (fail closed)


def test_falls_back_to_rules_when_ml_is_unavailable(monkeypatch):
    monkeypatch.setitem(scanner._ML, "ok", False)
    h, values = col("aadhaar", seed=4)
    d = scanner.classify_column("col_1", values)
    assert d["kind"] == "aadhaar" and d["source"] == "rules"


def test_rule_kind_threshold():
    _, values = col("card", seed=6)
    assert rule_kind(values)[0] == "card"
    assert rule_kind(values[:5] + ["hello"] * 10)[0] is None


def test_model_metadata_is_present():
    clf = Classifier.get()
    assert clf.kinds == synth.KINDS and clf.booster.num_feature() == len(FEATURE_NAMES)


def test_a_long_sample_is_scored_in_training_sized_blocks():
    """Features such as the shortest and longest value drift as a sample grows; with 200 values an address column was
    read as non-PII. The model now averages blocks of 20 values, so 200 values are no worse than 20."""
    from maskguard.ml.model import blocks
    r = random.Random(11)
    values = [synth.address(r) for _ in range(200)]
    values[17], values[133], values[150] = "??", "x", values[3] * 4  # malformed and outlier values, as in real data
    assert [len(b) for b in blocks(values)] == [20] * 10 and len(blocks(values[:20])) == 1
    for n in (20, 60, 200):
        assert decide("col_07", values[:n])["kind"] == "address", n


def test_a_leading_zero_anywhere_rules_out_pin_codes():
    r = random.Random(3)
    otps = [f"{r.randint(100000, 999999)}" for _ in range(60)]
    otps[45] = "012345"  # in the third block: averaging alone would outvote it
    assert decide("field_c", otps)["kind"] != "pincode"
