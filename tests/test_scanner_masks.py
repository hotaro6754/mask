from maskguard import masks
from maskguard.scanner import classify_column

def test_card_partial_matches_problem_statement():
    assert masks.partial("4111-2222-3333-1111", 4, 4) == "4111-XXXX-XXXX-1111"

def test_scrambled_header_still_detected_and_order_numbers_not_aadhaar(env):
    vals = [r[0] for r in env.conn.execute("SELECT credit_card FROM accounts")]
    assert classify_column("col_7", vals)["kind"] == "card"
    assert classify_column("order_ref", ["123456789012", "210987654321", "555555555555"]) is None
