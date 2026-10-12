from maskguard import masks
from maskguard.scanner import ScanWorker, classify_column_rules as classify_column, scan


def test_card_partial_matches_problem_statement():
    assert masks.partial("4111-2222-3333-1111", 4, 4) == "4111-XXXX-XXXX-1111"
    assert masks.partial("123", 4, 4) == "XXX"  # too short to keep both ends -> mask everything
    assert masks.email("ravi@bank.in") == "r***@bank.in"


def test_tags_from_values_even_with_misleading_headers(env):
    reg = env.gw.registry
    assert reg["support_tickets"]["contact"]["kind"] == "phone"
    assert reg["support_tickets"]["payment_ref"]["tag"] == "FINANCIAL_CONFIDENTIAL"
    assert "tag" not in reg["support_tickets"]["order_ref"]  # 12 digits but fails the Aadhaar checksum
    assert reg["users"]["aadhaar"]["kind"] == "aadhaar" and reg["users"]["pan"]["kind"] == "pan"
    assert reg["accounts"]["iban"]["confidence"] == "high"
    assert "tag" not in reg["users"]["city"] and "tag" not in reg["accounts"]["status"]


def test_rules_scanner_scrambled_header_and_low_ratio_goes_to_review():
    cards = ["4111111111111111", "5500005555555559", "340000000000009"] * 10
    assert classify_column("col_7", cards)["kind"] == "card"
    mixed = cards[:4] + ["hello"] * 6
    assert classify_column("col_8", mixed)["confidence"] == "review"
    assert classify_column("order_ref", ["123456789012", "210987654321", "555555555555"]) is None


def test_overrides_win(env):
    reg = scan(env.backend, overrides={"users": {"city": {"tag": "PII_MEDIUM", "kind": "address"}}})
    assert reg["users"]["city"]["tag"] == "PII_MEDIUM" and reg["users"]["city"]["confidence"] == "override"


def test_new_table_is_rejected_until_the_background_worker_scans_it(sqlite_env):
    from maskguard.rewriter import Rejected
    import pytest
    env = sqlite_env
    env.backend.admin_script("CREATE TABLE leads (id INTEGER, mobile TEXT); "
                             "INSERT INTO leads VALUES (1, '9876543210'), (2, '9123456780');")
    with pytest.raises(Rejected):
        env.run("support", "SELECT * FROM leads")
    worker = ScanWorker(env.backend, env.gw.update_registry, interval=3600)
    worker.run_once()
    assert worker.last_error is None
    assert env.run("support", "SELECT mobile FROM leads")[1][0][0] == "XXXXXX3210"
