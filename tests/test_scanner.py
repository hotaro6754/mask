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
    # demo approvals apply only where the scanner found nothing, so "approval" proves it left these columns alone
    assert reg["support_tickets"]["order_ref"]["source"] == "approval"  # 12 digits but fails the Aadhaar checksum
    assert reg["users"]["aadhaar"]["kind"] == "aadhaar" and reg["users"]["pan"]["kind"] == "pan"
    assert reg["accounts"]["iban"]["confidence"] == "high"
    assert reg["users"]["city"]["source"] == "approval" and reg["accounts"]["status"]["source"] == "approval"


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


def test_rules_scanner_finds_identifiers_inside_free_text():
    """Without LightGBM (e.g. no OpenMP runtime on a slim image) free text must still be checked for identifiers."""
    texts = ["Customer called from 9876543210 asking why the card was blocked.",
             "Please send the new statement to the registered address soon.",
             "Customer called from 9123456780 about a failed UPI payment today."] * 5
    r = classify_column("message", texts)
    assert r["tag"] == "PII_IN_TEXT" and "PHONE" in r["evidence"] and r["source"] == "rules+patterns"
    assert classify_column("notes", ["Fee reversal", "KYC update", "Card blocked"] * 5) is None  # labels, not text


def test_without_the_ml_scanner_the_demo_free_text_is_still_tagged_and_status_warns(sqlite_env, monkeypatch):
    from maskguard import scanner
    from maskguard.cli import status_label
    from maskguard.service import LocalService
    monkeypatch.setitem(scanner._ML, "ok", False)
    reg = scan(sqlite_env.backend)
    assert reg["support_tickets"]["message"]["tag"] == "PII_IN_TEXT"
    sqlite_env.gw.update_registry(reg)
    st = LocalService(sqlite_env.app).status()
    check = next(c for c in st["checks"] if c["name"] == "PII scanner")
    assert check["ok"] and check["warn"] and "rules only" in check["detail"] and "libgomp1" in check["detail"]
    assert all(c["ok"] for c in st["checks"]) and status_label(True, True).plain == "WARN"  # exit code unchanged
    monkeypatch.setitem(scanner._ML, "ok", True)
    assert "warn" not in next(c for c in LocalService(sqlite_env.app).status()["checks"] if c["name"] == "PII scanner")
