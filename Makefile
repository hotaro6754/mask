test:
	MASKGUARD_HMAC_KEY=test-key uv run pytest -q

bench:
	uv run python bench/overhead.py
