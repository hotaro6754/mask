export MASKGUARD_HMAC_KEY ?= dev-only-hmac-key-change-me
export MASKGUARD_JWT_SECRET ?= dev-only-jwt-secret-change-me-0123456789

.PHONY: install test test-pg bench dashboard api scan attack postman demo up down

install:
	uv sync

test:
	uv run pytest -q

test-pg:            ## needs a running Postgres, e.g. `docker compose up -d postgres`
	MASKGUARD_TEST_PG=postgresql://maskguard:maskguard@127.0.0.1:5432/bank uv run pytest -q

bench:
	uv run python bench/overhead.py

dashboard:
	uv run maskguard dashboard

api:
	uv run maskguard serve

scan:
	uv run maskguard scan

attack:
	uv run maskguard attack -u analyst.ali -p analyst123

postman:            ## API must be running on :8000
	npx -y newman@6 run postman/Smart-Data-Masking.postman_collection.json -e postman/Local.postman_environment.json

demo:               ## interactive security console
	uv run maskguard

up:
	docker compose up --build

down:
	docker compose down
