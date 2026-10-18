# Privacy accounting review: evidence and reproduction

This file is part of the review package described in `PRIVACY_ACCOUNTING_REVIEW_BRIEF.md`. It records how each
piece of evidence was produced, so the reviewer can reproduce it instead of relying on summaries. Everything here
is documentation; nothing in this file changes code, tests or the protocol.

## 1. Environment used for the recorded results

| Component | Version |
|---|---|
| OS | Linux 6.18 (x86_64, glibc 2.39), Ubuntu 24.04 userland |
| Python / uv | 3.13.16 / uv 0.11.32 (`uv run --offline`, dependencies from `uv.lock`) |
| pytest | 9.1.1 |
| SQLite | 3.45.1 (Python's `sqlite3`) |
| PostgreSQL | 16.15 (two clusters: one with `trust` authentication on port 5433, one with `scram-sha-256` on port 5434 to match CI) |
| MySQL | 8.4.11 (Docker `mysql:8.4`, host port 3307) |
| Drivers and frameworks | psycopg 3.3.6 (libpq 18.0), PyMySQL 2.2.8, FastAPI 0.143.0, Streamlit 1.65.0 |
| Node / Newman | Node 22.22.0, Newman 6.2.3 (`npx -y newman@6`) |

CI runs on GitHub's `ubuntu-latest` with `postgres:16` and `mysql:8.4` service containers
(`.github/workflows/ci.yml`).

## 2. Test suite

### 2.1 Commands

```bash
# The test databases. CI uses password authentication; so should you.
export MASKGUARD_TEST_PG='postgresql://postgres:<password>@127.0.0.1:5432/bank'
export MASKGUARD_TEST_MYSQL='mysql://root:<password>@127.0.0.1:3306/bank'
uv run pytest -q -rs                                   # full suite: SQLite, PostgreSQL and MySQL

# The CI steps after the suite (CI sets these two variables for the whole job)
export MASKGUARD_HMAC_KEY=ci-only-hmac-key MASKGUARD_JWT_SECRET=ci-only-jwt-secret-0123456789-0123456789
uv run maskguard attack -u analyst.ali -p analyst123   # must report 0 MaskGuard leaks, exit 0
uv run maskguard test                                  # attack suite per role + audit chain + integrity proof
uv run maskguard serve --port 8000 &                   # then:
npx -y newman@6 run postman/Smart-Data-Masking.postman_collection.json -e postman/Local.postman_environment.json
```

The masking functions fail closed without `MASKGUARD_HMAC_KEY`. Running `maskguard test` without it fails with
`OperationalError: user-defined function raised exception`; that is the intended refusal, not a test failure.

### 2.2 Recorded results

| Run | Code under test | Result |
|---|---|---|
| Full suite, PostgreSQL with `trust` auth | `63b0c25` | 474 passed, 6 xfailed, 1 skipped |
| Full suite, PostgreSQL with `scram-sha-256` (as CI) | `988271d` | 474 passed, 6 xfailed, 1 skipped |
| Production PostgreSQL tests only, `scram-sha-256` | `32ed792` (before the fixture fix) | 4 errors: `fe_sendauth: no password supplied` (the CI failure, reproduced) |
| Same, after the fix | `988271d` | 4 passed |
| `maskguard attack -u analyst.ali -p analyst123` | `988271d` | `PII leaks: naive 14/17 · MaskGuard 0/17 · firewall rejected 4/4`, exit 0 |
| `maskguard test` | `988271d` | every row PASS, exit 0 |
| Newman, Postman collection | `988271d` | 55 requests, 121 assertions, 0 failures |

- **The skipped test:** `tests/test_production.py::test_mysql_read_only_runtime_end_to_end` needs
  `MASKGUARD_TEST_MYSQL_ADMIN`, an account allowed to create users. Neither these runs nor CI set it.
- **The 6 xfails:** strict expected failures in `tests/test_dp_findings.py` that document F1, F2 (three
  variants), F4 and F6. They are the DP findings, not test noise. A fix turns them into failures until the marker
  is removed.

### 2.3 CI history on `claude/zealous-bell-me62fn`

Runs are listed at <https://github.com/hotaro6754/mask/actions?query=branch%3Aclaude%2Fzealous-bell-me62fn>.

| Runs | Commits | Conclusion and cause |
|---|---|---|
| 16 | `f57a5ff` | Failure in the `setup-uv` post-job cache prune only. Tests, attack suite, `maskguard test` and Newman all passed. Same cause as run 27 |
| 17–26 | `1c811c1` … `32ed792` | Failure in the test step: the three (later four) PostgreSQL production tests errored at setup because the `pg_prod_db` fixture dropped passwords from its connection URLs, and CI's PostgreSQL requires one. Every other test passed (run 25: 462 passed, 6 xfailed, 3 errors). The later CI steps were skipped |
| 27 | `988271d` ([run 27](https://github.com/hotaro6754/mask/actions/runs/39061323284)) | Every real step passed: tests (473 passed, 2 skipped, 6 xfailed), attack suite (`MaskGuard 0/17`), `maskguard test`, and Newman (121 assertions, 0 failures). The job then failed in the post-job step: `uv cache prune --ci` logged "Cache is currently in-use, waiting for other uv processes to finish", then "Timeout (300s) when waiting for lock". The Newman step had left `uv run maskguard serve` running, and it held uv's cache lock |
| 28 | `29f6ba1` | The workflow fix: the Newman API now runs from the synced venv (no uv lock) and is stopped on exit. **Success on every step** ([run 28](https://github.com/hotaro6754/mask/actions/runs/39090103420)): tests 473 passed, 2 skipped, 6 xfailed; attack suite `MaskGuard 0/17`; `maskguard test`; Newman 121 assertions, 0 failures; the post-job cache prune completed ("Removed 10789 files") |

**Why CI skips two tests while local runs skip one:**

- `test_mysql_read_only_runtime_end_to_end` needs `MASKGUARD_TEST_MYSQL_ADMIN`; neither CI nor these runs set it.
- `tests/test_dashboard_ui.py` needs a local Playwright install, which the CI image does not have.

**Reproducing the lock failure:** with a scratch `UV_CACHE_DIR`, start `uv run maskguard serve`, then run
`uv cache prune --ci`. It blocks; it was stopped by a 20 s timeout. With no `uv run` process alive it completes at
once, and with the new step it completes at once after Newman.

Each local "passed" result in this file came from a PostgreSQL that used `trust` authentication until the
`scram-sha-256` reproduction. That is why the fixture bug was not caught locally.

## 3. Live production check of the attack self-test fix (`63b0c25`)

### 3.1 What it shows

The real API server in production configuration refuses `/attacks` for support and admin users, whatever the
query parameters. PostgreSQL's own scan counters show that the protected tables were not read. An ordinary masked
query is the positive control: it does move the counters, so the counters work.

### 3.2 Procedure

The original run used a scratch directory (`$WORK`) that no longer exists. To reproduce, run these steps from the
repository root at `63b0c25` or later. They need a PostgreSQL 16 superuser URL in `ADMIN_URL`; the run used
`postgresql://postgres@127.0.0.1:5433/bank`.

1. Generate secrets: `export MASKGUARD_JWT_SECRET=$(openssl rand -hex 32) MASKGUARD_HMAC_KEY=$(openssl rand -hex 32)`.
2. Create the scratch database with `uv run python setup.py "$WORK"` (script below). It creates a database, a
   read-only gateway login, the masking functions (installed by the owner), demo-shaped synthetic data loaded by
   the owner, and a production user file with one admin and one support user.
3. Start the server in production:

   ```bash
   export MASKGUARD_ENV=production MASKGUARD_DEMO=0 MASKGUARD_USERS=$WORK/users.yaml \
          MASKGUARD_DB=$(python3 -c "import json;print(json.load(open('$WORK/live.json'))['gateway'])") \
          MASKGUARD_AUDIT=$WORK/state/audit.jsonl MASKGUARD_REGISTRY=$WORK/state/registry.yaml MASKGUARD_STATE_DIR=$WORK/state
   unset MASKGUARD_SEED_IF_EMPTY
   uv run maskguard serve --host 127.0.0.1 --port 8765 &
   curl -s http://127.0.0.1:8765/meta   # "environment":"production","demo_mode":false,"demo_identities":[]
   ```
4. Run `uv run python verify.py "$WORK"` (script below).
5. Check the CLI under the same environment:
   - `maskguard attack --user ops.lead --password …`
   - `maskguard attack --role support`
   - `maskguard simulate-attack`
   - `maskguard test`

   Each must exit 3 with `self-tests are disabled in production`.
6. Clean up: stop the server, then drop the scratch database and role.

`setup.py`:

```python
import json, secrets, sys
import psycopg, yaml
from maskguard.auth import hash_password
from maskguard.backends import connect, install_functions
from maskguard.seed import make_db

out, base = sys.argv[1], "postgresql://postgres@127.0.0.1:5433"   # ADMIN_URL without the database
name, role, gwpw = f"mg_live_{secrets.token_hex(4)}", f"mg_live_gw_{secrets.token_hex(4)}", secrets.token_hex(16)
with psycopg.connect(base + "/bank", autocommit=True) as c:
    c.execute(f'CREATE DATABASE "{name}"')
    c.execute(f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{gwpw}' NOSUPERUSER NOCREATEDB NOCREATEROLE")
owner = f"{base}/{name}"
with psycopg.connect(owner, autocommit=True) as c:
    c.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
install_functions(owner)
make_db(connect(owner, install=False), n=50)
with psycopg.connect(owner, autocommit=True) as c:
    c.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
    c.execute(f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{role}"')
users = {"ops.lead": ("admin", secrets.token_hex(12)), "desk.agent": ("support", secrets.token_hex(12))}
with open(f"{out}/users.yaml", "w") as f:
    yaml.safe_dump({"users": {u: {"role": r, "password_hash": hash_password(p)} for u, (r, p) in users.items()}}, f)
json.dump({"db": name, "role": role, "owner": owner, "gateway": f"postgresql://{role}:{gwpw}@127.0.0.1:5433/{name}",
           "users": users}, open(f"{out}/live.json", "w"))
```

`verify.py`:

```python
import json, sys, time, urllib.request, urllib.error
import psycopg

SP, URL = sys.argv[1], "http://127.0.0.1:8765"
live = json.load(open(f"{SP}/live.json"))
TABLES = ("users", "accounts", "support_tickets")


def call(method, path, body=None, tok=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {tok}"} if tok else {})})
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def scans():
    """Seq + index scans per protected table, read by the owner after the server's stats have been flushed."""
    time.sleep(12)  # PostgreSQL flushes an idle backend's statistics within ~10 s
    with psycopg.connect(live["owner"]) as c:
        c.execute("SELECT pg_stat_clear_snapshot()")
        rows = c.execute("SELECT relname, coalesce(seq_scan,0) + coalesce(idx_scan,0) FROM pg_stat_user_tables "
                         "WHERE relname = ANY(%s) ORDER BY relname", (list(TABLES),)).fetchall()
    return dict(rows)


tok = {u: call("POST", "/auth/login", {"username": u, "password": p})[1]["token"] for u, (_, p) in live["users"].items()}
s0 = scans()
st, body = call("POST", "/query", {"sql": "SELECT id, email, ssn FROM users ORDER BY id LIMIT 2"}, tok["desk.agent"])
print("positive control  POST /query as support:", st, "rows", body.get("rows"))
s1 = scans()
print("scan counters     before", s0, "after query", s1, "-> moved:", s1 != s0)
for user in ("desk.agent", "ops.lead"):
    for q in ("", "?demo=1", "?role=admin&env=development"):
        st, body = call("GET", "/attacks" + q, tok=tok[user])
        print(f"GET /attacks{q:30} as {user:10} ({live['users'][user][0]:7}) ->", st, json.dumps(body))
s2 = scans()
print("scan counters     after 6 x /attacks", s2, "-> unchanged:", s2 == s1)
audit = [json.loads(l) for l in open(f"{SP}/state/audit.jsonl")][-6:]
print("audit (last 6)   ", [{k: e.get(k) for k in ("user", "role", "channel", "decision", "reason")} for e in audit])
print("audit has sql/rewritten keys:", any(("sql" in e or "rewritten" in e) for e in audit))
```

### 3.3 Recorded output (2026-10-17, PostgreSQL 16.15, code at `63b0c25`)

The data is synthetic; masked values appear as the support role sees them. The audit line is condensed: the
six entries were identical apart from user and role, which were support and admin users. The CLI and server-log
lines come from step 5 and a log check, with whitespace aligned.

```
positive control  POST /query as support: 200 rows [[1, 'b***@example.com', 'XXX-XX-4078'], [2, 'b***@example.com', 'XXX-XX-1884']]
scan counters     before {'accounts': 8, 'support_tickets': 10, 'users': 10} after query {'accounts': 8, 'support_tickets': 10, 'users': 11} -> moved: True
GET /attacks                               as desk.agent (support) -> 403 {"detail": "self-tests are disabled in production"}
GET /attacks?demo=1                        as desk.agent (support) -> 403 {"detail": "self-tests are disabled in production"}
GET /attacks?role=admin&env=development    as desk.agent (support) -> 403 {"detail": "self-tests are disabled in production"}
GET /attacks                               as ops.lead   (admin  ) -> 403 {"detail": "self-tests are disabled in production"}
GET /attacks?demo=1                        as ops.lead   (admin  ) -> 403 {"detail": "self-tests are disabled in production"}
GET /attacks?role=admin&env=development    as ops.lead   (admin  ) -> 403 {"detail": "self-tests are disabled in production"}
scan counters     after 6 x /attacks {'accounts': 8, 'support_tickets': 10, 'users': 11} -> unchanged: True
audit (last 6)    6 × {'role': support|admin, 'channel': 'rest', 'decision': 'reject', 'reason': 'attack suite: self-tests are disabled in production'}
audit has sql/rewritten keys: False

maskguard attack --user ops.lead -> exit 3 : ✖ DENIED  self-tests are disabled in production
maskguard attack --role support  -> exit 3 : ✖ DENIED  self-tests are disabled in production
maskguard simulate-attack        -> exit 3 : ✖ DENIED  self-tests are disabled in production
maskguard test                   -> exit 3 : ✖ DENIED  self-tests are disabled in production
server log: 0 lines matching traceback|error|exception; /attacks requests logged as 403 Forbidden
```

Positive control in development (SQLite, synthetic data): `maskguard attack --role support` printed
`PII leaks: naive 14/17 · MaskGuard 0/17 · firewall rejected 4/4` and exited 0, and `maskguard simulate-attack` ran
to the threat engine's block.

## 4. Regression tests for the fix

All are in `tests/test_production.py`:

- `test_self_tests_refuse_outside_development_before_touching_the_database[*]` (four environments);
- `test_a_failing_audit_log_still_refuses_the_self_test`;
- `test_attacks_endpoint_is_refused_in_production_for_every_role`;
- `test_cli_and_dashboard_self_tests_are_refused_in_production`;
- `test_production_build_refuses_every_self_test_entry_point` (PostgreSQL; needs `MASKGUARD_TEST_PG`).

**Negative control:** with the guard in `attacks.require_self_test` replaced by an unconditional return, all of
these tests fail. The control was run locally against `63b0c25`'s tests; the edit was reverted and not committed.

## 5. Probes that informed the brief

Before the fix, a scratch probe ran on PostgreSQL 16 under the production profile:

- A `support` user received the full `/attacks` report, with leak counts and oracle results computed from real
  rows.
- The probe also checked database error text through the gateway in two cases. The text carried only the masked
  value the role can already see. Four noisy-aggregate queries designed to fail returned no exact value.

These probes cover only the cases tested. They are not regression tests, and they say nothing general about the
error paths (brief §6).
