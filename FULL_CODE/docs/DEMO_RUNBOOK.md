# Demo runbook

A 7-minute evaluator walkthrough. Every expected result below was captured from a real run on the synthetic demo
dataset (300 customers, seed 7). Request ids and timings will differ; values, masks and the policy version will not.

## 0. Setup (once)

Linux / macOS:

```bash
git clone <repo> && cd mask/FULL_CODE
uv sync                                   # Python 3.10+, installs everything incl. LightGBM model deps
export MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me
export MASKGUARD_JWT_SECRET=dev-only-jwt-secret-change-me-0123456789
```

Windows PowerShell:

```powershell
git clone <repo>; cd mask/FULL_CODE
uv sync
$env:MASKGUARD_HMAC_KEY="dev-only-hmac-key-change-me"
$env:MASKGUARD_JWT_SECRET="dev-only-jwt-secret-change-me-0123456789"
```

The first run creates `data/bank.db` with synthetic data, scans it and records an integrity baseline.
(`make …` targets exist for the common commands; on Windows use the `uv run …` forms shown.)

## 1. The branded CLI and real health checks

```bash
uv run maskguard              # interactive console: banner, live status, numbered actions
uv run maskguard doctor       # non-interactive check list, exit code 4 if anything fails
```

Expected: the MASKGUARD banner, then an engine-status panel where every line was actually checked:
DATABASE PASS `sqlite · 3 tables`, PII SCANNER PASS `12 sensitive columns · LightGBM + checksums`,
POLICY ENGINE PASS `v1-9140d3df20 · default deny`, AUDIT TRAIL PASS, INTEGRITY BASELINE PASS, HMAC KEY PASS,
THREAT ENGINE PASS, MODE `LOCAL · development · demo identities ON`. (Point `MASKGUARD_DB` at a stopped
PostgreSQL to see `UNAVAILABLE` and exit code 4 instead: nothing is shown as READY unless it was checked.)

In the interactive console: **[3] Masking playground** → table `accounts` → `first rows` → role `support`, then
`r` to switch role, `c` to compare all roles, `v` to verify the source is unchanged.

## 2. Scan the database for PII

```bash
uv run maskguard scan --sample-limit 200
```

Expected: 12 sensitive columns in 3 tables, no sample values printed, e.g.
`accounts credit_card FINANCIAL_CONFIDENTIAL card high 90% pass card checksum; ML top=card (1.00)`,
`support_tickets contact PII_HIGH phone high` (the header says "contact", the values say phone),
`support_tickets message PII_IN_TEXT free_text_pii high`, and `support_tickets order_ref` **not** tagged
(12-digit numbers that fail the Aadhaar checksum). `--dry-run` classifies without applying.

## 3. Inspect classifications and the effective policy

```bash
uv run maskguard pii list
uv run maskguard roles list
uv run maskguard policy explain --role analyst --table users
```

Expected for the analyst on `users`: `name PII_MEDIUM → REDACT`, `email/phone/aadhaar/pan/ssn PII_HIGH → HMAC`,
`id/city PUBLIC → ALLOW` (approved in `policies/public.demo.yaml`), each with the rule that decided it (`rule analyst.PII_HIGH`) and a synthetic example
(`123-45-6789 → <16-hex token>`). No database values appear.

## 4–8. Same query, three roles

```bash
uv run maskguard compare "SELECT name, ssn, email FROM users ORDER BY id LIMIT 2" --roles admin,support,analyst
```

Expected:

```
ADMIN · admin.ann
 name           ssn           email
 Matthew Rana   205-84-4078   boragirindra@example.com
SUPPORT · support.sam
 name           ssn [PARTIAL]   email [PARTIAL]
 Matthew Rana   XXX-XX-4078     b***@example.com
ANALYST · analyst.ali
 name [REDACT]   ssn [HMAC]                         email [HMAC]
 REDACTED        58fd7cb2ac03875b6c94f1370f69f816   423ef9aa927cc5b048aaaf98452d3bf1
                 (tokens depend on MASKGUARD_HMAC_KEY; these are for dev-only-hmac-key-change-me)
```

Cards, the problem statement's example:

```bash
uv run maskguard query --role support --table accounts --columns credit_card,balance,status -n 3 --explain
```

Expected: `credit_card [PARTIAL]` shows the first 4 and last 4 digits with the rest as X
(16-digit cards with dashes read like `4111-XXXX-XXXX-1111`), `balance [PARTIAL]` is rounded down to 10,000, and
**every row is `active`**, because Support's row filter hides frozen accounts. Run the same as `--role admin`: real
values and both statuses.

Bypass attempts get nothing:

```bash
uv run maskguard query --role support "WITH users AS (SELECT * FROM users) SELECT ssn FROM users LIMIT 1"   # still XXX-XX-…
uv run maskguard query --role support "UPDATE users SET name = 'x'"     # DENIED, exit code 3
uv run maskguard attack --role analyst                                  # 0/17 leaks vs 14/17 for naive masking
```

## 9. Explain the policy

Covered in step 3. `uv run maskguard policy list` prints the full role × column matrix.

## 10. Repeat through Postman

```bash
uv run maskguard serve --port 8000          # API + dashboard; keep it running (second terminal)
npx -y newman@6 run postman/Smart-Data-Masking.postman_collection.json -e postman/Local.postman_environment.json
```

Expected: `requests 55 · failed 0`, `assertions 121 · failed 0`. In the Postman app: import both files, pick the
*MaskGuard · Local* environment, Run collection. Folder 03 shows the same query as four roles; folder 05 the 25
negative/security cases.

## 11. Prove the source records did not change

```bash
uv run maskguard integrity proof
uv run maskguard integrity verify
uv run maskguard test                      # attack suite per role + audit chain + integrity proof
```

Expected: the proof runs the query as admin/support/analyst/auditor (all ALLOWED, 0/5/6/6 masked columns), refuses
six write attempts (UPDATE, DELETE, DROP, stacked write, INSERT … SELECT, SELECT INTO), and ends with
`source digest ed72f4a6… → ed72f4a6…  PASS  source mutation: NONE`. `integrity verify` shows every table MATCH with
row counts 300/300. `maskguard test` prints PASS for every line and exits 0.

To see the check fail when data really changes: change a row outside MaskGuard (e.g.
`sqlite3 data/bank.db "UPDATE users SET city='X' WHERE id=1"`), run `maskguard integrity verify` → `users CHANGED`,
exit code 5; `maskguard integrity baseline --reason "accepted change"` accepts it.

## 12. The same, visually

Open http://127.0.0.1:8000/ui/ (the server from step 10).

1. **Overview**: readiness checks, sensitive-column count, policy version, 24 h activity from the audit log.
2. **Masking playground**: table `users`, roles admin + support + analyst (+ auditor), **Run**. Four result cards
   from four separate requests (each with its own request id), masked columns labelled PARTIAL / HMAC / REDACT,
   "Why each field looks the way it does" per role, and **Source integrity: MATCH · Source mutation: NONE**.
   Switch to *SQL editor* → *Write attempt (refused)* to see every role refused.
3. **Policy studio**: click `support × PII_HIGH`, choose `allow`: the dialog flags *WEAKENS PROTECTION* and a
   non-admin warning, and refuses to apply without a reason and the confirmation box.
4. **Audit explorer**: filter `decision = reject`; expand a row: literals appear as `?`.
5. **Data integrity**: **Run full proof**: the same three steps as the CLI.
6. **API lab**: send `POST /query` as the current identity; copy the cURL.
7. Switch identity (top right) to `support`: Audit, Integrity and Policy editing now show *capability required*:
   the server returns 403 for those endpoints.

## Other backends

```bash
docker compose up --build        # PostgreSQL 16: API + dashboard :8000, classic dashboard :8501, PG proxy :6543
MASKGUARD_DB=postgresql://user:pw@host:5432/bank uv run maskguard status
psql "host=localhost port=6543 user=support.sam dbname=bank"     # via the wire proxy (password support123)
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `UNAVAILABLE cannot start the engine` | check `MASKGUARD_DB`; run `maskguard doctor` |
| Analyst queries fail with an HMAC error | set `MASKGUARD_HMAC_KEY` (≥ 16 bytes) |
| Tokens stop working after a restart | set `MASKGUARD_JWT_SECRET` |
| `/auth/demo` returns 404 | demo mode is off (`MASKGUARD_DEMO=0` or `MASKGUARD_ENV=production`); sign in with a user |
| `/auth/demo` returns 403 "only available from this machine" | the browser is on another host (or in Docker): set `MASKGUARD_DEMO=1` explicitly, synthetic data only (docker compose already does) |
| A demo user is suddenly refused with "blocked by the threat engine" | expected after bursts of refused queries: as admin, send `POST /threats/support.sam/unblock` (API lab), or restart the server (blocks are kept in memory) |
| Windows terminal shows boxes instead of the banner | the CLI falls back to a one-line banner when the terminal can't encode it; use Windows Terminal for the full one |
