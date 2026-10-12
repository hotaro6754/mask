# MaskGuard

**AI-powered PII discovery and leak-proof, role-based masking for SQLite, PostgreSQL and MySQL.**
MaskGuard sits in front of the database, finds sensitive columns with a LightGBM + checksum scanner, and masks them
per role at query time. Stored data never changes.

| Role | Sees |
|---|---|
| **Admin** | real values |
| **Support** | partial masks: `4111-XXXX-XXXX-1111`, `XXX-XX-6789`, `r***@bank.in`, `[PHONE]` inside notes, balances rounded to 10,000; frozen accounts hidden (row-level filter) |
| **Analyst** | `REDACTED` or keyed-HMAC tokens (joinable, not reversible); balances only through differentially private SUM/AVG/COUNT |
| **Auditor** | `REDACTED` for every personal-data column; reads policies, scanner evidence, the audit log and integrity proofs |

![The maskguard CLI: real health checks, then one query as four roles](docs/img/cli.png)

## What it does

1. **AI PII discovery.** A LightGBM classifier over 85 value statistics, combined with checksum validators
   (Aadhaar Verhoeff, PAN, GSTIN mod-36, EPIC, card Luhn, IBAN), tags 20 PII types, including Indian IDs and
   Devanagari names, even when column names lie. Checksum hits can never be downgraded, and uncertain columns are
   still masked for review. A background worker rescans, and new tables are blocked until they're scanned.
2. **Leak-proof masking.** Each table in a query is rewritten into a masked view
   (`FROM users` → `FROM (SELECT mg_partial(ssn,0,4) AS ssn, … FROM users) AS users`). Aliases, `*`, CTEs, joins,
   `WHERE`, `ORDER BY` and aggregates therefore only ever see masked values. Writes, stacked statements, catalogs,
   variables and unknown functions are rejected.
3. **Free-text redaction.** Identifiers inside notes and comments become `[PHONE]`, `[AADHAAR]`, `[UPI]` and so on,
   inside the database, with byte-identical output on all three engines.
4. **Insider-threat engine.** Rules and an IsolationForest score each user's query stream (enumeration, probing,
   bulk paging, firewall bursts, slow attacks) and alert or block.
5. **Differential privacy.** Analysts get useful noisy aggregates within a daily ε budget, but can't work out any
   one person's value.
6. **Plugs in anywhere.** A PostgreSQL wire-protocol proxy (psql or any driver), a REST API with a Python SDK, a
   Postman collection, a CLI and a Streamlit dashboard. A hash-chained audit log strips literals, so PII never
   reaches it.

## Results (details and reproduction: [docs/EVALUATION.md](docs/EVALUATION.md))

| | MaskGuard | Baseline |
|---|---|---|
| PII discovery, misleading column names (bharat-pii-bench, unseen seeds), macro-F1 | **0.999** | 0.844 |
| False positives on look-alike data (order numbers, SKUs, OTPs…) | **1.5%** | 22.2% |
| PII leaks across 17 bypass and inference attacks (PostgreSQL) | **0 / 17** | 15 / 17 (naive masking) |
| Simulated insider attacks detected (normal users blocked) | **95–100% (0%)** | — |
| Analyst AVG error at ε = 0.5, group of 150 | **5.4%** | — |
| Differencing attack on one balance (mean ₹4.45 lakh), median error | **₹22 lakh** | exact without DP |
| Added latency per query, p50, all features on | ~8 ms (SQLite, PostgreSQL), ~21 ms (MySQL) | — |

## Run it

```bash
uv sync
export MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me      # PowerShell: $env:MASKGUARD_HMAC_KEY="dev-only-hmac-key-change-me"
uv run maskguard                                           # interactive security console (banner, live checks, playground)
uv run maskguard serve                                     # REST API + Control Room dashboard: http://127.0.0.1:8000/ui/
```

Or `docker compose up --build`: PostgreSQL 16, API + dashboard on :8000, classic Streamlit dashboard on :8501, and the
PostgreSQL wire proxy on :6543. **[docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md)** walks through the whole demo with
exact commands and expected output.

| Interface | What it gives you |
|---|---|
| **CLI** `maskguard` | Interactive console, plus `doctor`, `status`, `db inspect`, `scan --dry-run`, `pii list`, `roles show`, `policy explain`, `query --role/--table`, `compare`, `audit list`, `integrity proof`, `test` and more. `--json` output, stable exit codes, and `--api URL` to run through the REST API |
| **Control Room** `/ui/` | Overview, live role playground (one real request per role, side by side, with per-field explanations and an integrity check), PII discovery, policy studio (validated, audited edits), role explorer, audit explorer, integrity proofs, API lab, CLI guide |
| **REST API** `/docs` | Health and readiness, demo identities, query and query builder, policy explain, matrix and edits, scan, audit search, integrity baseline, verify and proof. Capability-checked |
| **Postman** `postman/` | 54 requests and 119 body assertions, including 25 negative and security cases and integrity before and after. `npx newman run …` |
| **PostgreSQL proxy** :6543 | `psql "host=localhost port=6543 user=support.sam dbname=bank"`: any PostgreSQL client, masked |
| **Python SDK** | `MaskGuardClient.demo(url, "analyst").query_df("SELECT status, avg(balance) FROM accounts GROUP BY status")` |

![Control Room playground: four roles, four real requests, per-field explanations, integrity verified](docs/img/control-room-playground.png)

Demo identities (`policies/users.demo.yaml`, synthetic):
- `admin.ann`, `support.sam`, `analyst.ali`, `auditor.aud`, with passwords `<role>123`;
- `intruder.ian` for the threat demo.

Demo mode (one-click identities) is off when `MASKGUARD_ENV=production`, and refused if forced on there. Create
real users with `maskguard hash-password`. All settings are in `.env.example`.

## Architecture

Security boundary, role and capability model, policy semantics and integrity method: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
psql / drivers ─► PG wire proxy ─┐
REST API / SDK / Postman ────────┼─► Auth (JWT role) ─► Threat engine ─► Rewriter (sqlglot) ─► SQLite | PostgreSQL | MySQL
Dashboards / CLI ────────────────┘                                          ▲      ▲              (read-only)
                                                       Policy YAML ─────────┘      │                   │
                                                       AI PII scanner (background) ┴◄──────────────────┘
                                     Audit log (hash-chained, no literals) ◄── every decision, risk score, ε spent
```

## Configuration

| Variable | Default | |
|---|---|---|
| `MASKGUARD_DB` | `sqlite:///data/bank.db` | `postgresql://…` or `mysql://…` (MySQL needs `log_bin_trust_function_creators=1` for its masking functions) |
| `MASKGUARD_HMAC_KEY` | required | key for Analyst tokens; missing → error (fail closed) |
| `MASKGUARD_JWT_SECRET` | random per process | set it so tokens survive restarts and work across workers |
| `MASKGUARD_POLICY` | `policies/default.yaml` | role × tag → `allow` / `partial` / `hmac` / `redact` / `redact_text` / `aggregate` / `deny`; row caps; group floor; threat thresholds; DP ε and bounds |
| `MASKGUARD_USERS` | `policies/users.demo.yaml` | users, roles, PBKDF2 hashes |
| `MASKGUARD_OVERRIDES` | `policies/overrides.yaml` | manual tags that win over the scanner |
| `MASKGUARD_SCAN_INTERVAL` | `300` | background rescan period, in seconds |

## Tests

```bash
make test                                                      # SQLite
MASKGUARD_TEST_PG=postgresql://… MASKGUARD_TEST_MYSQL=mysql://… uv run pytest -q    # all three databases
uv run maskguard test                                          # security regression: attacks per role + integrity proof
make postman                                                   # Newman against a running API
```

CI (`.github/workflows/ci.yml`) runs the following, and fails on any leak, any failed assertion, or any change to
the source data:
- the test suite against PostgreSQL 16 and MySQL 8.4;
- the attack suite;
- `maskguard test`;
- the Postman collection under Newman.

The suite includes a Playwright walkthrough of the dashboard: every page, no JavaScript errors, and no horizontal
scroll at phone width. It also includes CLI tests for exit codes and JSON output in local and remote mode.

## Research context

[docs/REFERENCE_RESEARCH.md](docs/REFERENCE_RESEARCH.md) reviews 14 related open-source projects at source level. It
records what each one verifiably does, which ideas MaskGuard adopted (strictness-ordered actions, policy versions in
audit entries, explain output, negative API assertions, CLI conventions) and which it deliberately rejected
(post-query masking, regex SQL parsing, unsalted hashes).


Prabowo et al., *Privacy-Preserving Tools and Technologies: Government Adoption and Challenges*, IEEE Access 13
(2025), lists data masking's weakness as "limited protection against sophisticated attacks". It also names
automated PIA and better privacy–utility balance as open problems. [docs/ROADMAP.md](docs/ROADMAP.md) maps each of
these gaps to a MaskGuard component.

## Known limits

- HMAC tokens still allow equality joins and frequency analysis. Partial masks reveal the characters they leave
  visible.
- A column the scanner misses stays exposed until it's tagged. Uncertain columns are masked for review, and
  `overrides.yaml` lets you force a tag.
- The threat engine was evaluated on simulated sessions; recalibrate it on real normal traffic.
- Names and addresses inside free text need NER, which isn't integrated yet.
- Applications must not hold direct database credentials, or they bypass the gateway.

## Submission material

- `docs/MaskGuard_Round1_Submission.pptx`: the Round 1 deck.
- `docs/demo.mp4`: a walkthrough of the classic dashboard.
- `docs/IMPLEMENTATION_REPORT.md`: requirements matrix with evidence-based status, test totals and remaining work.
- `docs/EVALUATION.md` and `docs/eval/*.json`: every number behind the claims above.
