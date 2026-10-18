<div align="center">

# MaskGuard

**AI-powered PII discovery and query-time, role-based masking for SQLite, PostgreSQL and MySQL.**

MaskGuard sits in front of the database, finds sensitive columns with a LightGBM + checksum scanner, and rewrites
every query so each role sees only what its policy allows. Stored data never changes.

[![CI](https://github.com/hotaro6754/mask/actions/workflows/ci.yml/badge.svg?branch=claude/zealous-bell-me62fn)](https://github.com/hotaro6754/mask/actions/workflows/ci.yml?query=branch%3Aclaude%2Fzealous-bell-me62fn)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Databases](https://img.shields.io/badge/databases-SQLite%20%C2%B7%20PostgreSQL%20%C2%B7%20MySQL-4c8)
![Tests](https://img.shields.io/badge/tests-474%20passed-brightgreen)

[Demo video](docs/demo_full.mp4) · [Quick start](#quick-start) · [How it works](#how-it-works) ·
[Results](#results) · [Production](#production-profile) · [Privacy review](#noisy-aggregates-and-the-privacy-review) ·
[Deployment guide](docs/DEPLOYMENT.md)

<a href="https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/demo_full.mp4">
  <img src="docs/img/demo-video.png" alt="Watch the full MaskGuard walkthrough (8 minutes)" width="820">
</a>

</div>

---

## Why

Banks, NBFCs and fintechs give support, analytics and ops staff SQL access to tables of card numbers, Aadhaar, PAN
and balances. Two things go wrong:

- **Sensitive columns are hard to find.** Headers lie (`contact`, `ref_no`), and regexes confuse order numbers with
  Aadhaar numbers, so PII slips through unprotected.
- **Display masking leaks.** If masking is applied to the output only, `WHERE`, `ORDER BY`, aliases and aggregates
  still run on the real values, and a few probing queries recover them.

MaskGuard masks **inside the query**, at the table source, and finds the columns to mask with ML plus checksums.

## One query, four roles

| Role | Sees |
|---|---|
| **Admin** | real values |
| **Support** | partial masks: `4111-XXXX-XXXX-1111`, `XXX-XX-6789`, `r***@bank.in`, `[PHONE]` inside notes, balances rounded to 10,000; frozen accounts hidden by a row filter |
| **Analyst** | `REDACTED` or keyed HMAC tokens (joinable, not reversible); no individual balances |
| **Auditor** | `REDACTED` for every personal-data column; reads policies, scanner evidence, the audit log and integrity proofs |

![The Control Room playground: one query run as Admin, Support, Analyst and Auditor, with per-field explanations and an integrity check](docs/img/control-room-playground.png)

The same query from the CLI, one real authenticated request per role:

![maskguard compare: the same SELECT as four roles](docs/img/cli-roles.png)

## How it works

```
psql / drivers ─► PG wire proxy ─┐
REST API / SDK / Postman ────────┼─► Auth (JWT role) ─► Threat engine ─► Rewriter (sqlglot) ─► SQLite | PostgreSQL | MySQL
Dashboards / CLI ────────────────┘                                          ▲      ▲              (read-only)
                                                       Policy YAML ─────────┘      │                   │
                                                       AI PII scanner (background) ┴◄──────────────────┘
                                     Audit log (hash-chained, no literals) ◄── every decision and risk score
```

1. **AI PII discovery.** A LightGBM classifier over 85 value statistics, combined with checksum validators
   (Aadhaar Verhoeff, PAN, GSTIN mod-36, EPIC, card Luhn, IBAN), tags 20 PII types, including Indian IDs and
   Devanagari names, even when column names lie. Checksum hits can never be downgraded, and uncertain columns are
   still masked for review. A background worker rescans, and new tables are blocked until they're scanned.
2. **Masking inside the SQL.** Each table in a query is replaced by a masked view for the caller's role:

   ```sql
   SELECT email AS mail FROM users
   -- becomes
   SELECT email AS mail FROM (SELECT id, mg_email(email) AS email, mg_partial(ssn, 0, 4) AS ssn, … FROM main.users) AS users LIMIT 100
   ```

   Aliases, `*`, CTEs, joins, filters and sorting therefore work on the masked view, not the raw table. Writes,
   stacked statements, catalogs, variables and unknown functions are rejected, and every query runs read-only (a
   read-only transaction on PostgreSQL and MySQL, an authorizer on SQLite).
3. **Free-text redaction.** Identifiers inside notes and comments become `[PHONE]`, `[AADHAAR]`, `[UPI]` and so on,
   inside the database, with byte-identical output on all three engines.
4. **Insider-threat engine.** Rules and an IsolationForest score each user's query stream (enumeration, probing,
   bulk paging, firewall bursts, slow attacks) and alert or block.
5. **Audit and integrity.** A hash-chained audit log records every decision, with literals stripped so PII never
   reaches it. Integrity proofs hash the source tables before and after every role's queries and write attempts.
6. **Plugs in anywhere.** A PostgreSQL wire-protocol proxy (psql or any driver), a REST API with a Python SDK, a
   Postman collection, a CLI and two dashboards.

Security boundary, role and capability model, policy semantics and integrity method:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## See it work

<table>
<tr>
<td width="50%" valign="top">

**Attack suite.** 21 bypass and inference attacks, run against naive output masking and against MaskGuard.
Naive masking leaks 14 of 17 here (SQLite); MaskGuard leaks none, and all 4 unsafe statements are rejected.

![Attack suite: naive masking vs MaskGuard](docs/img/cli-attack-suite.png)

</td>
<td width="50%" valign="top">

**Insider threat.** An enumeration attack is scored query by query: it alerts at query 8 and is blocked at
query 22, with the reasons spelled out.

![Simulated enumeration attack scored and blocked by the threat engine](docs/img/cli-threat.png)

</td>
</tr>
<tr>
<td valign="top">

**PII discovery.** Every column with its classification, confidence, source (checksum or ML) and evidence.
Values are never displayed.

![Control Room: PII discovery](docs/img/control-room-discovery.png)

</td>
<td valign="top">

**Audit explorer.** Hash-chained, append-only, filterable. SQL is stored as a fingerprint with literals replaced
by `?`.

![Control Room: audit explorer, refusals expanded](docs/img/control-room-audit.png)

</td>
</tr>
</table>

**Security regression in one command:** the attack suite as every role, the audit chain, and an integrity proof that
the source data did not change.

![maskguard test: every check passes](docs/img/cli-security-test.png)

## Results

Details, method and reproduction: [docs/EVALUATION.md](docs/EVALUATION.md). Every number comes from a script in the
repository and a JSON file in `docs/eval/`.

| | MaskGuard | Baseline |
|---|---|---|
| PII discovery with misleading column names, macro-F1 (bharat-pii-bench, unseen seeds), **5 sample values** per column | **0.965** | 0.844 |
| Same, 20 sample values per column | **0.999** | 0.844 |
| False alarms on look-alike data (order numbers, SKUs, OTPs…), 5 / 20 values | **6.3% / 1.5%** | 22.2% |
| PII leaks across 17 bypass and inference attacks | **0 / 17** | 15 / 17 on PostgreSQL, 14 / 17 on SQLite and MySQL (naive masking) |
| Simulated insider attacks detected (normal users blocked) | **95–100% (0%)** | — |
| Added latency per query, p50, all features on | ~8 ms (SQLite, PostgreSQL), ~21 ms (MySQL) | — |
| Tests | **474 passed** on SQLite, PostgreSQL 16 and MySQL 8.4, plus 121 Postman assertions | — |

The attack suite is evidence for those 17 attack shapes, not a proof against every possible query. The threat
engine was evaluated on simulated sessions.

## Quick start

```bash
uv sync
export MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me      # PowerShell: $env:MASKGUARD_HMAC_KEY="dev-only-hmac-key-change-me"
uv run maskguard                                           # interactive security console (banner, live checks, playground)
uv run maskguard serve                                     # REST API + Control Room dashboard: http://127.0.0.1:8000/ui/
```

Or `docker compose up --build`. That starts PostgreSQL 16, the API and Control Room on :8000, the classic Streamlit
dashboard on :8501, and the PostgreSQL wire proxy on :6543. That Compose file is a **demo profile** for synthetic
data only. For real data, see [Production profile](#production-profile).

[docs/DEMO_RUNBOOK.md](docs/DEMO_RUNBOOK.md) walks through the whole demo with exact commands and expected output.

Demo identities (`policies/users.demo.yaml`, synthetic):
- `admin.ann`, `support.sam`, `analyst.ali` and `auditor.aud`, with passwords `<role>123`;
- `intruder.ian` for the threat demo.

| Interface | What it gives you |
|---|---|
| **CLI** `maskguard` | Interactive console, plus `doctor`, `status`, `db inspect`, `scan --dry-run`, `pii list`, `roles show`, `policy explain`, `query --role/--table`, `compare`, `audit list`, `integrity proof`, `test` and more. `--json` output, stable exit codes, and `--api URL` to run through the REST API |
| **Control Room** `/ui/` | Overview, live role playground, PII discovery, policy studio (validated, audited edits), role explorer, audit explorer, integrity proofs, API lab, CLI guide |
| **REST API** `/docs` | Health and readiness, query and query builder, policy explain, matrix and edits, scan, audit search, integrity baseline, verify and proof. Capability-checked |
| **Postman** `postman/` | 55 requests and 121 body assertions, including 26 negative and security cases. `npx newman run …` |
| **PostgreSQL proxy** :6543 | `psql "host=localhost port=6543 user=support.sam dbname=bank"`: any PostgreSQL client, masked |
| **Python SDK** | `MaskGuardClient.demo(url, "support").query_df("SELECT name, ssn FROM users LIMIT 5")` |

## Production profile

`MASKGUARD_ENV=production` turns MaskGuard into a fail-closed service. Full guide: **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.
The reference stack is `docker-compose.prod.yml`: the database on an internal network with a read-only gateway
account, an HTTPS API, required secrets, no demo identities and no seeding.

**It refuses to start on anything unsafe, and lists every problem at once:**

![Production refuses to start: every problem listed, exit code 4](docs/img/prod-refuses-unsafe.png)

**With a real configuration**, every startup check passes: PostgreSQL through a read-only account, demo identities
off, noisy aggregates disabled.

![maskguard status in production](docs/img/prod-status.png)

| Production refuses | Why |
|---|---|
| Demo identities, the demo user store, missing or example secrets | Shipped credentials and placeholder keys are as good as public |
| SQLite, seeding, or a database account that can write, create objects or own the masking functions | The gateway must not be able to change data or redefine its own masks |
| An API off loopback without TLS; the proxy or classic dashboard off loopback at all | The proxy has no TLS of its own; the dashboard's TLS is untested |
| **Noisy aggregates** (decision D11) | Their privacy accounting is under review; [see below](#noisy-aggregates-and-the-privacy-review) |
| **Self-tests**: the attack suite, simulated attack and benchmark | They send SQL straight to the database, bypassing the gateway |

![Noisy aggregates refused in production (D11)](docs/img/prod-d11.png)
![Self-tests refused for every role over the CLI](docs/img/prod-selftest-refused.png)
![GET /attacks returns 403 with a generic message](docs/img/prod-api-403.png)

Each refusal is audited (who, which channel, why), never with SQL or results:

![Audit records of the refusals](docs/img/prod-audit.png)

The self-test refusal was verified live on PostgreSQL: the protected tables' scan counters did not move during six
refused requests, while an ordinary masked query moved them.

## Noisy aggregates and the privacy review

In development, analysts can get noisy (Laplace) `SUM` / `AVG` / `COUNT` over protected numbers. **This is not a
differential-privacy guarantee.** An audit of the mechanism found ten gaps. For example:
- a join can multiply one customer's influence fourfold;
- `ORDER BY` can sort on true values before noise is added;
- budgets were per analyst account and renewed daily.

So the feature is refused in production (decision D11), and four of the gaps are pinned as strict expected-failure
tests that will fail the build once fixed:

![The DP findings as strict xfail tests](docs/img/review-dp-findings.png)

A full privacy-accounting design proposes a shared lifetime budget per dataset, crash-safe charging, an independent
evidence store and recovery fencing. It is **frozen at commit `a6891fd`** for independent review:

![The frozen protocol: hash computed from Git, no diff since](docs/img/review-frozen.png)

| Document | What it is |
|---|---|
| [docs/design/PRIVACY_ACCOUNTING.md](docs/design/PRIVACY_ACCOUNTING.md) | The design under review (frozen at `a6891fd`) |
| [docs/design/PRIVACY_ACCOUNTING_REVIEW_BRIEF.md](docs/design/PRIVACY_ACCOUNTING_REVIEW_BRIEF.md) | What the reviewer checks, their authority, and findings by status: historical, remediated, unresolved |
| [docs/design/PRIVACY_ACCOUNTING_REVIEW_EVIDENCE.md](docs/design/PRIVACY_ACCOUNTING_REVIEW_EVIDENCE.md) | Versions, exact commands, recorded results, CI history and the live production procedure |

Passing tests, or a model check that finds no counterexample, are evidence, not proof. Noisy aggregates return to
production only after the decisions, an implementation, recovery tests and independent approvals.

## Configuration

| Variable | Default | |
|---|---|---|
| `MASKGUARD_ENV` | `development` | `production` turns on every check above; any other value is refused |
| `MASKGUARD_DB` | `sqlite:///data/bank.db` | `postgresql://…` or `mysql://…` (MySQL needs `log_bin_trust_function_creators=1` for its masking functions) |
| `MASKGUARD_HMAC_KEY` | required | key for Analyst tokens; missing → error (fail closed) |
| `MASKGUARD_JWT_SECRET` | random per process | set it so tokens survive restarts and work across workers; required in production |
| `MASKGUARD_POLICY` | `policies/default.yaml` | role × tag → `allow` / `partial` / `hmac` / `redact` / `redact_text` / `aggregate` / `deny`; row filters; row caps; group floor; threat thresholds |
| `MASKGUARD_USERS` | `policies/users.demo.yaml` | users, roles, PBKDF2 hashes (`maskguard hash-password`); production needs its own file |
| `MASKGUARD_OVERRIDES` | `policies/overrides.yaml` | manual tags that win over the scanner |
| `MASKGUARD_SCAN_INTERVAL` | `300` | background rescan period, in seconds |

Development settings are in `.env.example`, production ones in `deploy/production.env.example`.

## Tests and CI

```bash
make test                                                      # SQLite
MASKGUARD_TEST_PG=postgresql://… MASKGUARD_TEST_MYSQL=mysql://… uv run pytest -q    # all three databases
uv run maskguard test                                          # security regression: attacks per role + integrity proof
make postman                                                   # Newman against a running API
```

On every push, [CI](.github/workflows/ci.yml) runs these against PostgreSQL 16 and MySQL 8.4, and fails on any leak,
any failed assertion, or any change to the source data:
- the full test suite;
- the attack suite;
- `maskguard test`;
- the Postman collection under Newman.

The suite also includes:
- a Playwright walkthrough of the dashboard: every page, no JavaScript errors, no horizontal scroll at phone width;
- CLI tests for exit codes and JSON output;
- the production-profile checks, including a full production build on PostgreSQL and HTTPS end to end.

## Known limits

- HMAC tokens still allow equality joins and frequency analysis. Partial masks reveal the characters they leave
  visible.
- A column the scanner misses stays exposed until it's tagged. Uncertain columns are masked for review, and
  `overrides.yaml` lets you force a tag. Untagged columns are returned as they are.
- The threat engine was evaluated on simulated sessions; recalibrate it on real normal traffic. Its state is per
  process.
- Names and addresses inside free text need NER, which isn't integrated yet.
- Applications must not hold direct database credentials, or they bypass the gateway.
- Noisy aggregates are experimental and off in production (above).
- The audit hash chain is unkeyed and local. It catches accidental or partial edits, not someone who can rewrite the
  whole file on the host. It also assumes **one writing process**: if the API and CLI commands (or several workers)
  append to the same audit file, the chain forks and verification reports it broken.
- The PostgreSQL proxy has no TLS of its own, so production keeps it on loopback. Its `Describe` path and its
  error messages are open items for the independent review.

## Research context

[docs/REFERENCE_RESEARCH.md](docs/REFERENCE_RESEARCH.md) reviews 14 related open-source projects at source level.
For each, it records:
- what the project verifiably does;
- which of its ideas MaskGuard adopted: strictness-ordered actions, policy versions in audit entries, explain
  output, negative API assertions, CLI conventions;
- which it deliberately rejected: post-query masking, regex SQL parsing, unsalted hashes.

Prabowo et al., *Privacy-Preserving Tools and Technologies: Government Adoption and Challenges*, IEEE Access 13
(2025), lists data masking's weakness as "limited protection against sophisticated attacks". It also names automated
PIA and better privacy–utility balance as open problems. [docs/ROADMAP.md](docs/ROADMAP.md) maps each gap to a
MaskGuard component.

## Submission material

- `docs/MaskGuard_Round1_Submission.pptx`: the Round 1 deck.
- [`docs/demo_full.mp4`](docs/demo_full.mp4): the full walkthrough (8 minutes, captioned, no audio). It covers:
  - a CLI tour on synthetic data;
  - the Control Room;
  - the production profile on PostgreSQL;
  - the privacy review package.
- `docs/demo.mp4`: the earlier, shorter walkthrough.
- `docs/IMPLEMENTATION_REPORT.md`: requirements matrix with evidence-based status, test totals and remaining work.
- `docs/EVALUATION.md` and `docs/eval/*.json`: every number behind the claims above.
