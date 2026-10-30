<div align="center">

# MaskGuard

**AI-powered PII discovery and query-time, role-based masking for SQLite, PostgreSQL and MySQL.**

MaskGuard sits in front of the database, finds sensitive columns with a LightGBM + checksum scanner, and rewrites
every query so each role sees only what its policy allows. Stored data never changes.

[![CI](https://github.com/hotaro6754/mask/actions/workflows/ci.yml/badge.svg?branch=claude/zealous-bell-me62fn)](https://github.com/hotaro6754/mask/actions/workflows/ci.yml?query=branch%3Aclaude%2Fzealous-bell-me62fn)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Databases](https://img.shields.io/badge/databases-SQLite%20%C2%B7%20PostgreSQL%20%C2%B7%20MySQL-4c8)
![Tests](https://img.shields.io/badge/tests-1235%20passed-brightgreen)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![PyPI](https://img.shields.io/pypi/v/maskguard)](https://pypi.org/project/maskguard/)

[Demo video](docs/demo_full.mp4) · [Beginner's guide](docs/GUIDE.md) · [The problem](#the-problem-we-solve) · [Quick start](#quick-start) · [How it works](#how-it-works) ·
[Results](#results) · [Production](#production-profile) · [Privacy review](#noisy-aggregates-and-the-privacy-review) ·
[Deployment guide](docs/DEPLOYMENT.md) · [FAQ](#faq)

<a href="https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/demo_full.mp4">
  <img src="docs/img/demo-video.png" alt="Watch the full MaskGuard walkthrough (12 minutes)" width="820">
</a>

</div>

---

## The problem we solve

**In banks and fintechs, hundreds of employees can see customers' private data they don't need, and that causes
leaks, insider fraud and legal risk.**

A support agent takes a call: "Is my card blocked?" To answer, they open the customer's record and see the full card
number, Aadhaar, phone and balance. They needed one fact; they saw everything. So did every other agent, analyst and
contractor with database access. One copied card list, or one screenshot, is a breach, and under India's DPDP Act
weak safeguards can cost up to ₹250 crore.

"Just hide the sensitive columns" sounds easy, but two things make it hard:

- **Nobody knows exactly which columns are sensitive.** Databases have thousands of columns with names like
  `contact` or `ref_no`. Regexes confuse a 12-digit order number with an Aadhaar number, so PII slips through.
- **Hiding values on screen can be tricked.** If masking only changes the *output*, the database still uses real
  values for `WHERE`, `ORDER BY`, aliases and aggregates. Asking "does this Aadhaar start with 1234?" over and over
  recovers the number without ever displaying it.

**MaskGuard is a gateway between people and the database.** It finds sensitive columns by looking at the values
(ML plus checksums), rewrites every query so the database itself returns only what that person's role allows,
watches for people probing, and logs every decision.

```mermaid
flowchart LR
    S["Support agent<br/>Analyst · Auditor · Apps · BI tools"] -->|"SQL"| M["MaskGuard<br/>find · mask · watch · log"]
    M -->|"rewritten, read-only query"| D[("Your database<br/>PostgreSQL · MySQL · SQLite")]
    D -->|"already-masked rows"| M
    M -->|"only what the role may see"| S
```

### Who uses it, where and when

| Where | Who | When | What changes |
|---|---|---|---|
| Customer support desk | Support agents | Every customer call | Last 4 digits instead of full card, Aadhaar, PAN; frozen accounts hidden |
| Analytics | Analysts in SQL, notebooks, BI tools (via the PostgreSQL proxy) | Reports and dashboards | Identities become joinable tokens: they can count and join, not identify |
| Internal apps | Back-office tools | Every lookup | Point the app at MaskGuard instead of the database; no app code changes |
| Compliance | Auditors, DPDP and RBI reviews | Audits and investigations | One tamper-evident log of who saw what, with no PII in it |
| Vendors and contractors | Outsourced teams | Whenever they need data | Masked access instead of raw access |

It runs on the organisation's own servers (or a laptop for a demo), next to the database. Nothing goes to an
outside service.

### Before and after

| Situation | Before | With MaskGuard |
|---|---|---|
| Support agent opens a record | Full card, Aadhaar and balance | `4111-XXXX-XXXX-1111`, `XXXX-XXXX-4078`, balance rounded |
| A new column `ref_no` holds Aadhaar numbers | Exposed; nobody notices | Found by its values and masked automatically |
| An employee guesses `WHERE aadhaar LIKE '1234%'` repeatedly | Learns the real number | Only masked values to compare against; blocked after a burst of probes |
| Auditor asks "who saw what?" | Scattered logs, if any | One hash-chained log of every query, role and decision |
| "Did the gateway change data?" | Can't prove it didn't | Integrity proof: table hashes match before and after |
| Same rules on three databases | Three setups that drift apart | One policy file |

New to all this? **[docs/GUIDE.md](docs/GUIDE.md)** explains every term from scratch, with diagrams and
step-by-step workflows. Common questions are answered in the [FAQ](#faq) at the end.

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
| Same, 200 sample values per column (what the scanner reads by default; 0% false alarms) | **1.000** | 0.844 (22.2% false alarms) |
| False alarms on look-alike data (order numbers, SKUs, OTPs…), 5 / 20 values | **6.3% / 1.5%** | 22.2% |
| **Organisers' Saffron Bank pack** (9 tables, 120 columns, 129,260 rows): sensitive columns found | **35 / 35** (22 on first contact; [what we fixed](docs/SAFFRON_VALIDATION.md)) | — |
| Same, raw values returned to Support or Analyst, 13,700 masked cells, as the organisers' users | **0** on SQLite, PostgreSQL and MySQL | — |
| PII leaks across 17 bypass and inference attacks | **0 / 17** | 15 / 17 on PostgreSQL, 14 / 17 on SQLite and MySQL (naive masking) |
| Simulated insider attacks detected (normal users blocked) | **95–100% (0%)** | — |
| Added latency per query, p50, all features on, 300 to 100,000 rows | 4–8 ms (SQLite, PostgreSQL), 6–22 ms (MySQL) | — |
| Tests | **1,235 passed** on SQLite, PostgreSQL 16 and MySQL 8.4 (incl. 672 attack-matrix cases, 0 leaks), plus 121 Postman assertions | — |

The attack suite is evidence for those 17 attack shapes, not a proof against every possible query. The threat
engine was evaluated on simulated sessions.

### Evidence status

What each claim rests on, as of 1.1.0 (25 Oct 2026). **Implemented**: in the code. **Tested**: automated tests run on
every push. **Measured**: a benchmark script with its result file in `docs/eval/`. **Experimental**: works in
development, off in production, not claimed.

| Capability | Status | Evidence |
|---|---|---|
| Column discovery from names and sample values (identifiers, Indian formats, misleading names) | Measured | bharat-pii-bench holdout at 5 to 200 values, per-label precision/recall: [EVALUATION §1](docs/EVALUATION.md#1-pii-discovery-ml-scanner--external-benchmark), `docs/eval/scanner_*.json` |
| Health data, staff names, personal attributes, money | Tested | Clinic database in `scripts/e2e/` and `tests/test_onboarding.py`; no public benchmark |
| Discovery and masking on the organisers' Saffron Bank pack, three databases | Measured | [docs/SAFFRON_VALIDATION.md](docs/SAFFRON_VALIDATION.md), `bench/saffron/`, `docs/eval/saffron_masking.json` |
| Mostly-empty, mixed and sparse columns | Tested | `tests/test_sampling.py` (null-heavy case on all three databases) |
| Unreviewed columns hidden until a person approves them | Tested | `tests/test_hardening.py`, e2e checks |
| Masking inside the SQL, by role, on SQLite / PostgreSQL / MySQL | Tested | `tests/test_attacks.py`, `tests/test_attack_matrix.py` (672 cases, 0 leaks) |
| Inference through predicates, joins, ordering, aggregates | Tested | 10 predicate oracles × 3 columns × 3 roles × 3 databases; small-group suppression |
| Inference through business dependencies between columns | **Not covered** | Known limit (Pappachan et al., TKDE 2024) |
| Statement firewall, read-only execution | Tested | `tests/test_attacks.py`, DB-level write refusal in e2e |
| Stored data unchanged | Tested | Table digests before/after the attack suite; `maskguard integrity proof` |
| Analyst tokens: 128-bit, optional per-column scope, same on every database | Tested | `tests/test_tokens.py` |
| Policy edits validated, versioned, audited; weakening needs a reason | Tested | `tests/test_policy_integrity.py`, `tests/test_api_v1.py` |
| Hash-chained audit without values, owner-only, anchorable head | Tested | `tests/test_policy_integrity.py`, `tests/test_attacks.py` |
| Latency overhead by table size and query shape | Measured | `bench/scale.py` → `docs/eval/perf_*.json` ([EVALUATION §6](docs/EVALUATION.md#6-performance)) |
| Insider-threat detection | Measured on simulations | `bench/eval_threat.py` → `docs/eval/threat_sim.json` |
| Identifiers inside free text | Measured | bharat-pii-bench T3 (13 types 100%; names and addresses 0%) |
| Noisy aggregates for analysts | **Experimental** | Off in production; not a differential-privacy guarantee ([design review](docs/design/PRIVACY_ACCOUNTING.md)) |
| PostgreSQL wire proxy | Tested, open review items | `tests/test_proxy.py`; `Describe` path and row filters under unusual shapes are open |

Benchmarks here use synthetic data. They show behaviour on those formats and sizes, not on every production schema.

## Quick start

Pick one way to install:

| Way | Command | Status |
|---|---|---|
| **pip, from PyPI** (recommended) | `pip install maskguard` | Works: [pypi.org/project/maskguard](https://pypi.org/project/maskguard/) |
| **pip, latest from GitHub** | `pip install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn"` | Works; includes changes made after the last release |
| **From source** (to develop or run the tests) | `git clone https://github.com/hotaro6754/mask && cd mask && uv sync` | Works now; prefix commands with `uv run` |
| **Docker** (demo stack with PostgreSQL) | `docker compose up --build` in the cloned repository | Works now |

Then start it:

```bash
maskguard                 # first run asks: demo data, or connect your own database
maskguard serve           # REST API + Control Room dashboard: http://127.0.0.1:8000/ui/
```

Nothing else to set up for a trial. On first run MaskGuard generates its secret keys for this machine
([Secret keys](#secret-keys)), and you choose what to protect:

| You pick | What happens |
|---|---|
| **Demo data** | A synthetic bank database is created in `./data/` with four demo logins, so you can see each role at once |
| **My own database** | You give a `postgresql://`, `mysql://` or `sqlite:///` URL. MaskGuard scans it, hides what it finds, and adds nothing to it. See [Use your own database](#use-your-own-database) |

![First run: every check passes, the key is generated for this machine](docs/img/first-run-status.png)

A pip install keeps its demo database, audit log and scanner registry in `./data/` of the folder you run it from.

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

### Use your own database

```bash
maskguard connect postgresql://user:password@host:5432/yourdb   # or mysql://… or sqlite:///file.db (asked if omitted)
maskguard pii list                                                # what was found, and what is waiting for a person
maskguard pii approve --suggested                                 # approve ids, keys and status lists in one step
maskguard pii tag customers.city --tag PII_MEDIUM                 # decide the rest yourself
maskguard compare "SELECT * FROM customers LIMIT 3"               # the same query as each role
```

![Connecting a clinic database it has never seen](docs/img/connect-own-database.png)

What happens:

1. **Connect.** MaskGuard tests the URL, installs its small masking functions (`mg_*`) once, and saves the
   connection for this folder in `maskguard.yaml` (readable only by you). Each database gets its own audit log,
   registry and integrity baseline in `data/<name>/`. **No demo data and no demo approvals are added.**
   `maskguard connect --demo` goes back to the demo.
2. **Sort.** The scanner reads a sample of each column and sorts it, from the values first and the column name second:

   | Found automatically | How |
   |---|---|
   | Aadhaar, PAN, cards, IBAN, phones, emails, UPI, SSN, GSTIN, … | Checksums and the ML classifier, even under misleading names (`contact` holding emails) |
   | Names, dates of birth, addresses, staff names (`Dr. Rao`) | ML classifier, names with a title |
   | **Health data** (`HEALTH`): diagnosis codes, blood groups, medication | ICD-10 and blood-group patterns in the values; health words in the name |
   | Money tied to a person: balances, amounts, fees, salaries, refunds | Money-like values plus the column name (not prices of products) |
   | Identifiers inside free text (notes, remarks) | Phone, Aadhaar, PAN, card, email and UPI patterns inside the text |
   | Personal attributes: gender, religion, caste, marital status | The column name alone |

3. **Hide.** Everything found is masked by role at once. Every other column is `UNREVIEWED` and **hidden from
   everyone except admin**: a scanner finding nothing is not proof there is nothing.
4. **Review.** The scanner suggests which unreviewed columns look safe (whole-number ids and keys, short lists like
   statuses). `maskguard pii approve --suggested` approves exactly those; `pii approve TABLE.COLUMN` and
   `pii tag TABLE.COLUMN --tag …` handle the rest. Decisions are saved in `policies/overrides.yaml`, audited, and
   applied at once.

For real data, run the same database in production mode on a read-only account: [Production profile](#production-profile).

### Secret keys

MaskGuard needs two secrets: `MASKGUARD_HMAC_KEY`, which turns values into analyst tokens, and
`MASKGUARD_JWT_SECRET`, which signs logins.

| | Development (trying it out) | Production |
|---|---|---|
| Who makes them | MaskGuard, on first run: random, 64 hex characters each | You, with a secret manager or `python -c "import secrets; print(secrets.token_hex(32))"` |
| Where they live | `data/secrets.yaml`, readable only by you, reused on every run | Environment variables (`deploy/production.env.example`) |
| `maskguard status` | `HMAC KEY  PASS  generated for this machine (data/secrets.yaml)` | `HMAC KEY  PASS  set` |
| If missing | Generated | **Refuses to start.** Also refuses keys under 32 characters and placeholders such as `dev-only-…` |

**What the HMAC key does.** When the policy gives a role a **token** for a column, MaskGuard runs each value
through HMAC-SHA256 with this key and keeps 32 hex characters (128 bits; 1.0.x kept 16, which is the first half of
today's token). Output for the demo's first customer
(`maskguard compare "SELECT ssn FROM users LIMIT 1" --roles admin,analyst`):

| Stored value (what Admin sees) | Key | What the Analyst sees |
|---|---|---|
| `205-84-4078` | `dev-only-hmac-key-change-me` | `58fd7cb2ac03875b6c94f1370f69f816` |
| `205-84-4078` again, in any row or table | same key | `58fd7cb2ac03875b6c94f1370f69f816` (same value + same key = same token) |
| `205-84-4078` | `a-different-key-0123456789` | `52cb704a817fb775540297564c22362f` (new key, new token) |
| `205-84-4078` with `hmac: {scope: column}` | same key | `891a02b49b57616f6f849274c2308baa` in `users.ssn`, `afd87416488537927b4116bfaf77ce78` in another column |

The token is **pseudonymous, not anonymous**: anyone holding the key can test guesses, and equal values give equal
tokens, so analysts can join and count. If they shouldn't link one column to another, set `hmac: {scope: column}`
in the policy: each column then gets its own tokens (a value still matches itself within its column). `hmac.length`
takes 16 to 64 hex characters.

- **Why a key:** the same value always gives the same token, so analysts can join and count without seeing it. A
  plain hash could be reversed by hashing every possible SSN or phone number; without the key, nobody can.
- **Why no built-in default:** a default key would be published with the code, and anyone could reverse the tokens.
  So it is generated per machine in development and supplied by you in production.
- **Keep it stable:** a new key gives every value a new token. Anyone with the key can test guesses against tokens,
  so treat it like a password; never commit `data/secrets.yaml`.
- **Where it is used:** in query results for columns whose action is `hmac` (default policy: the Analyst on
  `PII_HIGH` and `HEALTH`), and inside the database by `mg_token` on PostgreSQL and MySQL (after upgrading to 1.1,
run `maskguard db-install` once so the database has it). The gateway passes it to
  its own database session; it is not stored in any table. Logins use the separate JWT secret.

To use your own key in development instead, set `MASKGUARD_HMAC_KEY` (`export` on macOS/Linux, `$env:` in
PowerShell, `set` in cmd); it always wins over the generated one.

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
| `MASKGUARD_HMAC_KEY` | generated in development | key for Analyst tokens. Development: generated once into `data/secrets.yaml`. Production: required, ≥ 32 characters, no placeholder. See [Secret keys](#secret-keys) |
| `MASKGUARD_JWT_SECRET` | generated in development | signs logins; same rules as the HMAC key; identical on every instance in production |
| `MASKGUARD_SEED_IF_EMPTY` | `1` only for the bundled demo database | fill an empty database with synthetic demo data; never on for a database you name, unless you set it |
| `MASKGUARD_POLICY` | `policies/default.yaml` | role × tag → `allow` / `partial` / `hmac` / `redact` / `redact_text` / `aggregate` / `deny`; row filters; row caps; group floor; threat thresholds |
| `MASKGUARD_USERS` | `policies/users.demo.yaml` | users, roles, PBKDF2 hashes (`maskguard hash-password`); production needs its own file |
| `MASKGUARD_OVERRIDES` | `policies/overrides.yaml` | reviewed tags that win over the scanner (`PUBLIC` = approved); written by `maskguard pii approve` / `pii tag` |
| `MASKGUARD_SCAN_INTERVAL` | `300` | background rescan period, in seconds |

Development settings are in `.env.example`, production ones in `deploy/production.env.example`. `maskguard connect`
saves `MASKGUARD_*` settings for one folder in `maskguard.yaml`; environment variables always win over it.

## Tests and CI

```bash
make test                                                      # SQLite
MASKGUARD_TEST_PG=postgresql://… MASKGUARD_TEST_MYSQL=mysql://… uv run pytest -q    # all three databases
uv run maskguard test                                          # security regression: attacks per role + integrity proof
make postman                                                   # Newman against a running API
scripts/e2e/run.sh dist/maskguard-*.whl                        # a built wheel (or `pypi`) in fresh containers
```

On every push, [CI](.github/workflows/ci.yml) runs these against PostgreSQL 16 and MySQL 8.4, and fails on any leak,
any failed assertion, or any change to the source data:
- the full test suite;
- the attack suite;
- `maskguard test`;
- the Postman collection under Newman;
- **an end-to-end test in isolated containers** (`scripts/e2e/`): the built wheel is installed in a fresh
  `python:3.12` container next to a fresh PostgreSQL 16 container, on a clinic database that is not the demo, in
  production mode on a read-only account. 45 checks: automatic discovery (13 sensitive columns, misleading names,
  health data, a decoy that must not be flagged), unreviewed columns hidden until review, the four roles, bypass
  attempts (value guessing, writes, system catalogs, comments in the audit log), the database refusing writes from
  the gateway account, the integrity proof, the HTTPS API, refusals of unsafe settings, restarts, and a first-time
  user connecting a database in development.

The suite also includes:
- a Playwright walkthrough of the dashboard: every page, no JavaScript errors, no horizontal scroll at phone width;
- CLI tests for exit codes and JSON output;
- the production-profile checks, including a full production build on PostgreSQL and HTTPS end to end.

## Known limits

- HMAC tokens still allow equality joins and frequency analysis. Partial masks reveal the characters they leave
  visible.
- A column the scanner finds nothing in is `UNREVIEWED` and masked for every role except admin until a person
  approves it (`maskguard pii approve`). A column wrongly approved is exposed, so review approvals like code;
  `--suggested` only takes whole-number keys and short value lists, never dates or free text.
- The detectors for health data, staff names, personal attributes and money (1.0.3) are pattern- and name-based and
  were checked on the clinic test database, not on a public benchmark like the identifier scanner. Columns they miss
  stay `UNREVIEWED`, so they fail closed.
- The threat engine was evaluated on simulated sessions; recalibrate it on real normal traffic. Its state is per
  process.
- Names and addresses inside free text need NER, which isn't integrated yet.
- Masking hides values; it does not stop inference through business rules between columns. If a shown column
  determines a hidden one (a tax band from a salary, a district from a postcode), tag the shown column too.
- The scanner reads up to 200 non-empty values per column, in storage order. Personal data that appears only in rows
  beyond those can be missed; such a column stays `UNREVIEWED` (masked) unless someone approves it.
- Analyst tokens with the default `global` scope link equal values across tables, which is what makes joins work. Use
  `hmac: {scope: column}` if that linkability isn't wanted.
- Applications must not hold direct database credentials, or they bypass the gateway.
- Noisy aggregates are experimental and off in production (above).
- The audit hash chain is unkeyed and local. On its own it catches accidental or partial edits, not someone who can
  rewrite the whole file on the host; record `maskguard audit verify`'s head elsewhere and check it with `--anchor`. It also assumes **one writing process**: if the API and CLI commands (or several workers)
  append to the same audit file, the chain forks and verification reports it broken.
- The PostgreSQL proxy has no TLS of its own, so production keeps it on loopback. Its `Describe` path (which skips
  some gateway checks) and row filters under unusual query shapes are open items for the independent review. Its
  error messages no longer carry database text (fixed after an external source audit, 18 Oct 2026).

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
- `docs/MaskGuard_Final_Deck.pptx`: the finale deck (10 slides, speaker notes with timings), built on the Saffron Bank
  results.
- [`docs/HACKATHON_PREP.md`](docs/HACKATHON_PREP.md): finale preparation: judging parameters, the role-of-AI answer,
  demo script, questions, overnight feedback loop, code-freeze packaging (`scripts/package_submission.sh`), Stage 3.
- [`docs/demo_full.mp4`](docs/demo_full.mp4): the full walkthrough of 1.1.0 (12 minutes, captioned, no audio; every
  terminal and browser scene is a real recording of the 1.1.0 wheel). It covers:
  - the problem, and how MaskGuard sorts and hides;
  - **your own database**: first run, connecting a clinic database it has never seen, automatic discovery (health
    data, money, staff names, misleading column names), unreviewed columns hidden, review in two commands, the four
    roles with 128-bit tokens, free text, a guessing attempt and the integrity proof;
  - how the masking works on the demo bank: rewritten SQL, firewall, 17 attacks, the threat engine, a policy change
    refused until confirmed, the audit chain head and `--anchor`, the console;
  - the Control Room;
  - production on the clinic database: refusals, read-only account, the CLI proof as a real account, the audit log;
  - the 45-check end-to-end test in isolated containers, recorded live;
  - evidence and limits: the attack matrix and a latency run recorded live, the privacy review status.
- `docs/demo.mp4`: the earlier, shorter walkthrough.
- `docs/IMPLEMENTATION_REPORT.md`: requirements matrix with evidence-based status, test totals and remaining work.
- `docs/EVALUATION.md` and `docs/eval/*.json`: every number behind the claims above.

## License

[Apache License 2.0](LICENSE). Copyright 2026 G. Harshith, G. Praneeth, D. Mandeep and K. Surya Srinivas; see
[NOTICE](NOTICE).

## FAQ

### About the idea

<details>
<summary><b>What problem does MaskGuard solve, in one line?</b></summary>

Employees who query customer data see far more than their job needs. MaskGuard shows each person only what their
role allows, finds the sensitive columns automatically, and records every access, without changing the data or the
database.
</details>

<details>
<summary><b>Who is it for?</b></summary>

Organisations whose staff query live personal data in PostgreSQL or MySQL: banks, NBFCs, fintechs, insurers and
government data teams. It is aimed especially at those under DPDP pressure that can't justify an enterprise
data-security platform.
</details>

<details>
<summary><b>My database already has masking. Why add this?</b></summary>

Built-in masking (SQL Server, Oracle, Snowflake, PostgreSQL Anonymizer) is configured separately on each database
and assumes you already know which columns are sensitive. Several products mask only the displayed result, so
`WHERE`, `ORDER BY` and aliases still run on real values; Microsoft's own documentation warns not to rely on its
dynamic masking against ad-hoc queries. We compared MaskGuard with PostgreSQL Anonymizer at source level and found
bypasses there ([docs/research/SECURITY_COMPARISON.md](docs/research/SECURITY_COMPARISON.md)). MaskGuard discovers
the columns itself, masks inside the query, and applies one policy across databases.
</details>

<details>
<summary><b>Can't a team just ask ChatGPT or Claude to write this?</b></summary>

They can get masking code quickly; MaskGuard itself was built with AI assistance. Getting code is the easy part.
Knowing it can't be bypassed is the hard part:
- the obvious version masks the output, which leaks 14–15 of our 17 attacks;
- MaskGuard is checked on every push by an attack suite, 1,235 tests on three databases (including a 672-case attack matrix) and 121 API assertions;
- a security bug doesn't crash, it silently leaks, so untested security code is a liability.

The value is the tested, verified behaviour, not the lines of code.
</details>

<details>
<summary><b>Why not use an AI model at query time to decide what to hide?</b></summary>

It would send customer data to an outside service, which is exactly the leak you're preventing. It isn't
deterministic, adds latency and cost to every query, and can be manipulated by text hidden in the data.
MaskGuard uses ML only to *find* sensitive columns (locally); enforcement is fixed rules.
</details>

<details>
<summary><b>Does it replace encryption, firewalls or database permissions?</b></summary>

No. It is one layer: controlling what each person sees when they query. Keep encryption at rest and in transit,
network controls, database permissions and your login system. Applications that hold direct database credentials
bypass MaskGuard, so remove those.
</details>

<details>
<summary><b>Does it make us DPDP compliant?</b></summary>

Not by itself, and this isn't legal advice. It provides safeguards that DPDP Rule 6 names (masking, access
control, access logs) and generates a privacy impact assessment (PIA) draft. Compliance also covers consent,
notices, retention, breach reporting and more.
</details>

### Installing and connecting

<details>
<summary><b>How do I install it? Is there a pip package, an npm command or an .exe?</b></summary>

You need Python 3.10 or newer:

```bash
pip install maskguard
maskguard                 # first run: demo data, or connect your own database
maskguard serve           # dashboard at http://127.0.0.1:8000/ui/
```

The ML scanner needs the OpenMP runtime. Most systems have it; minimal ones don't (`python:*-slim` Docker images, a
fresh Mac). Without it, `maskguard status` shows `PII SCANNER WARN … rules only` and MaskGuard uses its rule-based
scanner; columns it misses stay masked as `UNREVIEWED`. Install it with `apt-get install libgomp1` (Debian/Ubuntu)
or `brew install libomp` (macOS).

To develop or run the tests, clone the repository and use `uv sync`. For the demo stack with PostgreSQL, run
`docker compose up --build`. There is no npm package or `.exe`: MaskGuard is a Python server that runs next to a
database. It is developed and tested on Linux. Windows and
macOS should work with Python 3.10+, but CI doesn't cover them. Step by step: [GUIDE §18](docs/GUIDE.md#18-installing-maskguard-on-your-computer).
</details>

<details>
<summary><b>Do I need to set an HMAC key?</b></summary>

Not to try it: from 1.0.3, development generates one per machine on first run and saves it in `data/secrets.yaml`
(readable only by you), so `maskguard status` passes straight away. Production refuses to start without your own
key. Details: [Secret keys](#secret-keys).
</details>

<details>
<summary><b>How do I connect my existing database?</b></summary>

One command, or choose "my own database" when `maskguard` first starts:

```bash
maskguard connect 'postgresql://user:password@db-host:5432/yourdb'     # or mysql://… or sqlite:///file.db
maskguard pii approve --suggested                                     # then review what is left
```

(Or set `MASKGUARD_DB` yourself; a database you name never gets demo data.) On first start it:
1. installs its masking functions (`mg_*`; on PostgreSQL also the `pgcrypto` extension);
2. scans every table and tags sensitive columns;
3. records an integrity baseline.

Columns it finds nothing in are `UNREVIEWED`: masked for everyone but admin until a person approves them with
`maskguard pii approve`. Review the tags and those columns with `maskguard pii list`, adjust the policy, create users, then point people and tools at
MaskGuard. **Try it on a staging copy first.** For production, install the functions once with the owner account
(`maskguard db-install`) and run the gateway through a read-only account. Full walkthrough:
[GUIDE §19](docs/GUIDE.md#19-connecting-your-existing-database), production: [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
</details>

<details>
<summary><b>Does MaskGuard change my data?</b></summary>

No. Every query runs read-only, and the firewall rejects writes. The only thing it adds to the database is its
masking functions (and `pgcrypto` on PostgreSQL). Integrity proofs hash your tables before and after to show
nothing changed. To remove it, stop using it and drop the `mg_*` functions.
</details>

<details>
<summary><b>Which databases are supported?</b></summary>

PostgreSQL, MySQL and SQLite, tested against PostgreSQL 16 and MySQL 8.4. Managed cloud versions (Amazon RDS,
Cloud SQL, Azure Database) are the same engines and should work, but haven't been tested. On MySQL with binary
logging, creating the functions needs `log_bin_trust_function_creators=1`. Oracle, SQL Server, MongoDB and
Snowflake are not supported.
</details>

<details>
<summary><b>Do my applications or tools need code changes?</b></summary>

Usually not. Point them at MaskGuard instead of the database:
- **PostgreSQL clients and BI tools** connect to the wire proxy on port 6543, as if it were a database. It is
  tested with `psql` and psycopg. The proxy has no TLS, so clients must allow non-SSL connections, and production
  keeps it on the same machine.
- **Programs** can use the REST API or the Python SDK.
- **People** can use the Control Room or the CLI.
</details>

<details>
<summary><b>Can staff update records through MaskGuard?</b></summary>

No. MaskGuard is for reading: only single `SELECT` statements are allowed. Updates keep going through your existing
applications, which should have their own access controls.
</details>

<details>
<summary><b>How do users log in? Is there SSO?</b></summary>

Users live in a YAML file with PBKDF2-hashed passwords (`maskguard hash-password`). Logging in gives a signed,
time-limited token (JWT) carrying the role. There is no SSO or LDAP integration yet.
</details>

<details>
<summary><b>How do I change what a role sees, or add a role?</b></summary>

Edit `policies/default.yaml` (or use the Control Room's policy studio). Each role maps each tag to an action:
`allow`, `partial`, `hmac`, `redact`, `redact_text`, `aggregate` or `deny`. Add row filters or row limits if
needed. Making a rule weaker requires a reason and confirmation, and every change is versioned and audited.
`maskguard policy explain --role R --table T` shows why each column is masked.
</details>

<details>
<summary><b>What happens when a new table or column appears?</b></summary>

A background worker rescans every 5 minutes (configurable). A new table is blocked until it has been scanned. You
can force a tag in `policies/overrides.yaml`. A new column the scanner finds nothing in is `UNREVIEWED`: masked
for every role except admin until you approve it as `PUBLIC` there (`maskguard pii list` shows what's waiting).
</details>

### Running it

<details>
<summary><b>How much slower are queries?</b></summary>

About 4–8 ms added per query (median) on SQLite and PostgreSQL and 6–22 ms on MySQL, with every feature on, measured
at 300, 10,000 and 100,000 rows per table. The added time does not grow with the table for queries that return a
bounded number of rows ([EVALUATION §6](docs/EVALUATION.md#6-performance)). Each query has a 5-second timeout on
PostgreSQL and MySQL.
</details>

<details>
<summary><b>What does MaskGuard store? Does data leave my servers?</b></summary>

It stores the audit log (no literal values), the scanner registry (tags and evidence, never values), integrity
hashes and policy history, in its data directory. Scanned sample values stay in memory. The ML models are bundled,
so nothing is sent to any outside service.
</details>

<details>
<summary><b>What if MaskGuard goes down?</b></summary>

People can't query through it until it's back. It fails closed rather than falling back to raw access. Running
several instances needs care today: threat-engine state is per process, and the audit log assumes one writing
process (see [Known limits](#known-limits)).
</details>

<details>
<summary><b>What about analysts' averages and totals?</b></summary>

Individual protected numbers are hidden from analysts. Noisy aggregates exist in development but are refused in
production until the privacy-accounting design passes independent review
([above](#noisy-aggregates-and-the-privacy-review)).
</details>

<details>
<summary><b>Is it free? What's the licence?</b></summary>

Yes. MaskGuard is licensed under the [Apache License 2.0](LICENSE): anyone may use, modify and distribute it,
including commercially, as long as they keep the licence and copyright notices ([NOTICE](NOTICE)). Apache-2.0 also
grants a patent licence from contributors, which legal teams at banks typically look for. It comes without
warranty.
</details>

<details>
<summary><b>Is it production-ready?</b></summary>

It is a working, tested prototype with a production profile that refuses unsafe settings. Before handling real
data:
- verify the production Docker build in your environment;
- read the known limits;
- run a pilot on staging data;
- have it security-reviewed.
</details>
