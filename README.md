<div align="center">

# MaskGuard

**AI-powered PII discovery and query-time, role-based masking for SQLite, PostgreSQL and MySQL.**

MaskGuard sits in front of the database, finds sensitive columns with a LightGBM + checksum scanner, and rewrites
every query so each role sees only what its policy allows. Stored data never changes.

[![CI](https://github.com/hotaro6754/mask/actions/workflows/ci.yml/badge.svg?branch=claude/zealous-bell-me62fn)](https://github.com/hotaro6754/mask/actions/workflows/ci.yml?query=branch%3Aclaude%2Fzealous-bell-me62fn)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Databases](https://img.shields.io/badge/databases-SQLite%20%C2%B7%20PostgreSQL%20%C2%B7%20MySQL-4c8)
![Tests](https://img.shields.io/badge/tests-474%20passed-brightgreen)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[Demo video](docs/demo_full.mp4) · [Beginner's guide](docs/GUIDE.md) · [The problem](#the-problem-we-solve) · [Quick start](#quick-start) · [How it works](#how-it-works) ·
[Results](#results) · [Production](#production-profile) · [Privacy review](#noisy-aggregates-and-the-privacy-review) ·
[Deployment guide](docs/DEPLOYMENT.md) · [FAQ](#faq)

<a href="https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/demo_full.mp4">
  <img src="docs/img/demo-video.png" alt="Watch the full MaskGuard walkthrough (8 minutes)" width="820">
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
- MaskGuard is checked on every push by an attack suite, 474 tests on three databases and 121 API assertions;
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
<summary><b>How do I try it on my own computer?</b></summary>

You need Python 3.10+, [uv](https://docs.astral.sh/uv/) and git:

```bash
git clone https://github.com/hotaro6754/mask && cd mask
uv sync
export MASKGUARD_HMAC_KEY=dev-only-hmac-key-change-me   # Windows PowerShell: $env:MASKGUARD_HMAC_KEY="dev-only-hmac-key-change-me"
uv run maskguard          # console with synthetic demo data
uv run maskguard serve    # dashboard at http://127.0.0.1:8000/ui/
```

Or `docker compose up --build` for the demo stack with PostgreSQL. It is developed and tested on Linux. Windows and
macOS should work with Python 3.10+, but CI doesn't cover them. Step by step: [GUIDE §18](docs/GUIDE.md#18-installing-maskguard-on-your-computer).
</details>

<details>
<summary><b>How do I connect my existing database?</b></summary>

Point `MASKGUARD_DB` at it and start MaskGuard:

```bash
export MASKGUARD_DB='postgresql://user:password@db-host:5432/yourdb'     # or mysql://user:password@host:3306/yourdb
export MASKGUARD_SEED_IF_EMPTY=0                                           # never add demo data to your database
uv run maskguard status
```

On first start it:
1. installs its masking functions (`mg_*`; on PostgreSQL also the `pgcrypto` extension);
2. scans every table and tags sensitive columns;
3. records an integrity baseline.

Review the tags with `maskguard pii list`, adjust the policy, create users, then point people and tools at
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
can force a tag in `policies/overrides.yaml`. A column the scanner tags as `PUBLIC` is returned as it is, so review
new tags.
</details>

### Running it

<details>
<summary><b>How much slower are queries?</b></summary>

About 8 ms added per query (median) on SQLite and PostgreSQL, about 21 ms on MySQL, with every feature on. Each
query has a 5-second timeout on PostgreSQL and MySQL.
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
