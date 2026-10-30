# MaskGuard

**AI-powered PII discovery and query-time, role-based masking for PostgreSQL, MySQL and SQLite.**

MaskGuard is a gateway between people and the database. It finds sensitive columns by looking at their values (a
LightGBM classifier plus checksum validators for Aadhaar, PAN, GSTIN, cards, IBAN and more). It rewrites every query
so the database itself returns only what the caller's role may see. It watches for probing, and records every
decision in a hash-chained audit log. Stored data never changes.

| Role | Sees |
|---|---|
| Admin | real values |
| Support | partial masks: `4111-XXXX-XXXX-1111`, `XXX-XX-6789`, `r***@bank.in`, rounded balances |
| Analyst | keyed tokens (joinable, not reversible); no individual balances |
| Auditor | `REDACTED`, plus the audit log, policies and integrity proofs |

![One query as four roles](https://raw.githubusercontent.com/hotaro6754/mask/claude/zealous-bell-me62fn/docs/img/control-room-playground.png)

## Install and try it

```bash
pip install maskguard
maskguard                                                # first run: demo data, or connect your own database
maskguard connect postgresql://user:pw@host:5432/yourdb  # or later, in one command (mysql:// and sqlite:/// too)
maskguard compare "SELECT name, ssn, phone FROM users LIMIT 2" --roles admin,support,analyst,auditor
maskguard serve                                          # REST API + Control Room at http://127.0.0.1:8000/ui/
```

Demo logins: `admin.ann`, `support.sam`, `analyst.ali` and `auditor.aud`, each with password `<role>123`. Data,
the audit log and the scanner registry are written to `./data/` in the folder you run it from.

In development the secret keys are generated on first run for this machine (`data/secrets.yaml`, readable only by
you); production refuses to start without your own. If `maskguard status` shows `PII SCANNER WARN … rules only`, the system lacks the OpenMP runtime the ML scanner needs: install `libgomp1`
(Debian/Ubuntu, including `python:*-slim` images) or `libomp` (macOS, with Homebrew).

On your own database MaskGuard adds no demo data. It finds identifiers, money, health data (diagnosis codes, blood
groups) and staff names by itself, masks them by role, and hides every other column (`UNREVIEWED`) from everyone but
admin until you review it: `maskguard pii approve --suggested` approves the ids and status lists it suggests,
`maskguard pii tag` handles the rest. For real data, run in production mode (`MASKGUARD_ENV=production`) on a
read-only account: it refuses to start on any unsafe setting.

## Results

- **PII discovery:** 0.965 F1 with misleading column names and 5 sample values per column; the benchmark baseline
  scores 0.844.
- **Attack suite:** 0 of the 17 bypass and inference attacks in its suite leak, against 14–15 of 17 for output-only
  masking. That is evidence for those attack shapes, not a proof for every query.
- **Tests:** 1,235 tests on SQLite, PostgreSQL 16 and MySQL 8.4.
- **Latency:** about 8 ms added per query.

## What's new in 1.1.0

- **Analyst tokens are 128-bit** (32 hex characters; a 1.0.x token is the first half of the new one). The optional
  `hmac: {scope: column}` gives each column its own tokens, so equal values can't be linked across columns. **After
  upgrading, run `maskguard db-install` once on PostgreSQL or MySQL**: production refuses to start until the new
  `mg_token` function is installed.
- **Scanner:** samples non-empty values, so a mostly-empty column is classified on real data. A column with even one
  email, PAN or IBAN among ordinary values is tagged for review, and stays masked. **Fix:** with the full 200-value
  sample, 1.0.x read postal-address columns as non-PII (the model was trained on 20–60 values); it now scores blocks
  of 20 and averages them: macro-F1 1.000 at 200 values on bharat-pii-bench (was 0.917).
- **Policy edits:** changing a rule between `partial`, `redact_text`, `hmac` and `aggregate` now needs confirmation and
  a reason. Each of the four reveals something the others hide, so none is "stricter" than another.
- **Audit:** the log file is readable only by its owner. `maskguard audit verify` prints the chain head to record
  elsewhere, and `--anchor <head>` later proves that entry is still in the chain.
- **Evidence:** an attack matrix and seeded fuzzer (672 cases, 0 leaks, on all three databases), the scanner measured
  at 5/10/20 values with per-label precision and recall, and latency at 300, 10,000 and 100,000 rows.

## What's new in 1.0.3

- **Your own database, in one step:** the first run asks "demo data or my own database"; `maskguard connect URL`
  saves and scans one. A database you name never gets demo data.
- **No key to set up:** development generates its secret keys on first run and keeps them; production still
  requires your own.
- **More found automatically:** health data (ICD-10 codes, blood groups, medication) as a new `HEALTH` class, staff
  names (`Dr. Rao`), personal attributes (gender, religion, …) and amounts/fees tied to a person.
- **Review in commands:** `maskguard pii approve [--suggested]` and `maskguard pii tag`.
- **`maskguard integrity proof -u USER`** works in production.
- Tested end to end in fresh containers on a database that is not the demo (`scripts/e2e/`, also in CI).

## What's new in 1.0.2

- **The rule-based scanner now finds identifiers inside free text.** It is the fallback when LightGBM can't load. In
  1.0.1 it missed them, so such a column stayed masked as `UNREVIEWED` instead of being tagged.
- **`maskguard status` warns** (`WARN`, exit code unchanged) when the scanner runs on rules only, and says what to
  install; `maskguard doctor` no longer fails on it.

## What's new in 1.0.1

Security fixes from an external source audit:
- **Unreviewed columns fail closed.** In 1.0.0 a column the scanner found nothing in was returned to every role
  unmasked. It is now `UNREVIEWED` (admin only) until a person approves it as `PUBLIC`.
- **SQL comments and MySQL optimizer hints** no longer reach the audit log or the database.
- **Database error text** no longer reaches clients through the PostgreSQL proxy or the classic dashboard.
- **The `query` capability** is enforced on every path.

Upgrade with `pip install -U maskguard`. On your own database, review the `UNREVIEWED` columns after upgrading.

## Learn more

- [README and screenshots](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/README.md)
- [Beginner's guide](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/GUIDE.md): every term,
  with diagrams and step-by-step workflows
- [Deployment guide](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/DEPLOYMENT.md)
- [12-minute walkthrough video](https://github.com/hotaro6754/mask/blob/claude/zealous-bell-me62fn/docs/demo_full.mp4)

Noisy analyst aggregates are experimental and refused in production until an independent privacy review. Licensed
under Apache-2.0.
