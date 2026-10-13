# Talent AP Mega Hackathon 2026: application text (BFSI · Problem 11)

Paste-ready answers for the InnoSmart application form. Applications close **15 Oct 2026**. Every number below is
reproducible from this repository (`docs/EVALUATION.md`, `docs/IMPLEMENTATION_REPORT.md`).

## Problem Understanding
Banks give support, analytics and operations staff SQL access to tables of card numbers, Aadhaar/SSN, PAN and
balances, usually with no per-role control over what each person sees. Two gaps make this dangerous:
- **Finding PII:** column names lie ("contact", "ref_no"), and regex rules confuse order numbers with Aadhaar.
- **Masking that leaks:** typical masking only hides the displayed column, so WHERE, ORDER BY, joins and
  aggregates still run on real values. A user can infer a masked SSN or balance without ever selecting it.

The challenge is to find sensitive columns automatically and mask them per role at query time, across more than
one database engine, without changing the stored data and with evidence that it works.

## Proposed Solution
MaskGuard is a privacy gateway in front of SQLite, PostgreSQL and MySQL.
- **Scanner:** a background scanner samples each column. A LightGBM classifier plus checksum validators (Luhn,
  Verhoeff, PAN, IBAN) tag it PII_HIGH, FINANCIAL_CONFIDENTIAL, PII_MEDIUM or PII_IN_TEXT, with the evidence
  recorded.
- **Masking:** every query is parsed and each table is rewritten into a masked view, so filters, joins and
  aggregates only ever see masked values.
  - Admin sees real values.
  - Support sees 4111-XXXX-XXXX-1111 and never sees frozen accounts.
  - Analyst gets keyed HMAC tokens and noisy aggregates.
  - Auditor sees everything redacted.
- **Protection:** queries run read-only, a SQL firewall blocks writes and tricks, and every decision goes to a
  hash-chained audit log with the values stripped out.
- **Demo:** evaluators switch roles in a security CLI, a web dashboard or a Postman suite, then run an integrity
  proof showing the source tables are byte-for-byte unchanged.

## Innovation / Differentiation
- **Leak-proof masking:** masking is applied inside the SQL, not on the output. 0 of 17 bypass and inference
  attacks leak, against 15 of 17 for column-level masking.
- **AI discovery that beats a public benchmark:** 0.965 macro-F1 on bharat-pii-bench with misleading column names,
  from only 5 sample values per column (benchmark baseline 0.844). False alarms are cut from 22.2% to 6.3%; with 20
  values per column the scores are 0.999 and 1.5%. It is built for Indian identifiers: Aadhaar, PAN, GSTIN, UPI and
  IFSC.
- **Provable integrity:** a one-click proof hashes the tables, runs the same query as every role, attempts six
  kinds of write, then hashes again.
- **Beyond masking:**
  - differentially private averages for analysts;
  - an insider-threat engine that catches 95–100% of simulated attacks without blocking normal users;
  - a validated, versioned and audited policy editor;
  - an automated Privacy Impact Assessment report.

## Technology / Methodology
- **Core:** Python, FastAPI, sqlglot (SQL rewriting).
- **ML:** LightGBM and scikit-learn (IsolationForest).
- **Databases:** SQLite, PostgreSQL (psycopg) and MySQL (PyMySQL).
- **Security:** JWT and PBKDF2 authentication, HMAC-SHA256 tokens, SHA-256 hash chain.
- **Interfaces:** Typer/Rich CLI, a plain HTML/JS dashboard under a strict Content Security Policy, and a
  PostgreSQL wire-protocol proxy.
- **Testing:** pytest (416 tests on 3 databases), Postman/Newman (121 assertions), Playwright, GitHub Actions,
  Docker.
- **Data:** synthetic only, generated with Faker.
- **Disclosure:** open-source libraries as listed, and the public bharat-pii-bench benchmark (Apache-2.0) for
  evaluation. An AI coding assistant was used during development. The architecture, the policy design, and the
  evaluation and attack methodology were reviewed and are explained by the team.

## Feasibility & Impact
It already runs: one Docker Compose command, about 8 ms added per query, and works with existing PostgreSQL
clients through the proxy. Masking policies are a YAML file, so a bank can adopt it without changing applications.
It supports controls expected under GDPR (pseudonymisation), HIPAA (minimum necessary access) and India's DPDP
Rules (masking, access logs).
- **Impact:** it cuts insider exposure of customer PII while keeping analytics usable, and gives auditors
  verifiable evidence.
- **Scale:** read replicas and multiple gateway instances.
- **Next steps:** name and address detection in free text, and enforcement through database roles.
