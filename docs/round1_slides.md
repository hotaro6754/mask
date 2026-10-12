# Round 1 idea submission — slide content

Paste each block into the matching slide of `Round1_Template submission_9.pptx`. If the template's headings
differ, map by meaning. Numbers marked *measured* come from `make test` / `make bench` in this repo; re-run them
on your own laptop and use your numbers.

---

## Title
**MaskGuard — query-time PII masking gateway**
Team: [team name] · Members: [names] · College: [college] · Problem: Smart Data Masking System for PII Protection

## Problem
- Internal users who can run SQL can see raw PII: card numbers, SSN/Aadhaar, PAN, balances.
- Native dynamic masking is a display filter: a `WHERE` predicate or `ORDER BY` still runs on the real value,
  so values can be inferred (Microsoft's own DDM docs warn about this).
- DPDP Rule 6(a) names masking/obfuscation/tokenisation as security safeguards and requires access logs kept
  for one year. Penalty for failing reasonable safeguards: up to ₹250 crore.

## Proposed solution
A gateway between users and the database that masks at query time, by role, without touching stored data.
- **Admin** → full values · **Support** → partial (`4111-XXXX-XXXX-1111`) · **Analyst** → `REDACTED` or keyed-HMAC token
- Every table read is rewritten into a masked derived table:
  `FROM users` → `FROM (SELECT mask(email) AS email, … FROM main.users) AS users`
- So aliases, `SELECT *`, CTEs, subqueries, joins, `WHERE`, `ORDER BY` and aggregates only ever see masked values.

## How it works (architecture)
1. **Auth** — role comes from an authenticated session, never from the query or request body.
2. **Scanner** — header heuristics + validators on sampled rows (Luhn for cards, Verhoeff for Aadhaar, PAN,
   IBAN, phone, SSN). Tags `PII_HIGH` / `FINANCIAL_CONFIDENTIAL` / `PII_MEDIUM` with evidence; header-only
   matches are still tagged (fail closed).
3. **Policy as code** — YAML: role × tag → allow / partial / hmac / redact / deny. Unknown role or tag → deny.
4. **Rewriter (sqlglot)** — only a single SELECT is allowed; unknown tables/functions rejected; row cap per role.
5. **Execution** — masking UDFs on SQLite; SQL functions on PostgreSQL.
6. **Audit** — hash-chained log with literals stripped, so a rejected query containing an Aadhaar never lands in the log.

## Uniqueness
- Masks at the **table source**, not the output column, which closes predicate, ordering and aggregate inference,
  not just what's displayed.
- **Attack suite** as the proof: alias, `*`, CTE, CTE shadowing, subquery, UNION, correlated subquery, join,
  ORDER BY probe, MIN/MAX probe, `WHERE =` / `LIKE` probes, stacked `DROP`, `load_extension`, forged role.
- India-aware scanner with checksum validators (Aadhaar Verhoeff, PAN) rather than plain 12-digit regex.
- Keyed HMAC (not plain hash), because formatted IDs are brute-forceable.

## Results so far (prototype, *measured*)
- 43 automated tests pass: 41 attack/role/audit tests across Support and Analyst + 2 scanner/mask tests;
  **0 raw values leaked** in any attack output.
- Gateway overhead: **~6.4 ms p50, ~11.5 ms p95** per query vs ~0.07 ms direct (SQLite, 300+300 rows,
  4 query shapes × 200 runs, cloud Linux VM — re-measure on your machine).

## Tech stack
Python · sqlglot · SQLite (UDFs) · PostgreSQL 16 (Docker) · python-stdnum · PyYAML · Faker · pytest · Streamlit (demo)

## Demo plan
Streamlit: log in as Admin / Support / Analyst → run the same query → see different masking side by side;
"Run attack suite" button with a leak counter; table checksum before/after to prove data is untouched;
live audit-log tail; p50/p95 latency.

## Limitations & next steps
- HMAC tokens still allow equality joins and frequency analysis; partial masks reveal their visible digits.
- A column the scanner misses is exposed → scanner flags low-confidence columns for review.
- In production the app must not hold direct DB credentials, or it can bypass the gateway.
- Next: aggregation floor (minimum group size), PostgreSQL backend on `postgres:16`, scanner evaluation on
  bharat-pii-bench with scrambled headers.

## Impact
Lets a bank or fintech give Support and Analytics teams SQL access without exposing raw PII, with a one-year
tamper-evident access log, supporting DPDP Rule 6 safeguards.
