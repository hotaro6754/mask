# MaskGuard explained from scratch

A beginner's guide to what MaskGuard does, how every part works, and how to use it. No prior knowledge of
databases, security or privacy is assumed: every term is explained the first time it appears, and there is an A–Z
glossary at the end.

> **How to read this.** Sections 1–5 explain the problem, who it's for and how it compares. Sections 6–17 open each
> part of the machine. Sections 18–21 show how to install it, connect your own database and run it for real.
> Sections 22–25 cover the privacy work, testing, step-by-step workflows and a day in the life. The diagrams are
> Mermaid flowcharts; GitHub draws them automatically.

**Contents**

1. [The problem, in plain words](#1-the-problem-in-plain-words)
2. [The idea in one picture](#2-the-idea-in-one-picture)
3. [Who, what, where, when, why and how](#3-who-what-where-when-why-and-how)
4. [Before and after](#4-before-and-after)
5. [What already exists, and where MaskGuard fits](#5-what-already-exists-and-where-maskguard-fits)
6. [Basic terms you need first](#6-basic-terms-you-need-first)
7. [The parts of MaskGuard](#7-the-parts-of-maskguard)
8. [The life of one query](#8-the-life-of-one-query)
9. [Finding sensitive data: the PII scanner](#9-finding-sensitive-data-the-pii-scanner)
10. [The policy: who sees what](#10-the-policy-who-sees-what)
11. [The masking actions, one by one](#11-the-masking-actions-one-by-one)
12. [Why mask inside the query](#12-why-mask-inside-the-query)
13. [The firewall and read-only execution](#13-the-firewall-and-read-only-execution)
14. [The insider-threat engine](#14-the-insider-threat-engine)
15. [The audit log and its hash chain](#15-the-audit-log-and-its-hash-chain)
16. [Integrity proofs](#16-integrity-proofs)
17. [Ways to connect](#17-ways-to-connect)
18. [Installing MaskGuard on your computer](#18-installing-maskguard-on-your-computer)
19. [Connecting your existing database](#19-connecting-your-existing-database)
20. [Where MaskGuard runs](#20-where-maskguard-runs)
21. [Development mode and production mode](#21-development-mode-and-production-mode)
22. [Noisy aggregates and differential privacy](#22-noisy-aggregates-and-differential-privacy)
23. [How it is tested](#23-how-it-is-tested)
24. [Workflows, step by step](#24-workflows-step-by-step)
25. [A day with MaskGuard](#25-a-day-with-maskguard)
26. [Exit codes and error messages](#26-exit-codes-and-error-messages)
27. [Known limits, explained](#27-known-limits-explained)
28. [Glossary A–Z](#28-glossary-az)
29. [Where to read next](#29-where-to-read-next)

---

## 1. The problem, in plain words

### A story

Priya works on a bank's customer-support desk. A customer calls: "Is my card blocked?" To answer, Priya opens the
customer's record. On her screen she sees:

- the full card number, `4111-2222-3333-1111`;
- the Aadhaar number;
- the phone number and email;
- the account balance.

She needed one fact: is the card active? She saw everything. So do the other 500 people on the support desk, the
analysts, the contractors and the vendors who have database access, for every customer, every day.

### Why that is a problem

- **Insider fraud.** One employee can copy card numbers or Aadhaar numbers and sell them. This is a common cause of
  real breaches.
- **Accidents.** A screenshot in a chat group, a laptop left open, a spreadsheet emailed to the wrong person.
- **The law.** India's **DPDP Act** (Digital Personal Data Protection Act, 2023) requires "reasonable security
  safeguards", and its rules name masking and access logs. Failing to protect personal data can cost up to ₹250
  crore. GDPR in Europe and HIPAA in US healthcare have similar rules.
- **Trust.** Customers leave a bank that leaks their data.

**The actual problem: too many people can see too much personal data, and nobody can prove who saw what.**

### Why the obvious fix doesn't work

"Just hide the sensitive columns." Two things get in the way:

1. **Nobody knows exactly which columns are sensitive.** A real bank database has thousands of columns, built by
   different teams over years. Column names lie: `contact` might hold phone numbers, `ref_no` might hold Aadhaar
   numbers. Simple pattern matching confuses a 12-digit order number with a 12-digit Aadhaar number.
2. **Hiding values on the screen can be tricked.** Many tools hide values only in the *displayed result*. The
   database still uses the real values while answering. A user can ask "is there a customer whose Aadhaar starts
   with 1234?", then "…with 12345?", and so on, and rebuild the number without it ever appearing on screen
   (section 12 shows exactly how).

MaskGuard fixes both: it **finds** sensitive columns by looking at the values, and it **masks them inside the question
itself**, so the database only ever works with masked values for that person.

## 2. The idea in one picture

```mermaid
flowchart LR
    U["Employee<br/>(support, analyst, auditor, admin)"] -->|"asks a question (SQL)"| G["MaskGuard gateway"]
    G -->|"rewritten question:<br/>only masked data for this role"| DB[("Bank database")]
    DB -->|"answer, already masked"| G
    G -->|"masked answer + audit record"| U
    S["AI scanner"] -.->|"which columns are sensitive"| G
    P["Policy file"] -.->|"what each role may see"| G
```

MaskGuard is a **gateway**: a door that every question must pass through. Employees never talk to the database
directly. The gateway knows who is asking (their **role**), which columns are sensitive (from the **scanner**), and
what each role may see (from the **policy**). It rewrites each question so the answer can only contain what that
role is allowed to see. The stored data is never changed.

The same question gives different answers to different people:

| Who asks | Email they see | Card number they see | Balance they see |
|---|---|---|---|
| Admin | `bharat.rana@example.com` | `4111-2222-3333-1111` | `4,52,310.50` |
| Support | `b***@example.com` | `4111-XXXX-XXXX-1111` | `450000` (rounded down to 10,000) |
| Analyst | a token like `423ef9aa927cc5b048aaaf98452d3bf1` | `REDACTED` | nothing individually; only group averages (and only in development) |
| Auditor | `REDACTED` | `REDACTED` | `REDACTED` |

## 3. Who, what, where, when, why and how

| Question | Answer |
|---|---|
| **What is it?** | A gateway that sits between people and a database and shows each person only what their role allows |
| **Who uses it?** | Banks, NBFCs, fintechs, insurers, hospitals and government offices that hold personal data in PostgreSQL or MySQL |
| **Who benefits?** | Customers (their data is safe), the organisation (fewer leaks, easier audits, lower legal risk), and employees (they can't be blamed for data they never saw) |
| **Where does it run?** | On the organisation's own servers, next to the database. For a demo, on a laptop. Nothing goes to an outside service |
| **When is it used?** | Every time someone looks at customer data: a support call, a report, an audit, an app lookup |
| **Why?** | To stop leaks and insider fraud, and to meet laws like DPDP, without stopping people from doing their jobs |
| **How?** | It finds sensitive columns, rewrites every query so the database returns only allowed data, watches for probing, and logs every decision |

### The people who use it

| Person | Their job | What they need | What MaskGuard shows them |
|---|---|---|---|
| **Support agent** | Answer customer calls | Confirm identity, check status | Last 4 digits of card, Aadhaar and phone; balance rounded to the nearest 10,000 below; frozen accounts hidden |
| **Analyst** | Find trends ("average balance by city") | Count, group and join records | Joinable codes (tokens) instead of identities; no individual balances |
| **Auditor** | Check rules are followed | Who did what, and when | The audit log, policies and scanner evidence; customer data redacted |
| **Admin / data owner** | Run the system | Everything, accountably | Real values; every action logged |
| **An application** | Show data in a back-office screen | Same as the person using it | Whatever that person's role allows |
| **A vendor or contractor** | A specific outsourced task | A narrow slice of data | Whatever their (usually strict) role allows |

### Where it fits in a company

```mermaid
flowchart LR
    subgraph People["People and tools"]
        A["Support desk"]
        B["Analysts<br/>(SQL, notebooks, BI)"]
        C["Auditors"]
        D["Internal apps"]
    end
    subgraph Server["Company server"]
        M["MaskGuard"]
    end
    subgraph Data["Data"]
        DB1[("Core banking<br/>PostgreSQL")]
        DB2[("Loans<br/>MySQL")]
    end
    A --> M
    B --> M
    C --> M
    D --> M
    M --> DB1
    M --> DB2
    X["Direct database access<br/>(removed for these users)"] -. x .-> DB1
```

The key change: people and tools that used to connect **directly** to the database now connect to **MaskGuard**
instead. MaskGuard is the only thing with database credentials for them.

## 4. Before and after

```mermaid
flowchart TB
    subgraph Before["Before"]
        U1["Support agent"] --> DBa[("Database")]
        DBa --> R1["Full card, Aadhaar,<br/>phone, balance"]
    end
    subgraph After["After"]
        U2["Support agent"] --> MG["MaskGuard"]
        MG --> DBb[("Database")]
        DBb --> MG
        MG --> R2["4111-XXXX-XXXX-1111<br/>XXXX-XXXX-4078<br/>balance rounded"]
        MG --> LOG["Audit log entry"]
    end
    Before ~~~ After
```

| Situation | Before | After |
|---|---|---|
| Support agent opens a record | Sees full card, Aadhaar, phone and balance | Sees the last 4 digits and a rounded balance; can still do the job |
| An analyst builds a report | Gets a raw data dump, or nothing | Gets tokens they can count and join, but not identify |
| A new column `ref_no` actually holds Aadhaar numbers | Exposed; nobody notices | Found by its values and masked automatically |
| An employee probes `WHERE aadhaar LIKE '1234%'` again and again | Eventually learns the number | Only masked values to compare against; the threat engine blocks them |
| Someone tries `UPDATE` or `DROP TABLE` through it | Depends on their database rights | Refused, and the attempt is logged |
| A DPDP or RBI auditor asks "who saw what?" | Scattered logs, if any | One tamper-evident log of every query, role and decision |
| "Can you prove nothing was changed?" | No | An integrity proof: table hashes match before and after |
| The same rules on three databases | Three separate setups that drift apart | One policy file |
| A suspicious pattern of queries | Nobody notices | An alert at risk 70, a block at 90 |

## 5. What already exists, and where MaskGuard fits

### Existing kinds of solutions

| Kind of tool | Examples | Good at | Gap for this problem |
|---|---|---|---|
| Masking built into the database | SQL Server dynamic data masking, Oracle Data Redaction, Snowflake masking policies, PostgreSQL Anonymizer | Included with the database; close to the data | Configured separately per database; assumes you already know which columns are sensitive; several mask only the displayed result, so `WHERE` and `ORDER BY` still use real values. Microsoft documents that its dynamic masking isn't meant to stop users running exhaustive queries |
| Enterprise data-security platforms | Immuta, Privacera, Cyral, DataSunrise and similar | Mature, many connectors, compliance reports | Expensive enterprise licences, built mainly around big cloud warehouses; Indian ID types aren't their focus |
| Masked copies (test-data tools) | Static masking products | Safe copies for developers and testers | A copy, not live access: support staff need today's data |
| PII-finding libraries | Microsoft Presidio and others | Finding PII in text | They find PII; they don't control who sees what inside the database |

### What MaskGuard adds

1. **Finds sensitive columns by itself**, including Indian IDs (Aadhaar, PAN, GSTIN, UPI, IFSC, EPIC) and columns with
   misleading names.
2. **Masks inside the query**, so the clever tricks of section 12 don't work.
3. **One policy across PostgreSQL, MySQL and SQLite.**
4. **More than masking:** insider-threat detection, a hash-chained audit log with no PII in it, and integrity proofs.
5. **Self-hosted and light**: about 8 ms added per query, runs on the organisation's own server.

### "Can't we just ask ChatGPT or Claude to build this?"

Partly, yes, and MaskGuard itself was built with an AI assistant. An AI can write masking code in an afternoon. But:

- **The quick version is usually display masking**, which our attack suite breaks in 14–15 of 17 attacks.
- **Security bugs are silent.** Broken masking doesn't crash; it leaks, and nobody notices until data is gone.
- **The value is the checking:** an attack suite, 1,244 tests on three databases, 121 API checks, a security
  comparison with an existing product, a production profile verified live, and a privacy audit that found and
  documented its own gaps.

A team with AI help could rebuild something similar, but it would then own the job of proving it safe, and of
maintaining it when a new bypass is found.

### "Why not let an AI decide, at query time, what to hide?"

- It would send customer data to an outside service: the very leak you're trying to stop.
- A security rule must give the same answer every time; a language model can vary.
- It adds seconds and cost to every query; MaskGuard adds milliseconds.
- Text hidden inside the data can manipulate a language model ("prompt injection"); fixed rules can't be argued with.

MaskGuard uses AI where it fits (finding sensitive columns, locally) and fixed rules for enforcement.

### What MaskGuard is not

- **Not a replacement for encryption**, network security or your login system. Keep all of those.
- **Not a write path.** It only answers `SELECT` queries; updates go through your existing applications.
- **Not a guarantee for people who bypass it.** Anyone with direct database credentials isn't protected by it.
- **Not a compliance certificate.** It provides safeguards the law asks for; compliance covers much more.

## 6. Basic terms you need first

**Database.** An organised store of data, like a set of spreadsheets that a program can search quickly. MaskGuard
works with three kinds: **SQLite** (a database in a single file, used for demos), **PostgreSQL** and **MySQL** (database
servers used by real companies).

**Table, row, column.** A table is one spreadsheet, for example `users`. Each **row** is one record (one customer).
Each **column** is one field (`name`, `phone`, `ssn`).

**SQL.** "Structured Query Language", the language used to ask a database questions. The most common question is
`SELECT`:

```sql
SELECT name, phone FROM users WHERE city = 'Pune' ORDER BY name LIMIT 10
```

Read it as: "give me the name and phone (`SELECT`) from the users table (`FROM`), only for people in Pune (`WHERE`),
sorted by name (`ORDER BY`), at most 10 rows (`LIMIT`)".

**Query.** One question written in SQL.

**Aggregate.** A calculation over many rows that returns one number: `COUNT` (how many), `SUM` (total), `AVG`
(average), `MIN`, `MAX`. `GROUP BY city` computes one aggregate per city.

**JOIN.** Combining two tables on a shared value, for example accounts with their owners:
`FROM accounts a JOIN users u ON u.id = a.user_id`.

**PII.** "Personally Identifiable Information": anything that identifies a person or is sensitive about them:
names, phone numbers, emails, Aadhaar, PAN, passport numbers, card numbers, bank accounts, addresses, dates of
birth, and so on.

**Masking.** Replacing a sensitive value with a safer version: hiding some characters (`XXX-XX-6789`), replacing it
with a token, or removing it (`REDACTED`).

**Role.** A label for a kind of user: `admin`, `support`, `analyst`, `auditor`. What you may see depends on your
role, not on your name.

**Policy.** The rule book that says, for each role and each kind of data, which masking to apply.

**Gateway.** A program that sits between users and the database and checks or changes every request.

**Read-only.** Allowed to read data but never to change it.

## 7. The parts of MaskGuard

```mermaid
flowchart TB
    subgraph Clients["Ways in"]
        CLI["CLI<br/>(terminal)"]
        CR["Control Room<br/>(web dashboard)"]
        API["REST API<br/>+ Python SDK"]
        PX["PostgreSQL proxy<br/>(psql, BI tools)"]
    end
    subgraph Gateway["MaskGuard gateway (one engine)"]
        AUTH["Authentication<br/>who are you? which role?"]
        TH["Threat engine<br/>is this user attacking?"]
        RW["Rewriter + firewall<br/>build the masked query, reject unsafe SQL"]
        EX["Read-only execution"]
        AU["Audit log<br/>hash-chained record of every decision"]
    end
    SC["PII scanner<br/>(background worker)"]
    POL["Policy<br/>policies/default.yaml"]
    DB[("SQLite / PostgreSQL / MySQL")]

    CLI --> AUTH
    CR --> AUTH
    API --> AUTH
    PX --> AUTH
    AUTH --> TH --> RW --> EX --> DB
    RW -.uses.-> POL
    RW -.uses.-> SC
    SC -.samples.-> DB
    AUTH -.writes.-> AU
    TH -.writes.-> AU
    RW -.writes.-> AU
    EX -.writes.-> AU
```

| Part | Job | Code |
|---|---|---|
| Authentication | Checks the password, issues a signed token that says who you are and your role | `src/maskguard/auth.py` |
| Threat engine | Watches each user's stream of queries and blocks attack patterns | `src/maskguard/threat.py` |
| Rewriter + firewall | Turns your query into a masked one, rejects anything unsafe | `src/maskguard/rewriter.py` |
| Gateway | Runs the steps in order and records the result | `src/maskguard/gateway.py` |
| Database backends | Talk to SQLite, PostgreSQL and MySQL, always read-only | `src/maskguard/backends.py` |
| PII scanner | Finds sensitive columns with ML and checksums | `src/maskguard/scanner.py`, `src/maskguard/ml/` |
| Policy store | Loads, validates and versions the rule book | `src/maskguard/policy.py`, `policies/default.yaml` |
| Audit log | Append-only, hash-chained record of every decision | `src/maskguard/audit.py` |
| Integrity proofs | Shows the source data never changed | `src/maskguard/integrity.py` |
| Interfaces | CLI, API, Control Room, proxy, SDK | `cli.py`, `api.py`, `web/`, `pgwire.py`, `client.py` |
| Configuration | Reads settings, refuses unsafe production setups | `src/maskguard/config.py` |

## 8. The life of one query

Follow one question from a support agent through the gateway.

```mermaid
sequenceDiagram
    autonumber
    actor S as Support agent
    participant G as Gateway
    participant T as Threat engine
    participant R as Rewriter + firewall
    participant D as Database (read-only)
    participant A as Audit log
    S->>G: SELECT name, ssn FROM users LIMIT 3  (with signed token)
    G->>G: Is the token valid? Role = support
    G->>T: Is this user currently blocked?
    T-->>G: No
    G->>R: Rewrite for role "support"
    R->>R: Single SELECT? Allowed functions only? Known tables?
    R-->>G: SELECT name, ssn FROM (SELECT name, mg_partial(ssn,0,4) AS ssn, … FROM users) AS users LIMIT 3
    G->>D: Run the rewritten query in a read-only transaction
    D-->>G: Matthew Rana | XXX-XX-4078 …
    G->>T: Record this query (shape, rows, decision)
    G->>A: Append: who, role, channel, decision, query fingerprint
    G-->>S: Masked rows + request id
```

In words:

1. **Authenticate.** The request carries a **token** (a signed note saying "this is support.sam, role support").
   The gateway checks the signature and that the user still exists with that role.
2. **Threat check.** If the threat engine has blocked this user, the request stops here.
3. **Rewrite.** The rewriter parses the SQL and checks it is safe (section 13). It then replaces every table name with a
   **masked view** for the caller's role (section 12).
4. **Policy checks.** In production, a query that would release a noisy aggregate is refused here (section 22).
5. **Execute read-only.** The rewritten query runs. The database cannot change anything.
6. **Score and record.** The threat engine updates the user's risk score; the audit log gets one entry.
7. **Respond.** The masked rows go back with a **request id**, so the matching audit entry can be found later.

If anything fails, the request is refused, the refusal is audited, and the error message never contains data.

## 9. Finding sensitive data: the PII scanner

Before masking anything, MaskGuard must know which columns are sensitive. Reading column names is unreliable, so
the scanner looks at the **values**.

```mermaid
flowchart TD
    A["New or changed table"] --> B["Sample up to N values per column<br/>(kept in memory, never shown or logged)"]
    B --> C["Checksum validators<br/>Aadhaar · PAN · GSTIN · card · IBAN · EPIC"]
    B --> D["79 value statistics + 20 column-name hints<br/>(length, digit share, separators, patterns…)"]
    D --> E["LightGBM classifier<br/>predicts the PII type + confidence"]
    C --> F{"Checksum hit?"}
    F -- yes --> G["Tag from the checksum<br/>(can never be downgraded)"]
    F -- no --> H{"ML confident?"}
    E --> H
    H -- yes --> I["Tag from the ML prediction"]
    H -- unsure --> J["Tag for review:<br/>still masked"]
    G --> K["Registry: column → tag + evidence"]
    I --> K
    J --> K
    K --> L["overrides.yaml can force a tag"]
    L --> M["Policy applies masks by tag"]
```

**Sampling.** The scanner reads a sample of values from each column (200 by default). The values stay in memory; they
are never printed, displayed or written to logs. Only the **evidence** is kept, for example "90% pass the card
checksum".

**Checksum validators.** Many ID numbers contain a built-in check digit, a digit computed from the others, so a
random number almost never passes:

- **Luhn** checks card numbers;
- **Verhoeff** checks Aadhaar numbers;
- **mod-36** checks GSTIN (Indian tax registration);
- **mod-97** checks IBAN (international bank account numbers);
- format rules check PAN and EPIC (voter ID).

If most values in a column pass, the column is almost certainly that ID type. A checksum hit can never be overridden
by the ML model.

**Features and LightGBM.** For columns without a checksum (names, phone numbers, emails, addresses), the scanner
computes 85 numbers that describe the values: average length, share of digits, presence of `@`, separators, script
(Latin or Devanagari), and so on. These numbers are called **features**. **LightGBM** is a machine-learning model
made of many small decision trees; trained on labelled examples, it predicts the PII type from those features.

**Tags.** The result for each column is a **tag** (a category):

| Tag | Meaning | Examples |
|---|---|---|
| `PII_HIGH` | Direct identifiers | Aadhaar, PAN, SSN, passport, phone, email |
| `FINANCIAL_CONFIDENTIAL` | Money and accounts | balances, card numbers, IBAN, account numbers |
| `PII_MEDIUM` | Quasi-identifiers: harmless alone, identifying together | name, date of birth, address, PIN code |
| `PII_IN_TEXT` | Identifiers inside free text | support notes mentioning a phone number |
| `HEALTH` | Health data: a special category in law (GDPR, DPDP), sensitive even without a name | diagnosis codes (ICD-10), blood groups, medication |
| `UNREVIEWED` | The scanner found nothing, and nobody has checked it yet. **Not the same as safe** | any column of a new database, until reviewed |
| `PUBLIC` | A person reviewed it and approved it as not personal | ids, statuses, cities |

**Unreviewed columns** are masked for every role except admin, because a scanner finding nothing is not proof there
is nothing. The scanner **suggests** which of them look safe (whole-number ids and keys, short lists like statuses),
and `maskguard pii approve --suggested` approves exactly those. **Uncertain columns** are still tagged and masked,
marked for human review. A person's decisions go in `policies/overrides.yaml`, written by `maskguard pii approve`
(PUBLIC) and `maskguard pii tag` (any tag), or by hand:

```yaml
users:
  id: {tag: PUBLIC}        # reviewed: an internal number, not personal data
  city: {tag: PUBLIC}
``` A **background worker** rescans every few minutes (`MASKGUARD_SCAN_INTERVAL`), and a new
table is blocked until it has been scanned.

How well does it work? On an independent Indian-PII benchmark with deliberately misleading column names, it scores
0.977 F1 with 5 sample values per column (0.999 with 20), against 0.844 for the benchmark's own baseline. **F1** is a
score from 0 to 1 that balances "found all the PII" against "did not flag non-PII".

## 10. The policy: who sees what

The policy is a YAML file (`policies/default.yaml`), a simple text format of keys and values. Its heart is a table:
for each **role** and each **tag**, which **action** to apply.

```yaml
default_action: deny            # a tag with no rule is denied (fail closed)
roles:
  admin:   {PII_HIGH: allow,   FINANCIAL_CONFIDENTIAL: allow,     PII_MEDIUM: allow,  PII_IN_TEXT: allow}
  support: {PII_HIGH: partial, FINANCIAL_CONFIDENTIAL: partial,   PII_MEDIUM: allow,  PII_IN_TEXT: redact_text}
  analyst: {PII_HIGH: hmac,    FINANCIAL_CONFIDENTIAL: aggregate, PII_MEDIUM: redact, PII_IN_TEXT: redact}
  auditor: {PII_HIGH: redact,  FINANCIAL_CONFIDENTIAL: redact,    PII_MEDIUM: redact, PII_IN_TEXT: redact}
```

Other parts of the policy:

| Setting | What it does | Default |
|---|---|---|
| `row_filters` | Hides whole rows from a role. Support never sees frozen accounts: `status <> 'frozen'` | support only |
| `max_rows` | The most rows one query can return, per role | admin 10,000 · support 100 · analyst 1,000 · auditor 100 |
| `min_group_size` | Aggregates over fewer rows than this are dropped, so a "group" of one person can't be singled out | 5 |
| `partial` | How many characters partial masking keeps at each end, per kind of value | card: first 4 + last 4 |
| `bucket_size` | Partial masking of numbers rounds down to this | 10,000 |
| `role_info.capabilities` | What each role may do besides querying (read the audit log, edit policy, run scans…) | see the file |
| `threat` | Alert and block thresholds | alert 70, block 90, 15 minutes |
| `dp` | Settings for the experimental noisy aggregates | ε 0.5 per query |

**Fail closed** means "when unsure, refuse". An unknown tag is denied; an unknown role is rejected outright.

**Capabilities** are separate from masking. A capability lets a role *do* something (such as `audit.read`), but no
capability can ever unmask data.

**Policy changes are versioned and audited.** Every audit entry records the policy version that decided it. Making a
rule weaker (for example support `partial` → `allow`) needs a written reason and an explicit confirmation.

**Asking "why is this masked?"** `maskguard policy explain --role support --table accounts` prints, for every column,
the tag, the action and the rule that decided it.

## 11. The masking actions, one by one

| Action | What the role sees | Example | Typical use |
|---|---|---|---|
| `allow` | The real value | `4111-2222-3333-1111` | Admin, data owners |
| `partial` | Some characters, the rest replaced by `X`. Emails keep the first letter and domain. Numbers are rounded down to the bucket | `4111-XXXX-XXXX-1111`, `XXX-XX-4078`, `b***@example.com`, `450000` | Support |
| `hmac` | A **keyed token**: the same input always gives the same token, but the token cannot be turned back into the value without the secret key | `423ef9aa927cc5b048aaaf98452d3bf1` (32 hex characters) | Analyst (lets them join and count without seeing identities) |
| `redact` | `REDACTED` (or `NULL` for numbers) | `REDACTED` | Auditor |
| `redact_text` | The text, with identifiers inside it replaced | `Call [PHONE] about card [CARD]` | Support reading notes |
| `aggregate` | Numbers only through noisy SUM/AVG/COUNT; never individually. **Experimental; off in production** | (section 22) | Analyst |
| `deny` | The column is refused | error | Anything without a rule |

**What is HMAC?** "Hash-based Message Authentication Code". A **hash function** turns any input into a fixed-length
fingerprint; the same input always gives the same fingerprint, and you can't run it backwards. **Keyed** means a secret
(`MASKGUARD_HMAC_KEY`) is mixed in, so an outsider can't just hash every possible phone number and compare. Plain hashes
of short IDs are easy to brute-force; keyed ones are not, as long as the key stays secret.

Masks are computed **inside the database** by small functions MaskGuard installs: `mg_partial`, `mg_email`,
`mg_token` (and the 1.0.x `mg_hmac`), `mg_bucket` and `mg_redact_text`. They give byte-identical results on SQLite, PostgreSQL and MySQL.

## 12. Why mask inside the query

This is the most important idea in MaskGuard.

**Naive masking** (a "display filter") runs your query on the real data, then hides columns in the result by name.
It fails in many ways:

| Trick | Query | What leaks with naive masking |
|---|---|---|
| Rename the column | `SELECT ssn AS x FROM users` | The filter looks for a column called `ssn`; there isn't one, so the real SSN is shown |
| Compute on it | `SELECT ssn \|\| '' FROM users` | Same: the result column has a new name |
| Ask yes/no questions | `SELECT count(*) FROM users WHERE ssn LIKE '123%'` | The count reveals whether the guess is right; repeat to recover the full number |
| Sort by it | `SELECT id FROM users ORDER BY ssn` | The order reveals the real values' order |
| Aggregate one row | `SELECT max(balance) FROM accounts WHERE id = 7` | One person's exact balance |

**MaskGuard instead replaces each table with a masked view before the database sees the query:**

```mermaid
flowchart LR
    Q["Your query<br/>SELECT ssn AS x FROM users<br/>WHERE ssn LIKE '123%'"] --> RW["Rewriter"]
    RW --> MQ["Masked query<br/>SELECT ssn AS x FROM (<br/>  SELECT mg_partial(ssn,0,4) AS ssn, …<br/>  FROM users) AS users<br/>WHERE ssn LIKE '123%'"]
    MQ --> DB[("Database")]
    DB --> R["Every reference to ssn now means<br/>the masked value XXX-XX-6789:<br/>the alias, the WHERE and the ORDER BY<br/>all work on masked data"]
```

Because the table itself is replaced, every part of the query (the alias, the `WHERE`, the `ORDER BY`, the join)
works on the masked view, not the raw table. Two extra protections cover what's left: small groups are suppressed
(`min_group_size`), and the threat engine catches users who try many guesses.

The **attack suite** tries 21 such attacks (17 that try to leak PII, 4 unsafe statements). Naive masking leaks 14–15 of
the 17; MaskGuard leaks none. That is evidence for those 17 shapes, not a mathematical proof against every possible
query.

## 13. The firewall and read-only execution

Before rewriting, the query is **parsed**: turned from text into a tree structure the program can inspect, using a
library called **sqlglot**. The firewall then refuses:

- anything other than a single `SELECT` (no `INSERT`, `UPDATE`, `DELETE`, `DROP`, `CREATE`…);
- **stacked statements**, such as `SELECT 1; DROP TABLE users`;
- `SELECT … INTO` and locking clauses;
- functions not on a short allow-list (so no `pg_read_file`, `load_extension`, `pg_sleep`…);
- session variables and parameters that could expose secrets;
- recursive queries;
- system catalogs (the database's internal tables).

Even if something slipped through, the query runs **read-only**: in a `READ ONLY` transaction on PostgreSQL and
MySQL, and through an "authorizer" that only permits reads on SQLite. In production, the database account itself can
only read (section 21). That is three layers, so one mistake isn't enough.

## 14. The insider-threat engine

Masking stops one query from returning raw values. A determined insider can still try **many** queries: guessing an
email over and over, binary-searching a balance, or paging through a whole table. The threat engine watches each
user's recent queries.

```mermaid
flowchart TD
    Q["Each query: shape (literals removed),<br/>decision, rows, masked columns touched"] --> W1["Short window<br/>last 40 queries / 5 minutes"]
    Q --> W2["Long window<br/>last 400 queries / 24 hours"]
    W1 --> R["Rules (explainable)<br/>enumeration · probing masked columns ·<br/>firewall bursts · bulk paging · slow attacks"]
    W2 --> R
    W1 --> M["ML: IsolationForest<br/>trained on normal sessions only"]
    R --> X["Risk = max(rules, ML), 0–100"]
    M --> X
    X --> D{"Risk level"}
    D -- "below 70" --> N["Allow"]
    D -- "70 to 89" --> AL["Allow + alert<br/>(dashboard, audit)"]
    D -- "90 or more" --> BL["Block the user for 15 minutes<br/>(rule evidence needed; ML alone only alerts)"]
```

**Rules** look for known patterns and give a reason each, for example "enumeration: same query shape 22× with
different values on a masked column".

**IsolationForest** is an ML model that learns what normal sessions look like and scores how unusual a new one is.
It was trained on simulated normal sessions only. By default the ML score can raise an alert but cannot block on its
own (`ml_can_block: false`), so a false alarm never locks someone out.

```mermaid
stateDiagram-v2
    [*] --> Normal
    Normal --> Alert: risk ≥ 70
    Alert --> Normal: behaviour returns to normal
    Alert --> Blocked: risk ≥ 90 with rule evidence
    Normal --> Blocked: risk ≥ 90 with rule evidence
    Blocked --> Normal: 15 minutes pass, or an admin unblocks
```

In the simulated evaluation it caught 95–100% of attack sessions and blocked no normal users. The engine's memory is
per process: a restart forgets it, and two gateway instances don't share it.

## 15. The audit log and its hash chain

Every decision (allowed, rejected, blocked, error, policy change, integrity check) is written to an **audit log**
(`data/audit.jsonl`, one JSON record per line). Each record contains who, which role, which channel, the decision,
the reason, the policy version and a request id.

**No personal data in the log.** The query is stored as a **fingerprint**: literals are replaced by `?`, so
`WHERE email = 'ravi@bank.in'` is logged as `WHERE email = ?`.

**Hash chain.** Each record includes the hash of the record before it:

```mermaid
flowchart LR
    G["genesis<br/>(fixed start value)"] --> E1["Entry 1<br/>data + prev = genesis<br/>hash = H1"]
    E1 --> E2["Entry 2<br/>data + prev = H1<br/>hash = H2"]
    E2 --> E3["Entry 3<br/>data + prev = H2<br/>hash = H3"]
    E3 --> E4["…"]
```

If someone edits, deletes or reorders an entry, its hash no longer matches what the next entry recorded, and
`maskguard audit verify` (or the "AUDIT TRAIL" check in `maskguard status`) reports the chain broken.

**Limits.**
- The chain is not keyed, so someone who can rewrite the whole file can rebuild a valid-looking chain. Ship the log
  to an external store if that matters.
- The log assumes **one writing process**. If an API server and CLI commands write to the same file at the same
  time, the chain forks and verification reports "CHAIN BROKEN" although nothing was tampered with (section 27).

## 16. Integrity proofs

How do you show that MaskGuard never changed the data? An **integrity proof**:

```mermaid
flowchart LR
    A["1. Hash every source table<br/>(digest before)"] --> B["2. Run the same query<br/>as every role"]
    B --> C["3. Attempt 6 kinds of write<br/>(UPDATE, DELETE, DROP, stacked, INSERT…SELECT, SELECT INTO)"]
    C --> D["4. Hash every table again<br/>(digest after)"]
    D --> E{"before = after?"}
    E -- yes --> P["PASS: source mutation NONE"]
    E -- no --> F["FAIL: exit code 5"]
```

A **digest** is a hash of a whole table's contents. If even one character changed, the digest changes. The proof
expects every write attempt to be refused and the digests to match. `maskguard integrity proof` runs it, the Control
Room has a button for it, and CI runs it on every push.

## 17. Ways to connect

Every interface goes through the same gateway, so the same rules apply everywhere.

```mermaid
flowchart LR
    T["Terminal"] -->|"maskguard …"| CLI["CLI"]
    B["Browser"] -->|":8000/ui/"| CR["Control Room"]
    P["Python script"] -->|"MaskGuardClient"| SDK["SDK"]
    PM["Postman / curl"] --> API
    SDK --> API["REST API :8000"]
    CR --> API
    PSQL["psql, BI tools"] -->|":6543"| PX["PostgreSQL wire proxy"]
    CLI --> GW["Gateway"]
    API --> GW
    PX --> GW
    GW --> DB[("Database")]
```

| Interface | What it is | Try it |
|---|---|---|
| **CLI** | Command-line tool with an interactive console | `uv run maskguard`, `maskguard status`, `maskguard compare "SELECT …"` |
| **REST API** | Web endpoints that programs call over HTTP; interactive docs at `/docs` | `curl localhost:8000/health` |
| **Control Room** | The web dashboard, served by the API | <http://127.0.0.1:8000/ui/> |
| **Python SDK** | A small Python client for the API | `MaskGuardClient.demo(url, "support").query("SELECT …")` |
| **PostgreSQL proxy** | Speaks PostgreSQL's network protocol, so existing tools connect to MaskGuard as if it were a database | `psql "host=localhost port=6543 user=support.sam dbname=bank"` |
| **Postman collection** | 55 ready-made API requests with 121 automatic checks | `npx newman run postman/…` |
| **Classic dashboard** | The original Streamlit dashboard | `maskguard dashboard --classic` (:8501) |

**JWT.** The API's login returns a **JSON Web Token**: a signed string that says who you are and your role, valid for a
limited time. Every later request sends it (`Authorization: Bearer …`). The role always comes from the signed token,
never from the request itself, so nobody can just claim to be admin.

**PBKDF2.** Passwords are never stored. The user file stores a PBKDF2-SHA256 hash, run 200,000 times so guessing is
slow. Create one with `maskguard hash-password`.

## 18. Installing MaskGuard on your computer

This gets you a working MaskGuard with synthetic (fake) bank data in a few minutes. Nothing touches any real
database.

### What you need

| Tool | What it is | Get it |
|---|---|---|
| **Python 3.11 or newer** | The language MaskGuard is written in | <https://www.python.org/downloads/> |
| **uv** | A fast tool that installs Python packages into a private folder for this project | <https://docs.astral.sh/uv/> |
| **git** | Downloads the code | <https://git-scm.com/> |
| Docker (optional) | Runs MaskGuard plus PostgreSQL in containers | <https://docs.docker.com/get-docker/> |

MaskGuard is developed and tested on Linux. Windows and macOS should work with Python 3.11+, but CI doesn't test them.

### The quickest way: pip

```bash
pip install maskguard
maskguard                  # first run asks: demo data, or your own database
```

The first run makes MaskGuard's secret keys for this computer (saved in `data/secrets.yaml`, readable only by you)
and asks whether to explore the demo data or connect your own database. No settings to type.

**pip** is Python's package installer. It downloads MaskGuard and everything it needs, and adds a `maskguard`
command. The demo database, audit log and scanner registry are created in `./data/` in the folder you run it from.
It comes from PyPI, the public Python package index: <https://pypi.org/project/maskguard/>. For changes made after
the last release, install straight from GitHub:
`pip install "git+https://github.com/hotaro6754/mask@claude/zealous-bell-me62fn#subdirectory=FULL_CODE"`.

There is no npm package and no `.exe`. MaskGuard is a Python server that runs next to a database, and a bundled
`.exe` would be hundreds of megabytes of ML libraries.

### From the source code (Linux or macOS)

Use this to develop MaskGuard or run its tests.

```bash
git clone https://github.com/hotaro6754/mask
cd mask/FULL_CODE
uv sync                                                   # installs everything into .venv/ (only this project)
uv run maskguard                                          # opens the console
```

### From the source code (Windows PowerShell)

```powershell
git clone https://github.com/hotaro6754/mask
cd mask/FULL_CODE
uv sync
uv run maskguard
```

### What happens the first time

```mermaid
flowchart TD
    A["uv run maskguard"] --> B["No database configured →<br/>use data/bank.db (SQLite file)"]
    B --> C{"Empty?"}
    C -- yes --> D["Create synthetic bank data<br/>(users, accounts, support tickets)"]
    C -- no --> E["Use it as it is"]
    D --> F["Install masking functions"]
    E --> F
    F --> G["Scan every table, tag sensitive columns"]
    G --> H["Record an integrity baseline"]
    H --> I["Show health checks and the menu"]
```

Then try:

```bash
uv run maskguard status                                     # every line is a real check
uv run maskguard compare "SELECT name, ssn, phone FROM users LIMIT 2" --roles admin,support,analyst,auditor
uv run maskguard attack --role support                      # 21 attacks: naive masking vs MaskGuard
uv run maskguard serve                                      # dashboard at http://127.0.0.1:8000/ui/
```

Demo logins: `admin.ann`, `support.sam`, `analyst.ali` and `auditor.aud`, each with password `<role>123` (for
example `support123`).

### With Docker instead

```bash
docker compose up --build
```

This starts PostgreSQL 16 with synthetic data, the API and Control Room on port 8000, the classic dashboard on 8501
and the PostgreSQL proxy on 6543. It is a **demo** stack (known passwords, open ports); never use it for real data.

### If something goes wrong

| Message | Meaning | Fix |
|---|---|---|
| `MASKGUARD_HMAC_KEY is not set` | Production has no token key (development makes one itself) | Set your own key: section 21 |
| `PII SCANNER  WARN  … rules only: install the OpenMP runtime …` | LightGBM can't load because the system lacks the OpenMP runtime (common on slim Docker images and fresh Macs). MaskGuard still runs on its rule-based scanner, which finds fewer columns; anything it misses stays masked as `UNREVIEWED` | Debian/Ubuntu: `sudo apt-get install libgomp1` · Fedora: `sudo dnf install libgomp` · macOS: `brew install libomp`. Then restart MaskGuard |
| `address already in use` | Port 8000 is taken | `uv run maskguard serve --port 8080` |
| `UNAVAILABLE … unsafe configuration` | You set `MASKGUARD_ENV=production` | Remove it for a demo, or follow section 21 |
| A command isn't found | You're outside the project folder, or `uv sync` didn't run | `cd mask/FULL_CODE && uv sync` |

## 19. Connecting your existing database

This is how MaskGuard goes from demo data to your own database. **Always try it on a staging copy first.**

### What MaskGuard needs from your database

| Need | Why |
|---|---|
| A connection URL | `postgresql://user:password@host:5432/dbname` or `mysql://user:password@host:3306/dbname` |
| Once: rights to create functions | It installs small masking functions (`mg_partial`, `mg_email`, `mg_hmac`, `mg_token`, `mg_bucket`, `mg_redact_text`). On PostgreSQL it also enables the `pgcrypto` extension |
| Always: read access to the tables | It only ever runs `SELECT` |
| MySQL with binary logging | `log_bin_trust_function_creators=1`, so the functions can be created |

It never changes your tables or rows, and never adds demo data to them. The secret key for tokens is passed in on
each connection, not stored in the database.

### Steps for a trial (development mode)

```bash
maskguard connect 'postgresql://user:password@staging-host:5432/yourdb'   # tests it, saves it, scans it
maskguard pii list                        # what was found, with evidence (never values), and what's UNREVIEWED
maskguard pii approve --suggested         # approve the ids, keys and status lists the scanner suggests
maskguard pii tag customers.city --tag PII_MEDIUM   # decide the rest yourself
maskguard compare "SELECT * FROM customers LIMIT 3" # the same query as each role
```

`connect` saves the URL for this folder in `maskguard.yaml` (readable only by you) and gives the database its own
folder for the audit log and registry (`data/<name>/`). `maskguard connect --demo` goes back to the demo. You can
also choose "my own database" when `maskguard` first starts, or set `MASKGUARD_DB` yourself.

### What happens on first connection

```mermaid
sequenceDiagram
    autonumber
    participant M as MaskGuard
    participant D as Your database
    M->>D: Connect with MASKGUARD_DB
    M->>D: Install mg_* masking functions (and pgcrypto on PostgreSQL)
    M->>D: List the tables (base tables only)
    loop each table
        M->>D: Read a sample of values per column
        M->>M: Checksums + ML → tag + evidence (values discarded)
    end
    M->>M: Save the registry (tags, no values)
    M->>D: Hash every table → integrity baseline
    M-->>M: Ready: queries now go through masked views
```

### Then make it yours

1. **Check the tags and review the rest.** `maskguard pii list`, or Control Room → PII discovery. Wrong tag?
   `maskguard pii tag TABLE.COLUMN --tag …`. Every column the scanner found nothing in is `UNREVIEWED` and masked
   for everyone but admin, ids and keys included, so joins on them won't match yet. `maskguard pii approve
   --suggested` approves the ones that look like keys or status lists; look at the rest yourself.
2. **Set the rules.** Edit `policies/default.yaml`: roles, what each sees per tag, row filters, row limits.
   `maskguard policy explain --role support --table accounts` shows the result.
3. **Create real users.** `maskguard hash-password` for each, into your own users file; set `MASKGUARD_USERS`.
4. **Point people and tools at MaskGuard**, not the database:
   - people: the Control Room (`maskguard serve`) or the CLI;
   - programs: the REST API or Python SDK;
   - PostgreSQL tools: the proxy on port 6543 (tested with `psql` and psycopg; it has no TLS, so clients must
     allow non-SSL, and it should stay on the same machine).
5. **Remove direct database access** for those people and tools. Otherwise they can go around MaskGuard.
6. **Prove it on your data.** `maskguard integrity proof --sql "SELECT * FROM your_table LIMIT 5"` runs that query as
   every role plus six write attempts and compares table hashes before and after. `maskguard integrity verify`
   compares the tables with the baseline. (The attack suite in `maskguard attack` and `maskguard test` is written
   for the demo tables, so run it on the demo data, not on yours.)

### Going to production

Production adds strict checks (section 21):
- run `maskguard db-install --db <owner URL>` once with the owner account to install the functions;
- give the gateway its own **read-only** database account;
- set `MASKGUARD_ENV=production`, with real secrets, your own users file, and TLS for the API.

MaskGuard refuses to start if anything is unsafe. Full guide: [DEPLOYMENT.md](DEPLOYMENT.md).

### Removing it

Stop using it, give people their previous access back if appropriate, and drop the `mg_*` functions (in `psql`,
`\df mg_*` lists them with their argument types). Your data was never changed.

### Questions people ask at this step

- **Views?** The scanner covers base tables. Queries go through masked views of those tables.
- **Cloud databases** (Amazon RDS, Cloud SQL, Azure)? Same engines; they should work, but haven't been tested.
- **Oracle, SQL Server, MongoDB, Snowflake?** Not supported.
- **Large tables?** The scanner samples values instead of reading everything, and queries have a 5-second timeout.

## 20. Where MaskGuard runs

Three common pictures, from smallest to production.

**A. On a laptop, for a demo or evaluation.** Everything on one machine, with synthetic data.

```mermaid
flowchart LR
    You["You (browser / terminal)"] --> MG["MaskGuard<br/>localhost:8000"] --> DB[("data/bank.db<br/>SQLite file")]
```

**B. On a company server, next to the database.** Staff and tools reach MaskGuard; only MaskGuard reaches the
database.

```mermaid
flowchart LR
    subgraph Office["Office network"]
        Staff["Staff browsers"]
        BI["BI tools / scripts"]
    end
    subgraph Srv["Company server"]
        MG["MaskGuard<br/>HTTPS API + Control Room"]
    end
    DB[("Company database<br/>read-only account for MaskGuard")]
    Staff -->|"HTTPS"| MG
    BI -->|"API / SDK"| MG
    MG --> DB
```

**C. The production Docker stack** (`docker-compose.prod.yml`). The database sits on an internal network with no
published port.

```mermaid
flowchart LR
    Client["Clients"] -->|"HTTPS 8443"| API["api container<br/>MaskGuard, read-only account"]
    subgraph Internal["internal Docker network (no outside access)"]
        API --> DB[("db container<br/>PostgreSQL 16")]
        INST["db-install job<br/>(owner account, runs once)"] --> DB
    end
```

## 21. Development mode and production mode

MaskGuard has two modes, set by `MASKGUARD_ENV`:

| | Development (default) | Production |
|---|---|---|
| Data | Synthetic bank data, created automatically | Yours; nothing is ever written |
| Users | Demo identities (`admin.ann`, `support.sam`… password `<role>123`) | Your own user file only |
| Secrets | Development placeholders allowed | Required, at least 32 characters, not copied from examples |
| Database | SQLite is fine | PostgreSQL or MySQL, through a read-only account |
| Network | Anything | API off loopback only with TLS; proxy and classic dashboard on loopback only |
| Noisy aggregates | Available, labelled experimental | Refused (decision D11) |
| Self-tests (attack suite, simulated attack, benchmark) | Available | Refused for every role |

**Loopback** is `127.0.0.1` / `localhost`: reachable only from the same machine. **TLS** is the encryption behind
`https://`.

**Startup in production refuses anything unsafe and lists every problem at once:**

```mermaid
flowchart TD
    S["maskguard serve<br/>MASKGUARD_ENV=production"] --> C["Run every check, collect every problem:<br/>• environment name valid<br/>• own user file, no demo identities, demo mode off<br/>• JWT and HMAC secrets set, ≥ 32 chars, not placeholders<br/>• PostgreSQL or MySQL, seeding off<br/>• masking functions installed, database account read-only<br/>• listening address safe (TLS off loopback)"]
    C --> D{"Any problem?"}
    D -- yes --> X["Refuse to start<br/>print the whole list, exit code 4"]
    D -- no --> OK["Start serving"]
    X --> F["Fix them all, start again"]
    F --> S
```

All problems are reported together, so you fix them in one go instead of one restart per problem.

**Least privilege.** The gateway's database account can only read tables. Installing the masking functions needs more
rights, so it is a separate one-time step run with the owner account: `maskguard db-install`. The gateway never holds
the owner password. If the account could write, create objects or own the masking functions, production refuses to
start.

**Reference stack.** `docker-compose.prod.yml` puts the database on an internal network with no published port,
creates the read-only gateway account, runs `db-install` once, and serves the API over HTTPS on `127.0.0.1:8443`.
Full guide: [DEPLOYMENT.md](DEPLOYMENT.md).

**Why self-tests are refused in production.** The attack suite's "naive" half sends SQL straight to the database to
show what a display filter would leak. That is useful on synthetic data and dangerous on real data, so production
refuses it for every role, before any read. The refusal is audited with who, which channel and why, never with SQL
or results.

## 22. Noisy aggregates and differential privacy

This section explains an advanced topic simply, and why the feature is switched off in production.

**The question.** An analyst wants "the average balance in Pune". The exact answer seems harmless. But by asking two
exact questions, "total balance of everyone in Pune" and "total balance of everyone in Pune except customer 7", and
subtracting, the analyst learns customer 7's balance exactly. This is a **differencing attack**.

**Differential privacy (DP)** is a mathematical way to stop that. Add carefully sized random **noise** to each answer,
so that any one person's presence or value changes the answer only a little compared with the noise. Key terms:

| Term | Meaning |
|---|---|
| **Noise** | A random number added to the true answer |
| **Laplace noise** | Noise from a specific bell-like distribution that DP uses |
| **Sensitivity** | The most one person can change the true answer. If balances are clipped to 0–10 lakh, one person changes a SUM by at most 10 lakh |
| **Clipping (bounds)** | Treat every value below/above a range as the edge of the range, so sensitivity is known |
| **ε (epsilon)** | The privacy "cost" of one answer. Smaller ε means more noise and more privacy |
| **Privacy budget** | The total ε allowed. Every answer spends some. When it's used up, no more answers |
| **Composition** | Privacy losses add up across answers; that's why a budget is needed |
| **Neighbouring datasets** | Two datasets that differ in one person. DP promises the answers look almost the same for both |

```mermaid
flowchart LR
    Q["SUM(balance) by city"] --> C["Clip each value<br/>to 0–10 lakh"]
    C --> S["True sum"]
    S --> N["+ Laplace noise<br/>scaled to sensitivity / ε"]
    N --> B{"Budget left?"}
    B -- yes --> A["Noisy answer<br/>budget reduced by ε"]
    B -- no --> R["Refused"]
```

**What MaskGuard does today.** In development, the `aggregate` action gives analysts noisy SUM/AVG/COUNT with a budget.
An audit of that mechanism found **ten gaps**, so it is **not** a differential-privacy guarantee yet. Examples:

- **F1, joins:** a join can repeat one customer's row 4 times, multiplying their influence 4× while the noise
  assumes 1×;
- **F2, ordering:** `ORDER BY` can sort groups by their true sums before noise is added;
- **F3/F4, budgets:** the budget renews every day and is per analyst account, so total privacy loss has no bound and
  two analysts get two budgets;
- **F6, per-row clipping:** a customer with two accounts can move a sum by twice the declared sensitivity.

Four of these are written as **strict expected-failure tests** (`tests/test_dp_findings.py`). An "xfail" test asserts
what *should* be true and is expected to fail today; "strict" means that once the gap is fixed the test passes
unexpectedly and fails the build, forcing someone to remove the marker deliberately.

**Decision D11:** production refuses noisy aggregates, before any budget is charged or data is read. Masking, tokens
and everything else keep working.

**The plan.** A full design (`docs/design/PRIVACY_ACCOUNTING.md`) proposes:
- one lifetime budget per dataset, shared by all analysts;
- crash-safe charging: the charge is recorded before the answer is computed;
- an independent evidence store, so restoring an old database backup can't reset the budget;
- recovery fencing, so a gateway paused during a recovery can't release an answer afterwards.

It is **frozen at commit `a6891fd`** for an independent reviewer. The reviewer may reject it.

```mermaid
stateDiagram-v2
    [*] --> Frozen: design frozen at a6891fd
    Frozen --> Reviewed: independent review (protocol, storage, DP maths, implementation gaps)
    Reviewed --> Decided: data owner sets budget and charging (D4/D5), mechanisms chosen (D13/D14)
    Decided --> Implemented: accountant built
    Implemented --> Tested: recovery, restore and race tests pass
    Tested --> Approved: independent approval of design and implementation
    Approved --> [*]: D11 lifted, aggregates back in production
    Reviewed --> Frozen: reviewer rejects or asks for changes (new revision, new review)
```

Passing tests or a model checker finding no counterexample are evidence, not proof; none of them alone reopens
production aggregates.

## 23. How it is tested

| Check | What it proves | Command |
|---|---|---|
| **Test suite** (pytest) | 1,244 tests on SQLite, PostgreSQL 16 and MySQL 8.4: masking, attack matrix, firewall, roles, scanner, threat engine, API, CLI, production refusals, DP findings, audit hardening | `uv run pytest -q` |
| **Attack suite** | 0 of 17 PII attacks leak; 4 of 4 unsafe statements rejected | `uv run maskguard attack --role support` |
| **Security regression** | Attack suite as every role + audit chain + integrity proof | `uv run maskguard test` |
| **Postman / Newman** | 55 API requests, 121 assertions, including 26 negative and security cases | `make postman` |
| **Dashboard walkthrough** | Every Control Room page loads, no JavaScript errors, works at phone width | part of pytest (Playwright) |

```mermaid
flowchart TD
    P["git push"] --> CI["GitHub Actions"]
    CI --> S1["Start PostgreSQL 16 + MySQL 8.4"]
    S1 --> T1["pytest on all 3 databases"]
    T1 --> T2["Attack suite: must be 0 leaks"]
    T2 --> T3["maskguard test"]
    T3 --> T4["Newman against a live API"]
    T4 --> G{"All green?"}
    G -- yes --> OK["✓ CI passes"]
    G -- no --> F["✗ CI fails: any leak, failed assertion<br/>or change to source data"]
```

**CI** ("continuous integration") runs all of this automatically on every push, so a change that breaks security
can't slip in unnoticed.

## 24. Workflows, step by step

### 24.1 First run on your laptop

```bash
git clone https://github.com/hotaro6754/mask && cd mask/FULL_CODE
uv sync                                                    # install dependencies (uv is a fast Python package manager)
uv run maskguard                                           # first run: demo data or your database, then a menu
```

Synthetic data is created automatically the first time. Then:

```bash
uv run maskguard status                                    # every line is a real check
uv run maskguard compare "SELECT name, ssn, phone FROM users LIMIT 2" --roles admin,support,analyst,auditor
uv run maskguard serve                                     # API + Control Room at http://127.0.0.1:8000/ui/
```

### 24.2 See the same query as every role

```mermaid
flowchart LR
    A["Open Control Room<br/>/ui/ → Masking playground"] --> B["Pick a table or write SQL"]
    B --> C["Tick the roles to compare"]
    C --> D["Run: one real request per role,<br/>each with that role's own token"]
    D --> E["Compare results side by side;<br/>click a field to see the rule"]
    E --> F["Source tables re-hashed:<br/>MATCH, mutation NONE"]
```

### 24.3 A new table arrives

1. The table is created in the database.
2. Until the background scanner has seen it, queries on it are blocked.
3. The scanner samples it and tags its columns (or run it now: `maskguard scan`).
4. Check the result: `maskguard pii list`, or Control Room → PII discovery.
5. If a column is wrong, `maskguard pii tag TABLE.COLUMN --tag …`. Columns it found nothing in are `UNREVIEWED`
   (masked for everyone but admin) until you `maskguard pii approve` them.
6. Queries now work, masked by policy.

### 24.4 Change the policy safely

```mermaid
flowchart TD
    A["Want to change a rule"] --> B["maskguard policy explain --role R --table T<br/>(see the current decision)"]
    B --> C{"Stricter or weaker?"}
    C -- stricter --> D["Apply (Control Room policy studio or YAML)"]
    C -- weaker --> E["Give a reason + confirm explicitly"]
    E --> D
    D --> F["Validated: default must stay deny/redact,<br/>roles and tags must exist"]
    F --> G["New policy version, audited"]
    G --> H["maskguard test: still 0 leaks?"]
```

### 24.5 Investigate a threat alert

1. Control Room → Overview (threat alerts and blocks), or the API: `GET /threats` lists each user's risk score,
   action and reasons.
2. Read the reasons, for example "enumeration: same query shape 22× with different values on a masked column".
3. Audit explorer: filter by that user and look at the fingerprints of their queries.
4. If it's a real attack, leave the block in place and escalate. If it's a false alarm, an admin unblocks
   (`POST /threats/{user}/unblock`; needs the `threats.manage` capability).

### 24.6 Deploy to production

```mermaid
flowchart TD
    A["Copy deploy/production.env.example → deploy/production.env"] --> B["Generate secrets<br/>python -c 'import secrets; print(secrets.token_hex(32))'"]
    B --> C["Create users: maskguard hash-password<br/>→ your own users file"]
    C --> D["Get a TLS certificate"]
    D --> E["docker compose -f docker-compose.prod.yml up -d --build"]
    E --> F["db-install runs once with the owner account"]
    F --> G["API starts as the read-only gateway account"]
    G --> H{"Started?"}
    H -- "no, exit 4" --> I["Read the list of problems, fix them all"]
    I --> E
    H -- yes --> J["curl --cacert ca.pem https://127.0.0.1:8443/health"]
```

Details and every variable: [DEPLOYMENT.md](DEPLOYMENT.md).

### 24.7 Prove nothing leaks before a release

```bash
uv run pytest -q              # all tests
uv run maskguard test         # attacks per role + audit chain + integrity proof; exit 6 if anything fails
```

### 24.8 Query from Python or psql

```python
from maskguard.client import MaskGuardClient
mg = MaskGuardClient.demo("http://127.0.0.1:8000", "support")      # development demo identity
print(mg.query("SELECT name, ssn FROM users LIMIT 3"))
```

```bash
psql "host=localhost port=6543 user=support.sam dbname=bank"     # password: support123 (development)
```

## 25. A day with MaskGuard

What a normal day looks like once it's running.

```mermaid
flowchart TD
    A["09:00 · Support desk opens<br/>agents look up customers: masked"] --> B["10:30 · An analyst runs a city report<br/>tokens and counts, no identities"]
    B --> C["12:00 · A new table appears<br/>blocked until the background scan tags it"]
    C --> D["14:15 · An agent queries the same column<br/>with 20 different values in 3 minutes"]
    D --> E["Threat engine: risk 74 → alert<br/>…keeps going → risk 90 → blocked 15 min"]
    E --> F["14:30 · Security team reads the reasons<br/>in the Control Room and audit log"]
    F --> G["17:00 · Auditor verifies the audit chain<br/>and runs an integrity proof: PASS"]
```

Every one of those events is in the audit log, with who, which role, which channel, the decision and the reason,
and none of the customers' values.

## 26. Exit codes and error messages

The CLI uses stable exit codes, so scripts can react to them:

| Code | Name | Meaning |
|---|---|---|
| 0 | OK | Success |
| 1 | ERROR | Unexpected error |
| 2 | USAGE | Wrong command or options |
| 3 | DENIED | Refused: not allowed, rejected by the firewall, blocked, or disabled in production |
| 4 | UNAVAILABLE | Can't start or reach the engine; in production, an unsafe configuration |
| 5 | INTEGRITY FAILED | Source data changed during an integrity proof |
| 6 | SECURITY FAILED | The security regression found a leak or failure |

Error messages never contain data values. A rejected query says why ("only a single SELECT is allowed") and gives a
request id you can look up in the audit log.

## 27. Known limits, explained

| Limit | What it means | Can it be fixed? |
|---|---|---|
| HMAC tokens allow equality joins and frequency analysis | Same input → same token, so analysts can join on it (the point) and can count how often each token appears | A trade-off. Per-analyst keys stop cross-analyst joins; suppressing rare values limits frequency analysis |
| Partial masks reveal the characters they keep | `XXX-XX-4078` shows the last 4 digits | By policy: keep fewer characters |
| A column wrongly approved as `PUBLIC` is exposed | Columns the scanner finds nothing in are masked (`UNREVIEWED`) until a person approves them; a wrong approval shows the column to everyone | Process: review approvals like code. (Fixed on 18 Oct 2026: before that, unreviewed columns were returned as they were) |
| Threat engine evaluated on simulated sessions | Real traffic may look different | Needs real normal traffic to recalibrate |
| Threat-engine state is per process | Restarts forget blocks; two instances don't share | Fixable: keep state in a shared database |
| Names and addresses inside free text | Need a named-entity recognition (NER) model | Needs a new ML dependency |
| Applications with direct database credentials bypass the gateway | MaskGuard can only protect queries that go through it | Operations: remove those credentials |
| Noisy aggregates are experimental | Section 16 | After independent review and implementation |
| Audit chain is unkeyed and local | Someone with full file access can rewrite it | Fixable: key the chain; ship to an external store |
| Audit log assumes one writing process | API + CLI writing the same file break the chain (false alarm) | Fixable: lock the file and re-read the last entry before each write |
| PostgreSQL proxy has no TLS; `Describe` under review | Production keeps the proxy on loopback. Its error messages no longer carry database text (fixed 18 Oct 2026) | TLS is fixable; `Describe` waits for the independent review |

## 28. Glossary A–Z

| Term | Meaning |
|---|---|
| **Aadhaar** | India's 12-digit national ID; its last digit is a Verhoeff check digit |
| **Aggregate** | A calculation over many rows returning one value (SUM, AVG, COUNT, MIN, MAX) |
| **Alert** | A warning raised when a user's risk score passes 70 |
| **API** | Application Programming Interface: endpoints programs call; here a REST API over HTTP |
| **Attack suite** | 21 crafted queries that try to bypass masking or the firewall |
| **Audit log** | Append-only record of every decision |
| **Authorizer** | SQLite's hook that MaskGuard uses to allow only reads |
| **Bucket** | Rounding a number down to a multiple of 10,000 (partial masking of amounts) |
| **Capability** | A permission to do something besides querying (read audit, edit policy…); never unmasks data |
| **Checksum / check digit** | A digit computed from the others that catches typos and random numbers |
| **CI** | Continuous integration: automatic tests on every push |
| **CLI** | Command-line interface: the `maskguard` command |
| **Clipping** | Limiting values to a range before aggregating, so one person's influence is bounded |
| **Column** | One field of a table |
| **Composition** | Privacy losses from many answers add up |
| **Control Room** | MaskGuard's web dashboard at `/ui/` |
| **CTE** | Common Table Expression: a named sub-query (`WITH x AS (…)`) |
| **D11** | The decision to refuse noisy aggregates in production until the privacy design is reviewed |
| **Database** | Organised, searchable data store |
| **default_action** | What happens to a tag with no rule: `deny` (fail closed) |
| **Demo identities** | Synthetic users for development (`admin.ann`, `support.sam`…) |
| **Deny** | Refuse a column entirely |
| **Differencing attack** | Learning one person's value by subtracting two aggregate answers |
| **Differential privacy (DP)** | A guarantee that any one person's data barely changes any answer, achieved with calibrated noise |
| **Digest** | A hash of a whole table's contents |
| **Docker / Compose** | Tools that package and run the app and its database as containers |
| **DPDP Act** | India's Digital Personal Data Protection Act, 2023 |
| **Enumeration** | Trying many values one by one to find a match |
| **Epsilon (ε)** | The privacy cost of an answer; smaller is more private |
| **Evidence** | Why the scanner tagged a column (e.g. "90% pass card checksum"), never the values |
| **Exit code** | A number a command returns: 0 success, others for kinds of failure |
| **F1 score** | 0–1 score balancing finding all PII against false alarms |
| **Fail closed** | When unsure, refuse |
| **Feature (ML)** | A number describing the data that a model learns from |
| **Fingerprint** | A query with its literal values replaced by `?`, safe to log |
| **Firewall** | The rules that reject unsafe SQL before it runs |
| **Gateway** | The program between users and the database that checks and rewrites every query |
| **GSTIN** | Indian GST registration number, with a mod-36 check character |
| **Hash** | A fixed-length fingerprint of data; can't be reversed |
| **Hash chain** | Records that each include the previous record's hash, so edits are detectable |
| **HMAC** | A keyed hash; tokens that can't be reversed or brute-forced without the key |
| **IBAN** | International bank account number, with a mod-97 check |
| **Integrity proof** | Hash tables, run every role and write attempts, hash again, compare |
| **IsolationForest** | An ML model that scores how unusual a session is |
| **JOIN** | Combining rows of two tables on a shared value |
| **JWT** | JSON Web Token: a signed, time-limited proof of identity and role |
| **Laplace noise** | The random noise used by the DP mechanism |
| **LightGBM** | A fast machine-learning model built from many decision trees |
| **Least privilege** | Giving an account only the rights it needs (here: read-only) |
| **Literal** | A fixed value written in a query, like `'Pune'` or `42` |
| **Loopback** | `127.0.0.1` / `localhost`: reachable only from the same machine |
| **Luhn** | The checksum used by card numbers |
| **Masked view** | A sub-query that returns a table's columns already masked for one role |
| **Masking** | Replacing sensitive values with safer versions |
| **max_rows** | The most rows one query may return, per role |
| **min_group_size** | Aggregates over fewer rows than this are suppressed |
| **Naive masking** | Hiding result columns by name after the query ran on real data (leaks) |
| **NER** | Named-entity recognition: ML that finds names, places, etc. in text |
| **Newman** | The command-line runner for Postman collections |
| **Noise** | Random numbers added to answers for privacy |
| **ORDER BY** | Sorting clause in SQL |
| **Override** | A manual tag in `overrides.yaml` that wins over the scanner |
| **PAN** | Indian Permanent Account Number (tax ID) |
| **Partial** | Masking that keeps a few characters (`XXX-XX-4078`) |
| **PBKDF2** | A slow password-hashing method; passwords are stored only as PBKDF2 hashes |
| **PIA** | Privacy Impact Assessment; MaskGuard generates one automatically |
| **PII** | Personally identifiable information |
| **Policy** | The rule book: role × tag → action, plus row filters, limits and thresholds |
| **Policy version** | A short id of the policy in force, recorded in every audit entry |
| **PostgreSQL** | A popular open-source database server |
| **Privacy budget** | The total ε allowed across answers |
| **Probing** | Filtering or sorting on masked columns to infer their values |
| **Proxy (PG wire)** | A MaskGuard listener that speaks PostgreSQL's protocol, so psql and BI tools can connect |
| **Query** | One question written in SQL |
| **Read-only** | Able to read, never to change |
| **Redact** | Replace with `REDACTED` / `NULL` |
| **redact_text** | Replace identifiers inside free text with labels like `[PHONE]` |
| **Registry** | The scanner's output: each column's tag and evidence |
| **Request id** | An id returned with every answer and stored in the audit entry |
| **REST** | A style of web API using HTTP verbs (GET, POST…) |
| **Rewriter** | The part that turns your query into the masked query |
| **Risk score** | 0–100 score of how much a user's recent queries look like an attack |
| **Role** | The kind of user: admin, support, analyst, auditor |
| **Row filter** | A rule that hides whole rows from a role |
| **Sampling** | Reading a limited number of values per column for the scanner |
| **Scanner** | The part that finds sensitive columns |
| **SDK** | Software development kit: here, the Python client for the API |
| **Seeding** | Creating synthetic demo data (development only) |
| **Self-test** | The attack suite, simulated attack and benchmark; development only |
| **Sensitivity** | The most one person can change an answer |
| **SQL** | Structured Query Language, for asking databases questions |
| **sqlglot** | The Python library MaskGuard uses to parse and rewrite SQL |
| **SQLite** | A database stored in a single file |
| **Stacked statement** | Several statements in one query (`SELECT 1; DROP TABLE x`); rejected |
| **Strict xfail** | A test expected to fail today that fails the build once the bug is fixed |
| **Synthetic data** | Realistic but fake data, safe for demos |
| **Table** | A set of rows and columns |
| **Tag** | A column's category: PII_HIGH, FINANCIAL_CONFIDENTIAL, PII_MEDIUM, PII_IN_TEXT, HEALTH, UNREVIEWED (nothing found, not yet checked) or PUBLIC (approved by a person) |
| **Threat engine** | The part that detects and blocks attack patterns across queries |
| **TLS** | The encryption behind `https://` |
| **Token (auth)** | The signed JWT you get at login |
| **Token (HMAC)** | A masked stand-in for a value, joinable but not reversible |
| **Verhoeff** | The checksum used by Aadhaar numbers |
| **WHERE** | The filtering clause in SQL |
| **YAML** | A simple text format for configuration files |

## 29. Where to read next

| If you want… | Read |
|---|---|
| The overview with screenshots | [README.md](../../README.md) |
| To watch it | [demo_full.mp4](demo_full.mp4) (12 minutes, captioned) |
| The exact demo commands and expected output | [DEMO_RUNBOOK.md](DEMO_RUNBOOK.md) |
| The security boundary and design | [ARCHITECTURE.md](ARCHITECTURE.md) |
| How every number was measured | [EVALUATION.md](EVALUATION.md) |
| To deploy for real | [DEPLOYMENT.md](DEPLOYMENT.md) |
| The privacy-accounting design and its review | [design/PRIVACY_ACCOUNTING.md](design/PRIVACY_ACCOUNTING.md), [the review brief](design/PRIVACY_ACCOUNTING_REVIEW_BRIEF.md), [the evidence](design/PRIVACY_ACCOUNTING_REVIEW_EVIDENCE.md) |
| What related tools do | [REFERENCE_RESEARCH.md](REFERENCE_RESEARCH.md) |
| What's planned | [ROADMAP.md](ROADMAP.md) |
