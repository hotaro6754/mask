# Finale preparation: TalentAP Mega Hackathon 2026, problem B1

The team's working guide for judging day. It covers what each stage scores, what to say, the live demo, likely
questions, the overnight feedback loop, the code freeze, and Stage 3.

- **Deck:** `docs/MaskGuard_Final_Deck.pptx`: 12 slides, with speaker notes on every slide carrying timings and the
  judging parameter each slide answers. The Round 1 deck, `docs/MaskGuard_Round1_Submission.pptx`, is kept as it was.
- **Evidence for every number:** `docs/EVALUATION.md` (benchmarks, attacks, performance) and
  `docs/SAFFRON_VALIDATION.md` (the organisers' dataset).

---

## 1. The day at a glance

| When | What happens | What we do |
|---|---|---|
| Before 6 pm | Setup | Demo machine ready (checklist in §5), deck open in presenter view, video downloaded as a fallback |
| 6 pm – 9 pm | **Stage 1 jury.** Marks are collected and kept aside | 25-mark pitch and demo (§2). Write down every question and suggestion the jury makes |
| 9 pm – 6 am | **Jury feedback round.** Teams act on the jury's feedback, use of AI, completeness, their parameters, experience and suggestions | Feedback loop (§7): small, tested commits only |
| 6 am | **Code freeze.** Submit a zip that matches git, with no `node_modules` and with the ignore file | `scripts/package_submission.sh TEAMID PSID` (§8) |
| After the freeze | **Code evaluation.** Final score = Stage 1 (70%) + AI evaluation of the code (30%): how accurate the models are, and against which baselines | The repository answers this on its own (§9) |
| Stage 3 | **Top 40 → top 10.** Presentation and market analysis | Dataset validation, other datasets, market analysis, 10-slide deck (§10); our chances (§11) |

---

## 2. Stage 1: 25 marks, five parameters

We read the "m" in the brief as marks: 5 + 5 + 5 (role of AI, implied) + 7 + 3 = 25. The deck runs about 13
minutes plus questions; if the slot is shorter, the cuts are in §2.8.

| # | Parameter | Marks | Slides | Time |
|---|---|---|---|---|
| 1 | Context and problem understanding | 5 | 1 title, 2 problem (Ravi's story), 3 how it works | 3 min |
| 2 | Architecture and tech stack: lasting choices, short-term anti-patterns avoided | 5 | 4 architecture | 1.5 min |
| 3 | Role of AI: why, and was it deliberate? | 5 (implied) | 5 role of AI (dashboard discovery screenshot), 6 accuracy, honestly, 7 no LLM, no quantum | 3.5 min |
| 5 | Presentation and demo | 3 | 8 dashboard, 9 command line, both live | 3.5 min |
| 4 | Solution completeness: functional, not a prototype | 7 | 10 proof on the organisers' data | 1.5 min |
| | Differentiators and market, close | — | 11 why MaskGuard, 12 close | 1.5 min |

**The deck's rule: one message per slide, plain words.** A judge who has seen 40 teams should be able to repeat each
slide's title as the whole message: everyone sees everything → one gate → AI finds, never decides → honest accuracy → classic ML, quantum-safe → dashboard →
command line → proof → why us → finds it, hides it, proves it.

### 2.1 Context and problem (5)

What the jury needs to hear: we understood *this* problem, in *this* dataset, for *this* industry.

- **The one-line problem.** Bank staff need customer data to do their jobs, but not the identities inside it.
  Nobody knows where all the personal data is, and masking only what is shown on screen leaks.
- **Show that you read their data.** These are the details the pack plants:
  - `col_7` holds PANs;
  - every Aadhaar number fails its Verhoeff check;
  - every PAN has `0000` as its digits;
  - `ref_no` holds card-shaped decoys;
  - phones, UPI IDs and dates of birth sit inside Hinglish notes.

  This is what separates us from teams that tested on their own data.
- **Why it matters now:**
  - IBM 2025: the average breach in India costs ₹22 crore, the highest ever recorded.
  - DPDP Rules were notified in November 2025, and obligations apply from May 2027.
  - DPDP penalties go up to ₹250 crore for failing to take security safeguards. Always say "up to".
- **Who has the problem:** support agents, analysts and auditors, who all query the same tables.

### 2.2 Architecture and tech stack (5)

The jury asks "how will this hold up long term, and which short-term shortcuts did you avoid?"

**Lasting choices (slide 4):**
- **One enforcement path.** CLI, REST API, the PostgreSQL wire proxy and the dashboard all go through the same
  gateway, so masking is implemented once.
- **A real SQL parser.** sqlglot parses each query into a syntax tree, and each base table is replaced by a masked
  view for the caller's role. CTEs, sub-queries, joins and window functions are all covered, which regex rewriting
  cannot do.
- **Masks run inside the database** as `mg_*` functions on SQLite, PostgreSQL and MySQL:
  - the data is never copied or changed;
  - WHERE, JOIN and aggregates see masked values;
  - MaskGuard adds 4–8 ms per query, 6–22 ms on MySQL.
- **Fail closed.** A column the scanner can't classify is `UNREVIEWED`, which is masked for everyone but admin.
  Production mode refuses to start with demo users, default keys or a database account that can write.
- **Policy as versioned YAML.** It is validated, every change is recorded, and weakening a rule needs a confirmation
  and a reason.

**Shortcuts we refused:**
- regex SQL parsing;
- masking only on screen;
- copying data into a masked replica;
- default secrets;
- untested merges.

**Stack:**
- Python 3.10+, sqlglot, LightGBM, scikit-learn, FastAPI, Typer + Rich;
- SQLite, PostgreSQL 16, MySQL 8.4;
- pytest, Playwright, Newman, Docker, GitHub Actions;
- published to PyPI as `maskguard`.

### 2.3 Role of AI (5): the answer to rehearse

> **"Was AI deliberate or for the sake of it?" Deliberate, in two places, and deliberately kept out of a third.**

**30-second version:**
> We use machine learning only where rules fail. Finding personal data is a pattern problem: column names lie, and
> real identifiers fail their own checksums. A LightGBM model reads the values. On a public benchmark with misleading
> column names, rules alone score 0.84 and rules plus the model score 0.97 or more. On your Saffron Bank data, the first
> run found 22 of 35 sensitive columns, and none of the 13 misses leaked, because unsure means hidden. The second place is
> spotting unusual query behaviour, with an IsolationForest. We kept AI out of the access decision on purpose:
> who sees what is a deterministic policy, so every mask is explainable and testable. AI suggests a tag, the policy
> decides, and a person approves. And yes, we used AI coding assistants to build it. Every change is gated by 1,235
> tests on three databases.

**Follow-ups to expect:**

| Question | Answer |
|---|---|
| Why LightGBM, not an LLM? | It is fast (about 2.6 ms per column at 20 values) and runs offline, so no customer data leaves the bank. It is small, explainable through its features, and measured: 0.84 → 0.97 over rules alone on the public benchmark. An LLM would send samples of personal data to a model to decide whether they are personal. |
| What was it trained on? | Synthetic columns from our own generator, never real personal data. It is evaluated on an external benchmark (bharat-pii-bench) with seeds we never trained on. |
| Isn't 0.999 too good to be true? | "On a synthetic benchmark, yes, read it as the ceiling: the data is clean. That's why we show the hard numbers next to it. On your data, first contact was F1 0.68 (22 of 35 found). After general fixes it is 0.90, with 8 false alarms on the bank's own branch details. And none of it leaked, because unsure columns stay hidden." (Slide 6.) |
| Isn't 0.90 tuned to our data? | "Partly, yes. The fixes were made after seeing it, which is why we also show the first-contact 0.68. The fixes are general rules, and we re-checked that the public benchmark didn't get worse. The safety net doesn't depend on accuracy." |
| What if the model is wrong? | A miss is not a leak. The column stays `UNREVIEWED`, so it is masked for every role except admin, until a person reviews it. A false alarm only means a reviewer approves the column. |
| Why not let AI decide access? | Access must be reproducible and auditable. The same query by the same role must always give the same answer, and an auditor must be able to read the reason. |
| How did you use AI to build it? | As a pair programmer under our design and review. Nothing merges without tests: 1,235 automated tests, 45 container checks and 121 Postman assertions, all in CI. |
| What about names and addresses inside free text? | Not solved yet, and we say so. Identifiers inside text (phones, PAN, Aadhaar, UPI, email, dates of birth) are redacted. Names inside prose need NER, which is next. |

### 2.4 Solution completeness (7): functional, not a prototype

Lead with the organisers' own data (slide 10); the AI accuracy, misses included, is on slide 6.

- **Data checked first.** All 9 Saffron Bank tables are identical in CSV, SQLite, PostgreSQL and MySQL: 129,260 rows,
  compared cell by cell.
- **Answer key written before any change** (`bench/saffron/truth.py`): 35 sensitive, 14 quasi-identifiers, 71 not
  personal.
- **First contact:** 22 of 35 sensitive columns tagged. Nothing was exposed, but 2 account-number columns were
  wrongly suggested PUBLIC.
- **After general fixes:** 35/35 tagged, 0 suggested PUBLIC. The external benchmark did not regress.
- **As the organisers' 9 users, on 3 databases:**
  - 0 raw values in 13,700 masked cells;
  - a guessed real PAN returns 1 row for admin and 0 for support and analyst;
  - 4/4 writes refused;
  - data unchanged;
  - audit chain intact.
- **Product features that make it more than a demo:**
  - `pip install maskguard`;
  - production profile, HTTPS API and read-only DB account;
  - audit export with an external anchor;
  - Postman suite;
  - Control Room dashboard;
  - container end-to-end test.

### 2.5 Presentation and demo (3)

The live demo script is in §4. Rules:
- One person drives, one person talks.
- Never type a long query live: paste it from the cheat sheet.
- If anything stalls for more than 10 seconds, say "here is the same thing captured this morning" and go to slides 8–9.

### 2.6 Our differentiators: say these in every round

Many teams on this problem use encryption or "quantum" ideas. Do not attack them; place them.

1. **It finds the personal data by itself.** Others assume someone already knows which columns are sensitive. In
   the organisers' data, `col_7` holds PANs; we found it, with the reason shown in the dashboard.
2. **Each role gets its own view of the same live data.** No copies, no second database.
3. **It stops guessing.** A search for a real PAN returns 0 rows for Support. Screen-only masking and encryption
   don't stop this.
4. **Proven on their data, on all three databases**, with their users, and both a dashboard and a command line.

The line for encryption and quantum-safe approaches:

> "Encryption, even quantum-safe, keeps outsiders out, and that matters. But once the bank's own app decrypts the
> data, every employee sees all of it. We answer a different question: what should this employee see? The two work
> together."

### 2.7 Facing the quantum teams (slide 7)

"Quantum" in this problem usually means one of three things. Know which one a team is using, and answer that one.

| What they built | What it really does | Our calm answer |
|---|---|---|
| **Post-quantum encryption** (Kyber / ML-KEM, Dilithium) of the data or the tokens | Protects stored or transmitted data against a future quantum attacker | "Good for outsiders. It doesn't decide what each employee sees after decryption, and it doesn't find the PII. Our masking already uses only symmetric cryptography (HMAC-SHA-256, SHA-256), which quantum computers don't break the way they break RSA." |
| **Quantum ML** (QSVM, VQC in Qiskit or PennyLane) to classify columns | Runs on a simulator on a normal computer, or on cloud quantum hardware | "On table data, recent benchmarks find quantum classifiers don't beat tuned classical models. Ours runs offline in about 3 ms a column from a 0.45 MB file, and we show its real accuracy, misses included." |
| **Quantum random numbers** for tokens or keys | Better randomness for key generation | "Our keys come from the operating system's cryptographic random generator (256-bit). Randomness isn't the weak point in masking; who sees what is." |

Rules:
- **Never say "quantum is hype".** Say "we chose what works in a bank today, and we're already quantum-safe where it
  matters."
- **Turn it into a demo challenge.** "Whatever approach you use, three questions decide it: does it find `col_7`? What
  does support see when they search a real PAN? Does the data stay in place?" We answer all three live.
- **If a judge loves quantum:** "Post-quantum TLS is a deployment setting in front of MaskGuard, not a rewrite. The
  masking layer itself has nothing a quantum computer breaks."

Why no LLM, in one breath: customer data would leave the bank (or need GPUs), the same column could get different
answers on different days, each call costs money and seconds, and a prompt can be manipulated. A 0.45 MB LightGBM
model has none of those problems, and the accuracy is shown honestly on slide 6.

### 2.8 If the slot is shorter

| Slot | Cut |
|---|---|
| 10 min | Skip slide 4's tech-stack talk (leave it on screen); live demo dashboard only, slide 9 as a picture |
| 7 min | Slides 1, 2, 3, 5, 6, 8, 10, 11, 12; demo is slides 8–9 themselves |
| 5 min | Slides 1, 3, 6, 8, 10, 11, and the 30-second AI answer |

---

## 3. Numbers to know by heart

| Claim | Number | Where it comes from |
|---|---|---|
| Saffron sensitive columns tagged | 35/35 (first contact 22/35) | `docs/SAFFRON_VALIDATION.md` §3 |
| Raw values leaked, Saffron, 3 DBs | 0 of 13,700 masked cells per DB | `docs/eval/saffron_masking.json` |
| Discovery, organisers' data (detection F1) | 0.68 first contact (precision 0.73, recall 0.63); 0.90 after fixes (0.81, 1.00) | `docs/SAFFRON_VALIDATION.md` §3 |
| Discovery, public benchmark, misleading names | 0.97 (5 values), 0.999 (20 values): synthetic, so an upper bound | `docs/EVALUATION.md` |
| Benchmark's own baseline | 0.844, with 22.2% false alarms on hard negatives | same |
| Our false alarms | 1.5% at 20 values (all OTP columns), 0% at 200 | same |
| Attacks | 0/17 leak; output-only masking leaks 14/17 | `maskguard attack` |
| Attack matrix | 672 cases, 0 leaks (12 families × 3 roles × 3 DBs + fuzzer) | `tests/test_attack_matrix.py` |
| Latency added | 4–8 ms SQLite/PostgreSQL, 6–22 ms MySQL, 300 → 100,000 rows | `docs/EVALUATION.md` §6 |
| Tests | 1,235 passed, 1 skipped, 6 xfailed; 45 container checks; 121 Postman assertions | CI |
| Tokens | 128-bit keyed (32 hex), optionally scoped per column | `mg_token` |
| Market | $1.47 B (2025) → $2.60 B (2030), 12% a year | Knowledge Sourcing Intelligence |
| Breach cost, India | ₹22 crore average, 2025 | IBM Cost of a Data Breach 2025 |
| DPDP | Rules Nov 2025; obligations from May 2027; up to ₹250 crore | DPDP Act 2023 and Rules |

**Do not quote:**
- a "₹28 crore for finance" figure: it is secondhand and we could not verify it;
- competitor prices as facts: they are review-site estimates, which is why the slide marks them with an asterisk.

---

## 4. Live demo script: dashboard, then command line (about 3.5 minutes)

**The night before:** prepare a Saffron run folder by following "Reproduce" in `docs/SAFFRON_VALIDATION.md`:
1. `maskguard connect` the SQLite copy;
2. `pii approve --suggested`, then approve the remaining non-personal columns;
3. create `users.yaml` from `data/users.csv`, and set `MASKGUARD_USERS` to it.

Keep the passwords out of the repository and out of the screen recording. Then rehearse the script below twice.

### 4.1 Dashboard (Control Room), 2 minutes

Start it in the prepared folder: `maskguard serve --port 8000`, then open `http://127.0.0.1:8000/`.

1. **PII discovery** (signed in as `admin_anita`): type `pan` in the search box. Point at `col_7`: "the column name says
   nothing; the scanner read the values and says PAN, and shows its reason, never the value." (This is slide 5.)
2. **Masking playground** → SQL editor, paste:
   `SELECT cust_nm, mob_no, pan_no, curr_bal FROM customers JOIN kyc_records USING (customer_id) JOIN accounts USING (customer_id) WHERE customer_id IN ('CIF-007KK65R', 'CIF-00JEQMK0', 'CIF-00JWD3QM') ORDER BY customer_id`
   and press Run. Sign out, sign in as `support_ravi`, Run again. Then do the same as `analyst_kavya`. (This is slide 8.)
3. As `support_ravi`, scroll to **Why each field looks the way it does**: every masked field shows its rule.
4. **Audit explorer**: every query you just ran, who ran it, with no values.

### 4.2 Command line, 1.5 minutes

```bash
# 1. Same query, three organiser users (slide 9 shows the captured version)
maskguard query --user admin_anita   "SELECT cust_nm, mob_no, pan_no, aadhaar_no, account_no, curr_bal FROM customers JOIN kyc_records USING (customer_id) JOIN accounts USING (customer_id) ORDER BY customer_id, open_dt LIMIT 3"
maskguard query --user support_ravi  "<same query>"
maskguard query --user analyst_kavya "<same query>"

# 2. The inference attack masking-on-screen cannot stop: guess a real PAN
maskguard query --user support_ravi "SELECT count(*) FROM kyc_records WHERE pan_no = '<a real PAN from the admin output>'"   # 0

# 3. Read-only, for every role
maskguard query --user admin_anita "UPDATE accounts SET curr_bal = 0"          # refused, exit code 3

# 4. Proof the data did not change, and the audit chain
maskguard integrity proof
maskguard audit verify
```

**Fallback order:**
1. Slides 8 and 9 are real captures from 30 Oct 2026; talk over them.
2. Demo bank with built-in identities: `maskguard compare "SELECT name, ssn, email FROM users ORDER BY id LIMIT 2" --roles admin,support,analyst`
   and `maskguard attack --role analyst`.
3. `docs/demo_full.mp4`.

**Pre-flight, 30 minutes before:**
- [ ] `maskguard doctor` passes
- [ ] Font size of the terminal is readable from the back (≥ 18 pt), dark theme, window maximised
- [ ] Queries pasted into a text file, ready to copy
- [ ] Notifications off, laptop on power, a second laptop with the deck and video
- [ ] Deck opened in presenter view: the notes carry the timings

---

## 5. Questions to prepare (with short answers)

| Question | Answer |
|---|---|
| How is this different from SQL Server Dynamic Data Masking or PostgreSQL Anonymizer? | DDM masks results only; Microsoft documents that it does not stop inference through WHERE. Anonymizer finds PII by column name and is PostgreSQL only. We find PII from values, mask inside the query, and run on three databases. |
| Why not just make a masked copy of the database? | A copy goes stale, doubles the attack surface and leaves the identities in a second place. We mask at query time, and the data stays where it is. |
| Can someone bypass the gateway? | Only with direct database credentials. Production runs MaskGuard with a read-only account, and users never get database credentials. The proxy speaks the PostgreSQL protocol, so BI tools connect to the gateway, not the database. |
| What about joins on masked columns? | Analysts get keyed tokens: the same input always gives the same token within a scope, so joins and counts still work without revealing values. |
| What does it cost in performance? | 4–8 ms per query on SQLite and PostgreSQL, 6–22 ms on MySQL, measured from 300 to 100,000 rows. Masks run inside the database. |
| What did your scanner get wrong on our data? | On first contact, 2 account-number columns were suggested PUBLIC and 11 columns were left unreviewed (masked). We fixed the general causes, not the dataset, and checked the external benchmark did not regress. It is all written up. |
| How do you know you didn't overfit to Saffron Bank? | The answer key was written first, every fix is a general rule (banking abbreviations, checksum-failing identifiers), and the external benchmark (unseen seeds) is unchanged at 0.999. |
| What can't it do? | Inference through business rules between columns; names inside prose (needs NER); the PostgreSQL proxy has no TLS of its own, so it is loopback-only in production. These are on slide 12 and in the README. |
| Is it DPDP-compliant? | It implements the safeguards DPDP asks for: purpose-based access, minimisation, audit. Compliance is an organisation's whole process, not one tool, so we don't claim certification. |
| How does a bank adopt it? | `pip install maskguard`, `maskguard connect` a read replica, review the tags, then point the support and analytics tools at the gateway. No schema or application change. |
| Who pays, and how much? | NBFCs, cooperative and small finance banks, fintechs and hospitals, who are bound by DPDP and can't buy a six-figure platform. Open core: free engine, paid support, DPDP reports and connectors. |
| What would you do with 90 more days? | NER for names in text, benchmarked before release; a pilot with one NBFC or cooperative bank on a read replica; a DPDP report export. |
| Other teams use quantum / encryption. Why not you? | Encryption, even quantum-safe, protects data from outsiders and in storage. It does not decide what each employee sees once the bank's app decrypts it, and a support agent can still guess a PAN through a search. MaskGuard answers that question and works alongside any encryption. |
| Why both a dashboard and a command line? | Compliance and support staff use the dashboard; IT teams and pipelines use the command line and JSON output. Both call the same engine, so the answer never differs. |
| Differential privacy? | Built, and refused in production on purpose: our own review found cases where noisy aggregates could be averaged out, so production masks instead (decision D11). It is documented rather than hidden. |
| Why three databases? | Banks run all three; the pack ships all three; and running the same attack matrix on all three is what shows the rewrite is not tied to one dialect. |

Honesty rules for every answer:
- Say "evidence for these query shapes", never "provably secure".
- If a judge finds a gap, thank them, write it down, and say what we would do. That feeds the overnight round.

---

## 6. Team roles on the day

| Role | During Stage 1 | Overnight |
|---|---|---|
| Presenter | Slides 1–7, 10–12, the AI answer | Rewrites the deck from feedback |
| Demo driver | Live demo, fallbacks | Implements code changes |
| Note-taker | Writes every jury question and suggestion verbatim | Runs the feedback log, tests and packaging |

---

## 7. Overnight feedback loop (9 pm – 6 am)

The jury looks at feedback implementation, use of AI, completeness, and their own suggestions. Treat every
suggestion as a ticket.

1. **Log it** in a feedback table, using the template below. Record exactly what was said, who said it, and which
   parameter it touches.
2. **Triage by 10 pm:**
   - **must**: a judge asked for it, or it is a bug;
   - **should**: improves a parameter;
   - **won't tonight**: risky. Reply in the deck instead.
3. **Implement in small commits.** Each commit:
   - runs `uv run pytest -q -x` before it is pushed;
   - changes one thing;
   - adds a test where it changes behaviour.
4. **Stop new features at 4 am.** From 4 to 6 am:
   - full test run;
   - README and deck updates;
   - re-record any changed demo steps;
   - package (§8).
5. **Show it in the morning:** add a "Feedback addressed" slide, or a section in the deck, with each point, what
   changed, and the commit.

```markdown
| # | Judge said (verbatim) | Parameter | Priority | Change | Commit | Test |
|---|---|---|---|---|---|---|
| 1 |  |  | must / should / won't |  |  |  |
```

Never do overnight:
- rewrite the core rewrite path;
- change the token format;
- touch the database schema;
- skip tests to save time.

---

## 8. Code freeze at 6 am: the zip

The required name is `teamid_psid.zip`. It should match the repository, without `node_modules` and with the ignore
file included. `scripts/package_submission.sh` builds it from what git tracks at `HEAD`, so ignored files can never
get in:

```bash
git status                     # must be clean; commit and push first
scripts/package_submission.sh <TEAMID> <PSID>              # → <TEAMID>_<PSID>.zip, about 26 MB with the demo videos
scripts/package_submission.sh <TEAMID> <PSID> --no-video   # → about 7 MB, if there is a size limit
```

The script:
- refuses to run with uncommitted changes;
- puts everything under a `<TEAMID>_<PSID>/` folder;
- includes `.gitignore`;
- fails if `node_modules`, `.venv`, `.env`, `data/` or `deploy/secrets` ended up inside.

Checklist:
- [ ] Final commit pushed to GitHub; CI green on that commit
- [ ] `uv run pytest -q` passes locally
- [ ] Zip built after the last commit; unzip it in a temp folder, then run `uv sync && uv run pytest -q` from inside it
- [ ] The organisers' dataset is **not** in the zip (it never enters the repository; scripts take its path)
- [ ] No passwords, keys or `users.yaml` with real hashes inside
- [ ] Uploaded before 6 am, and the upload confirmation saved

---

## 9. The AI evaluation of the code (30%)

The brief says it checks "how accurate models are and baselines". An automated reviewer reads the repository, so the
evidence must be easy to find from the README:

| What it will look for | Where it is |
|---|---|
| Model accuracy on held-out data | `docs/EVALUATION.md` §1–2: macro-F1 per sample size, per label, on unseen seeds |
| Baselines | The benchmark's own `regex_checksum` (0.844), our rules-only v1 (0.386), naive output masking (14/17 leaks) |
| Results on the provided dataset | `docs/SAFFRON_VALIDATION.md`, `docs/eval/saffron_masking.json` |
| Reproducibility | `bench/` scripts, result JSON in `docs/eval/`, commands in each doc |
| Tests and CI | 1,235 tests, GitHub Actions on every push, badge in the README |
| Honest limits | README "Known limits", `docs/design/PRIVACY_ACCOUNTING.md` |

Before the freeze, make sure the README's evidence table links each of these, and that every number in the deck
appears in a document with a reproducing command.

---

## 10. Stage 3: from 40 teams to 10

The brief names three things.

**1. Validate on the provided dataset, and on the other datasets we used.**
- Saffron Bank: discovery 35/35, masking 0 leaks on 3 databases (done; slides 6 and 10).
- bharat-pii-bench: the external benchmark, unseen seeds, at 5, 20, 50 and 200 values (done; slide 6).
- Our own generator: held-out seed 9001, used for training-distribution checks (`docs/EVALUATION.md`).
- The built-in demo bank: the 17-attack suite and the 672-case attack matrix.
- If time allows, add one more public dataset and report it the same way: answer key first, then score.

**2. Market analysis (slide 11, expand it for Stage 3).** Keep to sourced figures:
- **Market size:** $1.47 B → $2.60 B, 2025–2030, at 12% a year (Knowledge Sourcing). Estimates by other publishers
  differ ($0.8–3 B, 12–17% a year), so name the source.
- **Why now:** DPDP obligations from May 2027, and India's breach cost at ₹22 crore (IBM 2025).
- **Competitors:**
  - SQL Server DDM, which does not stop inference;
  - PostgreSQL Anonymizer, which finds PII by name only and runs on one database;
  - Immuta and Delphix, enterprise platforms whose review-site estimates are $100k–370k a year;
  - Presidio, which detects PII in text but has no gateway.
- **Beachhead:** NBFCs, cooperative and small finance banks, fintechs and hospitals.
- **Model:** open core, with paid support, DPDP reporting and connectors.

**3. A deck built the way winning decks are.** Notes from judges' write-ups (JetBrains, 2026; Salesforce hackathon
guidance; Reskilll's 3-minute pitch guide):
- State the problem in about 20 seconds, in the user's words, before any technology.
- One story end to end. Ours is a support agent who can't see a customer's PAN and can't guess it either.
- Show it working. A reliable demo beats more features, and a recorded fallback is good practice, not weakness.
- Numbers the judges can check, each with its source, put next to a baseline.
- Respect the time: rehearse to the minute, and finish early rather than late.
- Lead with strengths; state limits briefly and confidently on the last slide, not as apologies.

For Stage 3:
- add one slide on what changed after the jury's feedback;
- update the numbers if any changed overnight;
- rehearse the 5-minute cut.
- **If Stage 3 is strictly 10 slides:** the Stage 1 deck has 12. Fold slide 4 (architecture) into slide 3 (keep its
  four "built to last" ticks), and show slide 9 (command line) only live. Then the feedback slide makes it 11, so
  merge slide 7's quantum message into slide 11's encryption band.

---

## 11. Can we win? An honest read

Nobody can promise a result, but the position is strong, and the risks are known and fixable.

**Where we are strong:**
- **Completeness (7 marks, the largest share):** it runs on the organisers' own data, on all three of their
  databases, as their own users, with a dashboard and a command line. Most teams will show their own sample data.
- **The AI evaluation (30% of the final score):** accuracy against a named baseline on an external benchmark, 1,235
  tests, results files and reproduce commands. An automated code reviewer finds all of it from the README.
- **Role of AI:** a deliberate, defensible choice (classic ML, no LLM, AI never decides access), with a number.
- **Honesty:** we show our first-contact miss (22 of 35) and the fix. Judges trust teams that do.

**Where we can lose, and the fix:**

| Risk | Fix |
|---|---|
| Judges are impressed by "quantum" and "LLM" words | Slide 7, and the calm answer in §2.7. Turn it into the three-question demo challenge |
| The talk is too technical | Use the deck's words, not the code's: "find, hide, prove", "Ravi", "0 rows". Rehearse with someone non-technical |
| The live demo stalls | Prepared folder, pasted queries, slides 8–9 as fallback, video as a last resort |
| Running over time | Rehearse to 11 minutes; know the 7- and 5-minute cuts (§2.8) |
| A question we can't answer | "We haven't measured that; here is how we would." Write it down for the overnight round |

**The single most important thing:** a judge should leave able to say in one sentence what we built and why it is
different. "It finds personal data by itself, hides it inside every query per role, and proved it on our own data:
35 of 35 found, nothing leaked." Practise until every team member says it the same way.

---

## 12. Sources

- IBM, Cost of a Data Breach 2025, India: in.newsroom.ibm.com/2025-08-07-India-Records-Highest-Average-Cost-of-a-Data-Breach-IBM
- Knowledge Sourcing Intelligence, Data Masking Market: knowledge-sourcing.com/report/data-masking-market
- DPDP Rules 2025: Business Today, YourStory and Taxmann coverage of the November 2025 notification
- Microsoft Learn, Dynamic Data Masking: its limitation note on inference through filters
- Competitor pricing: review-site estimates (PeerSpot / IT Central Station); vendors do not publish list prices
- NIST IR 8547 (initial public draft, Nov 2024), Transition to Post-Quantum Cryptography Standards: csrc.nist.gov/pubs/ir/8547/ipd
  (its retirement plan covers quantum-vulnerable public-key algorithms; symmetric primitives are not scheduled)
- Bowles, Ahmed & Schuld (2024), "Better than classical? The subtle art of benchmarking quantum machine learning
  models", arXiv:2403.07059
- Benchmarking quantum kernel SVMs against classical baselines on tabular data, arXiv:2604.18837 (no significant
  quantum advantage in 29 pairwise comparisons)
- Pitch guidance: blog.jetbrains.com/ai/2026/06/how-to-win-a-hackathon-notes-from-the-judging-table/,
  developer.salesforce.com/blogs/2014/07/deliver-winning-pitch-hackathons, blogs.reskilll.com (3-minute pitch)
