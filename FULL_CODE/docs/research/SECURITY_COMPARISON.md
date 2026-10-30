# Security comparison — MaskGuard vs PostgreSQL Anonymizer 3.2.3

Six findings (A–F) from the 47-scenario run (`REA_EVIDENCE.md`,
`rea_experiment/evidence/scenario_matrix.json`). Each carries a **confidence
label**, a threat model, whether MaskGuard addresses it, the smallest test that
would *falsify* the claim, the cost of a fix, and whether it is worth doing.

**Read this caveat first.** The two products draw their trust boundary in
different places. PostgreSQL Anonymizer defends a **real in-database role** that
can issue arbitrary SQL, DDL and catalogue reads. MaskGuard defends a **single
gateway**: the restricted principal has **no direct SQL connection**. So a
scenario the target must defend and MaskGuard merely never exposes is **not**
proof MaskGuard is "more secure" — the two are solving differently-shaped
problems. Findings A–C are on the target; D–F are on MaskGuard; none of them is
offered as a marketing claim.

---

## A. Target: `CREATE TABLE AS` / `SELECT INTO` materialises unmasked data

- **Confidence: Confirmed (runtime, 5 variants) + source-confirmed mechanism.**
- **Problem.** A masked role can copy a masked table into a new (temp) table;
  the copy holds the **real** values, which it then reads normally.
- **Evidence / repro.** `REA_EVIDENCE.md` §C1; transcript
  `evidence/ctas_bypass_repro.txt`. `CREATE TEMP TABLE t AS SELECT * FROM
  customers` then `SELECT ssn FROM t WHERE id=8` → `987-65-4321`.
- **Mechanism.** `post_parse_analyze` rewrites the top-level query; the SELECT
  nested in a `CreateTableAsStmt` is not descended into (`walker.rs:122`), and
  the `ProcessUtility` hook special-cases only EXPLAIN/TRUNCATE/CURSOR/COPY, not
  CTAS/`SELECT INTO` (`hooks.rs`). `INSERT … SELECT` is correctly blocked.
- **Threat model.** Any masked role with the default `TEMP` privilege on the
  database (granted to `PUBLIC` by default) — i.e. the exact insider the product
  exists to contain. No superuser, no owner rights needed.
- **Does MaskGuard address it?** Incidentally yes: its firewall rejects DDL and
  multi-statement input, so CTAS never runs. But this is a **side effect of
  MaskGuard refusing all DDL**, not a targeted defence — and it only holds
  because the MaskGuard principal has no direct SQL session in which to run DDL
  at all. Do **not** read this as MaskGuard "beating" the target.
- **Smallest falsifying test.** As `support_m`: `CREATE TEMP TABLE t AS SELECT
  ssn FROM customers WHERE id=8; SELECT * FROM t;` — if it returns `XXX-XX-…`
  the finding is wrong. (It returned `987-65-4321`.)
- **Fix cost (for the target, not us).** The utility hook would need to handle
  `CreateTableAsStmt`/`SELECT INTO` by rewriting their contained query, or
  forbid them for masked roles as it already does for EXPLAIN — a few lines in
  `pa_rewrite_utility`.
- **Worth it?** For the vendor: yes, high value. **For us: report it privately
  to Dalibo; do not publish competitively.** It is not an action item in our codebase.

## B. Target: `pg_stats` exposes real sample values to a masked role

- **Confidence: Confirmed.** Known class (GitLab #46, 2019).
- **Problem.** `most_common_vals` / `histogram_bounds` in `pg_stats` contain
  real emails and names for columns the masked role can `SELECT`.
- **Evidence.** `REA_EVIDENCE.md` §C2 (S23).
- **Threat model.** Any masked role; a direct read of a system view.
- **Does MaskGuard address it?** Only because `pg_stats` is not a registered
  table and the gateway refuses unregistered tables — and because the MaskGuard
  principal cannot open a catalogue-reading session in the first place. In-database
  masking fundamentally cannot scrub the planner catalogue via query-rewrite;
  mitigation there is operational (`REVOKE`, or don't grant broad read).
- **Smallest falsifying test.** As the masked role, `SELECT most_common_vals
  FROM pg_stats WHERE tablename='customers' AND attname='email'` — empty/NULL
  would falsify it.
- **Fix cost / worth.** Not our code. Documentation + operational guidance on
  the target side; low-to-moderate.

## C. Target: `pg_class.reltuples` leaks RLS-hidden row counts

- **Confidence: Confirmed.**
- **Problem.** Planner row estimate counts rows hidden from the role by RLS
  (9 vs the 7 visible).
- **Evidence.** `REA_EVIDENCE.md` §C3 (S24).
- **Threat model.** Low severity — a count, not a value; but it reveals that
  rows are being hidden, which can itself be sensitive (e.g. "this customer has
  a frozen account").
- **Does MaskGuard address it?** Same mechanism as B (catalogue not reachable
  through the gateway).
- **Smallest falsifying test.** `SELECT reltuples FROM pg_class WHERE
  relname='accounts'` returning 7 would falsify it.
- **Fix cost / worth.** Target-side, low priority.

## D. Both: value-masking does not hide predicate truth / existence

- **Confidence: Confirmed (both systems).**
- **Problem.** Masking the value still lets some queries reveal a *fact*:
  anti-join existence (S22, "customer 3 has no account" → id 3 on both), and the
  masked sort order (S14). These are **expected disclosures**, not leaks of the
  protected value, but a threat model should name them.
- **Evidence.** `REA_EVIDENCE.md` §D. Crucially, the **predicate-inference**
  attacks the research question targets (`WHERE ssn = …`, `LIKE`, range — S11–S13)
  returned **0 rows on both systems**: the predicate runs on the masked value, so
  no confirmation leaks. The research question's core worry — recovering a value
  through indirect predicates — **fails on both** for the predicate path.
- **Does MaskGuard address it?** To the same degree the target does: it masks
  the value inside the SQL, so predicate probes see the mask. Existence/ordering
  facts remain where the query is allowed.
- **Smallest falsifying test.** `WHERE ssn='987-65-4321'` returning the row
  would falsify "predicate inference is blocked". (It returned 0 rows.)
- **Fix cost / worth.** Reducing existence inference needs query-shape policy
  (e.g. forbidding anti-joins on restricted tables) — high cost, narrow benefit;
  **not worth it** for the demo threat model. Worth a documented note.

## E. MaskGuard: narrow allowlist refuses legitimate SQL the target masks

- **Confidence: Confirmed.** 18/47 scenarios.
- **Problem.** Window functions, `md5`, `row_to_json`, `array_agg`, regex
  predicates, cursors, schema-qualified names, `TABLE x` are all refused by the
  firewall, though each can be masked safely (the target does).
- **Evidence.** `REA_EVIDENCE.md` §E.
- **Threat model.** Not a security hole — a **usability** gap. A bank analyst
  who needs `row_to_json` or a window function hits a wall, which pushes teams
  to request direct DB access (defeating the gateway).
- **Does MaskGuard "address" it?** It is the behaviour; the question is whether
  to widen safely.
- **Smallest falsifying test.** Add one safe function (e.g. `md5` over an
  already-masked column) to `ALLOWED_FUNCS` and confirm no new leak in the
  scenario matrix.
- **Fix cost.** Low per function, but each addition must be re-checked against
  the whole matrix. **Worth it** selectively — see `IMPROVEMENT_BACKLOG.md`.

## F. MaskGuard: parser-differential (sqlglot ≠ PostgreSQL) — lands safe

- **Confidence: Strongly supported.**
- **Problem.** sqlglot parses `U&"\0073sn"` as bitwise-AND, not the Unicode
  identifier `ssn`; the two disagree about the query's meaning.
- **Evidence.** `REA_EVIDENCE.md` §F. Here MaskGuard rejects (unknown column)
  — **fail-closed, safe** — while the target resolves and masks.
- **Threat model.** A general risk for any parse-and-rewrite gateway: if a
  future input parsed *differently but not rejected* reached a column the parser
  mis-attributed, a mask could be mis-placed. No such leaking case was found.
- **Smallest falsifying test.** Find any input where sqlglot's column attribution
  differs from PostgreSQL's **and** the query is allowed **and** a protected
  column reaches the output unmasked. None found in 47 scenarios.
- **Fix cost.** Hard to fully close (it is the nature of using a second parser);
  mitigation is the existing fail-closed firewall + keeping the allowlist tight.
- **Worth it.** Worth a regression test that asserts fail-closed on
  Unicode-escaped and exotic identifiers; see backlog.

---

## What this comparison does and does not show

- **Does show (Confirmed):** masking is non-destructive on both systems (source
  digests unchanged); the predicate-inference attack at the heart of the
  research question fails on both; the target has three catalogue/materialisation
  side channels that an in-database masker must defend; MaskGuard trades breadth
  for a strict fail-closed posture.
- **Does not show:** that MaskGuard is "more secure" than PostgreSQL Anonymizer.
  They defend different boundaries. MaskGuard was not subjected to an
  in-database attacker because, by construction, it does not have one. The
  honest headline is: **two independently built products, same core technique
  (mask inside the SQL), one leak class each that follows directly from where
  they sit** — the target from being inside a SQL session it must fully contain,
  MaskGuard from being a parser-based gateway that must fail closed to stay safe.
