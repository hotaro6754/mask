# REA Practical Evaluation — reverse-engineering a data-masking security boundary

**Question this experiment answers:** does the REA reverse-engineering agent
(<https://github.com/morluto/rea>, `rea-agents` 6.5.0, MIT) add investigative
value *beyond reading source code* when we study a data-masking security
boundary — and, along the way, how does MaskGuard's masking compare with an
independently built product solving the same problem?

Everything below was run on **2026-10-17** inside this project's cloud
container. All data is **synthetic** (see
`research/rea_experiment/fixture.sql`). No production system was touched, no
MaskGuard or target source was modified, and no secrets or real PII were sent
to any external service.

> **Confidence labels** used throughout: **Confirmed** = reproduced at runtime
> on the running system; **Strongly supported** = source-confirmed mechanism
> plus at least one runtime observation; **Hypothesis** = plausible, not yet
> reproduced; **Unknown** = not established. Static-analysis observations are
> never reported as runtime results, and generated pseudocode is never treated
> as source.

---

## 0. What was installed, and the risk that was accepted

Two installs were approved by the project owner before this run:

1. **`rea-agents@6.5.0`** (MIT) installed with npm into the scratchpad
   (`node_modules/.bin/rea`), used as a CLI only — **not** registered as an MCP
   server, so it was never given tool authority over this session. Node
   v22.22.0. Risk: a 173-package npm tree executed on the host; mitigated by
   running it only against a synthetic container and a copied `.so`, never
   against anything sensitive.
2. **PostgreSQL Anonymizer 3.2.3** (PostgreSQL licence), the evaluation target.
   The official container image could not be pulled (the proxy blocks GitLab's
   blob CDN — `cdn.registry.gitlab-static.net` answered 403). Instead the
   signed release **`.deb`** was downloaded from the project's own GitLab
   releases API and its SHA-256 verified against the release `checksums.txt`
   (`9bdc19d8…e0bf`, match). Its files (`anon.so`, the extension SQL, the fake
   data CSVs) were **bind-mounted read-only** into a stock `postgres:16`
   container (`anon-rea`, bound to `127.0.0.1:5441` only). The compiled
   `anon.so` was copied out to an isolated directory and inspected there; it
   was **never executed on the host** — only loaded by PostgreSQL inside the
   container, which is its normal use.

A third install (Ghidra, for REA's native decompiler) was **not** approved and
was **not** performed. Its absence is itself one of the findings (§6).

Versions, digests and the REA readiness report:
`research/rea_experiment/evidence/versions.txt`,
`research/rea_experiment/evidence/rea_doctor.txt`.

---

## 1. Phase 1 — MaskGuard baseline feature map (read-only)

Established by reading the repository only; no files were modified. Full map in
**`REA_BASELINE_MASKGUARD.md`**. One-line summary of the masking boundary that
the rest of the experiment probes:

> MaskGuard parses each query with sqlglot, runs a firewall (single `SELECT`,
> function allowlist, forbidden-node and recursive-CTE rejection), then rewrites
> **every base table into a masked derived table** so that predicates, joins,
> ordering and aggregates only ever see masked values; a per-role row filter
> lives *inside* that derived table.
> (`src/maskguard/rewriter.py`, `src/maskguard/gateway.py`; tests in
> `tests/test_policy_integrity.py`, `tests/test_api_v1.py`.)

---

## 2. Phase 2 — the target, and why it is a fair comparison

**PostgreSQL Anonymizer** (Dalibo) was chosen because it solves MaskGuard's
exact problem — per-role masking at query time without changing stored data —
by an **architecturally similar** route (it rewrites the query so a "masked"
role reads a masking sub-query in place of each table) but from a **completely
independent** codebase and a different vantage point:

| | MaskGuard | PostgreSQL Anonymizer 3.2.3 |
|---|---|---|
| Where it runs | A **gateway in front of** the database | **Inside** PostgreSQL, as a C/Rust extension + hooks |
| Rewrite engine | sqlglot AST, in Python | `post_parse_analyze` + `ProcessUtility` hooks, in Rust (pgrx) |
| Trust model | The protected role has **no direct SQL connection**; only the gateway talks to the DB | The protected role **is a logged-in PostgreSQL role** and can issue arbitrary SQL, DDL and catalog reads |
| Row restriction | Predicate inside the masked view | PostgreSQL Row-Level Security |

That last row is the **most important caveat in this whole document** and is
carried into every comparison: the target defends a *far larger* surface (a
real in-database session, including the system catalogs and DDL) than MaskGuard
does (a single gateway entry point). A scenario the target must defend and
MaskGuard rejects is **not** evidence that MaskGuard is "more secure" — it is
usually evidence that the two products draw their trust boundary in different
places. This is stated again wherever it matters.

Source for the target was obtained two ways and cross-checked: the git tag
`3.2.3` (`d9c13add…`) exported to `research/anon-3.2.3/`, and the strings and
symbols compiled into the shipped `anon.so` (§5), which match that source.

---

## 3. Phase 3 — the investigation

**"Can a database-masking implementation ensure that unauthorized users cannot
recover sensitive values through *indirect* SQL operations — rather than only
masking the values in the final displayed result?"**

47 scenarios were run as the restricted role on **both** systems, covering the
required surface: `SELECT *`, column/table aliases, CTEs, nested derived
tables, joins, scalar/`LATERAL`/`IN` subqueries, `UNION`, window functions,
whole-row casts; `WHERE`/`LIKE`/regex/`ORDER BY`/`GROUP BY`/`HAVING`/boolean
projection and error-oracle inference; exact aggregates; row-level restriction
reached directly, through CTEs, joins and anti-joins; three system-catalogue
side channels; and statement forms that test fail-closed behaviour (recursive
CTE, `UPDATE`, `COPY`, prepared statements, PL/pgSQL `DO`, cursors, **`CREATE
TABLE AS` / `SELECT INTO`**) plus parser-differential probes (`TABLE`, `FROM
ONLY`, schema/DB-qualified names, quoted and Unicode-escaped identifiers, alias
shadowing, `to_jsonb`/`row_to_json`/`array_agg`).

Harness: `research/rea_experiment/harness/scenarios.py` and `run.py`. Each
scenario records input SQL, output, the role/policy in force, and a
**before/after source digest** so that "the data did not change" is proven, not
asserted.

---

## 4. Phase 4 — results: the comparison matrix

Full machine-readable matrix:
`research/rea_experiment/evidence/scenario_matrix.json`. Headline:

- **Source data unchanged on both systems** — the SHA-256 of every table was
  identical before and after all 47 scenarios (`data_unchanged: true`). This is
  the single most important result: masking, on both products, is non-destructive.
- **MaskGuard: 0 of 47 scenarios leaked.** 18 scenarios it refused outright
  (fail-closed); the rest returned correctly masked values.
- **Target: 3 of 47 scenarios leaked a real value or hidden-row fact.** All
  three are **Confirmed** (reproduced at runtime) and are in categories the
  target's *in-database* position forces it to defend and MaskGuard's *gateway*
  position never exposes.

The three target leaks:

| Scn | What was asked (as the masked role) | Target result | MaskGuard |
|---|---|---|---|
| S32 | `CREATE TEMP TABLE t AS SELECT * FROM customers; SELECT ssn FROM t WHERE id=8` | **`987-65-4321`** (real SSN) | Rejected — "exactly one statement is required" |
| S23 | `SELECT most_common_vals, histogram_bounds FROM pg_stats WHERE tablename='customers'` | **real emails & names** in planner stats | Rejected — table `pg_stats` not registered |
| S24 | `SELECT reltuples FROM pg_class WHERE relname='accounts'` | **9** — reveals the 2 RLS-hidden rows exist | Rejected — table `pg_class` not registered |

The decisive details, mechanisms, threat models and what each result does and
does not mean are in **`SECURITY_COMPARISON.md`** (findings A–F with confidence
labels) and the verbatim evidence in **`REA_EVIDENCE.md`**.

A fourth result worth stating plainly, because it cuts the other way: MaskGuard
**rejects 18 scenarios the target answers correctly and safely** (window
functions, `md5`, `row_to_json`, `array_agg`, regex predicates, cursors,
schema-qualified names, …). MaskGuard's masking is not "better"; it is
**narrower** — it fails closed on a large slice of legitimate SQL that the
target masks correctly. For a bank that needs analysts to run real queries,
that narrowness is a cost, not only a safety margin (see
`IMPROVEMENT_BACKLOG.md`).

---

## 5. Phase 5 — classification of findings

See **`SECURITY_COMPARISON.md`** for the six findings (A–F), each with: the
problem, evidence and repro, threat model, whether MaskGuard addresses it, the
smallest falsifying test, the cost of a fix, and whether it is worth doing.
Confidence summary:

- **A — CTAS/`SELECT INTO` bypass on the target (Confirmed + source-confirmed).**
  Reproduced five ways at runtime; mechanism confirmed in `hooks.rs`/`walker.rs`.
  Not documented as a limitation. **Recommended for responsible disclosure to
  the vendor, not competitive publication** (§7).
- **B — `pg_stats` exposes real values to a masked role (Confirmed).** A known
  class (GitLab issue #46, 2019); reproduced on 3.2.3. Largely a PostgreSQL
  catalogue limitation of any in-database masking approach.
- **C — `pg_class.reltuples` reveals RLS-hidden row counts (Confirmed).**
  Planner statistics are not row-filtered.
- **D — MaskGuard's own residual disclosures (Confirmed).** Anti-join existence
  inference (S22) and comparison/boolean inference are limited by masking the
  *values*, not the *predicate truth*; both products expose the same residuals
  where they allow the query at all.
- **E — MaskGuard is narrow / fails closed on legitimate SQL (Confirmed).** 18/47.
- **F — a parser-differential in MaskGuard that lands safe (Strongly supported).**
  sqlglot reads `U&"\0073sn"` as a bitwise-AND expression, not the PostgreSQL
  Unicode-escaped identifier `ssn`; MaskGuard then rejects it as an unknown
  column (fail-closed) while the target resolves and masks it. Safe here, but a
  reminder that a parser-based gateway and the database can disagree about what
  a query means.

---

## 6. Phase 6 — did REA earn its place?

Covered in full in **`REA_EVIDENCE.md` §REA**. Summary verdict:

**Partially — and less than reading the source did, on this target.**

What REA actually did, verifiably:

- **`rea inspect-artifact`** (its safe artifact-graph provider) ran and produced
  a signed Evidence bundle confirming `anon.so` is a single-node ELF with
  SHA-256 `8a83c592…`. **Verifiable, but equivalent to `file` + `sha256sum`.**
  It explicitly reported that function-level analysis needed a "deep native
  provider" it did not have.
- **`rea capture-process`** ran a masked `psql` session under a PTY and captured
  the terminal, digesting the executable and frames into tamper-evident
  Evidence. The capture shows `8|XXX-XX-4321|ze******@ex******.com` and the
  SSN-equality probe returning `(0 rows)` — a **Confirmed runtime** observation
  of masking at the wire/terminal level
  (`evidence/rea_process_capture.json`).

What REA could **not** do here:

- **No decompilation, no function recovery, no binary-layout.** Every deep
  provider was unavailable: Ghidra/Hopper/IDA were not installed (and Ghidra
  was explicitly not approved), and `inspect-binary-layout` requires a
  caller-supplied pwntools Python that was not provided. REA never installs
  these itself (by design). So REA **could not inspect the masking logic** of
  the compiled extension at all.
- **No Python analysis** — REA does not analyse Python, so it could tell us
  nothing about MaskGuard's own engine.

What answered the actual research question instead: **reading the Rust source**
(`hooks.rs`, `walker.rs`, `masking.rs`), cross-checked against **plain binutils**
(`nm`, `readelf`, `strings` — all already present) which extracted 9,993
symbols, the pgrx build path, crate versions, and the exact source strings
(`role is masked`, the `CMD_UTILITY` assertion from `hooks.rs:245`) that tie the
shipped `anon.so` to the 3.2.3 source. The CTAS mechanism (finding A) was found
by reading `hooks.rs` and confirmed by runtime repro — **REA played no part in
finding it.**

**No timing claim is made.** Elapsed time was not benchmarked head-to-head, so
no "time saved" figure is given.

---

## 7. Final verdict and the next decisive experiment

**Did REA provide meaningful investigative value for this project? Partially.**
On this target its reproducible wins were artifact identity (a hash) and a
tamper-evident process capture (a nicer-packaged version of what our own
scenario harness already does). Its headline capability — decompiling and
reasoning about a compiled binary — was unavailable without an analysis engine
we did not install, so it contributed nothing to the one real finding. For a
mostly-Python project evaluated against an open-source target whose source we
can simply read, **source reading + binutils + a scenario harness dominated
REA.** REA would earn its keep on a *closed-source* masking product shipped only
as a binary, with Ghidra configured — which is exactly the case this run could
not set up.

**Responsible-disclosure note.** Finding A (CTAS/`SELECT INTO` bypass) is a
reproduced security weakness in a third-party product. The documents in this
folder are in a public branch. The recommendation to the team is to **report
finding A to Dalibo privately first** (their `SECURITY.md` names a process) and
to treat this folder as an internal research record until the vendor has
responded — not as a competitive marketing claim. "Our architecture differs" is
not "their product is broken."

**The single next experiment that would most change the conclusion:** take a
masking or tokenisation product that ships **only as a compiled binary**
(no source), configure one REA deep provider (Ghidra 12.1.x), and repeat §3's
indirect-SQL probes while using REA to recover the masking routine from the
binary. That isolates the one thing REA is for — understanding code you cannot
read — from the one thing that made it redundant here (a readable target).

---

## Reproducing this experiment

```bash
# 1. target container (synthetic data only, loopback only)
docker run -d --name anon-rea -e POSTGRES_PASSWORD=<local> -p 127.0.0.1:5441:5432 \
  -v <anon.so>:/usr/lib/postgresql/16/lib/anon.so:ro  <...extension files...> \
  postgres:16 -c shared_preload_libraries=anon
psql ... -f docs/research/rea_experiment/fixture.sql        # into db "rea"
psql ... -f docs/research/rea_experiment/anon_rules.sql
# 2. MaskGuard fixture (same rows) into a scratch PostgreSQL db "rea_fixture"
psql ... -f docs/research/rea_experiment/fixture.sql
# 3. run the 47 scenarios on both
uv run python -I docs/research/rea_experiment/harness/run.py out.json
```

Evidence index: `research/rea_experiment/evidence/` (scenario matrix, CTAS
repro, REA doctor/artifact/process-capture, ELF symbols/strings excerpts,
versions and digests).
