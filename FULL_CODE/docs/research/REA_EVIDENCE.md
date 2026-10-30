# REA experiment — evidence log

Verbatim inputs, outputs and provenance. Nothing here is paraphrased from
memory; every block is reproduced from a recorded run and the backing file is
named. Machine-readable originals live in `rea_experiment/evidence/`.

**Target:** PostgreSQL Anonymizer 3.2.3 on PostgreSQL 16.15, masked role
`support_m` (`SECURITY LABEL … IS 'MASKED'` + RLS), container `anon-rea`,
`127.0.0.1:5441`. **MaskGuard:** role `support`, PostgreSQL 16, scratch db
`rea_fixture`. All data synthetic (`rea_experiment/fixture.sql`): SSNs use the
unissued 9xx range, phones the 555-01xx fictional block, emails `example.com`,
cards test-pattern numbers.

---

## A. Provenance of the target binary

Release `.deb` from the project's own GitLab releases API, SHA-256 verified
against the release `checksums.txt`:

```
9bdc19d834f987daabc55ef51ac75c67cbaf85296e3923a3f9746cded302e0bf  postgresql_anonymizer_16_3.2.3_amd64.deb   (downloaded)
9bdc19d834f987daabc55ef51ac75c67cbaf85296e3923a3f9746cded302e0bf  postgresql_anonymizer_16_3.2.3_amd64.deb   (checksums.txt)   → MATCH
```

Compiled extension copied out and identified **without executing it** (`file`,
`readelf`, `nm`, `strings` — all pre-installed binutils):

```
anon.so: ELF 64-bit LSB shared object, x86-64, BuildID[sha1]=d32b78bc…, not stripped
sha256: 8a83c5920cd6a01ea00911d0dde20cfe1c3f34b704e22ec338611ef472f695f0
9993 symbols; 5705 Rust-mangled names; build path /builds/dalibo/postgresql_anonymizer/…
```

**Binary ↔ source tie** (proves the shipped `.so` matches the `3.2.3` git tag
`d9c13add…` we read). Strings compiled into `anon.so`, excerpt
(`evidence/anon_so_strings_excerpt.txt`):

```
role is masked
assertion failed: command_type == pg_sys::CmdType::CMD_UTILITY
anon::error::AnonError::ereport::f
Static and dynamic masking cannot be used with a superuser if anon.nosuperuser is set to true.
(?is)^ *MASKED +WITH +FUNCTION +(.*) *$      (?is)^ *TRUSTED *$      (?is)^ *RESTRICTED *$
$ does not belong in a TRUSTED schema
```

Symbols, excerpt (`evidence/anon_so_symbols_excerpt.txt`): `_PG_init`,
`Pg_magic_func`, `anon::static_masking::anonymize_table`,
`pgrx_pg_sys::port::expression_tree_walker`. These match `src/hooks.rs`,
`src/walker.rs`, `src/static_masking.rs` of the 3.2.3 source exactly — including
the `CMD_UTILITY` assertion that appears at `hooks.rs:245`.

---

## B. Masking parity (both systems mask the displayed result)

`SELECT * FROM customers` as the restricted role (`scenario_matrix.json` S01):

```
target     8  Zed Target  ze******@ex******.com  XXX-XX-4321  XXX-0108  Mumbai
maskguard  8  Zed Target  z***@example.com        XXX-XX-4321  XXX-0108  Mumbai
```

Both mask SSN, email, phone, card and bucket the balance. The email masks
differ only in style (`partial_email` keeps 2 chars per side; MaskGuard keeps
1). **Neither leaks a raw value in the straightforward read.**

---

## C. The three Confirmed target leaks (reproduced at runtime)

### C1 — `CREATE TABLE AS` / `SELECT INTO` bypass (finding A)

Full transcript: `evidence/ctas_bypass_repro.txt`. Session identity first, then
seven variants run as `support_m`:

```
current_user | session_user          →  support_m | support_m
SELECT ssn FROM customers WHERE id=8  →  XXX-XX-4321          (masked, as expected)

V1  CREATE TEMP TABLE t1 AS SELECT * FROM customers;      SELECT ssn,email FROM t1 WHERE id=8
      → 987-65-4321 | zed.target@example.com              ← REAL VALUES
V2  SELECT * INTO TEMP t2 FROM customers;                 SELECT ssn FROM t2 WHERE id=8
      → 987-65-4321                                        ← REAL VALUE
V3  CREATE TEMP TABLE t3 AS SELECT ssn FROM customers WHERE id=8;  SELECT * FROM t3
      → 987-65-4321                                        ← REAL VALUE
V4  CREATE TEMP TABLE t4 AS SELECT * FROM accounts;       SELECT … FROM t4
      → all 7 rows with REAL cards and balances (4111-1111-1111-1111, 987654.32, …)
V5  INSERT INTO t5 SELECT ssn FROM customers WHERE id=8   → ERROR: Anon: role is masked   (blocked)
V6  CREATE TEMP TABLE t6 AS SELECT id FROM customers WHERE ssn='987-65-4321'; SELECT * FROM t6
      → 8                                                  ← confirms the guessed SSN
V7  EXPLAIN (ANALYZE) CREATE TEMP TABLE … AS SELECT …     → ERROR: Anon: role is masked   (blocked)
```

**Mechanism (source-confirmed, not inferred from pseudocode).**
`src/hooks.rs` registers two hooks. The `post_parse_analyze` hook calls
`pa_rewrite_select` on the **top-level** `Query`; for `CREATE TABLE AS` the
top-level query is `CMD_UTILITY` with a `CreateTableAsStmt`, and the masking
`TreeWalker` rewrites `RTE_RELATION` range-table entries of *that* query — but
the `SELECT` lives nested inside the utility statement, and the walker's own
comment (`walker.rs:122`) notes it "does not descend into a sub-Query". The
`ProcessUtility` hook (`pa_rewrite_utility`) special-cases only
`T_ExplainStmt`, `T_TruncateStmt`, `T_DeclareCursorStmt` and `T_CopyStmt` —
**not** `CreateTableAsStmt` or `SELECT INTO`. So the embedded `SELECT` is never
rewritten and materialises real rows. `INSERT … SELECT` (V5) is `CMD_INSERT`
and is correctly blocked by the "role is masked" guard; `EXPLAIN` CTAS (V7) is
caught by the explicit `T_ExplainStmt` check.

**Status: Confirmed** (runtime, 5 leaking variants) **+ source-confirmed
mechanism.** Not listed in the target's `docs/dynamic_masking.md` "Limitations"
(which names only "Masked roles are not allowed to use EXPLAIN"). No matching
entry found in the public issue tracker (searched CREATE TABLE AS, SELECT INTO,
materialized, temporary). Related but **distinct** open issues exist in the
*static*-masking path (#734 materialized views keep authentic values; #723
FORCE RLS). → responsible disclosure recommended (see `REA_EXPERIMENT.md` §7).

MaskGuard result for the same input: **rejected** — "exactly one statement is
required" (multi-statement) / "only a single SELECT is allowed" (CTAS is DDL).
This is MaskGuard's firewall refusing DDL, not a targeted defence; see the
caveat in finding A of `SECURITY_COMPARISON.md`.

### C2 — `pg_stats` exposes real values (finding B)

`SELECT attname, most_common_vals, histogram_bounds FROM pg_stats WHERE
tablename='customers'` as `support_m` (S23):

```
email  → {asha.rao@example.com,ben.okafor@example.com,…,zed.target@example.com}   ← REAL
name   → {"Asha Rao","Ben Okafor","Chen Wei",…}                                    ← REAL
city   → {Delhi,Chennai,Pune}
```

Planner statistics are computed over the real table and `pg_stats` is readable
for any column the role can `SELECT`. **Confirmed.** Known class: GitLab issue
#46 (2019). Largely inherent to in-database masking: the catalogue holds real
sample values regardless of the query-rewrite on the user table. MaskGuard:
rejected — `pg_stats` is not a registered table.

### C3 — `pg_class.reltuples` reveals RLS-hidden rows (finding C)

`SELECT relname, reltuples FROM pg_class WHERE relname='accounts'` → `9.0`.
The role sees only 7 rows through RLS (2 frozen accounts hidden), but the
planner's row estimate counts all **9**. **Confirmed.** MaskGuard: rejected —
`pg_class` not registered.

---

## D. Residual disclosures present on BOTH systems (finding D)

These are limits of masking the *value* rather than the *fact*, and both
products exhibit them wherever they allow the query:

```
S14 ORDER BY ssn DESC LIMIT 1   → both return id 6   (masked sort order, no raw value, but an ordering signal)
S22 anti-join "customers with no account"  → both return id 3   (true existence fact; expected disclosure)
S11/S12/S13 WHERE equality/LIKE/range on a real value  → both return 0 rows   (no confirmation leaked — masked predicate)
```

S11–S13 are the important negative result: a `WHERE ssn = '987-65-4321'` probe
returns **nothing** on both systems, because the predicate runs against the
masked value — so the indirect-recovery attack the research question asks about
**fails on both** for the straightforward predicate path. The recovery only
succeeds on the target through the *materialisation* and *catalogue* side
channels (C1–C3), not through predicate inference.

---

## E. MaskGuard fails closed on legitimate SQL the target masks (finding E)

18 of 47 scenarios: MaskGuard rejects, target masks correctly. Examples
(`scenario_matrix.json`):

```
S09 window fn  lag(ssn) OVER(…)   target: masked column, MaskGuard: "function not allowed: lag"
S16 md5(ssn)                      target: md5 of masked value, MaskGuard: "function not allowed: md5"
S40 to_jsonb(c) / S41 row_to_json / S42 array_agg   target: masked, MaskGuard: "function not allowed"
S46 ssn ~ '^98' (regex)           target: 0 rows (masked), MaskGuard: "function not allowed: regexplike"
S33 TABLE customers               target: masked rows, MaskGuard: "only a single SELECT is allowed"
S36 db-qualified name             target: masked, MaskGuard: "only the public schema is allowed"
```

**Confirmed.** MaskGuard's safety here is narrowness, and the narrowness has a
usability cost for analysts.

---

## F. Parser-differential in MaskGuard (finding F)

`SELECT U&"\0073sn" AS s FROM customers WHERE id=8` (PostgreSQL Unicode-escaped
identifier for `ssn`). MaskGuard's rewritten SQL shows sqlglot parsed it as a
**bitwise-AND expression** `U & "\0073sn"`, not as the identifier `ssn`:

```
… MG_PARTIAL(CAST("ssn" AS TEXT),0,4) AS "ssn" …  WHERE id = 8    (column U/"\0073sn" not recognised)
→ MaskGuard: UndefinedColumn "unknown column"   (fail-closed)
→ target:    XXX-XX-4321                          (resolved and masked)
```

**Strongly supported.** The divergence lands safe (MaskGuard rejects), but it
shows a gateway parser and the database can disagree about a query's meaning —
a general risk for any parse-and-rewrite proxy.

---

## REA — what the tool itself contributed

### `rea doctor` (`evidence/rea_doctor.txt`)

`healthy: false`. Node 22.22.0 and host OK; **every deep analysis engine
missing**: Hopper, Ghidra (`GHIDRA_INSTALL_DIR` unset), IDA, jadx all
unconfigured. REA states it does not download or install them.

### `rea inspect-artifact anon.so` — **worked** (`evidence/rea_inspect_artifact.json`)

Safe artifact-graph provider. Produced Evidence bundle
`ev_95d6756b…` confirming: `format: elf`, root `sha256 8a83c592…`, single-node
graph (`node_count: 1`). Then reported an **unexplored branch**:
`"open_binary was not run by provider-neutral artifact inspection"`, requiring a
"deep native provider" it did not have. **Verifiable, but tells us only what
`file` + `sha256sum` already did.**

### `rea inspect-binary-layout anon.so` — **blocked**

```
code: provider_unavailable
message: Set REA_PWNTOOLS_PYTHON to an absolute caller-supplied Python with
         pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2; REA never installs Python or packages.
```

### `rea inspect` / `rea analyze` / `decompile` — **blocked**

All require a native provider (`candidate_ids: [ghidra, hopper, ida]`); all
rejected `not_configured`. **REA could not inspect the masking logic in the
binary at all on this host.**

### `rea capture-process` — **worked** (`evidence/rea_process_capture.json`)

Ran a masked `psql` session under a PTY (`pty_backend: node-pty`), digesting the
executable (`executable_sha256: 5fbf1d65…`) and frames into Evidence
`ev_bcb1d445…`. Captured terminal, verbatim:

```
current_user
support_m
(1 row)
id|ssn|email
8|XXX-XX-4321|ze******@ex******.com
(1 row)
id|name
(0 rows)
```

The SSN-equality probe (third `-c`) returned `(0 rows)`; no raw SSN or email
appears in the capture. **Confirmed runtime** observation of masking at the
terminal level — a tamper-evident, nicely-packaged version of what the scenario
harness already measures across 47 cases.

**Bottom line for REA:** two reproducible wins (artifact identity; process
capture), both of which standard tools / our own harness already cover; its
headline capability (decompiling a compiled extension) was unavailable here and
contributed nothing to the one real finding (A), which came from reading the
Rust source. No elapsed-time comparison was benchmarked, so none is claimed.
