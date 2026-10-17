# Privacy accounting for analyst aggregates: design proposal

| | |
|---|---|
| **Status** | Proposal under review. Only decision D11 is implemented: noisy aggregates are refused in production. The accounting design itself is **not** implemented. |
| **Scope** | The `aggregate` policy action: noisy `SUM`/`AVG`/`COUNT` over protected numeric columns, the ε budget, small-group suppression. |
| **Out of scope** | Masking actions (partial, HMAC, redact), the threat engine, the deployment profile. |
| **Date** | 2026-10-17, against commit `1c811c1` on `claude/zealous-bell-me62fn`. |

## 0. Summary

MaskGuard adds Laplace noise to analyst aggregates and keeps a per-user daily ε budget in memory. Reading the code
and probing it on the synthetic demo data (§1) shows the current accounting **does not support the claims made
for it**. The README says analysts "can't work out any one person's value". The submitted application says
"differentially private averages". Ten specific gaps stand between today's code and any formal statement. Three
are confirmed on the running code and can make a single release, or a single day's budget, leak more than the ε
charged:

- **Join fan-out.** A join accepted with sensitivity 1,000,000 when one account appears in 4 joined rows: up to
  4× the stated privacy loss for that query.
- **`ORDER BY` an aggregate alias.** The database sorts on the true protected sums before noise is added.
- **Budget scope.** Budgets reset every UTC day and are independent per analyst account, so total loss has no
  bound.

**Recommendation (for review):**

1. **Privacy model.** Protect the *values* of protected numeric attributes, at the level of the **customer**
   (the person), under a *replace-one-customer* neighbouring relation. Row existence and non-protected attributes
   are explicitly *not* protected, because the analyst role can already see them row by row.
2. **Budget.** One **lifetime ε budget per dataset**, shared by all analysts and all instances, with optional
   per-analyst quotas inside it.
3. **Accountant.** Charge before execution and never refund. The charge is an atomic conditional `UPDATE` in a
   **PostgreSQL state database** separate from the protected data, with idempotent replays. Every charge is also
   written to **independent recovery evidence** that can't be rolled back with the ledger (§9.6). If no trustworthy
   spending total can be established, aggregates stay off.
4. **Mechanism fixes before any claim:** per-customer contribution bounding, join and ordering restrictions,
   sensitivities matched to the neighbouring relation, an exact discrete noise sampler, and noisy (not exact)
   small-group thresholds.

Experiments in this plan can find violations. They cannot prove a guarantee. The claim at the end must rest on a
written derivation reviewed by someone with differential-privacy expertise (§13).

## 0.1 Decision gate (2026-10-17)

| Decision | Status | Record |
|---|---|---|
| **D11**: what happens before the fix | **Decided, implemented** | Production refuses any query that would release a noisy aggregate. The refusal happens before any budget is charged or data is read, and is audited. Masking, tokens, row filters and every other role are unchanged (`Gateway.allow_dp`, set false by `config.build` in production; `tests/test_production.py::test_production_refuses_noisy_aggregates_but_keeps_masking`). The feature returns to production only when §15 is met **and** an independent review (D12) signs off |
| **D2** (and D1): what is protected | **Decided** | Option B (§3): each **customer's** protected numeric values, under replace-one-customer. **Limitation, to be stated in every product claim:** membership and row existence are *not* protected, and neither are non-protected attributes |
| **D3**: budget scope | **Decided** | One budget per dataset, shared by all analysts, processes and servers, **enforced atomically** (§9). It needs a configured dataset identity, the declared privacy unit and contribution bounds, and defined behaviour for dataset changes and resets (§9.5). Per-analyst quotas inside it remain optional (open) |
| **D4/D5**: total budget, period, per-query charge | **Deferred to the data owner** | Set only after sensitivity, composition and the analyst workload have been reviewed. ε = 0.5 per query is a **candidate**, not a validated default. A lifetime cap is the conservative option, but it is only safe if the reset hazards in §9.5 are handled. Lifetime vs. renewing stays open until then |
| D6–D10, D12, D13, D14 | Open | §16 |

**Done** (as of `731cf01`): the known vulnerabilities are reproduced (`tests/test_dp_findings.py`, strict `xfail`,
with controls); production aggregates are disabled (D11), with a boundary test covering both the refusal and the
unaffected masking; privacy claims are corrected (README, ARCHITECTURE, EVALUATION, ROADMAP, DEPLOYMENT, generated
PIA).

**Gate before Phase 1:**

| Gate | Required before Phase 1 | Status |
|---|---|---|
| D4/D5 | The data owner approves the total privacy budget and the per-query charging policy | Open |
| D12 | An independent reviewer approves the privacy model and composition assumptions | Open |
| D13 | The recovery mechanism and its trust assumptions (§9.6, T1–T7) are selected | Open |
| D14 | The global recovery and fencing mechanism (§9.7, G1–G8, I2) is selected, and its race tests are specified | Open |
| Recovery tests | Rollback, concurrent charges, partial writes, retries, evidence loss and multi-gateway recovery races are tested (§13 items 11 and 13) | Open: specified, not yet runnable (no accountant exists) |
| D11 | Production aggregate queries stay disabled until every gate above passes | **In force** |

This document is a **specification, not a proof**. Synthetic probes and the tests in `tests/test_dp_findings.py` show
particular failures; passing tests will not establish differential privacy. The accountant, sensitivity calculations,
noise distribution, composition rules and query semantics all need independent review (§13, D12).

## 1. What the code does today, and what's wrong with it

### 1.1 Mechanism (as implemented)

- **Eligibility.** A column with action `aggregate` may appear only as `SUM(col)`, `AVG(col)` or `COUNT(col)`,
  directly in the top-level `SELECT` list of a single-`SELECT` query (`rewriter._dp_eligible`). Any other use leaves
  the column redacted, which fails closed.
- **Clipping.** Each row's value is clipped to `[lo, hi]` inside the masked view (`rewriter._mask_expr`). Bounds
  are per table and column since `f57a5ff`.
- **Noise.** Laplace with scale `sensitivity/ε`, where `sensitivity = max(|lo|, |hi|)` for SUM and 1 for COUNT.
  AVG is a noisy SUM (ε/2) over a noisy COUNT (ε/2), clamped to `[lo, hi]` (`dp.apply_noise`).
- **Charge.** `ε_per_query × number of protected outputs`, charged **before** execution, never refunded
  (`gateway._query`). The cost is fixed by the policy, so it doesn't depend on the data.
- **Budget.** `PrivacyLedger`: an in-memory dictionary keyed by `(user, UTC date)`, default 10 per day.
- **Suppression.** Analyst aggregates get `HAVING COUNT(*) >= 5` on the **true** count (`_apply_group_floor`).

What is already right and should be kept: costs fixed in advance and charged before data is touched (this closes
the budget covert channel described by Haeberlen et al. [12]); no refunds; correct ε/2 + ε/2 split for AVG; any
other use of a protected column (in `WHERE`, `HAVING`, `GROUP BY`, a direct `ORDER BY SUM(col)`) gets no noisy
release and the column stays redacted, so filters and ordering only ever see the redacted value; qualified column
lineage; ambiguous references get no release.

### 1.2 Findings

Evidence labels: **Confirmed** means observed on the running code. **Source** means read in the code and not
exercised. The probes ran against the seeded synthetic demo database in a scratch directory; queries are below
so they can be rerun.

| # | Finding | Evidence | Effect |
|---|---|---|---|
| F1 | **Join fan-out understates sensitivity.** `SELECT SUM(a.balance) FROM accounts a JOIN support_tickets t ON t.user_id = a.user_id` is accepted with sensitivity 1,000,000, but account 11 appears in 4 joined rows | Confirmed (plan and data) | That account can move the SUM by 4× the bound. Laplace calibrated to 1× gives up to **4ε** of loss for that query |
| F2 | **`ORDER BY` alias or position of a protected aggregate.** `… GROUP BY status ORDER BY s DESC` and `ORDER BY 2 DESC LIMIT 1` get a DP plan, and the database sorts on the true sums | Confirmed (plan: `ORDER BY s DESC` runs before noise) | Row order, and with `LIMIT` which group is returned, is a deterministic function of the true protected values. Not DP at any ε. (`ORDER BY SUM(balance)` written directly gets no DP plan and sees only the redacted column.) |
| F3 | **Budget renews every UTC day** | Confirmed (`remaining` 9.5 today, 10.0 tomorrow) | Total loss grows without limit over time. The same criticism was made of renewing budgets in deployed systems [15] |
| F4 | **Budget per analyst account** | Confirmed (a second analyst starts at 10.0) | Two analysts, or one person with two accounts, double the loss about the same customers. The protected party is the customer, not the analyst |
| F5 | **Budget in memory** | Source (`defaultdict` in `dp.py`) | A restart or a second instance starts with a full budget |
| F6 | **Clipping per row, not per person.** The schema allows several accounts per customer (`accounts.user_id`) | Source (demo data has one account per customer, so not observable there) | A customer with *k* accounts influences a SUM by *k*× the bound: the guarantee holds per account at best |
| F7 | **Sensitivity formula doesn't match a stated neighbouring relation.** `max(\|lo\|,\|hi\|)` is the add/remove-one-row sensitivity. If counts and row existence are public (F8), the relevant relation is replace-one, whose SUM sensitivity is `hi − lo` | Source | Equal for today's `[0, 10⁶]` bounds; **under-noised by up to 2×** for bounds that straddle zero (e.g. `[-10⁶, 10⁶]`) |
| F8 | **Exact `COUNT(*)` released next to noisy aggregates.** `SELECT status, avg(balance), count(*) … GROUP BY status` returned 150/150, equal to the true counts, and only the AVG was charged | Confirmed | Consistent only with a model where row existence is public. Under any membership-protecting model it voids the guarantee (cf. exact statistics plus correlations, [14]) |
| F9 | **Group floor on true counts** (`HAVING COUNT(*) >= 5` before noise) | Confirmed (rewritten SQL) | Same dependency as F8: harmless if counts are public, a leak if they aren't (§7) |
| F10 | **Floating-point Laplace sampler** (`random()` → `log`) | Source | The class of sampler shown by Mironov [10] to leak the input through gaps in attainable doubles |

**Reproduction status.** F1, F2, F4 and F6 are executable tests in `tests/test_dp_findings.py`, written to assert
the *required* behaviour and marked strict `xfail`. They fail on the code at `51f6826` (whose `src/` is identical to
`1c811c1`), and will fail the build as soon as a fix makes them pass, until the marker is removed. Measured with a
neighbouring-dataset harness (exact query on *D* and on *D′* = one customer's values replaced, noise excluded):

| Finding | Measured on the committed code |
|---|---|
| F6 | One customer with two accounts moved `SUM(balance)` by **2,000,000**; noise calibrated to 1,000,000 |
| F1 | One customer with four joined tickets moved it by **4,000,000**; noise calibrated to 1,000,000 |
| F2 | `ORDER BY s`, `ORDER BY 2` and `ORDER BY 2 … LIMIT 1` all produce a noisy release whose SQL sorts on true values |
| F4 | After one analyst spends 6 of 10, a second analyst still has 10 |

A control test (customers with one account each, no join) stays within the declared sensitivity, so the harness
isn't vacuous. F3 (daily renewal) is not encoded as a test, because the period is still open (D4). F5, F7, F9 and F10
are source-level findings.

The probe queries:

```sql
-- F1  (analyst)  plan sensitivity vs fan-out
SELECT SUM(a.balance) AS s FROM accounts a JOIN support_tickets t ON t.user_id = a.user_id;
--     owner check: SELECT a.id, count(t.id) FROM accounts a JOIN support_tickets t ON t.user_id = a.user_id
--                  GROUP BY a.id ORDER BY 2 DESC LIMIT 1;            -> account 11, 4 rows
-- F2
SELECT status, SUM(balance) AS s FROM accounts GROUP BY status ORDER BY s DESC;
SELECT status, SUM(balance) AS s FROM accounts GROUP BY status ORDER BY 2 DESC LIMIT 1;
-- F8
SELECT status, avg(balance) AS a, count(*) AS n FROM accounts GROUP BY status ORDER BY status;
```

### 1.3 Does today's accounting support the claims? No.

Even ignoring F1/F2, the budget allows unbounded averaging. Take the differencing attack in `docs/EVALUATION.md` §5:
SUM over a set with and without the target, at ε = 0.5 and bound 10⁶. Each noisy SUM has Laplace scale
*b* = 2×10⁶, variance 2*b*². A difference of two has standard deviation 2*b* = 4×10⁶. Averaging *k* differences
gives 4×10⁶/√*k*. The daily budget of 10 buys 20 queries, so 10 differences a day. By a normal approximation, which
is a calculation and not a measurement:

| Budget used | *k* | Std. dev. of the estimate | ≈ Median abs. error |
|---|---|---|---|
| 1 day, 1 analyst | 10 | ₹12.6 lakh | ₹8.5 lakh (the evaluation measured ₹7 lakh) |
| 30 days | 300 | ₹2.3 lakh | ₹1.6 lakh |
| 1 year | 3,650 | ₹66,000 | ₹45,000 |
| 1 year, 5 analyst accounts | 18,250 | ₹30,000 | ₹20,000 |

Against the evaluation's mean balance of ₹4.45 lakh, a year of ordinary use reaches roughly 10% accuracy for a
targeted customer, and faster with more accounts. So "can't work out any one person's value" is not supported. The
honest current statement is the one `docs/ARCHITECTURE.md` already makes: noisy aggregates, **not yet** a formal DP
guarantee.

Claims corrected on 2026-10-17 after D2 and D11 (§0.1). Each now says "experimental, not a formal DP guarantee,
disabled in production":
- `README.md` §"What it does" item 5 and the role table;
- `docs/ARCHITECTURE.md`;
- `docs/EVALUATION.md` §5 (status note added; measurements unchanged);
- `docs/ROADMAP.md`;
- `docs/DEPLOYMENT.md`;
- the generated PIA (`pia.py`), which no longer lists DP as a "control in place".

`docs/APPLICATION_TalentAP.md` stays as the record of what was submitted.

## 2. Threat model

| Actor | Assumed capabilities | In scope? |
|---|---|---|
| **Analyst** (role `analyst`, possibly several accounts, possibly colluding with other analysts) | Chooses queries adaptively. Retries and runs requests concurrently. Sees every released output, response timing and remaining budget. Knows public and auxiliary information, including everything the analyst role can read row by row (row existence, HMAC tokens, non-protected columns) | **Yes**: the adversary DP is meant to bound |
| Support / auditor roles | See partial or redacted values, never noisy aggregates of protected numbers | Not DP-relevant (masking covers them) |
| Admin | Sees raw values by policy | No: trusted |
| Host or database administrator | Can read the protected DB, the state DB and secrets | No: outside the trust boundary (`docs/DEPLOYMENT.md`) |
| Network attacker | Covered by TLS (production profile) | Not here |

Assumptions: the analyst can't write to the state DB or the protected DB (enforced by the production profile and
the state DB's own credentials), can't read other analysts' responses unless they share them (and sharing is
assumed, since budgets are global), and can't choose ε or bounds (fixed by policy, changed only by admins).

Side channels in scope: **budget** (closed by data-independent costs [12]), **timing** (partly: query time
depends on data volume, not values, for these aggregates; documented residual), **errors** (refusals depend only on
the query text and ledger state, never on data), **output order** (F2).

## 3. Privacy unit and neighbouring relation

DP protects whatever the neighbouring relation says two datasets may differ in, and nothing else. NIST SP 800-226
[3] puts the unit of privacy at the base of its evaluation "pyramid". This is the most important decision in the
document.

| Option | Neighbouring datasets differ in | What it protects | What MaskGuard would have to change |
|---|---|---|---|
| **A. Account, replace-one** | The protected values of one account row | One account's balance | Little (fix F1–F5, F7, F10). But a customer with several accounts gets *k*× the loss (F6) |
| **B. Customer, replace-one** (*recommended*) | The protected values of every row belonging to one customer | One person's balances, totals, amounts | Declare the unit and its join path in policy; bound each customer's contribution (§6.1); everything in A |
| **C. Customer, add/remove** | Whether a customer is in the data at all | Membership as well as values | Everything in B, plus: no exact counts (F8), noisy group selection (§7), and **removing the analyst's row-level access to the protected population**, because that access already reveals membership |

**Why B.** The analyst role is designed to see rows: tokens, statuses, cities. C would break that role. A doesn't
match the subject of protection (people, not account rows). B gives a precise, defensible statement:

> For any customer, the noisy aggregates released to all analysts together over the lifetime of the dataset satisfy
> ε-differential privacy with respect to replacing that customer's protected numeric values with any other values in
> the declared bounds, given everything the analyst role can see row by row.

What B does **not** protect, stated in the product: that a customer exists, their non-protected attributes, and
population-level inferences such as correlations between public attributes and balances. DP never protects
against the last of these [2, 14].

**Identities across datasets.** The unit is declared in policy as a key plus a join path, e.g.
`privacy_unit: {key: users.id, paths: {accounts: user_id, support_tickets: user_id}}`. Every protected table must
have a path to the unit key, or its `aggregate` columns fail closed. Two protected tables about the same customers
share one budget scope (§4). A different database whose customers overlap with this one isn't linkable by MaskGuard.
Its budget is separate, and the residual is documented.

## 4. Release scope and budget period

| Dimension | Proposal | Reason |
|---|---|---|
| Across analysts | **One shared scope per dataset**, optional per-analyst quotas whose sum ≤ the scope cap | The loss is borne by the customer. Per-analyst budgets assume no collusion and no shared results, which a bank can't enforce |
| Across instances and replicas | Same scope, because one ledger serves every gateway instance | Replicas hold the same customers |
| Across tenants and datasets | One scope per `dataset_id` (configured, stable, not derived from a hostname) | Different populations |
| Across policy versions | **Same scope**; policy edits never reset spending (§11) | Otherwise a policy edit is a budget reset |
| Across data changes | Same scope; spending accumulates as balances change | A customer persists over time, and continual release composes across versions [16] |
| Over time | **Lifetime cap** per scope (recommended), optionally with a per-day *rate limit* that doesn't renew the cap | Renewing caps make total loss unbounded (F3, [15]) |

The ε value is a policy decision (§16). For orientation only, 10 per year per dataset across all analysts is
already far more than the per-query figures most deployments publish.

## 5. Composition

Pure ε-DP with the Laplace mechanism (or its discrete analogue, §8) [1, 2]. Each query's cost is fixed by the
policy before execution, so stopping at the cap is a valid privacy filter under adaptive query choice [5].

| Release | Sensitivity under option B (per customer, after contribution bounding §6.1) | Charge |
|---|---|---|
| `SUM(col)` | `hi − lo` (replace-one; today's code uses `max(\|lo\|,\|hi\|)`, F7) | ε_q |
| `COUNT(col)` | 0 if `col` is `NOT NULL` (row existence is public under B), so release exactly at no charge; otherwise `m` = the per-customer row cap (null ↔ value flips) | 0 or ε_q |
| `AVG(col)` | Under B the row count is public, so AVG = noisy SUM ÷ exact count. All of ε_q goes to the SUM (better utility than today's ε/2 + ε/2) | ε_q |
| Several protected outputs in one query | Sequential composition | Σ of their charges |
| `GROUP BY` on non-protected keys | Parallel composition holds *within one query* if each customer contributes to at most one group. If a customer can fall in up to *C* groups (e.g. two accounts with different statuses), the L1 sensitivity across groups is *C*× per group: either bound *C* by the contribution step or charge *C*·ε_q | ε_q or *C*·ε_q |
| Repeated or overlapping queries | Sequential composition, with no deduplication of "similar" queries | each charged |
| Exact replay of a released result (same idempotency key) | Post-processing of an output already paid for | 0 |
| Two protected tables about the same customers | Same scope, so charges add | Σ |

Parallel composition across *separate* queries over disjoint subsets is **not** used. Adaptive "parallel" queries
are subtler than they look, as Ebadi and Sands point out about PINQ [4].

## 6. Query semantics

### 6.1 Contribution bounding (fixes F1, F6)

Clip per **customer**, not per row. Following Wilson et al. [6], the rewriter would emit a first stage that
aggregates each customer's rows, then clips:

```sql
-- SELECT status, SUM(balance) FROM accounts GROUP BY status      (analyst, option B)
SELECT status, SUM(LEAST(GREATEST(unit_sum, :lo), :hi)) AS s
FROM (SELECT a.status, a.user_id, SUM(a.balance) AS unit_sum      -- one row per (group, customer)
      FROM (<masked view of accounts>) a GROUP BY a.status, a.user_id) per_unit
GROUP BY status
```

The per-group count of contributing customers then becomes the row count (public under B), and the number of
groups per customer is bounded by keeping at most *C* rows per `user_id` (`ROW_NUMBER() … PARTITION BY user_id`)
before the outer aggregate.

### 6.2 Joins (F1)

Proposed rule: a DP query may join the protected table only to tables reached through a **declared many-to-one key**
(e.g. `accounts.user_id → users.id`, where `users.id` is unique). This is checked against catalogue constraints at
startup, never assumed. Any join that can duplicate protected rows is refused. With 6.1 in place, duplication
before the per-customer stage is also neutralised, because the stage aggregates per customer anyway. The
restriction is defence in depth. Elastic sensitivity [9] handles general equi-joins, but it is a larger change
and is not proposed for the first version.

### 6.3 Ordering and limits (F2)

Refuse `ORDER BY` and `LIMIT`/`OFFSET` that refer to a protected output, whether by alias, position or expression.
If ordering is wanted, the gateway sorts **after** adding noise, which is post-processing.

### 6.4 Lineage, ambiguity, filters

Keep the current rules:
- column references resolve to `(alias, column)`, and ambiguous references get no release;
- a protected column used in `WHERE`, `HAVING`, `GROUP BY` or a join condition makes the query ineligible: there
  is no noisy release and the column is redacted, so membership in a group never depends on protected values.
  Proposed: refuse such queries outright with a clear message, rather than silently answering over redacted
  values.

Add: refuse `DISTINCT` and window functions over protected columns (not reachable today; keep it that way
explicitly).

### 6.5 Bounds

`[lo, hi]` are policy, chosen from domain knowledge and never from the data. Computing them from the data would
itself leak. The PIA should flag bounds whose `hi − lo` makes noise exceed typical values.

## 7. Small-group suppression

**Why thresholding true counts can disclose membership.** A rule "release group *g* only if its true count ≥ *k*"
is a deterministic function of the data. Take two neighbouring datasets under add/remove, one where *g* has *k*
members and one where it has *k* − 1. The group appears with probability 1 in the first and 0 in the second.
No finite ε covers that, regardless of how much noise the released values get. The same applies to group keys that
only appear because they exist in the data. Korolova et al. [8] and Wilson et al. [6] use noisy thresholds for this
reason, and Desfontaines et al. study the general partition-selection problem [7].

**Under option B** (row existence public) the true count is public too, so today's floor reveals nothing about
protected values. It is consistent with B, but it is a trap: it becomes a leak the moment the model moves towards C
or row-level access narrows.

| Approach | Privacy | Utility cost | Notes |
|---|---|---|---|
| Exact threshold (today) | Valid only under B | None | Must be removed if the model ever protects membership |
| **Noisy threshold**: release *g* iff `count + Lap(1/ε_t) ≥ τ`, with the noisy count reusable as the released COUNT | Pure ε_t-DP when group keys come from a public domain; (ε, δ)-DP via partition selection when keys come from the data [6, 7, 8] | Groups near τ dropped or kept at random; costs ε_t (or ε_t, δ) | Valid under A, B and C |
| **Public domain, no suppression**: groups come from a declared value list (e.g. `status ∈ {active, frozen}`), all released including empty ones | Pure ε-DP, no selection leak | Small groups get large *relative* error; needs declared domains | Best for low-cardinality keys |
| Threshold applied to the *noisy* released count (post-processing) | As the noisy count | Same as noisy threshold | Combine with either of the above |

**Recommendation:** public-domain release for declared low-cardinality keys, a noisy threshold for everything else,
and the exact floor removed from DP queries. The floor remains a utility default for non-DP aggregates.

## 8. Noise generation (F10)

Replace the floating-point sampler with an **exact discrete sampler**: discrete Laplace (geometric) noise on
integer-scaled values, using the exact sampling algorithms of Canonne, Kamath and Steinke [11]. Alternatively,
apply Mironov's snapping mitigation [10]. Release values at a fixed resolution (e.g. whole rupees). Randomness
comes from the OS CSPRNG (`secrets`). A seeded generator is allowed only in tests, and only behind a flag that
production startup refuses.

## 9. Persistence and concurrency

### 9.1 Requirements

1. A charge is durable before any data is read (charge-then-execute).
2. Total charges in a scope never exceed the cap, under any concurrency, any number of instances, retries, crashes
   or failover.
3. There are no refunds once a query may have touched data, so a refund can never depend on the data (e.g. a
   timeout).
4. Retries with the same idempotency key never double-release fresh noise and never double-charge.
5. If the accountant is unavailable, DP releases are refused (fail closed).

Note the deployment constraint: the gateway's account on the **protected** database is read-only (production
profile), so the ledger **must live in a separate state store** with its own writable credentials
(`MASKGUARD_STATE_DB`).

### 9.2 Options

| Option | Atomic check-and-charge | Durability, restarts | Multi-instance | Failover | Verdict |
|---|---|---|---|---|---|
| **PostgreSQL state DB**: conditional `UPDATE … WHERE spent + :c <= cap` plus an append-only charge table in one transaction | Yes. A single-row update under row lock; at READ COMMITTED, PostgreSQL re-checks the `WHERE` on the latest row version after waiting for the lock [18] | WAL with `synchronous_commit=on` | Yes (shared DB) | No lost commits with synchronous replication to a standby | **Recommended** |
| Redis: Lua check-and-`INCRBYFLOAT` | Yes (single-threaded script) | Only with AOF `appendfsync always` | Yes | **Replication is asynchronous.** Redis documents that `WAIT` doesn't make it strongly consistent, so acknowledged writes can be lost on failover [17]. A lost charge is a silent refund, which is a privacy failure | Acceptable only single-node with no automatic failover, which removes its HA advantage |
| SQLite or file with `fcntl` locks | Yes, on one host | Yes | **No** (one host only) | n/a | Development only |
| In-memory (today) | Per process | **No** | **No** | n/a | Tests only; production refuses it |

### 9.3 Data model (PostgreSQL state DB)

```sql
CREATE TABLE dp_scope (
  scope_id       text PRIMARY KEY,                       -- e.g. 'bank-prod:customers'
  dataset_id     text NOT NULL,                          -- configured, stable identity of the protected data
  privacy_unit   text NOT NULL,                          -- e.g. 'users.id'
  neighbour      text NOT NULL CHECK (neighbour IN ('replace_one', 'add_remove')),
  epsilon_cap    numeric(12,6) NOT NULL CHECK (epsilon_cap > 0),
  epsilon_spent  numeric(12,6) NOT NULL DEFAULT 0,
  delta_cap      numeric(24,20) NOT NULL DEFAULT 0,
  delta_spent    numeric(24,20) NOT NULL DEFAULT 0,
  created_at     timestamptz NOT NULL DEFAULT now(),
  closed_at      timestamptz,                            -- closed scopes accept no charges
  CHECK (epsilon_spent <= epsilon_cap AND delta_spent <= delta_cap)
);

CREATE TABLE dp_quota (                                  -- optional per-analyst share of a scope
  scope_id text REFERENCES dp_scope, principal text,
  epsilon_cap numeric(12,6) NOT NULL, epsilon_spent numeric(12,6) NOT NULL DEFAULT 0,
  PRIMARY KEY (scope_id, principal), CHECK (epsilon_spent <= epsilon_cap)
);

CREATE TABLE dp_charge (                                 -- append-only; only `state` changes, and only forwards
  charge_id         uuid PRIMARY KEY,                    -- generated by the gateway at planning time; also the evidence key
  scope_id          text NOT NULL REFERENCES dp_scope,
  request_key       text NOT NULL,                       -- idempotency key (client-supplied or request id)
  principal         text NOT NULL,
  role              text NOT NULL,
  epsilon           numeric(12,6) NOT NULL CHECK (epsilon > 0),
  delta             numeric(24,20) NOT NULL DEFAULT 0,
  mechanism         jsonb NOT NULL,                      -- ops, sensitivities, bounds, unit/C caps: enough to re-derive the cost
  query_fingerprint text NOT NULL,                       -- literals stripped, as in the audit log
  policy_version    text NOT NULL,
  instance_id       text NOT NULL,
  charged_at        timestamptz NOT NULL DEFAULT now(),
  state             text NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'evidenced', 'released', 'failed_after_charge', 'imported')),
  UNIQUE (scope_id, request_key)
);
-- every state counts towards epsilon_spent: a charge is never discarded or refunded once it exists

ALTER TABLE dp_scope
  ADD COLUMN recovery_state text NOT NULL DEFAULT 'reconciling'
    CHECK (recovery_state IN ('consistent', 'reconciling', 'suspect')),  -- refuse-only cache (§9.7 G2)
  ADD COLUMN cached_epoch bigint NOT NULL DEFAULT 0,      -- refuse-only cache; the evidence store is the epoch authority
  ADD COLUMN charge_counter bigint NOT NULL DEFAULT 0;    -- fencing-token source (§9.7 "The counter"); never authorises

ALTER TABLE dp_charge
  ADD COLUMN counter bigint NOT NULL,                     -- fencing token issued at reserve; gaps are allowed
  ADD COLUMN epoch bigint NOT NULL,                       -- authorised epoch read from the evidence store at step 2
  ADD COLUMN request_fingerprint text NOT NULL,           -- digest of query fingerprint + mechanism; binds the key
  ADD COLUMN privacy_policy_version text NOT NULL,        -- digest of unit, join paths, neighbour relation, ε policy
  ADD COLUMN contribution_policy_version text NOT NULL,   -- digest of bounds, per-unit row cap, C (groups per unit)
  ADD CONSTRAINT dp_charge_counter_unique UNIQUE (scope_id, counter);

CREATE TABLE dp_release (                                -- noisy outputs only (already public to the requester)
  scope_id text, request_key text, result jsonb NOT NULL,
  released_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  PRIMARY KEY (scope_id, request_key)
);
```

Invariant, checked at startup and by a periodic job: `epsilon_spent = Σ dp_charge.epsilon` per scope, over charges
in every state. A mismatch sets the scope to `suspect` and DP fails closed.

### 9.4 Transaction flow (crash-safe charge protocol)

Two durable records exist for every charge: the ledger row (in the state database) and the evidence record (in the
independent store, §9.6). The protocol's one safety property:

> **I1. No protected aggregate is computed until its charge is durable in both the ledger and the evidence store.**
> **I2. No protected aggregate is released unless, after its release record is durable, the epoch it was authorised
> in is still the newest epoch in the evidence store.**

I1 means every released output, and every query whose outcome is unknown, has an evidence record. The ledger can lose
rows (rollback, failover, restore); the evidence can't (§9.6 T3). Rebuilding upwards from the evidence therefore
never under-counts what was released. I2 makes recovery a boundary that releases can't cross (§9.7).

```
1  plan      rewrite + mechanism + cost; charge_id := new UUID (bound to scope_id + request_key)
             (no data touched; refusals here are data-independent)
2  epoch     list epochs/<scope>/ in the evidence store (strongly consistent) -> E := newest allocated epoch
               - auth/<scope>/<E> absent (recovery active) or store unreachable -> refuse
             (the ledger's recovery_state and cached_epoch may refuse earlier, but never approve: §9.7 G2)
3  reserve   BEGIN (state DB primary)
               UPDATE dp_scope SET epsilon_spent = epsilon_spent + :eps, charge_counter = charge_counter + 1
                 WHERE scope_id = :s AND closed_at IS NULL AND recovery_state = 'consistent'
                   AND epsilon_spent + :eps <= epsilon_cap
                 RETURNING charge_counter
                 - 0 rows -> ROLLBACK, refuse (budget exhausted, or scope not consistent)
               INSERT INTO dp_charge (charge_id, scope_id, request_key, request_fingerprint, epsilon, …,
                                      counter, epoch = E, state = 'pending')
                 ON CONFLICT (scope_id, request_key) DO NOTHING
                 - conflict -> ROLLBACK, go to "retry" below (no new charge, nothing executed)
               UPDATE dp_quota … (same pattern; fixed lock order scope -> quota)
             COMMIT (synchronous_commit = on)   -- from here the charge counts and is never refunded
4  evidence  create-if-absent  charges/<scope>/<counter, zero-padded> = the evidence record (§9.6)
               - created, or already present with identical content -> continue
               - present for a DIFFERENT charge_id                  -> the ledger reissued a used counter
                                                                       (rollback): start recovery (§9.7), refuse
               - error or timeout (outcome unknown)                 -> refuse; the charge stays 'pending' and
                                                                       counted (the reaper finishes it)
5  fence     list charges/<scope>/ after <counter> (strongly consistent); each slot found must name a charge_id
             the ledger has
               - all present (ordinary newer concurrent charges)    -> continue
               - any missing (an evidenced charge lost by rollback) -> start recovery (§9.7), refuse
6  confirm   UPDATE dp_charge SET state = 'evidenced' WHERE charge_id = :c AND state = 'pending' RETURNING …
7  execute   only if step 6 returned the row; read-only query on the protected DB; add noise; hold the result
8  release   create-if-absent releases/<scope>/<charge_id> = {charge_id, epoch E, result digest}
             THEN list epochs/<scope>/ after E (strongly consistent)
               - none newer          -> the release is decided: continue to 9
               - any newer           -> do NOT send; refuse. The charge and the release record stay counted
               - store unreachable   -> do NOT send; refuse
9  respond   send the result; INSERT dp_release (local cache); UPDATE dp_charge SET state = 'released' (best effort)
```

**Retry with the same idempotency key** (same `scope_id`, `request_key`): the existing charge is found at step 3.
If the retry's `request_fingerprint` differs (the key is being reused for a different query), it is refused as a key
conflict, with no charge. Otherwise:
- if the charge is still `pending`, steps 4–6 are completed for **that** charge (create-if-absent rules out a
  duplicate evidence record);
- a stored result is returned only if its release record exists **and** its epoch is still the newest authorised
  epoch (a fresh step-8 check). A result decided before a recovery is never re-sent after it;
- otherwise the response is 409, "already charged; resubmit with a new key".

A retry never executes the query a second time, never creates a second charge, and never runs an uncharged query.
A new key is a new charge.

**Reaper.** A periodic job completes steps 4–6 for `pending` charges older than a timeout. It never voids or refunds
a charge, never executes a query and never releases. If a pending charge's counter collides at step 4, the
reconciler gives it a fresh counter (§9.7); it is never discarded.

| Crash or pause point | Ledger | Evidence | Outcome | Charge |
|---|---|---|---|---|
| Before step 3 commits | — | — | Nothing happened | None |
| After 3, before 4 | `pending` | no slot | Reaper or same-key retry writes the slot, then confirms. Never executed | Kept |
| During 4 (store wrote it, reply lost) | `pending` | slot | Create-if-absent reports "present, identical"; confirm | Kept |
| After 4, before 6 | `pending` | slot | As above | Kept |
| After 6 or 7, before 8 (including a long pause across a recovery) | `evidenced` | slot | Step 8 finds the newer epoch: not sent | Kept |
| After the step-8 check, before 9 | `evidenced` | slot + release record | The release was decided before any newer epoch existed (I2); recovery counts it | Kept |
| After 9 | `released` | slot + release record | Same-key retry returns the result only while its epoch is current | Kept |
| Ledger commit of step 3 lost in a failover (asynchronous standby) | absent | none | Step 4 never ran on the new primary, so the query was never executed | n/a |
| Ledger commit lost **after** step 4 wrote the slot | absent | slot | The next charge collides at 4 or finds the slot at 5: recovery imports it | Kept (imported) |

- **Concurrency across servers.** There is one serialisation point for budget: the conditional `UPDATE` of the
  scope row on the single state-database primary that every gateway uses. At READ COMMITTED, PostgreSQL
  re-evaluates the `WHERE` against the latest row version after waiting for the row lock [18]. So two gateways
  can't both approve against the same remaining budget **of a ledger that is current**. Whether the ledger *is*
  current, and whether service may run at all, is established by the evidence store (§9.7), not by the ledger.
- **Step 7 fails** (error, timeout). `state = 'failed_after_charge'`, with no refund, because whether a query times
  out can depend on data.
- **Step 9's bookkeeping fails.** The result was already sent. A same-key retry finds the release record and applies
  the epoch rule above.

### 9.5 Things that must never reset the budget

A lifetime (or any long-period) budget is only as strong as its weakest recovery procedure. The rule for every case
below: **spending about a population never goes down while the same people remain in scope.** Each case has an
acceptance test (§13 item 11).

| Case | Hazard | Rule |
|---|---|---|
| **Dataset identity** | A new connection URL, host, replica or database rebuild looks like a "new" dataset and gets a fresh scope | The scope is keyed by a configured `dataset_id`, never derived from the URL, host or database OID. `maskguard db-install` writes the `dataset_id` into a marker table in the protected database (owner account). The gateway reads the marker at startup, and refuses DP if it is missing or differs from the configured scope |
| **Dataset replacement or migration** (same customers, new database) | Treated as new data, so the budget restarts | The marker and `dataset_id` move with the data, so the same scope continues. A new scope over the same population needs an explicit admin action, a reason, a privacy-officer sign-off and a conservative carry-over of the old spending (§11) |
| **Customer deletion** | Deleting customers "frees" budget, or a re-onboarded customer starts fresh | `epsilon_spent` never decreases: no per-customer refunds. Deleted customers' past exposure stays recorded, and a returning customer is covered by the same scope |
| **Protected-database backup restore** | Older data plus an unchanged ledger | Safe: the ledger is separate and keeps every charge. The restore must keep the marker table |
| **Ledger restore, point-in-time recovery or failover** | `epsilon_spent` rolls back, which is a silent refund | Detected against the **independent recovery evidence** (§9.6), never against the local audit log alone. A change in the state database's identity or timeline puts every scope into `reconciling`; DP stays off until reconciliation (§9.6) completes |
| **Ledger lost** (empty state database) | Scopes recreated at zero | Scopes are never created implicitly. `maskguard dp-scope create` imports every evidence record for that `dataset_id` first, and is refused if the evidence is unreachable |
| **Ledger and audit log both lost or rolled back together** | No local record of past exposure | Rebuilt from the recovery evidence (§9.6). If the evidence is also unavailable, DP stays off until a privacy officer retires the dataset or opens a new scope with a documented conservative carry-over |
| **Clock** | A wrong gateway clock moves period boundaries | Lifetime scopes don't use dates. If renewing periods are chosen (D4), boundaries come from the state database's clock, never the gateway's |

### 9.6 Recovery evidence and trust model

**Why the audit log is not enough.** An earlier version of §9.5 detected ledger rollbacks by comparing against the
hash-chained audit log. That fails in the most likely incident, a restore from backup. The audit log lives on the
gateway host, usually in the same backup set and under the same administrators as the ledger. If both are restored
to the same older point they agree, and the check passes while the lifetime budget is silently exceeded. The hash
chain doesn't close the gap: it proves the records that exist were not altered, but not that later records ever
existed. A chain cut back to an older, consistent end still verifies.

**Requirements.** Whatever mechanism is chosen (D13) must provide:

| # | Requirement |
|---|---|
| R1 | **Independence.** The evidence lives in a store whose writes, deletions and restores are controlled by a different administrative and backup domain from the ledger, the audit log and the gateway host. Anyone able to restore the ledger must not be able to roll the evidence back. A second database under the same administrators or the same backup procedure does **not** qualify |
| R2 | **One immutable record per charge.** It is stored under the ledger-issued counter (the fencing token, §9.7) and identified by the `charge_id` it contains. The store enforces create-if-absent: a second write under the same key can't replace the first. The gateway's credential can create, read and list, but not overwrite or delete. Counters are unique, but **gaps are legitimate** after crashes and are never a failure condition. Reconciliation matches records by `charge_id` |
| R3 | **Durable before computation (I1).** The query runs only after the charge is recorded in the ledger and confirmed in the evidence (§9.4). If the evidence write fails or its outcome is unknown, the query is refused and the charge stays counted |
| R4 | **Set-based reconciliation.** At startup, periodically, and whenever the state database's identity or timeline changes, each scope's ledger charges are compared with its evidence records **by `charge_id`** (below). DP is allowed only while the scope is `consistent` |
| R5 | **Upward-only, no reset.** Reconciliation only adds charges and never removes one. Nothing lowers spending, and there is no reset command. A new scope for a `dataset_id` with evidence history first imports that history and needs a privacy-officer sign-off |
| R6 | **Authority over dataset history.** Scope creation, dataset replacement and protected-database restores all consult the evidence store, so none of them can produce a fresh budget for data that has been queried before |
| R7 | **Loss of the evidence itself** keeps DP off until a privacy officer decides. It is never recreated automatically |

**Fail closed.** If MaskGuard cannot establish a trustworthy spending total, protected aggregates stay unavailable.
Masking and every other function continue.

**What each record binds.** Restoring the amount spent isn't enough; recovery must also preserve the context that
made the charge valid. Each evidence record contains:
- `charge_id`, `counter`, `epoch`, `dataset_id`, `scope_id`;
- `request_key` and `request_fingerprint`;
- the pseudonymous principal;
- ε, δ and `charged_at`;
- the **privacy-policy version**: a digest of the privacy unit and its join paths, the neighbouring relation and the
  ε policy;
- the **contribution-bound policy version**: a digest of the clipping bounds, the per-unit row cap and *C* (groups
  per unit);
- the **query-policy version** (`policy_version`);
- the full mechanism parameters (operations, sensitivities, noise scales).

Recovery validates every imported record:
- its `dataset_id` and `scope_id` must match the scope;
- its recorded ε must be at least the cost recomputed from its mechanism under its own privacy-policy and
  contribution-bound versions.

A mismatch, or an unknown version, still counts the charge (the larger amount). It also marks the scope `suspect`
for review, so nothing is ever dropped because its context looks odd.

**Reconciliation: what "evidence is ahead" means operationally.** For each scope, with *L* the ledger's charges and
*E* the evidence records:

| Observation | Meaning | Action |
|---|---|---|
| A charge in *E* but not in *L* | The ledger lost rows (rollback, restore, failover): **evidence is ahead** | Scope → `reconciling`, DP refused. Import each missing charge as `imported` with the evidence's ε and δ, recompute `epsilon_spent`, re-verify, then `consistent` |
| `pending` in *L*, absent from *E* | A charge in flight or interrupted after step 3 | Normal: the reaper or a same-key retry completes it. The query was not executed (I1) |
| `evidenced`, `released` or `failed_after_charge` in *L*, absent from *E* | Evidence lost or tampered with | Scope → `suspect`, DP refused until a privacy officer decides (R7). Never "repaired" by deleting the ledger row |
| Same `charge_id` in both, contents differ | Tampering or a bug | Scope → `suspect` |
| Ledger total ≠ Σ of its charges | Ledger corruption | Scope → `suspect` |
| A slot's counter is reissued for a different `charge_id` (step 4), or a slot above a new counter has no ledger row (step 5) | The ledger was rolled back after charges were evidenced | Recovery (§9.7); the lost charges are imported from their slots |
| The ledger's `epoch` is below the latest authorisation record in the evidence store | The ledger was restored from before a completed recovery | Recovery (§9.7) |

Every outcome either adds charges or stops DP. None discards or refunds an uncertain charge. The trusted spending
total is the sum over the **union** of *L* and *E* by `charge_id`.

**Trust assumptions for the independent store.** The guarantees above are only as strong as these. Each must hold
for the deployment, and the data owner must accept the residual risks explicitly:

| # | Assumption | How it is checked |
|---|---|---|
| T1 | **Separate administrative authority.** No person or role that can restore, modify or administer the ledger, the audit log or the gateway hosts can also delete, overwrite or shorten retention in the evidence store. "A different account" is not enough if the same privileged operator controls both. Break-glass access to the evidence store needs two-person approval from its owning team | Organisational access review at D13 and periodically; not checkable by MaskGuard |
| T2 | **Least-privilege credentials.** The gateway holds a create-and-read credential, scoped to its dataset's prefix, that can't overwrite, delete, change retention or holds, or change store configuration. It is distinct from every ledger credential | At startup: attempting to overwrite or delete a dedicated canary record must be refused, otherwise DP stays off |
| T3 | **Store-enforced retention.** Immutability that no principal, including the store's own administrators, can remove or shorten before expiry (e.g. "compliance"-style retention in object stores), with retention ≥ the dataset's lifetime plus a margin | At startup: read the retention configuration (where the store exposes it) and the canary's retention; refuse DP if it is weaker |
| T4 | **Independent backup and recovery.** The store's durability comes from its own replication. Its restore procedures can't remove or replace existing records, and are separate from the ledger's backups | Reviewed at D13; documented runbook |
| T5 | **Consistency.** Create-if-absent is atomic, and after a successful write, reads and listings return the record (read-after-write) | Store documentation, plus a concurrent create-if-absent test (§13) |
| T6 | **Availability is a cost, not a weakness.** If the store is unreachable, DP is refused | Failure tests (§13) |
| T7 | **Residual risks, accepted or not by the data owner.** Anyone with authority over both domains (an organisation-wide super-administrator, the platform provider); collusion between the two teams; retention misconfigured at creation; provider data loss. **If one operator can control both systems, this design gives no rollback guarantee**, and the product must not claim one | Recorded with D13 |

**Candidate mechanisms** (selection at design review, D13):

| | Mechanism | Strengths | Costs and risks |
|---|---|---|---|
| M1 | **Write-once object storage with store-enforced retention**, under separate administrators (T1–T4); one immutable object per `charge_id`, created with a conditional create-if-absent write before computation (I1) | Strong rollback resistance; directly fits the per-charge protocol; no allowance needed | One remote write per charge (latency); the store's availability gates DP; separation must be organisational, not only an account boundary (T1) |
| M2 | **Signed checkpoints to an external append-only log** run by another party (or a transparency log), with the signing key in a KMS or HSM the ledger administrators can't use; each checkpoint covers the set of `charge_id`s since the last one | Cheaper than per-charge writes if checkpoints are batched | Batching weakens I1: charges after the last checkpoint have no independent evidence. Recovery must add a conservative allowance of *N* × the largest per-query charge for up to *N* uncheckpointed charges, which burns budget. Key management joins the trust base |
| M3 | **Replicated ledger in a second system operated by another team** (e.g. the privacy office) with its own backup policy | Uses familiar tooling | Acceptable only if R1 genuinely holds. Same-domain replicas and shared backups do not count |
| M4 | Hardware monotonic counters (e.g. TPM NV counters) | Rollback-resistant on one host | Doesn't fit multiple instances or host replacement; listed for completeness |

Candidate recommendation for review: **M1 with synchronous per-charge writes**. It needs no staleness allowance and
satisfies R3 directly. M2 is the fallback if per-charge latency is unacceptable. The choice depends on the
infrastructure the deploying organisation actually runs and on who administers it, so it is a review decision, not
something this document can settle.

### 9.7 Global recovery and fencing

**The race to rule out.** Gateway A authorises a query, then pauses. Gateway B detects a rollback and starts
recovery. A resumes and sends its result. A database restored from an old backup makes this worse, because it also
restores its own old `recovery_state = 'consistent'` and its old epoch. A store whose state may have been rolled
back cannot certify that its own state is current. Recovery is a safety boundary only if every gateway is fenced
**at the moment of release** by something a rollback can't undo.

**Required properties:**

| # | Property |
|---|---|
| G1 | **Fail closed, globally.** No gateway releases a protected aggregate while the evidence store is unreachable, its newest epoch can't be established, the newest epoch has no authorisation (recovery active), or ledger and evidence disagree (which always starts recovery) |
| G2 | **No approval from local state.** Caches, the ledger's `recovery_state` and `cached_epoch` may only *refuse*. Approval always comes from per-charge checks against the evidence store |
| G3 | **The evidence store is the epoch authority.** Epochs are allocated only there, atomically, each strictly greater than every epoch ever allocated for the scope. A restored ledger can't reinstate an older epoch, because validity is never read from the ledger |
| G4 | **Releases are fenced at release time (I2).** A result computed under epoch *E* is sent only if, after its release record is durable, no epoch newer than *E* exists. A check made before a pause is never enough on its own |
| G5 | **No computation against a rolled-back ledger.** A ledger that lost an evidenced charge is detected before any further aggregate is computed (counter fencing, below) |
| G6 | **Resume only after verification.** A new epoch is authorised only after reconciliation is verified. An authorisation for a superseded epoch has no effect |
| G7 | **One reconciler per epoch.** Two recovery attempts can't claim the same epoch, and a stale reconciler can't revive service in an epoch that has been superseded |
| G8 | **Recovery counts everything that was decided.** Every charge with a slot and every release record is counted. Stragglers from an old epoch can add charges, but can never release |

**Epochs and authorisation (G1, G3, G6, G7).** All in the evidence store, under the scope's prefix:
- `epochs/<E>` (zero-padded): created only by recovery. **Allocation** means listing `epochs/` (strongly
  consistent), taking the newest *E*, and creating `epochs/<E+1>` with create-if-absent.
  - Of two concurrent attempts, exactly one create succeeds. The loser stops: recovery is already in progress.
  - Because every allocation is "newest plus one" over a consistent listing and is never deleted (T3), each epoch is
    strictly greater than all earlier ones.
- `auth/<E>`: written once, by the reconciler that allocated *E*, only after verification.
- **Service may run** only when `auth/<newest E>` exists. A stale reconciler that writes `auth/<E>` after `E+1` has
  been allocated changes nothing, because *E* is no longer the newest.
- Allocating a new epoch is therefore an instant, global stop: from that moment no gateway passes step 2 or step 8,
  whatever its own cache or its ledger says.

**The release fence (G4, I2).** Step 8 writes the release record **first**, then lists `epochs/` after *E*. The
release is *decided* at that listing:
- If recovery allocated a newer epoch before it, the gateway doesn't send, which covers the paused-gateway race.
- If recovery allocates one after it, the release precedes recovery in the store's order, and recovery counts its
  record (G8).

Bytes may leave the gateway later, but no new decision is made then. This relies on the store's strongly consistent
listing (T5), and on gateways running honest code. A compromised gateway holds plaintext results, and no protocol
can stop it sending them; that case is outside the threat model (§2).

**The counter (G5).** What it is, and what it isn't:
- **What it represents.** A token issued by the ledger and unique per charge for the life of the scope. Its binding
  to one `charge_id` is recorded once in the evidence store (`charges/<counter>`, create-if-absent) and can never
  change.
- **How it advances.** By exactly one inside the step-3 transaction, together with the budget update. A refused or
  rolled-back reserve consumes nothing; gaps appear only when a crash falls between step 3's commit and step 4.
  Recovery raises it above every slot it has seen.
- **It never authorises.** Its only effect is to *trigger* refusal and recovery. The authority on what was spent is
  the set of evidence records (matched by `charge_id`). The authority on whether service may run is the epoch and
  authorisation records.
- **Why restoring either database can't make an old counter look current.**
  - Restoring the ledger lowers `charge_counter`. Every value it then reissues is either already bound to another
    charge (step 4 refuses) or lies below a bound value whose charge the restored ledger lacks (step 5 finds it).
    That happens before anything is computed.
  - The evidence store can't be restored to an earlier state (T3, T4). If that assumption fails, T7 applies and no
    rollback guarantee is claimed.
  - A restore that lost no evidenced charge reissues unbound values and passes. That is correct: nothing that was
    evidenced, and so nothing that was released, is missing.
- **It doesn't replace the evidence.** The counter checks are detectors. Reconciliation always works from the
  evidence records themselves.

**Recovery procedure:**
1. **Allocate** `epochs/<E+1>`. This stops service everywhere (G1). If the create fails, another recovery is
   running, so stop.
2. **Mark the ledger** `recovery_state = 'reconciling'`, `cached_epoch = E+1`. This is a refuse-only courtesy, not
   relied on.
3. **Reconcile** from a full, consistent listing of `charges/` and `releases/` (§9.6 table):
   - import every evidence-only charge;
   - give pending charges whose counter collides a fresh counter, then evidence them;
   - raise `charge_counter` above every slot;
   - validate context bindings;
   - compute the union total.
4. **Authorise** with create-if-absent `auth/<E+1>` = {epoch, union total, charge-set digest, counter high-water
   mark, ledger identity, verifier}. Written only if the reconcile step verified everything; otherwise service stays off.
5. **Set the ledger cache** back to `consistent`. Gateways resume because step 2 now finds `auth/<E+1>`, not because
   of this flag.

If the reconciler dies at any point, the newest epoch has no authorisation, so service stays off until a new recovery
allocates `E+2`.

Stragglers from epoch *E* may still write slots (counted, G8) but can't pass step 8. Their late slots name charges
the ledger already has, and the periodic reconciliation matches them.

**What triggers recovery** (any gateway, any time):
- a collision at step 4 or a missing ledger row at step 5;
- a ledger total that doesn't match its charges;
- an evidence store unavailable for longer than a set limit;
- a change in the state database's identity or timeline;
- a ledger `cached_epoch` older than an authorised epoch.

Recovery itself is the only thing that can turn service back on.

**Alternatives for D14:**
- leases with fencing tokens from a linearizable coordination service, where the release step (8) presents the token
  and the service refuses stale ones;
- a single centralised release-approval service.

Either must still meet G1–G8, including fencing at release time. The candidate above needs no extra service, and per
charge costs:
- two creates (the slot and the release record);
- three consistent listings (the epoch at step 2, the fence at step 5, the epoch at step 8).

It depends on the store's create-if-absent and strongly consistent listing (T5).

**Charge flow.** The crash-safe protocol is in §9.4: the epoch check, then ledger intent, then the evidence slot,
then the fence, then confirmation, computation, and a release fence before anything is sent.

**Recovery from a known-good checkpoint** follows the §9.7 procedure: allocate a new epoch first (stopping service
everywhere), restore the ledger from the checkpoint, reconcile from the evidence, and authorise only after
verification. Any `suspect` outcome leaves service off (R4, R7).

## 10. Failure behaviour

| Situation | Behaviour |
|---|---|
| State DB unreachable or ledger invariant broken | DP queries refused (503, fail closed). Non-DP queries continue, since they consume no budget (open decision D9) |
| Recovery evidence unreachable, or the scope is `reconciling` or `suspect` | DP disabled until reconciliation (§9.6) reaches `consistent`; masking continues |
| Evidence write fails or its outcome is unknown during a charge | Query refused, nothing computed; the charge stays `pending` and counted, and the reaper completes it |
| Budget or quota exhausted | Refused at step 3, before data access. The message gives the remaining budget only, which depends on query history, not data |
| Charge committed, query fails or times out | Charge kept as `failed_after_charge`, no refund |
| Gateway crash after charge | Charge kept; same-key retry gets 409; never a free fresh release |
| Policy changes while a request is in flight | The request uses the plan and cost computed in step 1 and recorded in `dp_charge.policy_version` |
| Scope closed (e.g. dataset retired) | All charges refused |
| Production startup with an `aggregate` action but no state DB | Refuse to start, an extension of the production profile's checks (open decision D11 on the interim stance) |

## 11. Policy changes

- **ε per query, bounds, unit caps.** Apply to future queries only. Spending is never refunded or recomputed.
- **Raising `epsilon_cap`.** Treated as a weakening, like masking weakenings today. Admin only, reason and
  confirmation required, audited, and appended to a scope history. Lowering below `epsilon_spent` closes the scope.
- **Changing the privacy unit or neighbouring relation.** Creates a new scope only through an explicit migration
  that records both. A new scope over the same customers **does not** reset their exposure: the loss already
  recorded still applies. The migration must carry a reviewed conservative carry-over, because composition across
  different units isn't automatic.
- **`dataset_id`.** Configured once. Changing it is the same as the previous point.

## 12. Implementation designs compared

| | **Design 1: Ledger-in-place** | **Design 2: Unit-bounded DP layer** (*recommended*) | **Design 3: Delegate to a DP library or engine** |
|---|---|---|---|
| What changes | Persistent ledger (§9) plus targeted fixes: F2 (refuse ordering), F1 (refuse fan-out joins), F3–F5 (scope), F7, F10 | Everything in 1, plus per-customer contribution bounding (§6.1), public-domain or noisy-threshold groups (§7), AVG with public count, declared unit and paths | Route `aggregate` queries to an established DP library (e.g. OpenDP or Google's differential-privacy library) for noise and bounding; keep MaskGuard's rewriter and ledger |
| Supports | Option A (per account) only | Option B (per customer); a path to C | A or B, depending on the library's model |
| Effort | Small | Medium | Medium to large (integration, SQL subset mapping) |
| Assurance | Own derivations for a small mechanism | Own derivations for a larger mechanism | Relies on a reviewed library; MaskGuard still owns sensitivity of its SQL subset and the ledger |
| Main risk | Guarantee at the wrong unit (F6) | More code to get right | Dependency weight and mismatch between the library's model and MaskGuard's SQL rewrite |

**Recommendation: Design 2, with the noise primitives taken from a vetted library if the dependency is accepted
(D8).** Design 1 alone produces a correct statement about the wrong thing: account rows instead of people.

Explicit assumptions behind it:
1. Analysts keep row-level access to non-protected data, so option B is the right model (D2).
2. Protected numeric columns have meaningful public bounds.
3. Every protected table has a declared path to the customer key.
4. One PostgreSQL state database is available with synchronous replication if HA is required, **and** a recovery
   evidence store in a separate administrative and backup domain (§9.6 R1).
5. Analyst query rates are low enough for per-scope row serialisation.

## 13. Verification

**No experiment proves differential privacy.** Statistical tests can only find violations [13]. The guarantee
rests on items 1 and 2.

1. **Written derivation.** For each mechanism (SUM, COUNT, AVG, grouped release, noisy threshold), state the
   neighbouring relation, derive the sensitivity after contribution bounding, and cite the theorem used (Laplace
   or discrete Laplace mechanism [1, 2, 11]; sequential and parallel composition and filters [2, 5]; partition
   selection [7]).
2. **Independent review** of 1 and of the code paths that compute sensitivity and charge the ledger (D12).
3. **Eligibility tests.** F1, F2, F8 and F9 become regression tests that must be refused or handled: fan-out
   joins, `ORDER BY`/`LIMIT` on protected outputs by alias, position or expression, protected columns in
   `WHERE`/`HAVING`/`GROUP BY`/joins.
4. **Sensitivity property tests (Hypothesis).** For generated small datasets *D* and neighbours *D′* (replace one
   customer's values within bounds), check that the exact query output differs by at most the declared
   sensitivity. Brute force over many generated pairs and query shapes.
5. **Neighbouring-dataset statistical tests.** Run each mechanism many times on *D* and *D′*, and test whether any
   output event's probability ratio exceeds e^ε (in the style of Ding et al. [13]). Include **known-bad
   controls** (today's fan-out join, `ORDER BY s`, a deliberately under-noised mechanism) that the harness must
   flag. This demonstrates the test's power without claiming proof.
6. **Sampler tests.** Distribution goodness-of-fit against the exact discrete Laplace pmf. Check that the set of
   attainable outputs doesn't depend on the input (the Mironov class [10]).
7. **Ledger concurrency.** 200 concurrent charges against a cap that admits exactly *n*: exactly *n* succeed,
   `epsilon_spent = n·ε`, never above the cap. Repeat with three gateway processes.
8. **Crash and restart.** Kill the gateway between steps 3 and 4, 6 and 8, and 8 and 9. Check that the invariant
   holds and same-key retries behave per §9.4. Restart: spending persists.
9. **Failover**, if HA is in scope: promote the standby under load and confirm no committed charge is lost.
10. **Reproducible evaluation.** Extend `bench/eval_dp.py` to the full lifetime budget with several colluding
    analysts, and report the differencing-attack error as in §1.3. Seeds are used only in test mode.
11. **Reset-hazard, crash and restore tests** (§9.4–§9.6). Each must end with DP either enabled at the trusted total
    (the union of ledger and evidence charges) or disabled:

    | Scenario | Expected |
    |---|---|
    | Crash after steps 3, 4, 6, 7 and 8 (fault injection at each point) | Matches the crash table in §9.4; the charge is never lost or duplicated, and no query runs without both records |
    | Same-key retry at each of those crash points | Completes the existing charge; no second evidence record, no second charge, no execution |
    | Evidence write succeeds but the reply is lost (partial write) | Retry finds "present, identical" and confirms |
    | Two writers race to create the same `charge_id` | Exactly one record; the other sees "present" |
    | Same `charge_id` with different content | Scope `suspect`, DP off |
    | Parallel charges from several gateway instances near the cap | Total ≤ cap; every approved charge has evidence; no double approval |
    | Ledger rolled back alone | Evidence-only charges imported; DP back on only when `consistent` |
    | Audit log rolled back alone | No effect on the trusted total (the audit log is not the evidence) |
    | Ledger and audit log rolled back **together** from the same backup | Detected and imported from the evidence |
    | State-database failover or PITR (timeline change) | Every scope `reconciling` until reconciled |
    | Ledger and audit log both lost | Rebuilt from the evidence; DP on only after reconciliation |
    | Evidence store unreachable | DP off; masking works |
    | Evidenced charge missing from the evidence store | Scope `suspect`, DP off |
    | Evidence store lost | DP off until a privacy-officer decision; no automatic recreation |
    | Gateway credential tries to overwrite or delete the canary, or shorten retention | Refused by the store; if it isn't, DP stays off (T2, T3) |
    | Recovery from a known-good checkpoint | Missing charges imported; DP on at the trusted total |
    | Protected database replaced or restored, marker kept | Same scope continues |
    | Protected database with missing or different marker | DP off |
    | `dp-scope create` for a `dataset_id` with evidence history | Imports that history first; refused if the evidence is unreachable |
    | Customers deleted | `epsilon_spent` unchanged |
    | Restart | Spending persists |
12. **Budget-store failure tests**:
    - state database unreachable, read-only or slow, and the ledger invariant deliberately broken: DP is refused,
      masking keeps working;
    - concurrent consumption across processes and servers (item 7) never exceeds the cap.
13. **Multi-gateway recovery races** (§9.7). At least three gateway processes, with fault injection and the ability
    to pause any process at any step:

    | Scenario | Passes only if |
    |---|---|
    | **A authorises, pauses before releasing; B detects a rollback and starts recovery; A resumes** | A does not release its result (refused at step 8); A's charge and release record stay counted (G4, G8) |
    | A pauses after its step-8 check; B allocates a new epoch; A resumes | A's release is the one decided before the new epoch; recovery counts its release record (I2, G8) |
    | **Old budget database restored while the evidence store holds a newer epoch** | Every gateway refuses until a new epoch above the store's newest is authorised; the restored `recovery_state` and `cached_epoch` are ignored (G2, G3) |
    | **Two gateways start recovery concurrently** (including against a restored ledger) | Exactly one `epochs/<E+1>` create succeeds; the other stops; no service until `auth/<E+1>` (G7) |
    | A reconciler dies after allocating, before authorising | Service stays off; the next recovery allocates `E+2` (G1, G6) |
    | A stale reconciler writes `auth/<E>` after `E+1` exists | No effect; service stays off until `auth/<E+1>` (G6, G7) |
    | A gateway with a cached "healthy" state during recovery | Refused at step 2 or step 8 (G1, G2) |
    | Ledger restored from a file-level backup (no timeline change) while gateways run | The first charge anywhere collides at step 4 or fails step 5; nothing computed against the restored ledger (G5) |
    | Restore where the next counter falls in a crash gap | Caught at step 5 (G5) |
    | Pending charge whose counter collides after a restore | Recovery gives it a fresh counter; never discarded |
    | Asynchronous failover that lost evidenced commits | Detected at the next charge; imported (G5) |
    | Evidence store unreachable, or its epochs unreadable | No gateway releases (G1) |
    | Same-key retry across a recovery | The stored result is not re-sent; 409 (G4) |
    | Duplicate requests with the same key | One charge, one slot, at most one release |
    | Same key reused for a different query | Refused as a key conflict; no charge |
    | Restore that lost no evidenced charge | Not flagged; totals match the evidence (harmless) |

## 14. Migration plan

| Phase | Content | Gate to the next phase |
|---|---|---|
| 0 | **Done 2026-10-17:** D1, D2, D3 and D11 decided; D11 enforced; claims in README, ARCHITECTURE, EVALUATION, ROADMAP, DEPLOYMENT and the generated PIA corrected; findings encoded as strict-`xfail` tests. **Open:** D4–D10, D12, D13, D14 | D4/D5 approved, D12 review done, D13 and D14 selected, **before Phase 1 starts** |
| 1 | Mechanism fixes without persistence: F2, F1 (join rule), F7 (sensitivity by relation), F10 (discrete sampler), §6.1 contribution bounding with a declared unit | Verification items 3–6 pass |
| 2 | Accountant interface; PostgreSQL implementation (§9); in-memory implementation for tests only; production requires `MASKGUARD_STATE_DB`. **Backfill:** initialise each scope's `epsilon_spent` from the audit log's `dp_epsilon` entries, summed across all analysts (conservative) | Items 7–9 pass |
| 3 | Suppression change (§7) and AVG-with-public-count | Items 3–6 rerun |
| 4 | Written derivation and independent review; update claims to exactly the reviewed statement | Review sign-off |
| 5 | Fold items 3–10 into MaskGuard Assurance as standing checks | n/a |

## 15. Acceptance criteria (for the eventual implementation)

1. A written privacy statement (unit, relation, ε cap, scope, period) appears in the docs and in `/meta`, and
   matches the code.
2. F1–F10 are each fixed or explicitly accepted under the chosen model, each with a regression test.
3. Ledger invariants hold under the concurrency, multi-instance, crash and restart tests, plus the failover test
   if HA is claimed.
4. No code path releases a protected aggregate without a committed charge (code review plus a test that fails if
   one does).
5. With the accountant unavailable, DP queries are refused and everything else keeps working.
6. Production refuses to start with `aggregate` in policy and no state DB.
7. The fencing mechanism (D14) is selected and meets G1–G8 and I2, and every race in §13 item 13 passes, including
   the paused-gateway release race and concurrent recovery against a restored ledger.
8. The recovery mechanism (D13) is selected; its trust assumptions T1–T7 are documented and accepted by the data
   owner; it meets R1–R7 and invariant I1; and every scenario in §13 item 11 passes, including crashes at each step,
   same-key retries, partial writes, concurrent charges, and the ledger and audit log being rolled back together.
   The budget-store failure tests pass (item 12).
9. Statistical tests find no violation for supported mechanisms, and do flag every known-bad control.
10. Every strict `xfail` in `tests/test_dp_findings.py` has become a passing test (its marker removed).
11. An independent DP reviewer signs off the derivation. Public claims say exactly what was signed off. Only then is
    the production refusal (D11) lifted.

## 16. Decisions needed before implementation

| # | Decision | Recommendation |
|---|---|---|
| D1 | Privacy unit: customer or account | **Decided**: customer (`users.id`), with D2 |
| D2 | Neighbouring relation: replace-one values (B) or add/remove membership (C) | **Decided**: B. Membership and row existence are not protected, and the product says so |
| D3 | Budget scope: shared per dataset, or per analyst assuming no collusion | **Decided**: shared per dataset, enforced atomically; optional quotas still open |
| D4 | Period and ε cap: lifetime or renewing; the value | **Deferred to the data owner** after review; lifetime only with §9.5 in place |
| D5 | ε per query and per-output split | **Deferred to the data owner**; 0.5 is a candidate, not a validated default |
| D6 | Suppression approach | Public domains for low-cardinality keys, noisy threshold otherwise |
| D7 | Joins: many-to-one only, per-unit stage, or elastic sensitivity | Many-to-one only, plus the per-unit stage |
| D8 | Noise primitives: in-house discrete sampler or a vetted library dependency | Vetted library if the dependency is acceptable |
| D9 | When the accountant is down: refuse DP only, or suspend the analyst role | Refuse DP only |
| D10 | HA requirement for the state DB (synchronous standby) | Required if the gateway is HA |
| D11 | Interim production stance until phase 4 | **Decided and implemented**: noisy aggregates refused in production; development keeps them, labelled "not a formal DP guarantee" |
| D12 | Who reviews the derivation | An independent reviewer with DP expertise, outside the team |
| D14 | Global recovery and fencing mechanism (§9.7, G1–G8, I2) | Candidate: epochs allocated and authorised only in the evidence store (create-if-absent), a release fence at release time, counter fencing as a rollback detector, ledger state refuse-only. Alternatives: leases with fencing tokens from a linearizable coordination service, or a central release-approval service; either must fence at release time. Selected at design review with D13 |
| D13 | Recovery evidence mechanism (§9.6), its trust assumptions T1–T7, and who administers it | Candidate: M1 (write-once storage with store-enforced retention, one record per `charge_id`) under a separate administrative domain; M2 as fallback. Selected at design review, with T7's residual risks accepted in writing |

## 17. References

Checked against publisher or index pages on 2026-10-17, except [1], [2], [16] and [18], which are cited from the
standard sources.

1. C. Dwork, F. McSherry, K. Nissim, A. Smith. *Calibrating Noise to Sensitivity in Private Data Analysis.* TCC 2006.
2. C. Dwork, A. Roth. *The Algorithmic Foundations of Differential Privacy.* Foundations and Trends in Theoretical Computer Science 9(3–4), 2014.
3. J. Near, D. Darais (N. Lefkovitz, G. Howarth, eds.). *Guidelines for Evaluating Differential Privacy Guarantees.* NIST SP 800-226, March 2025. doi:10.6028/NIST.SP.800-226. <https://csrc.nist.gov/pubs/sp/800/226/final>
4. F. McSherry. *Privacy Integrated Queries.* SIGMOD 2009. <https://www.microsoft.com/en-us/research/publication/privacy-integrated-queries/>; and H. Ebadi, D. Sands. *Featherweight PINQ.* Journal of Privacy and Confidentiality, 2016. <https://arxiv.org/abs/1505.02642>
5. R. Rogers, A. Roth, J. Ullman, S. Vadhan. *Privacy Odometers and Filters: Pay-as-you-Go Composition.* NIPS 2016, 1921–1929. <https://arxiv.org/abs/1605.08294>
6. R. J. Wilson, C. Y. Zhang, W. Lam, D. Desfontaines, D. Simmons-Marengo, B. Gipson. *Differentially Private SQL with Bounded User Contribution.* PoPETs 2020(2), 230–250. doi:10.2478/popets-2020-0025
7. D. Desfontaines, J. Voss, B. Gipson, C. Mandayam. *Differentially private partition selection.* PoPETs 2022(1), 339–352. doi:10.2478/popets-2022-0017
8. A. Korolova, K. Kenthapadi, N. Mishra, A. Ntoulas. *Releasing Search Queries and Clicks Privately.* WWW 2009, 171–180. doi:10.1145/1526709.1526733
9. N. Johnson, J. P. Near, D. Song. *Towards Practical Differential Privacy for SQL Queries.* PVLDB 11(5), 2018, 526–539. <https://arxiv.org/abs/1706.09479>
10. I. Mironov. *On Significance of the Least Significant Bits for Differential Privacy.* CCS 2012, 650–661.
11. C. Canonne, G. Kamath, T. Steinke. *The Discrete Gaussian for Differential Privacy.* NeurIPS 2020; Journal of Privacy and Confidentiality 12(1), 2022. <https://arxiv.org/abs/2004.00010>
12. A. Haeberlen, B. C. Pierce, A. Narayan. *Differential Privacy Under Fire.* USENIX Security 2011. <https://www.usenix.org/conference/usenix-security-11/differential-privacy-under-fire>
13. Z. Ding, Y. Wang, G. Wang, D. Zhang, D. Kifer. *Detecting Violations of Differential Privacy.* CCS 2018, 475–489. doi:10.1145/3243734.3243818
14. D. Kifer, A. Machanavajjhala. *No Free Lunch in Data Privacy.* SIGMOD 2011, 193–204. doi:10.1145/1989323.1989345
15. J. Tang, A. Korolova, X. Bai, X. Wang, X. Wang. *Privacy Loss in Apple's Implementation of Differential Privacy on MacOS 10.12.* arXiv:1709.02753, 2017.
16. C. Dwork, M. Naor, T. Pitassi, G. N. Rothblum. *Differential Privacy Under Continual Observation.* STOC 2010.
17. Redis documentation, *Redis replication* (asynchronous replication; `WAIT` and consistency). <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>
18. PostgreSQL documentation, *Transaction Isolation* (READ COMMITTED update re-check). <https://www.postgresql.org/docs/current/transaction-iso.html>
