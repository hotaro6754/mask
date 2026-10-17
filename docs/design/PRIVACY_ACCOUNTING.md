# Privacy accounting for analyst aggregates: design proposal

| | |
|---|---|
| **Status** | Proposal for review. **Nothing here is implemented**, and runtime behaviour is unchanged. |
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
   **PostgreSQL state database** separate from the protected data, with idempotent replays.
4. **Mechanism fixes before any claim:** per-customer contribution bounding, join and ordering restrictions,
   sensitivities matched to the neighbouring relation, an exact discrete noise sampler, and noisy (not exact)
   small-group thresholds.

Experiments in this plan can find violations. They cannot prove a guarantee. The claim at the end must rest on a
written derivation reviewed by someone with differential-privacy expertise (§13).

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

Claims to correct once a decision is taken (not edited in this proposal):
- `README.md` §"What it does" item 5;
- `docs/EVALUATION.md` §5 (budget wording);
- `docs/ROADMAP.md`;
- `pia.py` (the generated PIA prints ε figures).

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

CREATE TABLE dp_charge (                                 -- append-only; never updated except `outcome`
  charge_id         bigserial PRIMARY KEY,
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
  outcome           text NOT NULL DEFAULT 'charged'
                    CHECK (outcome IN ('charged', 'released', 'failed_after_charge')),
  UNIQUE (scope_id, request_key)
);

CREATE TABLE dp_release (                                -- noisy outputs only (already public to the requester)
  scope_id text, request_key text, result jsonb NOT NULL,
  released_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
  PRIMARY KEY (scope_id, request_key)
);
```

Invariant, checked at startup and by a periodic job: `epsilon_spent = Σ dp_charge.epsilon` per scope. A mismatch
makes DP fail closed.

### 9.4 Transaction flow

```
1  plan       rewrite + mechanism + cost      (no data touched; refusals here are data-independent)
2  charge     BEGIN
                INSERT INTO dp_charge (…) ON CONFLICT (scope_id, request_key) DO NOTHING RETURNING charge_id
                  - conflict + dp_release row exists  -> COMMIT, return the stored result (no charge, no new noise)
                  - conflict, no release              -> COMMIT, 409 "already charged; resubmit with a new key"
                UPDATE dp_scope SET epsilon_spent = epsilon_spent + :eps
                  WHERE scope_id = :s AND closed_at IS NULL AND epsilon_spent + :eps <= epsilon_cap
                  - 0 rows -> ROLLBACK, refuse "budget exhausted" (before any data access)
                UPDATE dp_quota … (same pattern; fixed lock order scope -> quota)
              COMMIT                               (synchronous_commit = on)
3  execute    read-only query on the protected DB; add noise
4  record     INSERT dp_release …; UPDATE dp_charge SET outcome = 'released'   (best effort)
5  respond
```

- **Concurrency.** Charges on one scope serialise on its row. At analyst query rates that contention is
  negligible.
- **Crash between 2 and 5.** The charge stands, with no refund. A retry with the same key gets 409. A new key
  means a new release and a new charge. That is conservative: the earlier output may or may not have left the
  server.
- **Step 3 fails** (error, timeout). `outcome = 'failed_after_charge'`, with no refund, because whether a query
  times out can depend on data.
- **Step 4 fails.** The result is still returned. A later retry with the same key can't be served from cache
  (409), so it never produces a second free release.

## 10. Failure behaviour

| Situation | Behaviour |
|---|---|
| State DB unreachable or ledger invariant broken | DP queries refused (503, fail closed). Non-DP queries continue, since they consume no budget (open decision D9) |
| Budget or quota exhausted | Refused at step 2, before data access. The message gives the remaining budget only, which depends on query history, not data |
| Charge committed, query fails or times out | Charge kept, outcome recorded, no refund |
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
4. One PostgreSQL state database is available with synchronous replication if HA is required.
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
8. **Crash and restart.** Kill the gateway between steps 2 and 3, and between 3 and 4. Check that the invariant
   holds and same-key retries behave per §9.4. Restart: spending persists.
9. **Failover**, if HA is in scope: promote the standby under load and confirm no committed charge is lost.
10. **Reproducible evaluation.** Extend `bench/eval_dp.py` to the full lifetime budget with several colluding
    analysts, and report the differencing-attack error as in §1.3. Seeds are used only in test mode.

## 14. Migration plan

| Phase | Content | Gate to the next phase |
|---|---|---|
| 0 | Decisions D1–D12. Correct the claims in §1.3. Optionally adopt the interim production stance (D11): refuse `aggregate` in production until phase 4 | Decisions recorded |
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
7. Statistical tests find no violation for supported mechanisms, and do flag every known-bad control.
8. An independent DP reviewer signs off the derivation. Public claims say exactly what was signed off.

## 16. Decisions needed before implementation

| # | Decision | Recommendation |
|---|---|---|
| D1 | Privacy unit: customer or account | Customer (`users.id`) |
| D2 | Neighbouring relation: replace-one values (B) or add/remove membership (C) | B, keeping analyst row-level access. C only if analysts lose row access to the protected population |
| D3 | Budget scope: shared per dataset, or per analyst assuming no collusion | Shared per dataset, optional quotas |
| D4 | Period and ε cap: lifetime or renewing; the value | Lifetime cap; value set by the data owner and privacy officer |
| D5 | ε per query and per-output split | Keep 0.5 per protected output as the starting point; revisit after phase 1 utility numbers |
| D6 | Suppression approach | Public domains for low-cardinality keys, noisy threshold otherwise |
| D7 | Joins: many-to-one only, per-unit stage, or elastic sensitivity | Many-to-one only, plus the per-unit stage |
| D8 | Noise primitives: in-house discrete sampler or a vetted library dependency | Vetted library if the dependency is acceptable |
| D9 | When the accountant is down: refuse DP only, or suspend the analyst role | Refuse DP only |
| D10 | HA requirement for the state DB (synchronous standby) | Required if the gateway is HA |
| D11 | Interim production stance until phase 4 | Refuse `aggregate` in production; keep it in demo with "not formal DP" labelling |
| D12 | Who reviews the derivation | An independent reviewer with DP expertise, outside the team |

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
