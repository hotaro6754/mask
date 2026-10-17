# Privacy accounting: review brief clarification

| | |
|---|---|
| **What this is** | Clarifications to the *review brief* (§9.8 and §13 item 14) of the privacy-accounting design. Scope of the review only. |
| **What this is not** | A change to the protocol. No invariant, obligation, store requirement, step, decision or claim in the design is added, removed or reworded here. |
| **Date** | 2026-10-17 |
| **Author** | The design's author. This file defines what the reviewer is asked to check; it is not part of the review. |

## 1. The revision under review

The reviewer reviews exactly this text, and the verdict names it:

| | |
|---|---|
| Document | `docs/design/PRIVACY_ACCOUNTING.md` |
| Frozen at commit | `a6891fd0a52252d7b65454bab9c912b9c559ddb2` (branch `claude/zealous-bell-me62fn`) |
| Git blob | `41c52f6640f46413dfdc3798a92dbe388e5b593e` |
| SHA-256 | `ddd6b7955132185a49bdf8e83bc4bec4f248646b53ba6d6a78504da0d5bbe98a` |

Compute these from Git yourself. Don't copy them from this file or from the handoff message:

```bash
F=docs/design/PRIVACY_ACCOUNTING.md
FROZEN=a6891fd0a52252d7b65454bab9c912b9c559ddb2
git cat-file -t "$FROZEN"                         # commit
git rev-parse "$FROZEN:$F"                        # blob of the frozen text
git show "$FROZEN:$F" | sha256sum                 # SHA-256 of the frozen text
git diff --stat "$FROZEN" <brief commit> -- "$F"  # empty: the protocol is unchanged
git diff --stat "$FROZEN" <brief commit>          # only this file changed
```

`<brief commit>` is the commit that holds the revision of this file you received. The handoff names it in full; a
file cannot contain its own commit id.

The protocol document is not edited while the review is open. If the review finds defects, the fix is a new
revision, and that revision needs its own review. A verdict on `a6891fd` does not carry over to it.

Where this file and §9.8 differ, this file sets **what is reviewed**. The design document still sets **what the
protocol is**. If the reviewer finds that a clarification below asks about behaviour the protocol doesn't specify,
report that as a finding against `a6891fd`. Do not fill the gap with an assumption.

### 1.1 The reviewer's authority

The reviewer is not asked to validate the author's design. Any of these is a valid outcome:

- the protocol is rejected;
- an invariant, obligation or trust assumption is missing or wrong;
- the selected store, or any practical store, cannot provide S1–S3, so a serialised alternative is needed (§9.7);
- the DP mechanism can't support the claims, and noisy aggregates should stay disabled.

Where the design states a preference, the reviewer can disagree and give reasons. Examples are Design 2 (§12),
the candidate mechanism for D13, ε = 0.5, and the recovery mechanism of §9.7. Nothing in this file or the design
limits which questions the reviewer may raise.

## 2. Clarifications

### C1. Model completeness: lost acknowledgements and evidence-store outages

The §9.8 model lists crashes, pauses, ledger rollback, restore and failover, the store's S1–S3 and analyst retries.
It must also include:

- **Lost acknowledgements.** The effect is durable but the caller never sees the reply. Model this for each write
  the protocol depends on:
  - the ledger reservation (step 3);
  - the evidence-slot create (step 4);
  - the confirm (step 6);
  - the release-record create (step 8, O1);
  - the `epochs/<E>` create (S1, O2);
  - the `auth/<E>` write.

  The caller's view after a timeout is "unknown outcome". The model must cover the case where the caller assumes
  failure and the effect exists anyway.
- **Evidence-store outages.** The store refuses, times out, or is reachable from some gateways and not others. This
  can happen during a charge, during the release fence, and during recovery. The outage then ends.
- **Recovery and retry behaviour around both of the above.** This covers:
  - a gateway retrying a create whose acknowledgement was lost (S1's create-if-absent answers "exists");
  - an analyst retrying with the same or a conflicting key;
  - a reconciler retrying after an outage;
  - a recovery that starts during an outage, and one that starts as the outage ends.

  These actions must interleave with every other action in the model.

The invariants are those in §9.8. A lost acknowledgement or an outage may make the protocol refuse service. That is
acceptable: the protocol is meant to fail closed (§10). It must never produce a disclosure without charge evidence.
It must never authorise a release after a newer epoch began. It must never remove a charge, or let a charge go
uncounted.

### C2. Disclosure-path coverage: the SDK is a path

Obligation O3 names the API, CLI, PostgreSQL proxy, dashboards, caches and error handlers. The **SDK** (the Python
client, `MaskGuardClient`) is a disclosure path too, and the review covers it alongside the others.

Most paths go through `Gateway.query` / `Gateway._query`, which is where D11 refuses noisy aggregates in
production. **Some do not.** They call the database directly and skip the gateway's firewall decision, audit
record, threat engine and D11 check; they are listed in the second table.

Both tables give the call sites at `a6891fd`, found by searching the source (`src/` is unchanged since then). They
are a starting point, not a proof that the list is complete. Completeness is part of question 1.

| Path | Call site at `a6891fd` | What to check |
|---|---|---|
| REST API | `src/maskguard/api.py` `_run` → `gateway.query` (`POST /query`, `POST /query/table`) | Response body and metadata: rows, `rewritten_sql`, timing, budget fields, `X-Request-ID` |
| **SDK** | `src/maskguard/client.py` `MaskGuardClient.query` / `query_raw` / `query_df` / `query_table` (HTTP to the API) | It must not retry a request in a way that re-sends a release outside a step-8 check. It must not keep results. `MaskGuardError.detail` must carry only what the API's error handler sent |
| CLI | `src/maskguard/service.py` `LocalService.query` → `gw.query(channel="cli")`; remote mode goes through the SDK (`RemoteService`, whose `_cache` holds signed-in clients, not results) | Printed output and error messages |
| PostgreSQL proxy | `src/maskguard/pgwire.py` → `gateway.query` | Wire-protocol rows, `ErrorResponse` and notice text |
| Dashboards | `src/maskguard/dashboard.py` playground (`gw.query`); the performance tab (below); Control Room `/ui/` uses the API | Displayed results |
| Caches | No result cache found at `a6891fd`. `RemoteService._cache` caches clients. | Confirm. Any cache that is added later is a path in its own right |
| Error handlers | `api.py` `_run` (`Rejected` text, `safe_error`), `gateway.safe_error`; simple-protocol errors in `pgwire.py` give the exception type only, **extended-protocol errors echo up to 200 characters of the exception text** (`pgwire.py`, `extended`) | Messages must not depend on protected values or on releases before noise |
| Internal callers | `integrity.py` probes (`observe=False`); `threat_sim.live_attack` (`simulate-attack`, dashboard) | Confirm none returns a noisy result to a user. If one can, it is a disclosure path |

**The dashboard performance tab needs specific attention.** It runs each preset `n` times (20–300) through
`gw.query` and shows only latency percentiles. One preset is a noisy aggregate
(`SELECT status, count(*), avg(balance) FROM accounts GROUP BY status`, noisy for the analyst role). When results aren't displayed:

- Under an accountant, each run is a charged release that nobody sees. With 300 runs a click, this tab can
  spend the budget quickly. This bears on composition (C3) and per-analyst quotas (§4).
- Run time, and whether a run is refused, can still depend on the data or the budget. That is a disclosure through
  a side channel.

The tab also runs the same presets straight against the database for its baseline (next table). D11 makes the
gateway half refuse aggregates in production. The direct half is unaffected, but only its timing is shown.

**Paths that bypass the gateway** at `a6891fd`:

| Path | Call site | Reachable in production | What it returns |
|---|---|---|---|
| Attack self-test: `GET /attacks` (any authenticated role), `maskguard attack`, dashboard attack tab | `attacks.run_suite`: `_facts` and `_secrets` read every protected column in full with `backend.admin_query`; the "naive" half runs 21 crafted statements through `naive.naive_query` → `backend.execute` | **Yes.** Probed on 2026-10-17 against PostgreSQL 16 with `MASKGUARD_ENV=production`, demo mode off, a read-only gateway account and a production user store. A `support` user got 200 and the full report | Leak counts per attack, and oracle results computed from real rows (for example `true guess -> [(1,)], false guess -> [(0,)]`). No raw values were in the response. The naive statements are not checked by the gateway's firewall and are not audited by it |
| Proxy `Describe` | `pgwire.describe`: `rewrite()` then `backend.execute("SELECT * FROM (…) LIMIT 0")` | Yes (proxy is loopback-only in production) | Column names only, no rows. Skips the audit, the threat engine and D11. Rewriter errors still apply |
| Dashboard performance baseline | `dashboard.py`: `backend.execute(q)` on the presets | Wherever the classic dashboard runs (loopback-only in production) | Latency only |
| Threat-model training simulation | `threat_sim._run`: `rewrite()` then `backend.execute` | No. Called from `threat_sim.sessions`, used only by `bench/eval_threat.py` and tests | Row counts into training events |

The attack self-test is a gap in the production profile, outside this protocol, and is reported to the owner
separately. It is listed here because O3 asks for every path, and this one returns results derived from real
data to any role without passing the gateway.

### C3. Differential-privacy review scope

Question 6 ("the DP model itself") covers all of the following. Each one gets a verdict of its own.

| Area | Design section | Findings it addresses |
|---|---|---|
| Privacy unit and neighbouring relation | §3 | D1, D2 |
| **Noise generation**: sampler correctness, floating-point attacks, randomness source, choice of discrete or continuous mechanism | §8 | F10 |
| **Contribution bounds**: per-customer clipping before aggregation, the path from each protected table to the customer key | §6.1, §6.5 | F6 |
| **Per-query semantics**: which SQL forms are accepted; joins; `ORDER BY` and `LIMIT`; filters and lineage; `GROUP BY` with suppression; `COUNT` and `AVG` | §6.2–§6.4, §7 | F1, F2, F8, F9 |
| **Sensitivity**: the derivation for each accepted form, under the declared neighbouring relation | §3, §6 | F7 |
| **Composition**: across queries, analysts and instances in one dataset scope; across epochs and recovery; charges kept as `failed_after_charge` | §4, §5, §9.4 | F3, F4, F5 |

The DP verdict is separate from the protocol verdict. A correct protocol does not make the mechanism
differentially private, and a correct mechanism does not make the accounting safe. Experiments such as
`tests/test_dp_findings.py` can show a gap exists. They cannot establish a guarantee (§13).

### C4. Review report requirements

The report records the following. §13 item 14 lists only some of them.

1. **Revision reviewed.** The identifiers in §1 of this file.
2. **Model and assumptions.** The specification itself (attached, runnable). Also:
   - what was abstracted away;
   - which store semantics were assumed;
   - how each model action maps to a protocol step (§9.4, §9.7);
   - every assumption beyond those in the design (T1–T7, S1–S3).
3. **Invariants.** The exact formulas checked, each mapped to a §9.8 invariant or to G1–G8, I1 or I2.
4. **Explored bounds.** For example:
   - the number of gateways, reconcilers, charges, epochs, retries, lost acknowledgements and outages;
   - the depth, and the number of distinct states;
   - whether the exploration was exhaustive within those bounds, or simulation only.
5. **Negative controls.** At least S2 weakened and O2 dropped (§9.8), plus any the reviewer adds. For each:
   - the expected counterexample;
   - whether the checker found it.

   A control that fails to produce its counterexample invalidates the run that used it.
6. **Counterexamples.** Each one minimised, attached as a trace, and classified as one of:
   - a protocol defect;
   - a defect in the specification;
   - a violated assumption.

   Each must be reproducible as a test in §13 item 13.
7. **Properties outside the model.** Name each property the model does not cover. These include, at least:
   - liveness;
   - unbounded behaviour;
   - the DP mathematics (C3);
   - whether a future implementation conforms to the model;
   - whether the selected store actually provides S1–S3 (D13);
   - timing and other side channels;
   - operational procedures (restore, key handling).
8. **Verdict per question.** For each of questions 1–6 in §9.8, one of:
   - "holds within the stated bounds and assumptions";
   - "fails", with the counterexample attached;
   - "not assessed".
9. **A written verdict in five separate parts.** A finding in one part does not decide another.
   1. **Protocol and recovery safety:** I1, I2, G1–G8, O1–O3, and the disclosure-path inventory (C2).
   2. **Storage guarantees and trust assumptions:** S1–S3 on the store D13 would select, and T1–T7 and R1–R7, with
      the residual risks the data owner would accept.
   3. **Differential-privacy mathematics:** every area in C3.
   4. **Implementation gaps and required remediation:** what today's code (`dp.py`, `rewriter.py`, the paths in
      C2) would have to change, and what an implementation must demonstrate.
   5. **The exact conditions for reopening production aggregates:** stated so they can be checked, including what
      must be re-reviewed after implementation.

A check that finds no counterexample is reported as **no counterexample within the stated bounds**. It is not
reported as "proven" or "secure" (§9.8).

## 3. What the reviewer receives

All files are at commit `a6891fd`, except this file, which comes from the commit that adds it:

- `docs/design/PRIVACY_ACCOUNTING.md`: the protocol and the DP design under review.
- `docs/design/PRIVACY_ACCOUNTING_REVIEW_BRIEF.md`: this scope clarification.
- `tests/test_dp_findings.py`: reproductions of F1, F2, F4 and F6. They are strict xfails, with controls.
- The mechanism as it stands today: `src/maskguard/dp.py` and `src/maskguard/rewriter.py`.
- The disclosure paths listed in C2.
- The D11 refusal:
  - `src/maskguard/gateway.py` (`allow_dp`);
  - `src/maskguard/config.py` (`allow_dp=not production`);
  - `tests/test_production.py::test_production_refuses_noisy_aggregates_but_keeps_masking`;
  - `docs/DEPLOYMENT.md`.

The accountant is **not implemented**. The review covers the design and today's mechanism. It does not cover an
implementation.

## 4. Gate status

**D11 remains in force:** production refuses noisy aggregates. Lifting it needs every row of the §0.1 gate. At the
date above, all of these are open:

- **D4/D5:** the data owner approves the total budget and the per-query charging policy.
- **D12:** this review's verdict, including the DP verdict.
- **D13:** selecting the recovery evidence mechanism and its trust assumptions (§9.6, T1–T7).
- **D14:** selecting the global recovery and fencing mechanism (§9.7), or a serialised alternative.
- The recovery tests in §13 items 11–13. These cannot run until an accountant exists.

The release gate does not depend on how far the review has got. These are different things, and none of them
alone establishes that an implementation provides the intended guarantee:

- a completed review;
- a model check that finds no counterexample within its bounds;
- a passing test suite.

Noisy aggregates stay disabled in production until every one of these is complete:

- the decisions above;
- the accountant's implementation;
- the recovery and restore tests;
- the independent approvals of both the design and the implementation (§15).

None of these is changed by this file.
