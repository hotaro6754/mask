"""Automated Privacy Impact Assessment (PIA) generated from the live system state.

Prabowo et al. (IEEE Access 2025) name automated PIA as the first open research gap for government privacy. This
report is assembled from facts MaskGuard already holds, not from a questionnaire: the scanner's data inventory, the
policy (what each role actually sees, computed by the same function the rewriter uses), active controls, and what the
audit log shows happened. Output: Markdown (convert with any tool) and a JSON summary.
"""
import collections, datetime, json, os

from .rewriter import action_for

ACTION_TEXT = {"allow": "full value", "partial": "partially masked", "hmac": "keyed token", "redact": "redacted",
               "redact_text": "identifiers removed from text", "aggregate": "noisy SUM/AVG/COUNT only", "deny": "denied"}
DPDP_RULE6 = [
    ("Security safeguards: encryption, obfuscation, masking or virtual tokens",
     "Query-time masking per role, keyed-HMAC tokens, free-text redaction; stored data unchanged."),
    ("Access control over computer resources", "Authenticated sessions (PBKDF2 + signed JWT), role from session only, "
     "read-only execution, statement firewall, per-role row caps."),
    ("Visibility of access: logs, monitoring and review", "Hash-chained audit log of every query, rejection, "
     "threat alert and privacy-budget charge; literals stripped so personal data never enters the log."),
    ("Measures for continued processing after compromise", "Threat engine blocks a user mid-session; data is "
     "never modified by MaskGuard (table checksums verify this)."),
    ("Retain logs for one year", "Append-only audit log; retention is set by deployment (rotate ≥ 1 year)."),
]


def _audit_stats(path, since_days=30):
    stats = collections.Counter()
    users, alerts, eps = set(), collections.Counter(), collections.defaultdict(float)
    if not os.path.exists(path):
        return stats, users, alerts, eps
    cutoff = datetime.datetime.now().timestamp() - since_days * 86400
    for line in open(path):
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("ts", 0) < cutoff:
            continue
        stats[e.get("decision", "?")] += 1
        users.add(e.get("user"))
        if e.get("threat_action") in ("alert", "block"):
            alerts[(e.get("user"), e.get("threat_action"))] += 1
        if e.get("dp_epsilon"):
            eps[e.get("user")] += float(e["dp_epsilon"])
    return stats, users, alerts, eps


def build(app, since_days=30):
    gw, reg, policy = app.gateway, app.gateway.registry, app.gateway.policy
    roles = list(policy["roles"])
    inventory, matrix = [], []
    for table, cols in sorted(reg.items()):
        for col, meta in cols.items():
            if not meta.get("tag"):
                continue
            inventory.append({"table": table, "column": col, "kind": meta.get("kind"), "tag": meta["tag"],
                              "confidence": meta.get("confidence"), "source": meta.get("source"),
                              "evidence": meta.get("evidence")})
            matrix.append({"column": f"{table}.{col}", **{r: ACTION_TEXT.get(action_for(meta, r, policy), "?") for r in roles}})
    stats, users, alerts, eps = _audit_stats(gw.audit.path, since_days)
    review = [i for i in inventory if i["confidence"] == "review"]
    risks = [
        "Keyed tokens allow equality joins and frequency analysis by roles that receive them.",
        "Partial masks reveal the characters they keep (e.g. last four digits).",
        "A personal-data column the scanner misses stays exposed until tagged; scheduled rescans and manual overrides mitigate this.",
        "Applications or people holding direct database credentials bypass MaskGuard; restrict them to the gateway's role.",
        "Names and addresses embedded in free text are not yet detected (structured identifiers are).",
    ]
    if review:
        risks.insert(0, f"{len(review)} column(s) tagged with low confidence need human review: "
                        + ", ".join(f"{i['table']}.{i['column']}" for i in review))
    return {"generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "backend": app.backend.dialect, "tables": len(reg), "tagged_columns": len(inventory),
            "inventory": inventory, "access_matrix": matrix, "roles": roles,
            "controls": {"masking": True, "threat_engine": gw.threat is not None,
                         "threat_thresholds": {"alert": gw.threat.alert, "block": gw.threat.block} if gw.threat else None,
                         "differential_privacy": policy.get("dp"), "row_caps": policy.get("max_rows"),
                         "min_group_size": policy.get("min_group_size"), "row_filters": policy.get("row_filters") or {},
                         "audit_chain_valid": gw.audit.verify()},
            "activity": {"days": since_days, "decisions": dict(stats), "users": len(users - {None}),
                         "threat_events": [{"user": u, "action": a, "count": n} for (u, a), n in alerts.items()],
                         "epsilon_spent": {u: round(v, 2) for u, v in eps.items()}},
            "dpdp_rule6": DPDP_RULE6, "residual_risks": risks}


def to_markdown(r):
    L = [f"# Privacy Impact Assessment — MaskGuard", "",
         f"Generated {r['generated_at']} from the live system ({r['backend']}). {r['tagged_columns']} personal-data "
         f"columns across {r['tables']} tables.", "", "## 1. Data inventory (automated discovery)", "",
         "| Table | Column | Type | Tag | Confidence | Source | Evidence |", "|---|---|---|---|---|---|---|"]
    L += [f"| {i['table']} | {i['column']} | {i['kind']} | {i['tag']} | {i['confidence']} | {i['source']} | {i['evidence']} |"
          for i in r["inventory"]]
    L += ["", "## 2. Who sees what (computed from the enforced policy)", "",
          "| Column | " + " | ".join(r["roles"]) + " |", "|---|" + "---|" * len(r["roles"])]
    L += [f"| {m['column']} | " + " | ".join(m[x] for x in r["roles"]) + " |" for m in r["access_matrix"]]
    c = r["controls"]
    L += ["", "## 3. Controls in place", "",
          f"- Query-time masking: on. Stored data is never modified.",
          f"- Threat engine: {'on, alert at ' + str(c['threat_thresholds']['alert']) + ', block at ' + str(c['threat_thresholds']['block']) if c['threat_engine'] else 'off'}.",
          f"- Differential privacy: ε per query {c['differential_privacy'].get('epsilon_per_query') if c['differential_privacy'] else '-'}, "
          f"daily budget {c['differential_privacy'].get('daily_budget') if c['differential_privacy'] else '-'}.",
          f"- Row caps {c['row_caps']}; aggregates over fewer than {c['min_group_size']} rows suppressed.",
          f"- Row-level filters: {c['row_filters'] or 'none'}.",
          f"- Audit log hash chain: {'intact' if c['audit_chain_valid'] else 'BROKEN — investigate'}.", "",
          f"## 4. Activity, last {r['activity']['days']} days", "",
          f"- Decisions: {r['activity']['decisions'] or 'none recorded'}; distinct users: {r['activity']['users']}."]
    for t in r["activity"]["threat_events"]:
        L.append(f"- Threat engine {t['action']}: {t['user']} ({t['count']} queries).")
    for u, e in r["activity"]["epsilon_spent"].items():
        L.append(f"- Privacy budget spent by {u}: ε = {e}.")
    L += ["", "## 5. DPDP Rules 2025, Rule 6 (reasonable security safeguards) mapping", "",
          "| Safeguard | How it is met |", "|---|---|"]
    L += [f"| {a} | {b} |" for a, b in r["dpdp_rule6"]]
    L += ["", "## 6. Residual risks and actions", ""] + [f"- {x}" for x in r["residual_risks"]]
    L += ["", "_Automatically generated; review and sign off by the Data Protection Officer before filing._"]
    return "\n".join(L) + "\n"
