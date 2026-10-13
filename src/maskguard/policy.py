"""Policy engine: one place that says what each role may see and do, shared by the API, CLI and both dashboards.

Enforcement still happens in exactly one code path (rewriter.rewrite, called by Gateway.query). This module gives
everything around it a single source of truth:

  * action catalog + strictness order (the strictest action wins when rules conflict; unknown -> deny)
  * role capabilities (who may read the audit log, verify integrity, edit policy, ...) - checked by the API and CLI
  * explain(): the per-column decision trace for a role and table, computed with the same action_for() the rewriter uses
  * version(): a content hash, written into every audit entry, so each decision can be tied to the exact policy
  * PolicyStore: validated, audited runtime edits with history; weakening a rule needs explicit confirmation
"""
import copy, hashlib, json, os, threading, time

from . import masks
from .rewriter import action_for, compile_row_filter

# Strictness order: higher = more protective. Conflicts resolve to the strictest action.
ACTIONS = {
    "allow":       (0, "Full value", "Returned unchanged."),
    "partial":     (1, "Partial mask", "Separators and a few edge characters kept; the rest becomes X. Numbers rounded down to a bucket."),
    "redact_text": (2, "Redact identifiers in text", "Identifiers inside free text become [PHONE], [AADHAAR], ...; the rest of the text stays."),
    "hmac":        (3, "Keyed token (HMAC-SHA256)", "Deterministic 16-hex token: joinable and countable, not reversible without the server key."),
    "aggregate":   (4, "Noisy aggregates only", "Usable only as SUM/AVG/COUNT with Laplace noise and a daily epsilon budget; any other use is redacted."),
    "redact":      (5, "Redacted", "Replaced by the literal REDACTED (NULL for numbers)."),
    "deny":        (6, "Withheld", "Value withheld: the column returns NULL for this role."),
}
CAPABILITIES = {
    "query":              "Run SELECT queries through the masking gateway",
    "policy.read":        "Read and explain the policy of every role",
    "policy.write":       "Change masking rules at runtime (validated, versioned, audited)",
    "registry.read":      "See PII scanner classifications and evidence",
    "scan.run":           "Trigger a rescan of the database",
    "audit.read":         "Read and verify the hash-chained audit log",
    "integrity.verify":   "Verify source tables against the integrity baseline",
    "integrity.baseline": "Record a new integrity baseline",
    "threats.manage":     "See threat-engine alerts and lift blocks",
    "pia.read":           "Generate the Privacy Impact Assessment",
}
DEFAULT_CAPABILITIES = ["query"]  # a role with no role_info entry can only query (and read its own policy)

# Synthetic example per data kind, used only for previews; never derived from the database.
EXAMPLES = {
    "card": "4111-1111-1111-1111", "ssn": "123-45-6789", "aadhaar": "2345 6789 0123", "pan": "ABCPE1234F",
    "phone": "9876543210", "email": "riya.sharma@example.in", "upi": "riya.sharma@okaxis", "iban": "GB82WEST12345698765432",
    "gstin": "27ABCPE1234F1Z5", "passport": "K1234567", "voter_id": "ABC1234567", "bank_account": "123456789012",
    "ifsc": "HDFC0001234", "pincode": "560001", "vehicle_reg": "KA01AB1234", "dob": "1990-04-17", "name": "Riya Sharma",
    "address": "12 MG Road, Bengaluru", "balance": 452310.75, "amount": 18250.00,
    "free_text_pii": "Customer called from 9876543210 about card 4111-1111-1111-1111.",
}


def strictness(action):
    return ACTIONS.get(action, ACTIONS["deny"])[0]


def version(policy):
    """Short content hash of the effective policy (key order independent)."""
    body = json.dumps(policy, sort_keys=True, default=str).encode()
    return f"v{policy.get('version', 1)}-{hashlib.sha256(body).hexdigest()[:10]}"


def capabilities(role, policy):
    info = (policy.get("role_info") or {}).get(role) or {}
    return list(info.get("capabilities", DEFAULT_CAPABILITIES))


def can(role, capability, policy):
    return role in policy.get("roles", {}) and capability in capabilities(role, policy)


def roles(policy):
    out = []
    for r, rules in policy["roles"].items():
        info = (policy.get("role_info") or {}).get(r) or {}
        out.append({"role": r, "label": info.get("label", r.title()), "description": info.get("description", ""),
                    "capabilities": capabilities(r, policy), "rules": dict(rules),
                    "max_rows": (policy.get("max_rows") or {}).get(r),
                    "min_group_size": (policy.get("min_group_size") or {}).get(r),
                    "row_filters": (policy.get("row_filters") or {}).get(r, {})})
    return out


def view_within(role, caller, policy):
    """True if `role` never sees more than `caller`: every classification is at least as strictly masked, and every
    row filter the caller has, `role` has too. Used to stop a low role from borrowing a stronger role's view."""
    if role == caller:
        return True
    rules = policy["roles"]
    default = policy.get("default_action", "deny")
    for tag in known_tags(policy):
        if strictness(rules[role].get(tag, default)) < strictness(rules[caller].get(tag, default)):
            return False
    rf = policy.get("row_filters") or {}
    return all((rf.get(role) or {}).get(t) == f for t, f in (rf.get(caller) or {}).items())


def known_tags(policy, registry=None):
    tags = {t for rules in policy["roles"].values() for t in rules}
    for cols in (registry or {}).values():
        tags |= {m["tag"] for m in cols.values() if m.get("tag")}
    return sorted(tags)


def _rule_source(meta, role, policy):
    tag = meta.get("tag")
    if not tag:
        return "untagged: no PII found"
    if tag in policy["roles"][role]:
        return f"roles.{role}.{tag}"
    return f"default_action={policy.get('default_action', 'deny')} (no rule for {tag})"


def preview(meta, action, policy):
    """(synthetic input, output) showing what `action` does to this kind of value. Mirrors rewriter._mask_expr."""
    kind = meta.get("kind")
    num = meta.get("type") == "num"
    ex = EXAMPLES.get(kind, 452310.75 if num else "sample-value-1234")
    if action == "allow":
        return ex, ex
    if action == "partial":
        if num:
            return ex, masks.bucket(float(ex), policy.get("bucket_size", 10000))
        if kind in ("email", "upi"):
            return ex, masks.email(ex)
        p = policy["partial"].get(kind, policy["partial"]["default"])
        return ex, masks.partial(ex, p["prefix"], p["suffix"])
    if action == "hmac":
        try:
            return ex, masks.token(ex)
        except RuntimeError:
            return ex, "<16-hex HMAC token>"
    if action == "redact_text":
        from .textpii import redact
        return ex, redact(str(ex))
    if action == "aggregate":
        return ex, "AVG/SUM/COUNT only (+ Laplace noise)" if num else "REDACTED"
    if action == "redact":
        return ex, None if num else "REDACTED"
    return ex, None


def explain(role, table, registry, policy):
    """Per-column decision trace for `role` on `table`, computed with the rewriter's own action_for()."""
    if role not in policy["roles"]:
        raise KeyError(f"unknown role: {role}")
    reg = {t.lower(): c for t, c in registry.items()}
    if table.lower() not in reg:
        raise KeyError(f"table not registered: {table}")
    rf = ((policy.get("row_filters") or {}).get(role) or {}).get(table.lower())
    cols = []
    for col, meta in reg[table.lower()].items():
        action = action_for(meta, role, policy)
        ex_in, ex_out = preview(meta, action, policy)
        _, name, detail = ACTIONS.get(action, ACTIONS["deny"])
        cols.append({"column": col, "sql_type": meta.get("sql_type"), "tag": meta.get("tag") or "PUBLIC",
                     "kind": meta.get("kind"), "confidence": meta.get("confidence"), "source": meta.get("source"),
                     "evidence": meta.get("evidence"), "action": action, "action_label": name,
                     "transformation": detail, "rule": _rule_source(meta, role, policy),
                     "example_in": ex_in, "example_out": ex_out})
    return {"role": role, "table": table.lower(), "policy_version": version(policy),
            "row_filter": rf, "max_rows": (policy.get("max_rows") or {}).get(role),
            "min_group_size": (policy.get("min_group_size") or {}).get(role), "columns": cols,
            "note": "Examples are synthetic and generated from the masking functions; no database values are shown."}


def matrix(registry, policy):
    """Every tagged column x every role -> action."""
    rows = []
    for t, cols in sorted(registry.items()):
        for c, m in cols.items():
            rows.append({"table": t, "column": c, "tag": m.get("tag") or "PUBLIC", "kind": m.get("kind"),
                         **{r: action_for(m, r, policy) for r in policy["roles"]}})
    return {"roles": list(policy["roles"]), "policy_version": version(policy), "rows": rows}


def validate(policy):
    """Problems that make a policy unsafe to load. Returns a list of strings (empty = valid)."""
    errs = []
    if policy.get("default_action", "deny") not in ("deny", "redact"):
        errs.append("default_action must be deny or redact (fail closed)")
    for r, rules in (policy.get("roles") or {}).items():
        for tag, a in (rules or {}).items():
            if a not in ACTIONS:
                errs.append(f"roles.{r}.{tag}: unknown action {a!r}")
    for r, tables in (policy.get("row_filters") or {}).items():
        if r not in policy.get("roles", {}):
            errs.append(f"row_filters.{r}: unknown role")
        for t, f in (tables or {}).items():
            try:
                compile_row_filter(f, t)
            except Exception as e:
                errs.append(f"row_filters.{r}.{t}: {e}")
    for r, info in (policy.get("role_info") or {}).items():
        for c in info.get("capabilities", []):
            if c not in CAPABILITIES:
                errs.append(f"role_info.{r}: unknown capability {c!r}")
    return errs


class PolicyError(ValueError):
    pass


class PolicyStore:
    """Holds the live policy. Edits are validated, versioned, appended to a history file and audited by the caller.

    Runtime edits change the in-memory policy (the YAML file stays the reviewed baseline; `reset` returns to it).
    A change that makes a rule less strict must be confirmed explicitly; a role can never be granted `allow` on a tag
    unless it already holds it or the change is confirmed with a reason.
    """

    def __init__(self, policy, history_path=None):
        errs = validate(policy)
        if errs:
            raise PolicyError("; ".join(errs))
        self.baseline = copy.deepcopy(policy)
        self.policy = policy
        self.history_path, self.lock = history_path, threading.Lock()

    def history(self, n=50):
        if not self.history_path or not os.path.exists(self.history_path):
            return []
        return [json.loads(l) for l in open(self.history_path) if l.strip()][-n:]

    def _record(self, entry):
        if self.history_path:
            os.makedirs(os.path.dirname(self.history_path) or ".", exist_ok=True)
            with open(self.history_path, "a") as f:
                f.write(json.dumps(entry) + "\n")

    def check_rule(self, role, tag, action):
        """Dry run: (current action, warnings, weakening?) for a proposed change."""
        if role not in self.policy["roles"]:
            raise PolicyError(f"unknown role: {role}")
        if action not in ACTIONS:
            raise PolicyError(f"unknown action: {action}; choose one of {', '.join(ACTIONS)}")
        current = self.policy["roles"][role].get(tag, self.policy.get("default_action", "deny"))
        weaker = strictness(action) < strictness(current)
        warnings = []
        if weaker:
            warnings.append(f"weakens {role}/{tag}: {current} -> {action}")
        if action == "allow" and tag in ("PII_HIGH", "FINANCIAL_CONFIDENTIAL") and role != "admin":
            warnings.append(f"grants raw {tag} values to non-admin role {role}")
        if action == "aggregate" and tag != "FINANCIAL_CONFIDENTIAL":
            warnings.append("aggregate only adds noise to numeric columns; text columns under this tag are redacted")
        return current, warnings, weaker

    def set_rule(self, role, tag, action, actor, reason="", confirm=False):
        with self.lock:
            current, warnings, weaker = self.check_rule(role, tag, action)
            if current == action:
                return {"changed": False, "version": version(self.policy), "warnings": []}
            if weaker and not (confirm and reason.strip()):
                raise PolicyError("this change weakens protection; resend with confirm=true and a reason")
            before = version(self.policy)
            new = copy.deepcopy(self.policy)
            new["roles"][role][tag] = action
            errs = validate(new)
            if errs:
                raise PolicyError("; ".join(errs))
            self.policy.clear(); self.policy.update(new)  # in place: the gateway holds this dict
            entry = {"ts": time.time(), "actor": actor, "change": "set_rule", "role": role, "tag": tag,
                     "from": current, "to": action, "reason": reason, "weakening": weaker,
                     "version_before": before, "version_after": version(self.policy)}
            self._record(entry)
            return {"changed": True, "version": entry["version_after"], "warnings": warnings, "entry": entry}

    def reset(self, actor):
        with self.lock:
            before = version(self.policy)
            self.policy.clear(); self.policy.update(copy.deepcopy(self.baseline))
            entry = {"ts": time.time(), "actor": actor, "change": "reset", "version_before": before,
                     "version_after": version(self.policy)}
            self._record(entry)
            return entry
