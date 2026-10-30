"""Rewrite one SELECT so every base table is read through a masked derived table.

    FROM users  ->  FROM (SELECT "id", mg_email(CAST("email" AS TEXT)) AS "email", ... FROM main.users) AS users

Aliases, SELECT *, CTEs, subqueries, joins, predicates, ORDER BY and aggregates then only ever see masked
values. Anything that isn't a single SELECT, or touches an unregistered table or function, is rejected.
"""

from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope


class Rejected(Exception):
    pass


ALLOWED_FUNCS = {
    "count",
    "sum",
    "avg",
    "min",
    "max",
    "lower",
    "upper",
    "length",
    "substring",
    "coalesce",
    "abs",
    "round",
    "trim",
    "concat",
    "dpipe",
    "cast",
    "trycast",
    "nullif",
    "if",
    "case",
    "extract",
    "currentdate",
    "floor",
    "ceil",
    "and",
    "or",
    "xor",
    "exists",
}  # sqlglot models these operators as Func nodes
ROOTS = (exp.Select, exp.SetOperation)
FORBIDDEN = (
    exp.Into,
    exp.Lock,
    exp.Command,
    exp.Pragma,
    exp.Set,
    exp.Parameter,
    exp.SessionParameter,
    exp.Placeholder,
)  # variables could expose session secrets
DEFAULT_SCHEMA = {"sqlite": "main", "postgres": "public"}


@dataclass
class Result:
    sql: str
    masked: list = field(default_factory=list)
    shape: dict = field(default_factory=dict)  # what the query does, for the threat engine (no literal values)
    dp: dict = None  # differential-privacy plan when protected aggregates are used


DP_FUNCS = (exp.Sum, exp.Avg, exp.Count)


def _dp_bounds(policy, table, col):
    b = (policy.get("dp") or {}).get("bounds") or {}
    lo, hi = b.get(f"{table}.{col}") or b.get(col) or b.get("default") or [0, 1_000_000]
    return float(lo), float(hi)


def _dp_columns(jobs, registry, role, policy):
    """Numeric columns this role may only see through DP aggregates: {(alias, name): (table, lo, hi)}.
    Keyed by the table's alias so same-named columns in joined tables keep their own bounds."""
    out = {}
    for t in jobs:
        table = t.name.lower()
        for c, m in registry[table].items():
            if m.get("type") == "num" and action_for(m, role, policy) == "aggregate":
                out[(t.alias_or_name.lower(), c.lower())] = (table, *_dp_bounds(policy, table, c.lower()))
    return out


AMBIGUOUS = object()


def _dp_key(col, dp_cols):
    """The DP column a reference points at: its key, None if it isn't one, AMBIGUOUS if that can't be told."""
    name, qual = col.name.lower(), col.table.lower()
    if qual:
        return (qual, name) if (qual, name) in dp_cols else None
    hits = [k for k in dp_cols if k[1] == name]
    return hits[0] if len(hits) == 1 else (AMBIGUOUS if hits else None)


def _dp_eligible(tree, dp_cols):
    """True only if every reference to a DP column is SUM/AVG/COUNT(col) directly in the top-level SELECT list."""
    if not isinstance(tree, exp.Select) or tree.args.get("with") or len(list(tree.find_all(exp.Select))) != 1:
        return False
    if any(
        isinstance(e, exp.Star) or (isinstance(e, exp.Column) and isinstance(e.this, exp.Star))
        for e in tree.expressions
    ):
        return False
    for c in tree.find_all(exp.Column):
        key = _dp_key(c, dp_cols)
        if key is AMBIGUOUS:  # fail closed: the column then stays redacted outside DP
            return False
        if key is None:
            continue
        agg = c.parent
        if not isinstance(agg, DP_FUNCS) or agg.args.get("this") is not c:
            return False
        holder = agg.parent
        if holder is tree:
            continue
        if not (isinstance(holder, exp.Alias) and holder.parent is tree):
            return False
    return True


def _dp_plan(tree, dp_cols, policy):
    """Rewrite AVG(col) -> SUM(col) + hidden COUNT(col), and describe the noise to add per output column."""
    eps = float((policy.get("dp") or {}).get("epsilon_per_query", 0.5))
    ops, extra = [], []
    n_visible = len(tree.expressions)
    for i, proj in enumerate(list(tree.expressions)):
        node = proj.this if isinstance(proj, exp.Alias) else proj
        if not isinstance(node, DP_FUNCS) or not isinstance(node.this, exp.Column):
            continue
        key = _dp_key(node.this, dp_cols)
        if key is None or key is AMBIGUOUS:
            continue
        _, lo, hi = dp_cols[key]
        sens = max(abs(lo), abs(hi))
        if isinstance(node, exp.Count):
            ops.append({"index": i, "type": "count", "epsilon": eps})
        elif isinstance(node, exp.Sum):
            ops.append({"index": i, "type": "sum", "epsilon": eps, "sensitivity": sens})
        else:
            col = node.this.copy()
            node.replace(exp.Sum(this=node.this.copy()))
            extra.append(exp.Count(this=col).as_(f"__mg_cnt_{i}"))
            ops.append(
                {
                    "index": i,
                    "type": "avg",
                    "epsilon": eps,
                    "sensitivity": sens,
                    "lo": lo,
                    "hi": hi,
                    "count_index": n_visible + len(extra) - 1,
                }
            )
    for e in extra:
        tree.append("expressions", e)
    return {"ops": ops, "n_visible": n_visible, "epsilon": eps, "cost": round(eps * len(ops), 4)}


def _shape(tree, jobs, registry, role, policy):
    """Query features for insider-threat detection, computed before rewriting."""
    masked_cols = {
        c.lower() for t in jobs for c, m in registry[t.name.lower()].items() if action_for(m, role, policy) != "allow"
    }
    pred_nodes = list(tree.find_all(exp.Where, exp.Having)) + [
        j.args["on"] for j in tree.find_all(exp.Join) if j.args.get("on")
    ]
    pred_cols = {c.name.lower() for n in pred_nodes for c in n.find_all(exp.Column)}
    order_cols = {c.name.lower() for o in tree.find_all(exp.Order) for c in o.find_all(exp.Column)}
    lits = [lit.this for lit in tree.find_all(exp.Literal)]
    lim = tree.args.get("limit") if isinstance(tree, exp.Select) else None
    lim_n = lim.expression.name if lim is not None and lim.expression is not None else ""
    top = tree if isinstance(tree, exp.Select) else None
    return {
        "tables": sorted({t.name.lower() for t in jobs}),
        "n_literals": len(lits),
        "literal_hash": hash(tuple(lits)) & 0xFFFFFFFF,
        "pred_masked": len(pred_cols & masked_cols),
        "order_masked": len(order_cols & masked_cols),
        "small_limit": bool(lim_n.isdigit() and int(lim_n) <= 5),
        "offset": bool(top is not None and top.args.get("offset")),
        "aggregate": bool(top is not None and _is_aggregate(top)),
        "star": any(isinstance(e, exp.Star) for e in (top.expressions if top else [])),
    }


def _as_text(c):
    return exp.Cast(this=c, to=exp.DataType.build("text"))


def token_settings(policy):
    """(hex length, scope mode) for the hmac action: 32 hex = 128 bits by default; scope "global" keeps tokens
    joinable across tables and columns, "column" gives every column its own tokens (no linking through tokens)."""
    h = policy.get("hmac") or {}
    return int(h.get("length", 32)), h.get("scope", "global")


def _mask_expr(col, meta, action, policy, dp_bounds=None, scope=""):
    c = exp.column(col, quoted=True)
    kind, num = meta.get("kind"), meta.get("type") == "num"

    def fn(name, *args):
        return exp.Anonymous(this=name, expressions=list(args))

    if action == "allow":
        return c
    if action == "partial":
        if num:
            return fn("mg_bucket", c, exp.Literal.number(policy.get("bucket_size", 10000)))
        if kind in ("email", "upi"):
            return fn("mg_email", _as_text(c))
        p = policy["partial"].get(kind, policy["partial"]["default"])
        return fn("mg_partial", _as_text(c), exp.Literal.number(p["prefix"]), exp.Literal.number(p["suffix"]))
    if action == "hmac":
        length, mode = token_settings(policy)
        return fn(
            "mg_token", _as_text(c), exp.Literal.string(scope if mode == "column" else ""), exp.Literal.number(length)
        )
    if action == "redact_text":  # identifiers inside free text -> [PHONE], [AADHAAR], ...
        return fn("mg_redact_text", _as_text(c))
    if action == "aggregate":
        if num and dp_bounds:  # usable only through noisy SUM/AVG/COUNT: clip to bound each person's influence
            lo, hi = dp_bounds
            return exp.Least(
                this=exp.Greatest(this=c, expressions=[exp.Literal.number(lo)]), expressions=[exp.Literal.number(hi)]
            )
        action = "redact"  # any other use of the column: fail closed
    if action == "redact":  # typed NULL keeps avg()/sum() valid on Postgres
        return exp.Cast(this=exp.Null(), to=exp.DataType.build("double")) if num else exp.Literal.string("REDACTED")
    return exp.Cast(this=exp.Null(), to=exp.DataType.build("double" if num else "text"))  # deny / unknown action


def _validate(tree):
    if not isinstance(tree, ROOTS):
        raise Rejected("only a single SELECT is allowed")
    for node in tree.walk():
        if isinstance(node, exp.With) and node.args.get("recursive"):
            raise Rejected("recursive queries are not allowed")
        if isinstance(node, FORBIDDEN):
            raise Rejected(f"{type(node).__name__} is not allowed")
        if isinstance(node, exp.Func) and node.key not in ALLOWED_FUNCS:
            raise Rejected(f"function not allowed: {node.name or node.key}")


def _is_aggregate(select):
    if select.args.get("group"):
        return True
    return any(agg.parent_select is select for e in select.expressions for agg in e.find_all(exp.AggFunc))


def _apply_group_floor(select, k):
    """Small-cell suppression: aggregate results built from fewer than k rows are dropped."""
    floor = exp.GTE(this=exp.Count(this=exp.Star()), expression=exp.Literal.number(k))
    having = select.args.get("having")
    select.set("having", exp.Having(this=exp.and_(having.this, floor) if having else floor))


ROW_FILTER_NODES = (
    exp.Column,
    exp.Identifier,
    exp.Literal,
    exp.Null,
    exp.Boolean,
    exp.Paren,
    exp.Tuple,
    exp.Neg,
    exp.EQ,
    exp.NEQ,
    exp.GT,
    exp.GTE,
    exp.LT,
    exp.LTE,
    exp.And,
    exp.Or,
    exp.Not,
    exp.In,
    exp.Is,
    exp.Between,
)


def compile_row_filter(sql, table):
    """Parse a policy row filter ("status <> 'frozen'"); only column-vs-literal comparisons are accepted."""
    tree = sqlglot.parse_one(sql)
    for node in tree.walk():
        if not isinstance(node, ROW_FILTER_NODES):
            raise ValueError(f"row filter for {table} may only compare columns with literals: {sql}")
    return tree


def _row_filter(policy, role, table, real_table, columns):
    """Policy row filter for this role and table, with columns pinned to the real table (or None)."""
    sql = ((policy.get("row_filters") or {}).get(role) or {}).get(table)
    if not sql:
        return None
    try:
        cond = compile_row_filter(sql, table)
    except Exception:  # noqa: BLE001 (a row filter that does not compile refuses the query: fail closed)
        raise Rejected("row filter in policy is invalid; refusing the query") from None
    real_cols = {c.lower(): c for c in columns}
    for c in cond.find_all(exp.Column):
        if c.name.lower() not in real_cols:
            raise Rejected("row filter in policy references an unknown column; refusing the query")
        c.replace(exp.column(real_cols[c.name.lower()], table=real_table, quoted=True))
    return cond


PUBLIC = "PUBLIC"  # a person reviewed the column and approved it as non-personal (overrides.yaml)
UNREVIEWED = "UNREVIEWED"  # the scanner found nothing, and nobody has approved it: not the same as safe


def tag_of(meta):
    return meta.get("tag") or UNREVIEWED


def action_for(meta, role, policy):
    tag = tag_of(meta)
    if tag == PUBLIC:
        return "allow"
    return policy["roles"][role].get(tag, policy["default_action"])  # no rule for UNREVIEWED -> default (fail closed)


def _materialize_joined(owners, masked_cols):
    """MySQL merges each masked view into the outer query (fast: functions run only on the rows that come back). But a
    join *on a masked column* would then re-run the mask function for every pair of rows compared; such views get a
    NO_MERGE hint so MySQL computes them once. Returns {select: [aliases]}."""
    out = {}
    for select, aliases in owners.items():
        conds = [j.args["on"] for j in select.args.get("joins") or [] if j.args.get("on") is not None]
        names = [i.name.lower() for j in select.args.get("joins") or [] for i in (j.args.get("using") or [])]
        where = select.args.get("where")
        if where is not None:  # comma joins: a comparison between two columns
            conds += [
                p
                for p in where.find_all(exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE, exp.NullSafeEQ)
                if len(list(p.find_all(exp.Column))) > 1
            ]
        hit = set()
        for c in (col for cond in conds for col in cond.find_all(exp.Column)):
            if c.table:
                if c.name.lower() in masked_cols.get(c.table.lower(), ()):
                    hit.add(c.table.lower())
            else:
                names.append(c.name.lower())
        hit |= {a for a in aliases for n in names if n in masked_cols.get(a, ())}
        if hit:
            out[select] = sorted(hit)
    return out


def rewrite(sql, role, registry, policy, dialect="sqlite", schema=None):
    if role not in policy["roles"]:
        raise Rejected(f"unknown role: {role}")
    # every path (API, CLI, SDK, proxy, dashboards) reaches the data through here; a role with no role_info
    # entry keeps policy.DEFAULT_CAPABILITIES, which is ["query"]
    if "query" not in ((policy.get("role_info") or {}).get(role) or {}).get("capabilities", ["query"]):
        raise Rejected(f"role '{role}' lacks capability 'query'")
    try:
        stmts = sqlglot.parse(sql, dialect=dialect)
    except Exception as e:  # noqa: BLE001 (sqlglot's message quotes the SQL, which can contain personal data: report position only)
        errs = getattr(e, "errors", None) or [{}]
        where = f" (line {errs[0].get('line')}, col {errs[0].get('col')})" if errs[0].get("line") else ""
        raise Rejected(f"unparseable SQL{where}") from None
    if len(stmts) != 1 or stmts[0] is None:
        raise Rejected("exactly one statement is required")
    tree = stmts[0]
    _validate(tree)
    for hint in list(tree.find_all(exp.Hint)):  # MySQL /*+ ... */ hints could lift the time limit (MAX_EXECUTION_TIME,
        hint.pop()  # SET_VAR) or change the plan; the client gets none of them

    schema = (schema or DEFAULT_SCHEMA.get(dialect, "public")).lower()
    k = (policy.get("min_group_size") or {}).get(role)
    if k:
        for select in list(tree.find_all(exp.Select)):
            if _is_aggregate(select):
                _apply_group_floor(select, k)

    real_names = {t.lower(): t for t in registry}  # canonical spelling as found in the database
    registry = {t.lower(): cols for t, cols in registry.items()}
    masked, jobs, owners = [], [], {}
    for scope in traverse_scope(tree):
        for table in scope.tables:
            if isinstance(scope.sources.get(table.alias_or_name), exp.Table):  # base table, not CTE/subquery
                if table.args.get("catalog") or (table.args.get("db") and table.text("db").lower() != schema):
                    raise Rejected(f"only the {schema} schema is allowed")
                if table.name.lower() not in registry:
                    raise Rejected(f"table not registered: {table.name}")
                jobs.append(table)
                if isinstance(scope.expression, exp.Select):
                    owners.setdefault(scope.expression, []).append(table.alias_or_name.lower())
    shape = _shape(tree, jobs, registry, role, policy)
    dp_cols = _dp_columns(jobs, registry, role, policy)
    refs = [_dp_key(c, dp_cols) for c in tree.find_all(exp.Column)]
    used = {k[1] for k in refs if k is not None and k is not AMBIGUOUS}
    dp_plan = None
    if used and _dp_eligible(tree, dp_cols):
        dp_plan = _dp_plan(tree, dp_cols, policy)
        dp_plan["columns"] = sorted(used)
    no_merge = {}
    if dialect == "mysql":
        masked_cols = {
            t.alias_or_name.lower(): {
                c.lower() for c, m in registry[t.name.lower()].items() if action_for(m, role, policy) != "allow"
            }
            for t in jobs
        }
        no_merge = _materialize_joined(owners, masked_cols)
    for table in jobs:
        projections = []
        for col, meta in registry[table.name.lower()].items():
            action = action_for(meta, role, policy)
            if action != "allow":
                masked.append(f"{table.name.lower()}.{col}:{action}")
            key = (table.alias_or_name.lower(), col.lower())
            bounds = dp_cols[key][1:] if dp_plan and key in dp_cols else None
            projections.append(
                _mask_expr(col, meta, action, policy, bounds, scope=f"{table.name.lower()}.{col.lower()}").as_(
                    col, quoted=True
                )
            )
        inner = exp.Table(
            this=exp.to_identifier(real_names[table.name.lower()], quoted=True), db=exp.to_identifier(schema)
        )  # pinned to the real table: a CTE can't capture it
        view = exp.select(*projections).from_(inner)
        cond = _row_filter(
            policy, role, table.name.lower(), real_names[table.name.lower()], registry[table.name.lower()]
        )
        if cond is not None:  # row-level security: rows outside the role's scope never enter the view
            view = view.where(cond)
            masked.append(f"{table.name.lower()}:row_filter")
        table.replace(view.subquery(table.alias_or_name))
    for select, aliases in no_merge.items():
        select.set(
            "hint",
            exp.Hint(expressions=[exp.Anonymous(this="NO_MERGE", expressions=[exp.to_identifier(a)]) for a in aliases]),
        )

    cap = (policy.get("max_rows") or {}).get(role)
    if cap:
        if isinstance(tree, exp.Select):
            lim = tree.args.get("limit")
            n = lim.expression.name if lim is not None and lim.expression is not None else None
            if n is None or not n.isdigit() or int(n) > cap:
                tree.set("limit", None)
                tree = tree.limit(cap)
        else:
            tree = exp.select("*").from_(tree.subquery("q")).limit(cap)
    # comments never reach the database: nothing a client writes in one can be executed there (e.g. MySQL /*! */)
    return Result(tree.sql(dialect=dialect, comments=False), sorted(set(masked)), shape, dp_plan)
