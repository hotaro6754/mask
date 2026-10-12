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


ALLOWED_FUNCS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "substring", "coalesce", "abs",
                 "round", "trim", "concat", "dpipe", "cast", "trycast", "nullif", "if", "case", "extract",
                 "currentdate", "floor", "ceil",
                 "and", "or", "xor", "exists"}  # sqlglot models these operators as Func nodes
ROOTS = (exp.Select, exp.SetOperation)
FORBIDDEN = (exp.Into, exp.Lock, exp.Command, exp.Pragma, exp.Set)
DEFAULT_SCHEMA = {"sqlite": "main", "postgres": "public"}


@dataclass
class Result:
    sql: str
    masked: list = field(default_factory=list)
    shape: dict = field(default_factory=dict)  # what the query does, for the threat engine (no literal values)


def _shape(tree, jobs, registry, role, policy):
    """Query features for insider-threat detection, computed before rewriting."""
    masked_cols = {c.lower() for t in jobs for c, m in registry[t.name.lower()].items()
                   if action_for(m, role, policy) != "allow"}
    pred_nodes = list(tree.find_all(exp.Where, exp.Having)) + [j.args["on"] for j in tree.find_all(exp.Join) if j.args.get("on")]
    pred_cols = {c.name.lower() for n in pred_nodes for c in n.find_all(exp.Column)}
    order_cols = {c.name.lower() for o in tree.find_all(exp.Order) for c in o.find_all(exp.Column)}
    lits = [l.this for l in tree.find_all(exp.Literal)]
    lim = tree.args.get("limit") if isinstance(tree, exp.Select) else None
    lim_n = lim.expression.name if lim is not None and lim.expression is not None else ""
    top = tree if isinstance(tree, exp.Select) else None
    return {"tables": sorted({t.name.lower() for t in jobs}),
            "n_literals": len(lits), "literal_hash": hash(tuple(lits)) & 0xFFFFFFFF,
            "pred_masked": len(pred_cols & masked_cols), "order_masked": len(order_cols & masked_cols),
            "small_limit": bool(lim_n.isdigit() and int(lim_n) <= 5), "offset": bool(top is not None and top.args.get("offset")),
            "aggregate": bool(top is not None and _is_aggregate(top)), "star": any(isinstance(e, exp.Star) for e in (top.expressions if top else []))}


def _as_text(c):
    return exp.Cast(this=c, to=exp.DataType.build("text"))


def _mask_expr(col, meta, action, policy):
    c = exp.column(col, quoted=True)
    kind, num = meta.get("kind"), meta.get("type") == "num"
    fn = lambda name, *args: exp.Anonymous(this=name, expressions=list(args))
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
        return fn("mg_hmac", _as_text(c))
    if action == "redact_text":  # identifiers inside free text -> [PHONE], [AADHAAR], ...
        return fn("mg_redact_text", _as_text(c))
    if action == "redact":  # typed NULL keeps avg()/sum() valid on Postgres
        return exp.Cast(this=exp.Null(), to=exp.DataType.build("double")) if num else exp.Literal.string("REDACTED")
    return exp.Cast(this=exp.Null(), to=exp.DataType.build("double" if num else "text"))  # deny / unknown action


def _validate(tree):
    if not isinstance(tree, ROOTS):
        raise Rejected("only a single SELECT is allowed")
    for node in tree.walk():
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


def action_for(meta, role, policy):
    if not meta.get("tag"):
        return "allow"
    return policy["roles"][role].get(meta["tag"], policy["default_action"])


def rewrite(sql, role, registry, policy, dialect="sqlite"):
    if role not in policy["roles"]:
        raise Rejected(f"unknown role: {role}")
    try:
        stmts = sqlglot.parse(sql, dialect=dialect)
    except Exception as e:
        raise Rejected(f"unparseable SQL: {e}") from None
    if len(stmts) != 1 or stmts[0] is None:
        raise Rejected("exactly one statement is required")
    tree = stmts[0]
    _validate(tree)

    schema = DEFAULT_SCHEMA.get(dialect, "public")
    k = (policy.get("min_group_size") or {}).get(role)
    if k:
        for select in list(tree.find_all(exp.Select)):
            if _is_aggregate(select):
                _apply_group_floor(select, k)

    registry = {t.lower(): cols for t, cols in registry.items()}
    masked, jobs = [], []
    for scope in traverse_scope(tree):
        for table in scope.tables:
            if isinstance(scope.sources.get(table.alias_or_name), exp.Table):  # base table, not CTE/subquery
                if table.args.get("catalog") or (table.args.get("db") and table.text("db").lower() != schema):
                    raise Rejected(f"only the {schema} schema is allowed")
                if table.name.lower() not in registry:
                    raise Rejected(f"table not registered: {table.name}")
                jobs.append(table)
    shape = _shape(tree, jobs, registry, role, policy)
    for table in jobs:
        projections = []
        for col, meta in registry[table.name.lower()].items():
            action = action_for(meta, role, policy)
            if action != "allow":
                masked.append(f"{table.name.lower()}.{col}:{action}")
            projections.append(_mask_expr(col, meta, action, policy).as_(col, quoted=True))
        inner = exp.Table(this=exp.to_identifier(table.name), db=exp.to_identifier(schema))  # pinned: a CTE can't capture it
        table.replace(exp.select(*projections).from_(inner).subquery(table.alias_or_name))

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
    return Result(tree.sql(dialect=dialect), sorted(set(masked)), shape)
