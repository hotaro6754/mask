from dataclasses import dataclass, field
import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import traverse_scope


class Rejected(Exception):
    pass


ALLOWED_FUNCS = {"count", "sum", "avg", "min", "max", "lower", "upper", "length", "substring", "coalesce", "abs",
                 "round", "trim", "concat", "cast", "trycast", "nullif", "if", "extract", "currentdate"}
ROOTS = (exp.Select, exp.SetOperation)
FORBIDDEN = (exp.Into, exp.Lock, exp.Command, exp.Pragma, exp.Set)
DEFAULT_SCHEMA = {"sqlite": "main", "postgres": "public"}


@dataclass
class Result:
    sql: str
    masked: list = field(default_factory=list)


def _mask_expr(col, meta, action, policy):
    c = exp.column(col, quoted=True)
    kind, num = meta.get("kind"), meta.get("type") == "num"
    fn = lambda name, *args: exp.Anonymous(this=name, expressions=list(args))
    if action == "allow":
        return c
    if action == "partial":
        if num:
            return fn("mg_bucket", c, exp.Literal.number(policy.get("bucket_size", 10000)))
        if kind == "email":
            return fn("mg_email", c)
        p = policy["partial"].get(kind, policy["partial"]["default"])
        return fn("mg_partial", c, exp.Literal.number(p["prefix"]), exp.Literal.number(p["suffix"]))
    if action == "hmac":
        return fn("mg_hmac", exp.Cast(this=c, to=exp.DataType.build("text")))
    if action == "redact":
        return exp.Null() if num else exp.Literal.string("REDACTED")
    return exp.Null()  # deny / unknown


def _validate(tree):
    if not isinstance(tree, ROOTS):
        raise Rejected("only a single SELECT is allowed")
    for node in tree.walk():
        if isinstance(node, FORBIDDEN):
            raise Rejected(f"{type(node).__name__} is not allowed")
        if isinstance(node, exp.Func) and node.key not in ALLOWED_FUNCS:
            raise Rejected(f"function not allowed: {node.name or node.key}")


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

    registry = {t.lower(): cols for t, cols in registry.items()}
    masked, jobs = [], []
    for scope in traverse_scope(tree):
        for table in scope.tables:
            if isinstance(scope.sources.get(table.alias_or_name), exp.Table):  # base table, not CTE/subquery
                if table.name.lower() not in registry:
                    raise Rejected(f"table not registered: {table.name}")
                jobs.append(table)
    for table in jobs:
        projections = []
        for col, meta in registry[table.name.lower()].items():
            action = "allow" if not meta.get("tag") else policy["roles"][role].get(meta["tag"], policy["default_action"])
            if action != "allow":
                masked.append(f"{table.name.lower()}.{col}:{action}")
            projections.append(_mask_expr(col, meta, action, policy).as_(col, quoted=True))
        inner = table.copy()
        inner.set("alias", None)
        if not inner.args.get("db"):  # pin to the real schema so a CTE named like the table can't capture it
            inner.set("db", exp.to_identifier(DEFAULT_SCHEMA.get(dialect, "public")))
        table.replace(exp.select(*projections).from_(inner).subquery(table.alias_or_name))

    cap = policy.get("max_rows", {}).get(role)
    if cap:
        if isinstance(tree, exp.Select):
            lim = tree.args.get("limit")
            n = lim.expression.name if lim is not None and lim.expression is not None else None
            if n is None or not n.isdigit() or int(n) > cap:
                tree.set("limit", None)
                tree = tree.limit(cap)
        else:
            tree = exp.select("*").from_(tree.subquery("q")).limit(cap)
    return Result(tree.sql(dialect=dialect), masked)
