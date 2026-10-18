"""maskguard: the MaskGuard command-line interface.

Run `maskguard` with no arguments in a terminal for the interactive console, or `maskguard --help` for commands.
Results go to stdout (use --json for machine-readable output); banners, progress and diagnostics go to stderr.

Exit codes: 0 ok · 1 error · 2 usage · 3 denied (policy, firewall or credentials) · 4 unavailable (database/API)
            5 integrity check failed · 6 security regression test failed
"""
import csv, getpass, json, os, shutil, sys, time
from typing import List, Optional

import typer
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from . import __version__, config
from .attacks import SelfTestDisabled, require_self_test
from .service import Denied, Unavailable, connect

OK, ERROR, USAGE, DENIED, UNAVAILABLE, INTEGRITY_FAILED, SECURITY_FAILED = 0, 1, 2, 3, 4, 5, 6
VERSION = __version__

# palette: cyan = system info, green = verified, amber = warning, red = denied/failure. Every status also has a word.
C = {"info": "cyan", "ok": "green3", "warn": "dark_orange", "bad": "red1", "muted": "grey58", "accent": "chartreuse3"}
ACTION_STYLE = {"allow": C["ok"], "partial": "gold3", "redact_text": "gold3", "hmac": "medium_purple1",
                "aggregate": "deep_sky_blue1", "redact": C["bad"], "deny": C["bad"], "row_filter": "deep_sky_blue1"}

out = Console(highlight=False, soft_wrap=False)
err = Console(stderr=True, highlight=False)
state = {"api": None, "user": None, "password": None, "service": None, "json": False}

app = typer.Typer(add_completion=False, no_args_is_help=False, rich_markup_mode="rich",
                  pretty_exceptions_show_locals=False,
                  help="[bold]MaskGuard[/] · PII discovery and query-time, role-based masking for SQLite, PostgreSQL and MySQL.\n\n"
                       "Run [bold]maskguard[/] with no arguments for the interactive console.")
db_app = typer.Typer(help="Database connection and schema.", no_args_is_help=True)
pii_app = typer.Typer(help="PII classifications found by the scanner.", no_args_is_help=True)
roles_app = typer.Typer(help="Roles, capabilities and their masking rules.", no_args_is_help=True)
policy_app = typer.Typer(help="Inspect, explain and change the masking policy.", no_args_is_help=True)
audit_app = typer.Typer(help="Hash-chained audit trail.", no_args_is_help=True)
integrity_app = typer.Typer(help="Prove that masking never changes the source data.", invoke_without_command=True)
for name, sub in (("db", db_app), ("pii", pii_app), ("roles", roles_app), ("policy", policy_app), ("audit", audit_app),
                  ("integrity", integrity_app)):
    app.add_typer(sub, name=name)


# ---------------------------------------------------------------- branding

LETTERS = {
    "M": ["███╗   ███╗", "████╗ ████║", "██╔████╔██║", "██║╚██╔╝██║", "██║ ╚═╝ ██║", "╚═╝     ╚═╝"],
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "K": ["██╗  ██╗", "██║ ██╔╝", "█████╔╝ ", "██╔═██╗ ", "██║  ██╗", "╚═╝  ╚═╝"],
    "G": [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
}
TAGLINE = "PII DISCOVERY  ·  DYNAMIC MASKING  ·  POLICY ENFORCEMENT  ·  AUDIT"


def _unicode_ok(console):
    enc = (getattr(console.file, "encoding", None) or "utf-8").lower()
    try:
        "█╗·━".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def banner(console=err):
    """Two-tone wordmark: MASK in steel, GUARD in the accent. Falls back to one line on narrow or non-UTF-8 terminals."""
    if console.width >= 80 and _unicode_ok(console):
        lines = []
        for i in range(6):
            t = Text("  ")
            t.append("".join(LETTERS[c][i] for c in "MASK"), style="bold grey70")
            t.append("".join(LETTERS[c][i] for c in "GUARD"), style=f"bold {C['accent']}")
            lines.append(t)
        sub = Text("  " + TAGLINE, style=C["info"])
        console.print(Group(*lines, sub))
    else:
        t = Text("[#] MASK", style="bold")
        t.append("GUARD", style=f"bold {C['accent']}")
        t.append(f"  v{VERSION}  data security engine", style=C["muted"])
        console.print(t)


def status_label(ok, warn=False):
    if ok and warn:  # works, degraded: no change to the exit code
        return Text("WARN", style=f"bold {C['warn']}")
    return Text("PASS", style=f"bold {C['ok']}") if ok else Text("FAIL", style=f"bold {C['bad']}")


def status_panel(st, console=err):
    """Only real checks: nothing is shown as READY unless the check above ran and passed."""
    g = Table.grid(padding=(0, 2))
    g.add_column(style="bold", min_width=19); g.add_column(min_width=6); g.add_column(style=C["muted"])
    for c in st["checks"]:
        g.add_row(c["name"].upper(), status_label(c["ok"], c.get("warn")), c["detail"])
    mode = f"{st['mode'].upper()} · {st['environment']} · demo identities {'ON' if st['demo_mode'] else 'OFF'}"
    if st.get("api"):
        mode += f" · {st['api']}"
    g.add_row("MODE", Text("INFO", style=f"bold {C['info']}"), mode)
    console.print(Panel(g, box=box.ROUNDED, border_style=C["info"], title="[bold]engine status[/]", title_align="left",
                        expand=False))


# ---------------------------------------------------------------- helpers

def svc():
    if state["service"] is None:
        with err.status("[cyan]starting engine…[/]", spinner="dots"):
            state["service"] = connect(state["api"], state["user"], state["password"])
    return state["service"]


def emit_json(obj):
    sys.stdout.write(json.dumps(obj, indent=2, default=str, ensure_ascii=False) + "\n")


def fail(msg, code):
    err.print(Text.assemble(("✖ " if _unicode_ok(err) else "x ", C["bad"]),
                            ({DENIED: "DENIED", UNAVAILABLE: "UNAVAILABLE", USAGE: "USAGE", INTEGRITY_FAILED: "INTEGRITY FAILED",
                              SECURITY_FAILED: "SECURITY TEST FAILED"}.get(code, "ERROR"), f"bold {C['bad']}"), f"  {msg}"))
    raise typer.Exit(code)


def guarded(fn):
    """Map service errors to stable exit codes; never print tracebacks (they can contain configuration)."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            return fn(*a, **kw)
        except typer.Exit:
            raise
        except typer.BadParameter as e:
            fail(f"invalid usage: {e}", USAGE)
        except (Denied, SelfTestDisabled) as e:
            fail(str(e), DENIED)
        except Unavailable as e:
            fail(str(e), UNAVAILABLE)
        except config.UnsafeConfiguration as e:  # the whole list: the operator needs every problem, not the first
            fail(str(e), UNAVAILABLE)
        except RuntimeError as e:
            fail(str(e)[:300], UNAVAILABLE)
        except KeyboardInterrupt:
            raise typer.Exit(130)
    return wrapper


def cell(v, width=34):
    s = "NULL" if v is None else str(v)
    return s if len(s) <= width else s[: width - 1] + "…"


def column_actions(result):
    """Display hint: output column -> masking action, from the gateway's list of masked table columns."""
    acts = {}
    for m in result.get("masked", []):
        target, _, action = m.partition(":")
        if "." in target:
            acts.setdefault(target.split(".", 1)[1].lower(), action)
    return acts


def result_table(r, max_rows=20, title=None):
    acts = column_actions(r)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", title=title, title_justify="left", pad_edge=False)
    for c in r["columns"]:
        a = acts.get(c.lower())
        head = Text(c)
        if a:
            head.append(f" [{a.upper()}]", style=ACTION_STYLE.get(a, C["warn"]))
        t.add_column(head, overflow="fold", max_width=36)
    for row in r["rows"][:max_rows]:
        t.add_row(*[Text(cell(v), style=ACTION_STYLE.get(acts.get(c.lower()), "")) for c, v in zip(r["columns"], row)])
    return t


def result_footer(r):
    bits = [f"{r['row_count']} rows", f"{r['ms']} ms", f"request {r.get('request_id', '?')}", f"policy {r.get('policy_version', '?')}"]
    if r.get("dp"):
        bits.append(f"ε spent {r['dp']['epsilon']} (left today {r['dp']['remaining']})")
    if r.get("risk"):
        bits.append(f"risk {r['risk']}")
    return Text(" · ".join(bits), style=C["muted"])


def explain_table(ex):
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    t.add_column("Field", no_wrap=True); t.add_column("Classification", no_wrap=True); t.add_column("Conf.", no_wrap=True)
    t.add_column("Policy action", no_wrap=True); t.add_column("Synthetic example → result", overflow="fold")
    t.add_column("Decided by", overflow="fold", style=C["muted"])
    for c in ex["columns"]:
        a = c["action"]
        t.add_row(c["column"], Text(c["tag"], style=TAG_STYLE.get(c["tag"], "")), c.get("confidence") or "—",
                  Text(f"{a.upper()}", style=f"bold {ACTION_STYLE.get(a, '')}"),
                  f"{cell(c['example_in'], 24)} → {cell(c['example_out'], 24)}" if a != "allow" else "unchanged",
                  c["rule"].replace("roles.", "rule "))
    return t


def identity_opts(role, user, password):
    if user and password is None:
        password = getpass.getpass(f"password for {user}: ")
    if not user and not role:
        raise typer.BadParameter("give --role (demo identities) or --user/--password")
    return dict(role=role, user=user, password=password)


# ---------------------------------------------------------------- root

@app.callback(invoke_without_command=True)
def root(ctx: typer.Context,
         api: Optional[str] = typer.Option(None, "--api", envvar="MASKGUARD_API", help="Use a running API instead of the in-process engine."),
         user: Optional[str] = typer.Option(None, "--as-user", envvar="MASKGUARD_USER", help="Operator identity for --api calls."),
         password: Optional[str] = typer.Option(None, "--as-password", envvar="MASKGUARD_PASSWORD", hidden=True),
         no_color: bool = typer.Option(False, "--no-color", help="Disable colour (NO_COLOR is honoured too)."),
         version: bool = typer.Option(False, "--version", help="Print the version and exit.")):
    if no_color:
        out.no_color = err.no_color = True
    state.update(api=api, user=user, password=password, service=None)
    if version:
        sys.stdout.write(f"maskguard {VERSION}\n")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            interactive()
        else:
            banner()
            sys.stdout.write(ctx.get_help() + "\n")


@app.command()
def version():
    """Print the version."""
    sys.stdout.write(f"maskguard {VERSION}\n")


@app.command()
@guarded
def status(json_out: bool = typer.Option(False, "--json")):
    """Engine, database, scanner, policy, audit and integrity status (real checks)."""
    st = svc().status()
    if json_out:
        return emit_json(st)
    banner()
    status_panel(st, out)
    if not all(c["ok"] for c in st["checks"]):
        raise typer.Exit(UNAVAILABLE)


@app.command()
@guarded
def doctor(json_out: bool = typer.Option(False, "--json")):
    """Diagnose the installation: dependencies, configuration, database, model, policy, audit, integrity."""
    import importlib
    checks = []
    for mod in ("sqlglot", "lightgbm", "fastapi", "psycopg", "pymysql", "rich", "typer"):
        try:
            importlib.import_module(mod)
            checks.append({"name": f"python: {mod}", "ok": True, "detail": "importable"})
        except Exception as e:
            if mod == "lightgbm":  # optional at run time: the scanner falls back to rules (and says so)
                from .scanner import ML_HINT
                checks.append({"name": "python: lightgbm", "ok": True, "warn": True,
                               "detail": f"{type(e).__name__}: scanner uses rules only; {ML_HINT}"})
                continue
            checks.append({"name": f"python: {mod}", "ok": mod in ("psycopg", "pymysql"), "detail": type(e).__name__})
    key = os.environ.get("MASKGUARD_HMAC_KEY", "")
    checks.append({"name": "MASKGUARD_HMAC_KEY", "ok": len(key.encode()) >= 16,
                   "detail": "set (≥ 16 bytes)" if len(key.encode()) >= 16 else
                             "too short: use ≥ 16 random bytes" if key else "missing: analyst tokens will fail closed"})
    checks.append({"name": "MASKGUARD_JWT_SECRET", "ok": True,
                   "detail": "set" if os.environ.get("MASKGUARD_JWT_SECRET") else "not set: tokens reset on restart (warning)"})
    try:
        demo = config.demo_enabled()
        checks.append({"name": "demo identities", "ok": True,
                       "detail": f"{'enabled' if demo else 'disabled'} (environment {config.environment()})"})
    except RuntimeError as e:
        checks.append({"name": "demo identities", "ok": False, "detail": str(e)})
    try:
        st = svc().status()
        checks += st["checks"]
    except (Unavailable, RuntimeError) as e:
        checks.append({"name": "engine", "ok": False, "detail": str(e)[:200]})
    if json_out:
        emit_json({"ok": all(c["ok"] for c in checks), "checks": checks})
    else:
        banner()
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
        t.add_column("Check"); t.add_column("Result"); t.add_column("Detail", style=C["muted"])
        for c in checks:
            t.add_row(c["name"], status_label(c["ok"], c.get("warn")), c["detail"])
        out.print(t)
    if not all(c["ok"] for c in checks):
        raise typer.Exit(UNAVAILABLE)


# ---------------------------------------------------------------- db

@db_app.command("list")
@guarded
def db_list(json_out: bool = typer.Option(False, "--json")):
    """Configured backends and the active one."""
    url = os.environ.get("MASKGUARD_DB", "sqlite:///data/bank.db")
    safe = url.split("@")[-1] if "@" in url else url
    rows = [{"backend": b, "supported": True, "active": url.startswith(p), "driver": d}
            for b, p, d in (("sqlite", "sqlite", "stdlib sqlite3"), ("postgresql", "postgres", "psycopg 3"),
                            ("mysql", "mysql", "PyMySQL"))]
    if json_out:
        return emit_json({"active": safe if not state["api"] else state["api"], "backends": rows})
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    t.add_column("Backend"); t.add_column("Driver"); t.add_column("Active")
    for r in rows:
        t.add_row(r["backend"], r["driver"], Text("ACTIVE", style=C["ok"]) if r["active"] else Text("—", style=C["muted"]))
    out.print(t)
    out.print(Text(f"connection: {state['api'] or safe}  (credentials never printed)", style=C["muted"]))


@db_app.command("test")
@guarded
def db_test(json_out: bool = typer.Option(False, "--json")):
    """Connect and run a read-only probe."""
    t0 = time.perf_counter()
    st = svc().status()
    dbc = next(c for c in st["checks"] if c["name"].lower() == "database")
    res = {"ok": dbc["ok"], "detail": dbc["detail"], "backend": st["backend"], "ms": round((time.perf_counter() - t0) * 1000, 1)}
    if json_out:
        emit_json(res)
    else:
        out.print(Text.assemble(status_label(res["ok"]), f"  {res['backend']} · {res['detail']} · {res['ms']} ms"))
    if not res["ok"]:
        raise typer.Exit(UNAVAILABLE)


@db_app.command("inspect")
@guarded
def db_inspect(table: Optional[str] = typer.Argument(None), json_out: bool = typer.Option(False, "--json")):
    """Tables, row counts, and per-column type and classification. No values are read for display."""
    s = svc()
    inv = s.inventory()
    if table:
        inv = [r for r in inv if r["table"] == table.lower()]
        if not inv:
            fail(f"unknown table: {table}", DENIED)
    if json_out:
        return emit_json({"tables": s.tables() if not table else None, "columns": inv})
    if not table:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, title="tables", title_justify="left")
        t.add_column("Table"); t.add_column("Columns", justify="right"); t.add_column("Rows", justify="right"); t.add_column("Scanned")
        for r in s.tables():
            t.add_row(r["table"], str(r["columns"]), "—" if r["rows"] is None else str(r["rows"]),
                      Text("YES", style=C["ok"]) if r["scanned"] else Text("NO (blocked)", style=C["warn"]))
        out.print(t)
    out.print(pii_table(inv, show_public=True))


# ---------------------------------------------------------------- scanner

TAG_STYLE = {"PII_HIGH": C["bad"], "FINANCIAL_CONFIDENTIAL": "gold3", "PII_MEDIUM": C["warn"], "PII_IN_TEXT": "medium_purple1",
             "PUBLIC": C["muted"], "UNREVIEWED": C["warn"]}


def pii_table(rows, show_public=False):
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    for h in ("Table", "Column", "Classification", "Kind", "Confidence"):
        t.add_column(h, no_wrap=True)
    t.add_column("Signals (no values)", overflow="fold", ratio=1)
    for r in rows:
        tag = r.get("tag") or "UNREVIEWED"
        if tag == "PUBLIC" and not show_public:
            continue
        t.add_row(r["table"], r["column"], Text(tag, style=f"bold {TAG_STYLE.get(tag, '')}"), r.get("kind") or "—",
                  r.get("confidence") or "—", Text(cell(r.get("evidence") or "", 70), style=C["muted"]))
    return t


@app.command()
@guarded
def scan(table: Optional[List[str]] = typer.Option(None, "--table", "-t", help="Limit the scan to these tables."),
         sample_limit: int = typer.Option(200, "--sample-limit", min=10, max=5000, help="Values sampled per column."),
         dry_run: bool = typer.Option(False, "--dry-run", help="Classify but do not apply the result."),
         watch: int = typer.Option(0, "--watch", help="Rescan every N seconds (Ctrl-C to stop)."),
         report: Optional[str] = typer.Option(None, "--out", help="Also write a JSON scan report here."),
         json_out: bool = typer.Option(False, "--json"),
         database: Optional[str] = typer.Option(None, "--database", help="sqlite | postgresql | mysql: assert the active backend.")):
    """Scan the database for sensitive columns (LightGBM + checksum validators). Sample values are never printed."""
    s = svc()
    if database and not s.status()["backend"].startswith(database.lower()[:5]):
        fail(f"active backend is {s.status()['backend']}, not {database}; set MASKGUARD_DB", USAGE)
    while True:
        with err.status(f"[cyan]scanning {', '.join(table) if table else 'all tables'} · sample {sample_limit}/column…[/]"):
            r = s.scan(table or None, sample_limit, dry_run)
        if report:
            with open(report, "w") as f:
                json.dump(r, f, indent=2, default=str)
        if json_out:
            emit_json(r)
        else:
            out.print(pii_table(r["tagged"]))
            out.print(Text(f"{len(r['tagged'])} sensitive columns in {len(r['tables'])} tables · {r['ms']} ms · "
                           f"{'DRY RUN: not applied' if dry_run else 'applied to the live registry'} · "
                           f"{r['scanned_at']}", style=C["muted"]))
            err.print(Text("Sampling is probabilistic: a column with no PII in the sample is not proven clean. "
                           "Force tags in policies/overrides.yaml.", style=C["warn"]))
        if not watch:
            break
        time.sleep(watch)


@pii_app.command("list")
@guarded
def pii_list(tag: Optional[str] = typer.Option(None, help="Only this classification."),
             json_out: bool = typer.Option(False, "--json")):
    """Every column classified as sensitive, plus unreviewed columns (masked until approved as PUBLIC)."""
    rows = [r for r in svc().inventory() if r["tag"] != "PUBLIC" and (not tag or r["tag"] == tag.upper())]
    if json_out:
        return emit_json(rows)
    out.print(pii_table(rows))
    by = {}
    for r in rows:
        by[r["tag"]] = by.get(r["tag"], 0) + 1
    out.print(Text(" · ".join(f"{k} {v}" for k, v in sorted(by.items())), style=C["muted"]))


@pii_app.command("show")
@guarded
def pii_show(table: str, json_out: bool = typer.Option(False, "--json")):
    """All columns of one table with classification and evidence."""
    rows = [r for r in svc().inventory() if r["table"] == table.lower()]
    if not rows:
        fail(f"unknown or unscanned table: {table}", DENIED)
    if json_out:
        return emit_json(rows)
    out.print(pii_table(rows, show_public=True))


# ---------------------------------------------------------------- roles & policy

@roles_app.command("list")
@guarded
def roles_list(json_out: bool = typer.Option(False, "--json")):
    """Roles with descriptions and capabilities."""
    rs = svc().roles()
    if json_out:
        return emit_json(rs)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    t.add_column("Role"); t.add_column("Who"); t.add_column("Capabilities", style=C["muted"], overflow="fold")
    for r in rs:
        t.add_row(Text(r["role"], style="bold"), r.get("description", ""), ", ".join(r.get("capabilities", [])))
    out.print(t)


@roles_app.command("show")
@guarded
def roles_show(role: str, json_out: bool = typer.Option(False, "--json")):
    """One role: rules per classification, row filters, limits, capabilities."""
    r = next((x for x in svc().roles() if x["role"] == role), None)
    if r is None:
        fail(f"unknown role: {role}", DENIED)
    if json_out:
        return emit_json(r)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    t.add_column("Classification"); t.add_column("Action")
    for tag, a in r.get("rules", {}).items():
        t.add_row(tag, Text(a.upper(), style=f"bold {ACTION_STYLE.get(a, '')}"))
    info = Table.grid(padding=(0, 2))
    info.add_row("Row filters", ", ".join(f"{k}: {v}" for k, v in (r.get("row_filters") or {}).items()) or "none")
    info.add_row("Row cap", str(r.get("max_rows") or "none"))
    info.add_row("Min group size", str(r.get("min_group_size") or "none"))
    info.add_row("Capabilities", ", ".join(r.get("capabilities", [])))
    out.print(Panel(Group(Text(r.get("description", ""), style=C["muted"]), t, info), title=f"[bold]{role}[/]",
                    title_align="left", border_style=C["info"], box=box.ROUNDED, expand=False))


@policy_app.command("list")
@guarded
def policy_list(json_out: bool = typer.Option(False, "--json")):
    """The role x column matrix: what each role gets for every column."""
    m = svc().matrix()
    if json_out:
        return emit_json(m)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, title=f"policy {m['policy_version']}", title_justify="left")
    t.add_column("Column"); t.add_column("Classification")
    for r in m["roles"]:
        t.add_column(r)
    for row in m["rows"]:
        if row["tag"] == "PUBLIC":
            continue
        t.add_row(f"{row['table']}.{row['column']}", row["tag"],
                  *[Text(row[r].upper(), style=ACTION_STYLE.get(row[r], "")) for r in m["roles"]])
    out.print(t)
    out.print(Text("Strictness: allow < partial < redact_text < hmac < aggregate < redact < deny. "
                   "PUBLIC columns were approved by a person and are always allowed; columns the scanner found nothing in "
                   "are UNREVIEWED until approved; tags without a rule fall back to default_action (deny).", style=C["muted"]))


@policy_app.command("explain")
@guarded
def policy_explain(role: str = typer.Option(..., "--role", "-r"), table: str = typer.Option(..., "--table", "-t"),
                   json_out: bool = typer.Option(False, "--json")):
    """Why each field of TABLE is shown, masked, tokenised or withheld for ROLE (synthetic examples only)."""
    ex = svc().explain(role, table)
    if json_out:
        return emit_json(ex)
    out.print(Rule(f"[bold]{role}[/] on [bold]{ex['table']}[/] · policy {ex['policy_version']}", align="left", style=C["info"]))
    out.print(explain_table(ex))
    extra = []
    if ex.get("row_filter"):
        extra.append(f"row filter: {ex['row_filter']}")
    if ex.get("max_rows"):
        extra.append(f"row cap {ex['max_rows']}")
    if ex.get("min_group_size"):
        extra.append(f"aggregates need ≥ {ex['min_group_size']} rows")
    out.print(Text(" · ".join(extra + [ex["note"]]), style=C["muted"]))


@policy_app.command("set")
@guarded
def policy_set(role: str, tag: str, action: str, reason: str = typer.Option("", "--reason"),
               confirm: bool = typer.Option(False, "--confirm", help="Required when the change weakens protection."),
               json_out: bool = typer.Option(False, "--json")):
    """Change one rule at runtime (validated, versioned, audited). The YAML file stays the reviewed baseline."""
    r = svc().set_rule(role, tag.upper(), action, reason, confirm)
    if json_out:
        return emit_json(r)
    out.print(Text.assemble(("CHANGED" if r["changed"] else "UNCHANGED", f"bold {C['ok'] if r['changed'] else C['muted']}"),
                            f"  {role}/{tag.upper()} → {action} · policy {r['version']}"))
    for w in r.get("warnings", []):
        err.print(Text(f"warning: {w}", style=C["warn"]))


@policy_app.command("history")
@guarded
def policy_history(json_out: bool = typer.Option(False, "--json")):
    """Runtime policy changes (who, what, why, version before/after)."""
    h = svc().policy_history()
    if json_out:
        return emit_json(h)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    for c in ("When", "Actor", "Change", "Reason", "Version"):
        t.add_column(c)
    for e in h:
        what = f"{e.get('role')}/{e.get('tag')}: {e.get('from')} → {e.get('to')}" if e["change"] == "set_rule" else "reset"
        t.add_row(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])), e["actor"], what, e.get("reason", ""), e["version_after"])
    out.print(t if h else Text("no runtime changes", style=C["muted"]))


# ---------------------------------------------------------------- query & compare

def _sql_or_table(sql, table, columns, limit):
    if sql and table:
        raise typer.BadParameter("give SQL or --table, not both")
    if not sql and not table:
        raise typer.BadParameter("give SQL or --table")
    return sql, table, [c.strip() for c in columns.split(",")] if columns else None, limit


@app.command()
@guarded
def query(sql: Optional[str] = typer.Argument(None, help="A single SELECT."),
          role: Optional[str] = typer.Option(None, "--role", "-r", help="Run as this role's demo identity."),
          user: Optional[str] = typer.Option(None, "--user", "-u"), password: Optional[str] = typer.Option(None, "--password", "-p"),
          table: Optional[str] = typer.Option(None, "--table", "-t", help="Query builder: SELECT … FROM TABLE."),
          columns: Optional[str] = typer.Option(None, "--columns", "-c", help="Comma-separated, with --table."),
          limit: int = typer.Option(10, "--limit", "-n", min=1, max=1000),
          explain: bool = typer.Option(False, "--explain", help="Also print the per-field policy decision."),
          show_sql: bool = typer.Option(False, "--show-sql", help="Print the rewritten (masked) SQL."),
          csv_path: Optional[str] = typer.Option(None, "--csv", help="Export the masked result as CSV."),
          max_rows: int = typer.Option(20, "--max-rows", help="Rows to display (export keeps all)."),
          json_out: bool = typer.Option(False, "--json")):
    """Run one query through the gateway as an authenticated identity. Output is already masked for that role."""
    sql, table, cols, limit = _sql_or_table(sql, table, columns, limit)
    ident = identity_opts(role, user, password)
    s = svc()
    r = s.query_table(table, cols, limit, **ident) if table else s.query(sql, **ident)
    if csv_path:
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f); w.writerow(r["columns"]); w.writerows(r["rows"])
        err.print(Text(f"wrote {r['row_count']} masked rows to {csv_path}", style=C["muted"]))
    if json_out:
        return emit_json(r)
    out.print(Rule(f"[bold]{r['role'].upper()}[/] · {r['user']}", align="left", style=C["info"]))
    out.print(result_table(r, max_rows))
    if r["row_count"] > max_rows:
        out.print(Text(f"… {r['row_count'] - max_rows} more rows not shown (--max-rows)", style=C["muted"]))
    out.print(result_footer(r))
    if show_sql:
        out.print(Syntax(r["rewritten_sql"], "sql", word_wrap=True, theme="ansi_dark"))
    if explain:
        tables = {m.partition(":")[0].split(".")[0] for m in r["masked"]} or ({table} if table else set())
        for t in sorted(tables):
            out.print(explain_table(s.explain(r["role"], t)))


@app.command()
@guarded
def compare(sql: Optional[str] = typer.Argument(None),
            roles: str = typer.Option("admin,support,analyst", "--roles", help="Comma-separated demo roles."),
            table: Optional[str] = typer.Option(None, "--table", "-t"), columns: Optional[str] = typer.Option(None, "--columns", "-c"),
            limit: int = typer.Option(5, "--limit", "-n", min=1, max=100),
            json_out: bool = typer.Option(False, "--json"), sql_opt: Optional[str] = typer.Option(None, "--sql", hidden=True)):
    """The same query as several roles (each a real, audited query under that role's demo identity)."""
    sql = sql or sql_opt
    sql, table, cols, limit = _sql_or_table(sql, table, columns, limit)
    s = svc()
    rl = [r.strip() for r in roles.split(",") if r.strip()]
    if table:
        res = {r: s.query_table(table, cols, limit, role=r) for r in rl}
        sql = next(iter(res.values()))["sql"]
    else:
        res = s.compare(sql, rl)
    if json_out:
        return emit_json({"sql": sql, "results": res})
    out.print(Syntax(sql, "sql", theme="ansi_dark", word_wrap=True))
    for r in rl:
        x = res[r]
        if "error" in x:
            out.print(Rule(f"[bold]{r.upper()}[/]", align="left", style=C["bad"]))
            out.print(Text(f"DENIED  {x['error']}", style=C["bad"]))
            continue
        out.print(Rule(f"[bold]{r.upper()}[/] · {x['user']}", align="left", style=C["info"]))
        out.print(result_table(x, limit))
        out.print(result_footer(x))


@app.command()
@guarded
def attack(user: Optional[str] = typer.Option(None, "--user", "-u"), password: Optional[str] = typer.Option(None, "--password", "-p"),
           role: Optional[str] = typer.Option(None, "--role", "-r"), json_out: bool = typer.Option(False, "--json")):
    """Attack suite (21 bypass and inference attacks): naive masking vs MaskGuard, as one identity."""
    r = svc().attacks(**identity_opts(role, user, password))
    if json_out:
        emit_json(r)
    else:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
        for c in ("Attack", "Category", "Naive masking", "MaskGuard"):
            t.add_column(c)
        for x in r["results"]:
            nv, mg = x["naive"]["status"], x["maskguard"]["status"]
            t.add_row(x["attack"], x["category"], Text(nv, style=C["bad"] if nv == "LEAK" else C["muted"]),
                      Text(mg, style=C["bad"] if mg == "LEAK" else C["ok"]))
        out.print(t)
        sc = r["score"]
        out.print(Text(f"PII leaks: naive {sc['naive_leaks']}/{sc['pii_attacks']} · MaskGuard {sc['maskguard_leaks']}/"
                       f"{sc['pii_attacks']} · firewall rejected {sc['firewall_rejected']}/{sc['firewall_attacks']}", style="bold"))
    if r["score"]["maskguard_leaks"]:
        raise typer.Exit(SECURITY_FAILED)


@app.command("test")
@guarded
def security_test(roles: str = typer.Option("support,analyst,auditor", "--roles"), json_out: bool = typer.Option(False, "--json")):
    """Security regression: attack suite per role, audit chain, and an integrity proof. Exit 6 on any failure."""
    s = svc()
    report = {"attacks": {}, "audit_chain": None, "integrity": None}
    for r in [x.strip() for x in roles.split(",") if x.strip()]:
        with err.status(f"[cyan]attack suite as {r}…[/]"):
            report["attacks"][r] = s.attacks(role=r)["score"]
    report["audit_chain"] = s.audit_verify()
    with err.status("[cyan]integrity proof…[/]"):
        p = s.integrity_proof()
    report["integrity"] = {k: p[k] for k in ("status", "before", "after")}
    report["integrity"]["unauthorized_attempts"] = {a["attempt"]: a["status"] for a in p["unauthorized_attempts"]}
    ok = (all(v["maskguard_leaks"] == 0 for v in report["attacks"].values()) and report["audit_chain"]
          and p["status"] == "PASS")
    report["passed"] = ok
    if json_out:
        emit_json(report)
    else:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
        t.add_column("Check"); t.add_column("Result"); t.add_column("Detail", style=C["muted"])
        for r, sc in report["attacks"].items():
            t.add_row(f"attack suite as {r}", status_label(sc["maskguard_leaks"] == 0),
                      f"{sc['maskguard_leaks']}/{sc['pii_attacks']} leaks (naive {sc['naive_leaks']}) · "
                      f"firewall {sc['firewall_rejected']}/{sc['firewall_attacks']}")
        t.add_row("audit hash chain", status_label(report["audit_chain"]), "every entry links to the previous hash")
        t.add_row("source data unchanged", status_label(p["status"] == "PASS"),
                  f"{len(p['queries'])} role queries + {len(p['unauthorized_attempts'])} write attempts · digest {p['after'][:16]}…")
        out.print(t)
    if not ok:
        raise typer.Exit(SECURITY_FAILED)


# ---------------------------------------------------------------- audit & integrity

@audit_app.command("list")
@guarded
def audit_list(n: int = typer.Option(20, "-n"), user: Optional[str] = None, role: Optional[str] = None,
               decision: Optional[str] = None, search: Optional[str] = typer.Option(None, "--search", "-q"),
               request_id: Optional[str] = typer.Option(None, "--request-id"), json_out: bool = typer.Option(False, "--json")):
    """Recent audit events (literals are stripped before logging, so no personal data appears)."""
    a = svc().audit(n, user=user, role=role, decision=decision, text=search, request_id=request_id) \
        if svc().mode == "local" else svc().audit(n, user=user, role=role, decision=decision, q=search, request_id=request_id)
    if json_out:
        return emit_json(a)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    for c in ("Time", "Request", "Channel", "User", "Role", "Decision", "Detail"):
        t.add_column(c, overflow="fold")
    for e in a["entries"]:
        d = e.get("decision", "?")
        style = C["ok"] if d == "allow" else C["bad"] if d in ("reject", "blocked", "denied", "error") else C["info"]
        detail = e.get("sql") or e.get("target") or ""
        if e.get("reason"):
            detail = f"{detail} — {e['reason']}"
        t.add_row(time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0))), e.get("request_id", "—"), e.get("channel", "—"),
                  e.get("user", "—"), e.get("role", "—"), Text(d.upper(), style=f"bold {style}"), cell(detail, 80))
    out.print(t)
    out.print(Text.assemble(("audit chain ", C["muted"]), status_label(a["chain_valid"])))


@audit_app.command("verify")
@guarded
def audit_verify():
    """Verify the hash chain (detects edited, removed or reordered entries)."""
    ok = svc().audit_verify()
    out.print(Text.assemble(status_label(ok), "  audit chain " + ("intact" if ok else "BROKEN")))
    if not ok:
        raise typer.Exit(INTEGRITY_FAILED)


def _integrity_report(r, json_out):
    if json_out:
        return emit_json(r)
    if r["status"] == "NO_BASELINE":
        out.print(Text("NO BASELINE  run `maskguard integrity baseline` first", style=C["warn"]))
        return
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    for c in ("Table", "Status", "Rows before", "Rows after", "Schema", "Content digest (SHA-256)"):
        t.add_column(c)
    for x in r["tables"]:
        st = x["status"]
        t.add_row(x["table"], Text(st, style=f"bold {C['ok'] if st == 'MATCH' else C['bad']}"),
                  str(x.get("rows_before")), str(x.get("rows_after")),
                  "changed" if x.get("schema_changed") else "same", (x.get("digest_after") or "")[:24] + "…")
    out.print(t)
    out.print(Text(f"baseline {r.get('baseline_taken_at')} → verified {r.get('verified_at')}", style=C["muted"]))


@integrity_app.callback(invoke_without_command=True)
def integrity_default(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        integrity_verify(json_out=False)


@integrity_app.command("verify")
@guarded
def integrity_verify(json_out: bool = typer.Option(False, "--json")):
    """Recompute row counts, schema and content digests and compare with the baseline."""
    with err.status("[cyan]hashing source tables…[/]"):
        r = svc().integrity_verify()
    _integrity_report(r, json_out)
    if r["status"] != "MATCH":
        raise typer.Exit(INTEGRITY_FAILED)


@integrity_app.command("baseline")
@guarded
def integrity_baseline(reason: str = typer.Option("", "--reason"), json_out: bool = typer.Option(False, "--json")):
    """Record a new baseline (do this when the data is known-good and quiet)."""
    snap = svc().integrity_baseline(reason)
    if json_out:
        return emit_json(snap)
    out.print(Text(f"baseline recorded · {len(snap['tables'])} tables · {snap['combined_sha256'][:24]}…", style=C["ok"]))


@integrity_app.command("proof")
@guarded
def integrity_proof(sql: Optional[str] = typer.Option(None, "--sql"), json_out: bool = typer.Option(False, "--json")):
    """Digest → same query as every role → write attempts → digest. PASS only if nothing changed."""
    with err.status("[cyan]running the immutability proof…[/]"):
        p = svc().integrity_proof(sql)
    if json_out:
        emit_json(p)
    else:
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, title="1 · same query, every role", title_justify="left")
        t.add_column("Role"); t.add_column("Result"); t.add_column("Rows"); t.add_column("Masked columns"); t.add_column("Request")
        for q in p["queries"]:
            t.add_row(q["role"], q["status"], str(q.get("rows", "—")), str(q.get("masked", "—")), q.get("request_id", "—"))
        out.print(t)
        t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False, title="2 · write attempts through the gateway", title_justify="left")
        t.add_column("Attempt"); t.add_column("Result"); t.add_column("Reason", style=C["muted"])
        for a in p["unauthorized_attempts"]:
            t.add_row(a["attempt"], Text(a["status"], style=C["ok"] if a["status"] == "REJECTED" else C["bad"]), a.get("reason", ""))
        out.print(t)
        out.print(Text.assemble(("3 · source digest  ", "bold"), f"{p['before'][:20]}… → {p['after'][:20]}…  ", status_label(p["status"] == "PASS"),
                                ("  source mutation: NONE" if p["status"] == "PASS" else "  source mutation: DETECTED",
                                 C["ok"] if p["status"] == "PASS" else C["bad"])))
    if p["status"] != "PASS":
        raise typer.Exit(INTEGRITY_FAILED)


@integrity_app.command("history")
@guarded
def integrity_history(json_out: bool = typer.Option(False, "--json")):
    """Past verifications."""
    h = svc().integrity_history()
    if json_out:
        return emit_json(h)
    t = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    for c in ("When", "Actor", "Status", "Changed tables"):
        t.add_column(c)
    for e in h:
        t.add_row(e.get("verified_at", ""), e.get("actor", ""), Text(e["status"], style=C["ok"] if e["status"] == "MATCH" else C["bad"]),
                  ", ".join(e.get("changed", [])) or "—")
    out.print(t)


# ---------------------------------------------------------------- operations (unchanged behaviour)

@app.command()
@guarded
def seed():
    """(Re)create the synthetic demo tables and record a fresh integrity baseline. Never in production."""
    from .seed import make_db
    from .service import LocalService
    if config.environment() == "production":
        fail("seeding is disabled in production: it writes synthetic demo data into the database", DENIED)
    s = svc()
    if not isinstance(s, LocalService):
        fail("seed runs locally only", USAGE)
    make_db(s.app.backend)
    s.app.integrity.record_baseline("cli-operator", "reseeded")
    out.print("seeded users, accounts, support_tickets (synthetic) · baseline recorded")


def _listen_or_fail(service, host, tls=False):
    try:
        problems = config.listen_problems(service, host, tls)
    except config.UnsafeConfiguration as e:
        fail(str(e), UNAVAILABLE)
    if problems:
        fail(str(config.UnsafeConfiguration(problems)), UNAVAILABLE)


def _serve(host, port, ssl_certfile=None, ssl_keyfile=None):
    import uvicorn
    if bool(ssl_certfile) != bool(ssl_keyfile):
        fail("TLS needs both --ssl-certfile and --ssl-keyfile", USAGE)
    _listen_or_fail("api", host, tls=bool(ssl_certfile))
    from . import api
    try:  # build before uvicorn so an unsafe configuration exits with a clean message and code 4, not a traceback
        api.state["app"] = config.build(start_worker=True)
    except config.UnsafeConfiguration as e:
        fail(str(e), UNAVAILABLE)
    except Exception as e:
        fail(f"cannot start the engine: {type(e).__name__}: {str(e)[:160]}", UNAVAILABLE)
    banner()
    url = f"{'https' if ssl_certfile else 'http'}://{host}:{port}"
    err.print(Text(f"API on {url}  ·  dashboard {url}/ui/  ·  docs {url}/docs", style=C["info"]))
    uvicorn.run("maskguard.api:app", host=host, port=port, ssl_certfile=ssl_certfile, ssl_keyfile=ssl_keyfile)


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000,
          ssl_certfile: Optional[str] = typer.Option(None, "--ssl-certfile", envvar="MASKGUARD_TLS_CERT",
                                                     help="PEM certificate (chain): serve HTTPS."),
          ssl_keyfile: Optional[str] = typer.Option(None, "--ssl-keyfile", envvar="MASKGUARD_TLS_KEY",
                                                    help="PEM private key for --ssl-certfile.")):
    """REST API + Control Room dashboard (http://HOST:PORT/ui/, OpenAPI at /docs). Production: TLS off loopback."""
    _serve(host, port, ssl_certfile, ssl_keyfile)


@app.command()
def dashboard(port: int = 8000, host: str = "127.0.0.1", classic: bool = typer.Option(False, "--classic", help="Streamlit dashboard instead.")):
    """Open the Control Room web dashboard (or the classic Streamlit one)."""
    if classic:
        import subprocess
        _listen_or_fail("classic dashboard", host)
        path = os.path.join(os.path.dirname(__file__), "dashboard.py")
        raise typer.Exit(subprocess.call([sys.executable, "-m", "streamlit", "run", path, "--server.port", str(port),
                                          "--server.address", host, "--server.headless", "true",
                                          "--client.toolbarMode", "minimal"]))
    _serve(host, port, os.environ.get("MASKGUARD_TLS_CERT"), os.environ.get("MASKGUARD_TLS_KEY"))


@app.command()
def proxy(host: str = "127.0.0.1", port: int = 6543):
    """PostgreSQL wire-protocol proxy: point psql or any driver at MaskGuard. Production: loopback only (no TLS)."""
    import asyncio
    from .pgwire import serve as pgserve
    _listen_or_fail("proxy", host)
    a = config.build(start_worker=True)
    err.print(f"MaskGuard PostgreSQL proxy on {host}:{port} (backend: {a.backend.dialect})")
    asyncio.run(pgserve(a, host, port))


@app.command("db-install")
@guarded
def db_install(db: str = typer.Option(..., "--db", envvar="MASKGUARD_DB_ADMIN",
                                      help="Owner/admin URL, not the gateway's runtime account.")):
    """Install or update the masking functions in the database. Run once per database (and after upgrades) with an
    owner account; the gateway itself then only needs read access."""
    from .backends import install_functions
    dialect = install_functions(db)
    out.print(f"masking functions installed ({dialect}). The gateway's runtime account needs only SELECT"
              f"{' and EXECUTE on these functions' if dialect == 'mysql' else ''}: see docs/DEPLOYMENT.md.")


@app.command("hash-password")
def hash_password_cmd():
    """Hash a password for the users file."""
    from .auth import hash_password
    sys.stdout.write(hash_password(getpass.getpass("password: ")) + "\n")


@app.command("train-scanner")
def train_scanner(per_kind: int = 300, seed_: int = typer.Option(7, "--seed")):
    """Retrain the LightGBM PII column classifier (synthetic data only)."""
    from .ml.model import train
    train(n_per_kind=per_kind, seed=seed_)


@app.command()
def classify(column: str, values: List[str]):
    """Classify one column from sample values (values are only used in memory)."""
    from .scanner import classify_column
    r = classify_column(column, values) or {"tag": "UNREVIEWED", "evidence": "no PII found; approve as PUBLIC after review"}
    sys.stdout.write(json.dumps({k: v for k, v in r.items() if k != "probs"}, default=str) + "\n")


@app.command()
@guarded
def pia(out_path: str = typer.Option("data/pia.md", "--out"), days: int = 30):
    """Automated Privacy Impact Assessment from the live system (Markdown + JSON)."""
    from .pia import build, to_markdown
    from .service import LocalService
    s = svc()
    if not isinstance(s, LocalService):
        fail("pia runs locally; use GET /pia on the API", USAGE)
    r = build(s.app, days)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    open(out_path, "w").write(to_markdown(r))
    json.dump(r, open(os.path.splitext(out_path)[0] + ".json", "w"), indent=2, default=str)
    out.print(f"PIA written to {out_path} ({r['tagged_columns']} personal-data columns, {len(r['residual_risks'])} residual risks)")


@app.command("simulate-attack")
@guarded
def simulate_attack(kind: str = typer.Option("enumeration", "--kind",
                    help="enumeration | binary_search | order_probe | bulk_paging | firewall_probe")):
    """Run an insider attack as intruder.ian and watch the threat engine block it."""
    from .threat_sim import live_attack
    a = config.build()
    require_self_test(a.gateway, channel="cli", what="simulated attack")  # before the demo login
    sess = a.auth.login("intruder.ian", "intruder123")
    a.gateway.threat.unblock(sess.user)
    for n, sql, risk, action, reasons, outcome in live_attack(a.gateway, sess, kind):
        style = C["bad"] if action == "block" else C["warn"] if action == "alert" else ""
        out.print(Text(f"{n:3} risk {risk:3} {action:5} {sql[:70]:70} -> {outcome[:60]}", style=style))
    out.print("reasons: " + "; ".join(reasons))


# ---------------------------------------------------------------- interactive console

MENU = [("1", "Scan database for sensitive fields"), ("2", "Inspect PII classifications"),
        ("3", "Masking playground"), ("4", "Compare results across roles"), ("5", "Inspect effective policies"),
        ("6", "View audit events"), ("7", "Verify database integrity"), ("8", "Run security regression tests"),
        ("9", "Database and engine diagnostics"), ("0", "Exit")]


def _menu():
    g = Table.grid(padding=(0, 2))
    g.add_column(style=f"bold {C['accent']}"); g.add_column()
    for k, label in MENU:
        g.add_row(f"[{k}]", label)
    out.print(Panel(g, title="[bold]actions[/]", title_align="left", border_style=C["muted"], box=box.ROUNDED, expand=False))


def _pick(prompt, choices, default=None):
    out.print(Text("  " + "  ".join(f"[{i + 1}] {c}" for i, c in enumerate(choices)), style=C["muted"]))
    i = IntPrompt.ask(prompt, choices=[str(i + 1) for i in range(len(choices))],
                      default=(choices.index(default) + 1) if default in choices else 1, show_choices=False)
    return choices[i - 1]


def _run_safely(fn, *a, **kw):
    try:
        fn(*a, **kw)
    except typer.Exit as e:
        if e.exit_code not in (0, None):
            out.print(Text(f"(exit code {e.exit_code})", style=C["muted"]))
    except (Denied, Unavailable) as e:
        out.print(Text(f"DENIED  {e}", style=C["bad"]))
    except typer.BadParameter as e:
        out.print(Text(f"invalid input: {e}", style=C["warn"]))


def playground():
    s = svc()
    tables = sorted({r["table"] for r in s.inventory()})
    roles = [r["role"] for r in s.roles()]
    table = _pick("table", tables, "users" if "users" in tables else None)
    presets = {f"first rows of {table}": None, "custom SQL": "custom"}
    choice = _pick("query", list(presets))
    sql = None
    if presets[choice] == "custom":
        sql = Prompt.ask("SQL", default=f"SELECT * FROM {table} LIMIT 5")
    role = _pick("role", roles, "support" if "support" in roles else None)
    while True:
        out.print(Rule(f"MASKING PLAYGROUND · {table} · {role.upper()}", style=C["accent"], align="left"))
        try:
            r = s.query(sql, role=role) if sql else s.query_table(table, None, 5, role=role)
            out.print(result_table(r, 10))
            out.print(result_footer(r))
            ex = s.explain(role, table)
            out.print(explain_table(ex))
            if ex.get("row_filter"):
                out.print(Text(f"row filter for {role}: {ex['row_filter']}", style=C["info"]))
        except (Denied, Unavailable) as e:
            out.print(Text(f"DENIED  {e}", style=C["bad"]))
        nxt = Prompt.ask("\\[r] switch role · \\[c] compare all roles · \\[v] verify source unchanged · \\[b] back",
                         choices=["r", "c", "v", "b"], default="r")
        if nxt == "b":
            return
        if nxt == "r":
            role = _pick("role", roles, role)
        elif nxt == "c":
            q = sql or s.query_table(table, None, 3, role=role)["sql"]
            _run_safely(compare, sql=q, roles=",".join(roles), table=None, columns=None, limit=3, json_out=False, sql_opt=None)
        elif nxt == "v":
            _run_safely(integrity_verify, json_out=False)


def interactive():
    banner(out)
    try:
        st = svc().status()
        status_panel(st, out)
    except (Unavailable, RuntimeError) as e:
        out.print(Text(f"UNAVAILABLE  {e}", style=C["bad"]))
        out.print("Check MASKGUARD_DB / MASKGUARD_API and run `maskguard doctor`.")
        raise typer.Exit(UNAVAILABLE)
    demo = st["demo_mode"]
    out.print(Text(f"identity: CLI operator ({st['mode']}) · data queries run as {'demo identities' if demo else '--user/--password'}",
                   style=C["muted"]))
    while True:
        _menu()
        try:
            choice = Prompt.ask("[bold]maskguard[/]", choices=[k for k, _ in MENU], default="3", show_choices=False)
        except (KeyboardInterrupt, EOFError):
            choice = "0"
        if choice == "0":
            out.print(Text("bye", style=C["muted"]))
            return
        try:
            if choice == "1":
                _run_safely(scan, table=None, sample_limit=IntPrompt.ask("sample size per column", default=200),
                            dry_run=Confirm.ask("dry run (do not apply)?", default=False), watch=0, report=None,
                            json_out=False, database=None)
            elif choice == "2":
                _run_safely(pii_list, tag=None, json_out=False)
            elif choice == "3":
                playground()
            elif choice == "4":
                tables = sorted({r["table"] for r in svc().inventory()})
                t = _pick("table", tables, "users" if "users" in tables else None)
                _run_safely(compare, sql=None, roles=",".join(r["role"] for r in svc().roles()), table=t, columns=None,
                            limit=3, json_out=False, sql_opt=None)
            elif choice == "5":
                _run_safely(policy_list, json_out=False)
                if Confirm.ask("explain one role on one table?", default=True):
                    roles = [r["role"] for r in svc().roles()]
                    tables = sorted({r["table"] for r in svc().inventory()})
                    _run_safely(policy_explain, role=_pick("role", roles), table=_pick("table", tables), json_out=False)
            elif choice == "6":
                _run_safely(audit_list, n=15, user=None, role=None, decision=None, search=None, request_id=None, json_out=False)
            elif choice == "7":
                if Confirm.ask("run the full proof (same query as every role + write attempts)?", default=True):
                    _run_safely(integrity_proof, sql=None, json_out=False)
                else:
                    _run_safely(integrity_verify, json_out=False)
            elif choice == "8":
                _run_safely(security_test, roles="support,analyst,auditor", json_out=False)
            elif choice == "9":
                _run_safely(doctor, json_out=False)
        except KeyboardInterrupt:
            out.print(Text("\n(cancelled)", style=C["muted"]))


# ---------------------------------------------------------------- entry point

def _legacy_argv(argv):
    """Keep pre-1.0 invocations working: `roles "SQL"`, `audit --verify`, `audit -n 5`, `query -u U "SQL"`."""
    if len(argv) >= 2 and argv[0] == "roles" and argv[1] not in ("list", "show", "--help", "-h"):
        return ["compare", "--roles", ",".join(config.DEMO_ACCOUNTS), argv[1]] + argv[2:]
    if argv[:1] == ["audit"] and (len(argv) == 1 or argv[1].startswith("-")) and "--help" not in argv:
        return ["audit", "verify"] if "--verify" in argv else ["audit", "list"] + argv[1:]
    return argv


def main(argv=None):
    argv = _legacy_argv(list(sys.argv[1:] if argv is None else argv))
    try:
        rc = app(args=argv, prog_name="maskguard", standalone_mode=False)
        return rc if isinstance(rc, int) else OK
    except typer.Exit as e:
        return e.exit_code or 0
    except SystemExit as e:  # click usage errors
        return e.code if isinstance(e.code, int) else USAGE
    except Exception as e:
        if hasattr(e, "show") and hasattr(e, "exit_code"):  # click/typer usage errors (typer vendors click)
            e.show(); return USAGE
        if type(e).__name__ == "Abort":
            return 130
        err.print(Text(f"ERROR  {type(e).__name__}: {str(e)[:200]}", style=C["bad"]))
        return ERROR


if __name__ == "__main__":
    sys.exit(main())
