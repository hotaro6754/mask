"""PostgreSQL wire-protocol front end: point psql, psycopg, or any libpq/JDBC client at MaskGuard instead of the
database. Users log in with their MaskGuard credentials; every query goes through the same gateway (masking,
threat engine, DP budget, audit) as the API and dashboard.

    maskguard proxy --port 6543
    psql "host=localhost port=6543 user=support.sam dbname=bank"

Supported: protocol 3.0, cleartext password auth (put TLS in front, e.g. a TLS-terminating load balancer, for
anything beyond a demo network), the simple query protocol, and the extended protocol for unnamed or named
statements with text-format parameters. A few session statements clients send on connect (SET, SHOW, BEGIN /
COMMIT / ROLLBACK, version(), current_schema()) are answered locally and never reach the database. Catalog
introspection (pg_catalog, information_schema) is refused by the gateway like any other unregistered table.
"""
import asyncio, decimal, datetime, re, struct

from .gateway import safe_error
from .rewriter import Rejected, rewrite

SERVER_PARAMS = {"server_version": "16.0 (MaskGuard)", "server_encoding": "UTF8", "client_encoding": "UTF8",
                 "DateStyle": "ISO, MDY", "integer_datetimes": "on", "standard_conforming_strings": "on",
                 "TimeZone": "UTC", "application_name": "", "is_superuser": "off"}
OID_TEXT, OID_INT8, OID_FLOAT8, OID_NUMERIC, OID_BOOL = 25, 20, 701, 1700, 16


def _msg(t, payload=b""):
    return t + struct.pack("!I", len(payload) + 4) + payload


def _cstr(s):
    return s.encode() + b"\x00"


def _error(message, code="42501", severity="ERROR"):
    return _msg(b"E", b"S" + _cstr(severity) + b"V" + _cstr(severity) + b"C" + _cstr(code) + b"M" + _cstr(message) + b"\x00")


def _oid(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return OID_TEXT
    if all(isinstance(v, bool) for v in vals):
        return OID_BOOL
    if all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return OID_INT8
    if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return OID_FLOAT8
    if all(isinstance(v, (int, float, decimal.Decimal)) for v in vals):
        return OID_NUMERIC
    return OID_TEXT


def _text(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "t" if v else "f"
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.isoformat(sep=" ") if isinstance(v, datetime.datetime) else v.isoformat()
    return str(v)


def row_description(columns, rows):
    out = struct.pack("!H", len(columns))
    for i, name in enumerate(columns):
        oid = _oid([r[i] for r in rows])
        out += _cstr(str(name)) + struct.pack("!IhIhih", 0, 0, oid, -1, -1, 0)
    return _msg(b"T", out)


def data_rows(rows):
    out = b""
    for r in rows:
        payload = struct.pack("!H", len(r))
        for v in r:
            t = _text(v)
            payload += struct.pack("!i", -1) if t is None else struct.pack("!I", len(t.encode())) + t.encode()
        out += _msg(b"D", payload)
    return out


_SESSION_RE = re.compile(r"^\s*(set|reset|begin|start\s+transaction|commit|end|rollback|discard|deallocate|listen|unlisten)\b", re.I)


def local_answer(sql):
    """Statements answered by the proxy itself: (columns, rows, tag) or None to send to the gateway."""
    s = sql.strip().rstrip(";").strip()
    low = s.lower()
    if not s:
        return [], [], "EMPTY"
    m = _SESSION_RE.match(low)
    if m:
        word = m.group(1).split()[0].upper()
        return [], [], {"START": "BEGIN", "END": "COMMIT"}.get(word, word)
    if low.startswith("show "):
        name = low[5:].strip()
        val = {"transaction isolation level": "read committed", "server_version": SERVER_PARAMS["server_version"],
               "standard_conforming_strings": "on", "client_encoding": "UTF8", "timezone": "UTC",
               "search_path": "public", "datestyle": "ISO, MDY"}.get(name, "")
        return [name.replace(" ", "_")], [(val,)], "SHOW"
    if re.fullmatch(r"select\s+(pg_catalog\.)?version\(\)", low):
        return ["version"], [("PostgreSQL 16.0 (MaskGuard gateway)",)], "SELECT 1"
    if re.fullmatch(r"select\s+(pg_catalog\.)?current_schema\(\)", low):
        return ["current_schema"], [("public",)], "SELECT 1"
    if re.fullmatch(r"select\s+1", low):
        return ["?column?"], [(1,)], "SELECT 1"
    return None


def _decode_binary(raw, oid):
    """Binary-format parameter -> text, for the types drivers send in binary by default."""
    if oid == 21:
        return str(struct.unpack("!h", raw)[0])
    if oid == 23:
        return str(struct.unpack("!i", raw)[0])
    if oid == 20:
        return str(struct.unpack("!q", raw)[0])
    if oid == 700:
        return repr(struct.unpack("!f", raw)[0])
    if oid == 701:
        return repr(struct.unpack("!d", raw)[0])
    if oid == 16:
        return "true" if raw[:1] == b"\x01" else "false"
    if oid == 1700:  # numeric: ndigits, weight, sign, dscale, base-10000 digits
        nd, weight, sign, dscale = struct.unpack("!hhHh", raw[:8])
        digits = struct.unpack(f"!{nd}H", raw[8:8 + 2 * nd])
        if sign == 0xC000:
            return "NaN"
        val = sum(decimal.Decimal(d) * (decimal.Decimal(10000) ** (weight - i)) for i, d in enumerate(digits))
        val = val.quantize(decimal.Decimal(1).scaleb(-dscale)) if dscale else val.to_integral_value()
        return ("-" if sign == 0x4000 else "") + str(val)
    if oid in (0, 25, 1043, 18, 19, 1042, 114, 3802):
        return raw.decode()
    raise ValueError(f"binary parameter of type {oid} is not supported; send it as text")


_NUMERIC_OIDS = (20, 21, 23, 700, 701, 1700)


def _bind_params(sql, params, types):
    """Inline text parameters ($1, $2 ...) as SQL literals so the gateway parses one complete statement."""
    def lit(i):
        v = params[i]
        if v is None:
            return "NULL"
        if types and i < len(types) and types[i] in _NUMERIC_OIDS and re.fullmatch(r"-?\d+(\.\d+)?(e-?\d+)?", v):
            return v
        return "'" + v.replace("'", "''") + "'"
    return re.sub(r"\$(\d+)", lambda m: lit(int(m.group(1)) - 1), sql)


class Connection:
    def __init__(self, app, reader, writer):
        self.app, self.r, self.w = app, reader, writer
        self.session = None
        self.statements, self.portals = {}, {}
        self.skip_until_sync = False

    async def read_startup(self):
        while True:
            n = struct.unpack("!I", await self.r.readexactly(4))[0]
            body = await self.r.readexactly(n - 4)
            code = struct.unpack("!I", body[:4])[0]
            if code in (80877103, 80877104):      # SSLRequest / GSSENCRequest: not offered here
                self.w.write(b"N"); await self.w.drain(); continue
            if code == 80877102:                   # CancelRequest
                return None
            parts = body[4:].split(b"\x00")
            return {parts[i].decode(): parts[i + 1].decode() for i in range(0, len(parts) - 1, 2) if parts[i]}

    async def authenticate(self, params):
        self.w.write(_msg(b"R", struct.pack("!I", 3)))  # cleartext password
        await self.w.drain()
        t = await self.r.readexactly(1)
        n = struct.unpack("!I", await self.r.readexactly(4))[0]
        pw = (await self.r.readexactly(n - 4)).rstrip(b"\x00").decode()
        if t != b"p":
            return False
        try:
            self.session = self.app.auth.login(params.get("user", ""), pw)
        except PermissionError:
            self.w.write(_error("password authentication failed", "28P01", "FATAL")); await self.w.drain()
            return False
        out = _msg(b"R", struct.pack("!I", 0))
        for k, v in SERVER_PARAMS.items():
            out += _msg(b"S", _cstr(k) + _cstr(v))
        out += _msg(b"K", struct.pack("!II", 0, 0)) + _msg(b"Z", b"I")
        self.w.write(out); await self.w.drain()
        return True

    async def run_sql(self, sql):
        """-> (columns, rows, tag) or raises Rejected/Exception."""
        local = local_answer(sql)
        if local is not None:
            return local
        loop = asyncio.get_running_loop()
        res = await loop.run_in_executor(None, lambda: self.app.gateway.query(self.session, sql, channel="pgwire"))
        return res.columns, res.rows, f"SELECT {len(res.rows)}"

    async def describe(self, query, nparams):
        """Result columns of a prepared statement without reading data: rewrite for this role, run with LIMIT 0."""
        sql = _bind_params(query, [None] * nparams, [])
        local = local_answer(sql)
        if local is not None:
            return local[0]
        gw = self.app.gateway
        res = rewrite(sql, self.session.role, gw.registry, gw.policy, gw.backend.dialect, gw.backend.default_schema)
        loop = asyncio.get_running_loop()
        cols, _ = await loop.run_in_executor(None, gw.backend.execute, f"SELECT * FROM ({res.sql}) AS mg_describe LIMIT 0")
        return cols[: res.dp["n_visible"]] if res.dp else cols

    async def simple_query(self, sql):
        try:
            cols, rows, tag = await self.run_sql(sql)
            if tag == "EMPTY":
                out = _msg(b"I")
            else:
                out = (row_description(cols, rows) + data_rows(rows) if cols else b"") + _msg(b"C", _cstr(tag))
        except Rejected as e:
            out = _error(f"MaskGuard: {e}")
        except PermissionError as e:
            out = _error(f"MaskGuard: {e}", "28000")
        except Exception as e:
            out = _error(safe_error(e), "XX000")
        self.w.write(out + _msg(b"Z", b"I")); await self.w.drain()

    async def extended(self, t, body):
        if self.skip_until_sync and t != b"S":
            return
        try:
            if t == b"P":                                   # Parse
                name, rest = body.split(b"\x00", 1)
                query, rest = rest.split(b"\x00", 1)
                n = struct.unpack("!H", rest[:2])[0]
                types = list(struct.unpack(f"!{n}I", rest[2:2 + 4 * n])) if n else []
                self.statements[name.decode()] = (query.decode(), types)
                self.w.write(_msg(b"1"))
            elif t == b"B":                                 # Bind
                portal, rest = body.split(b"\x00", 1)
                stmt, rest = rest.split(b"\x00", 1)
                nfmt = struct.unpack("!H", rest[:2])[0]; rest = rest[2:]
                fmts = struct.unpack(f"!{nfmt}h", rest[:2 * nfmt]); rest = rest[2 * nfmt:]
                nparams = struct.unpack("!H", rest[:2])[0]; rest = rest[2:]
                query, types = self.statements[stmt.decode()]
                params = []
                for i in range(nparams):
                    ln = struct.unpack("!i", rest[:4])[0]; rest = rest[4:]
                    raw = None if ln < 0 else rest[:ln]; rest = rest[max(ln, 0):]
                    binary = (fmts[i] if nfmt > 1 else fmts[0]) if nfmt else 0
                    oid = types[i] if i < len(types) else 0
                    params.append(None if raw is None else _decode_binary(raw, oid) if binary else raw.decode())
                nres = struct.unpack("!H", rest[:2])[0] if len(rest) >= 2 else 0
                if nres and any(struct.unpack(f"!{nres}h", rest[2:2 + 2 * nres])):
                    raise ValueError("binary result format is not supported; request text results")
                sql = _bind_params(query, params, types)
                self.portals[portal.decode()] = await self.run_sql(sql)
                self.w.write(_msg(b"2"))
            elif t == b"D":                                 # Describe statement or portal
                kind, name = body[:1], body[1:].rstrip(b"\x00").decode()
                if kind == b"S":
                    query, types = self.statements[name]
                    nparams = max([int(x) for x in re.findall(r"\$(\d+)", query)] + [len(types)])
                    types = (types + [0] * nparams)[:nparams]
                    self.w.write(_msg(b"t", struct.pack("!H", nparams) + b"".join(struct.pack("!I", x) for x in types)))
                    cols = await self.describe(query, nparams)
                    self.w.write(row_description(cols, []) if cols else _msg(b"n"))
                else:
                    cols, rows, tag = self.portals[name]
                    self.w.write(row_description(cols, rows) if cols else _msg(b"n"))
            elif t == b"E":                                 # Execute
                name = body.split(b"\x00", 1)[0].decode()
                cols, rows, tag = self.portals.pop(name)
                self.w.write((data_rows(rows) if cols else b"") + (_msg(b"I") if tag == "EMPTY" else _msg(b"C", _cstr(tag))))
            elif t == b"C":                                 # Close
                kind, name = body[:1], body[1:].rstrip(b"\x00").decode()
                (self.statements if kind == b"S" else self.portals).pop(name, None)
                self.w.write(_msg(b"3"))
            elif t == b"S":                                 # Sync
                self.skip_until_sync = False
                self.w.write(_msg(b"Z", b"I"))
            elif t == b"H":                                 # Flush
                pass
        except Rejected as e:
            self.w.write(_error(f"MaskGuard: {e}")); self.skip_until_sync = True
        except Exception as e:
            self.w.write(_error(safe_error(e), "XX000")); self.skip_until_sync = True  # never the database's text
        await self.w.drain()

    async def serve(self):
        try:
            params = await self.read_startup()
            if params is None or not await self.authenticate(params):
                return
            while True:
                t = await self.r.readexactly(1)
                n = struct.unpack("!I", await self.r.readexactly(4))[0]
                body = await self.r.readexactly(n - 4)
                if t == b"X":
                    return
                if t == b"Q":
                    await self.simple_query(body.rstrip(b"\x00").decode())
                else:
                    await self.extended(t, body)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            return
        finally:
            self.w.close()


async def serve(app, host="127.0.0.1", port=6543, ready=None):
    server = await asyncio.start_server(lambda r, w: Connection(app, r, w).serve(), host, port)
    if ready is not None:
        ready.set()
    async with server:
        await server.serve_forever()
