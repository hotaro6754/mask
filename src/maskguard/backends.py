"""Database abstraction: one interface over SQLite and PostgreSQL.

Gateway queries always run read-only: SQLite through an authorizer that only allows reads, PostgreSQL inside
a READ ONLY transaction with a statement timeout. Seeding and scanning use the admin paths.

In development the gateway installs its masking functions itself. In production it connects with a read-only
account (install=False): the functions must already exist (`maskguard db-install`, run with an owner account), and
privilege_problems() reports anything the account could use to write or change the database.
"""
import hashlib, re, sqlite3, threading, time
from urllib.parse import urlparse

from . import masks
from .textpii import pg_function_sql

NUMERIC_TYPES = {"INTEGER", "INT", "BIGINT", "SMALLINT", "TINYINT", "MEDIUMINT", "REAL", "NUMERIC", "FLOAT",
                 "DOUBLE", "DECIMAL", "DOUBLE PRECISION"}

PG_FUNCTIONS = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION mg_partial(v text, pre int, suf int) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE total int; seen int := 0; res text := ''; ch text; p int := pre; s int := suf;
        seps text := E' \t\n\r-/.,:()+_@#';
BEGIN
  IF v IS NULL THEN RETURN NULL; END IF;
  total := length(translate(v, seps, ''));
  IF p + s >= total THEN p := 0; s := 0; END IF;
  FOREACH ch IN ARRAY regexp_split_to_array(v, '') LOOP
    IF strpos(seps, ch) = 0 THEN
      seen := seen + 1;
      res := res || CASE WHEN seen <= p OR seen > total - s THEN ch ELSE 'X' END;
    ELSE
      res := res || ch;
    END IF;
  END LOOP;
  RETURN res;
END $$;

CREATE OR REPLACE FUNCTION mg_email(v text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN v IS NULL THEN NULL
              WHEN position('@' in v) = 0 OR position('@' in v) = length(v) THEN '***'
              ELSE left(v, least(1, position('@' in v) - 1)) || '***@' || substr(v, position('@' in v) + 1) END $$;

-- Key comes from a session setting the gateway sets on connect; unset key -> error (fail closed).
CREATE OR REPLACE FUNCTION mg_hmac(v text) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN v IS NULL THEN NULL
              ELSE substr(encode(hmac(v, current_setting('maskguard.hmac_key'), 'sha256'), 'hex'), 1, 16) END $$;
-- Scoped, variable-length token (1.1): same HMAC over "scope<US>value" (or the bare value with no scope)
CREATE OR REPLACE FUNCTION mg_token(v text, scope text, n int) RETURNS text LANGUAGE sql STABLE AS $$
  SELECT CASE WHEN v IS NULL THEN NULL
              ELSE substr(encode(hmac(CASE WHEN scope = '' THEN v ELSE scope || chr(31) || v END,
                                      current_setting('maskguard.hmac_key'), 'sha256'), 'hex'), 1, n) END $$;

CREATE OR REPLACE FUNCTION mg_bucket(v numeric, size int) RETURNS numeric LANGUAGE sql IMMUTABLE AS $$
  SELECT floor(v / size) * size $$;
CREATE OR REPLACE FUNCTION mg_bucket(v double precision, size int) RETURNS numeric LANGUAGE sql IMMUTABLE AS $$
  SELECT floor(v::numeric / size) * size $$;
"""


class Backend:
    dialect = None
    default_schema = None

    def tables(self):
        raise NotImplementedError

    def columns(self, table):  # -> [(name, sql_type)]
        raise NotImplementedError

    def sample(self, table, column, n=200):
        """Up to n non-null values, in storage order. Read only to classify the column: never logged or stored."""
        q = f'SELECT "{column}" FROM {self._qualified(table)} WHERE "{column}" IS NOT NULL LIMIT {int(n)}'
        return [r[0] for r in self.admin_query(q)[1]]

    def checksum(self, table):
        cols, rows = self.admin_query(f"SELECT * FROM {self._qualified(table)} ORDER BY 1")
        h = hashlib.sha256(repr(cols).encode())
        for r in rows:
            h.update(repr(tuple(str(v) for v in r)).encode())
        return h.hexdigest()

    def _qualified(self, table):
        return f'"{self.default_schema}"."{table}"'

    def privilege_problems(self):
        return [f"{self.dialect} has no database accounts to restrict"]

    def _require_functions(self, probe):
        """Fail closed if the masking functions are missing or this account can't run them."""
        try:
            self.execute(probe)
        except Exception as e:
            raise RuntimeError(f"masking functions are missing or not executable by this account ({type(e).__name__}): "
                               "run `maskguard db-install` with an owner account first") from None


class SQLiteBackend(Backend):
    dialect, default_schema = "sqlite", "main"
    _READ_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}

    def __init__(self, path=":memory:"):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        masks.register_sqlite(self.conn)
        self.lock = threading.Lock()

    @staticmethod
    def _readonly(action, *_):
        return sqlite3.SQLITE_OK if action in SQLiteBackend._READ_ACTIONS else sqlite3.SQLITE_DENY

    timeout_s = 5.0  # same budget as PostgreSQL's statement_timeout and MySQL's max_execution_time

    def execute(self, sql):
        with self.lock:
            deadline = time.monotonic() + self.timeout_s
            self.conn.set_authorizer(self._readonly)
            self.conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 20000)  # 1 = interrupt
            try:
                cur = self.conn.execute(sql)
                return [d[0] for d in cur.description or []], cur.fetchall()
            finally:
                self.conn.set_authorizer(None)
                self.conn.set_progress_handler(None, 0)

    def admin_query(self, sql, params=()):
        with self.lock:
            cur = self.conn.execute(sql, params)
            return [d[0] for d in cur.description or []], cur.fetchall()

    def admin_script(self, sql):
        with self.lock:
            self.conn.executescript(sql)
            self.conn.commit()

    def insert_many(self, table, rows):
        if rows:
            with self.lock:
                self.conn.executemany(f'INSERT INTO "{table}" VALUES ({",".join("?" * len(rows[0]))})', rows)
                self.conn.commit()

    def tables(self):
        return [r[0] for r in self.admin_query(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")[1]]

    def columns(self, table):
        return [(r[1], (r[2] or "").upper()) for r in self.admin_query(f'PRAGMA table_info("{table}")')[1]]


PG_PROBE = ("SELECT mg_partial('x', 0, 1), mg_email('a@b.c'), mg_token('x', '', 32), mg_bucket(1::numeric, 10), "
            "mg_bucket(1::float8, 10), mg_redact_text('x')")
MYSQL_PROBE = "SELECT mg_partial('x', 0, 1), mg_email('a@b.c'), mg_token('x', '', 32), mg_bucket(1, 10), mg_redact_text('x')"
MYSQL_FUNCTION_NAMES = ("mg_partial", "mg_email", "mg_hmac", "mg_token", "mg_bucket", "mg_redact_text")
# What a MySQL gateway account may hold. Anything else (writes, DDL, routines, *_ADMIN, FILE, SUPER…) is refused.
MYSQL_READ_PRIVILEGES = {"SELECT", "EXECUTE", "USAGE", "SHOW VIEW"}


class PostgresBackend(Backend):
    dialect, default_schema = "postgres", "public"

    def __init__(self, url, hmac_key=None, statement_timeout_ms=5000, install=True):
        import psycopg
        self.url = url
        self.conn = psycopg.connect(url, autocommit=True)
        self.lock = threading.Lock()
        with self.lock:
            if install:
                self.conn.execute(PG_FUNCTIONS)
                self.conn.execute(pg_function_sql())
            key = hmac_key if hmac_key is not None else masks._key().decode()
            self.conn.execute("SELECT set_config('maskguard.hmac_key', %s, false)", (key,))
            self.conn.execute(f"SET statement_timeout = {int(statement_timeout_ms)}")
        if not install:
            self._require_functions(PG_PROBE)

    def privilege_problems(self):
        """Anything beyond read access: role attributes, write/DDL rights on tables, schemas or the database."""
        user, *flags = self.admin_query(
            "SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication "
            "FROM pg_roles WHERE rolname = current_user")[1][0]
        problems = [f"database account {user} has {name}" for name, on in
                    zip(("SUPERUSER", "CREATEROLE", "CREATEDB", "BYPASSRLS", "REPLICATION"), flags) if on]
        writable = [r[0] for r in self.admin_query(
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
            "AND (has_table_privilege(c.oid, 'INSERT') OR has_table_privilege(c.oid, 'UPDATE') "
            "OR has_table_privilege(c.oid, 'DELETE') OR has_table_privilege(c.oid, 'TRUNCATE') "
            "OR has_table_privilege(c.oid, 'TRIGGER') OR pg_has_role(c.relowner, 'USAGE')) ORDER BY 1")[1]]
        if writable:
            problems.append(f"database account {user} can write to or owns {len(writable)} table(s): "
                            f"{', '.join(writable[:5])}{' …' if len(writable) > 5 else ''}")
        schema_create, db_create = self.admin_query(
            "SELECT has_schema_privilege('public', 'CREATE'), has_database_privilege(current_database(), 'CREATE')")[1][0]
        if schema_create:
            problems.append(f"database account {user} can create objects in schema public (it could replace the "
                            "masking functions)")
        if db_create:
            problems.append(f"database account {user} can create schemas in this database")
        owned = [r[0] for r in self.admin_query(
            "SELECT DISTINCT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.proname LIKE 'mg\\_%' AND pg_has_role(p.proowner, 'USAGE') ORDER BY 1")[1]]
        if owned:
            problems.append(f"database account {user} owns the masking functions ({', '.join(owned)}) and could "
                            "redefine them: install them with the owner account (`maskguard db-install`)")
        roles = [r[0] for r in self.admin_query(
            "SELECT r FROM unnest(ARRAY['pg_write_all_data', 'pg_write_server_files', 'pg_read_server_files', "
            "'pg_execute_server_program']) r WHERE to_regrole(r) IS NOT NULL AND pg_has_role(current_user, r, 'MEMBER')")[1]]
        problems += [f"database account {user} is a member of {r}" for r in roles]
        return problems

    def execute(self, sql):
        with self.lock:
            with self.conn.transaction():
                self.conn.execute("SET TRANSACTION READ ONLY")
                cur = self.conn.execute(sql)
                return [d.name for d in cur.description or []], cur.fetchall()

    def admin_query(self, sql, params=None):
        with self.lock:
            cur = self.conn.execute(sql, params)
            return [d.name for d in cur.description or []], (cur.fetchall() if cur.description else [])

    def admin_script(self, sql):
        with self.lock:
            self.conn.execute(sql)

    def insert_many(self, table, rows):
        if rows:
            with self.lock, self.conn.cursor() as cur:
                cur.executemany(f'INSERT INTO "{table}" VALUES ({",".join(["%s"] * len(rows[0]))})', rows)

    def tables(self):
        return [r[0] for r in self.admin_query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' "
            "AND table_type = 'BASE TABLE' ORDER BY table_name")[1]]

    def columns(self, table):
        return [(r[0], r[1].upper()) for r in self.admin_query(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = 'public' "
            "AND table_name = %s ORDER BY ordinal_position", (table,))[1]]


MYSQL_FUNCTIONS = [
    """CREATE FUNCTION mg_partial(v TEXT, pre INT, suf INT) RETURNS TEXT DETERMINISTIC NO SQL
BEGIN
  DECLARE total INT DEFAULT 0; DECLARE seen INT DEFAULT 0; DECLARE i INT DEFAULT 1;
  DECLARE res TEXT DEFAULT ''; DECLARE ch VARCHAR(4); DECLARE p INT DEFAULT pre; DECLARE s INT DEFAULT suf;
  DECLARE seps VARCHAR(32) DEFAULT CONCAT(' ', CHAR(9), CHAR(10), CHAR(13), '-/.,:()+_@#');
  IF v IS NULL THEN RETURN NULL; END IF;
  WHILE i <= CHAR_LENGTH(v) DO
    IF LOCATE(SUBSTRING(v, i, 1), seps) = 0 THEN SET total = total + 1; END IF;
    SET i = i + 1;
  END WHILE;
  IF p + s >= total THEN SET p = 0; SET s = 0; END IF;
  SET i = 1;
  WHILE i <= CHAR_LENGTH(v) DO
    SET ch = SUBSTRING(v, i, 1);
    IF LOCATE(ch, seps) = 0 THEN
      SET seen = seen + 1;
      SET res = CONCAT(res, IF(seen <= p OR seen > total - s, ch, 'X'));
    ELSE
      SET res = CONCAT(res, ch);
    END IF;
    SET i = i + 1;
  END WHILE;
  RETURN res;
END""",
    """CREATE FUNCTION mg_email(v TEXT) RETURNS TEXT DETERMINISTIC NO SQL
RETURN CASE WHEN v IS NULL THEN NULL
            WHEN LOCATE('@', v) = 0 OR LOCATE('@', v) = CHAR_LENGTH(v) THEN '***'
            ELSE CONCAT(LEFT(v, LEAST(1, LOCATE('@', v) - 1)), '***@', SUBSTRING(v, LOCATE('@', v) + 1)) END""",
    # HMAC-SHA256 built from SHA2 (RFC 2104); key comes from a session variable the gateway sets on connect
    """CREATE FUNCTION mg_hmac(v TEXT) RETURNS CHAR(16) NOT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE k VARBINARY(64);
  IF v IS NULL THEN RETURN NULL; END IF;
  IF @maskguard_hmac_key IS NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'maskguard hmac key not set'; END IF;
  SET k = CAST(@maskguard_hmac_key AS BINARY);
  IF LENGTH(k) > 64 THEN SET k = UNHEX(SHA2(k, 256)); END IF;
  SET k = RPAD(k, 64, X'00');
  RETURN LEFT(SHA2(CONCAT(k ^ UNHEX(REPEAT('5c', 64)),
                          UNHEX(SHA2(CONCAT(k ^ UNHEX(REPEAT('36', 64)), CAST(v AS BINARY)), 256))), 256), 16);
END""",
    # Scoped, variable-length token (1.1): HMAC over "scope<US>value", or the bare value when scope is ''
    """CREATE FUNCTION mg_token(v TEXT, scope TEXT, n INT) RETURNS VARCHAR(64) NOT DETERMINISTIC READS SQL DATA
BEGIN
  DECLARE k VARBINARY(64);
  DECLARE m LONGBLOB;
  IF v IS NULL THEN RETURN NULL; END IF;
  IF @maskguard_hmac_key IS NULL THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'maskguard hmac key not set'; END IF;
  SET k = CAST(@maskguard_hmac_key AS BINARY);
  IF LENGTH(k) > 64 THEN SET k = UNHEX(SHA2(k, 256)); END IF;
  SET k = RPAD(k, 64, X'00');
  SET m = IF(scope = '', CAST(v AS BINARY), CONCAT(CAST(scope AS BINARY), X'1F', CAST(v AS BINARY)));
  RETURN LEFT(SHA2(CONCAT(k ^ UNHEX(REPEAT('5c', 64)),
                          UNHEX(SHA2(CONCAT(k ^ UNHEX(REPEAT('36', 64)), m), 256))), 256), n);
END""",
    """CREATE FUNCTION mg_bucket(v DOUBLE, size INT) RETURNS DOUBLE DETERMINISTIC NO SQL
RETURN FLOOR(v / size) * size""",
]


def mysql_redact_function():
    from .textpii import PATTERNS
    steps = "\n".join(f"  SET s = REGEXP_REPLACE(s, {_sql_str(p)}, {_sql_str('[' + label + ']')});" for label, p in PATTERNS)
    return ("CREATE FUNCTION mg_redact_text(v TEXT) RETURNS TEXT DETERMINISTIC NO SQL\nBEGIN\n  DECLARE s TEXT DEFAULT v;\n"
            "  IF v IS NULL THEN RETURN NULL; END IF;\n" + steps + "\n  RETURN s;\nEND")


def _sql_str(s):
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"


class MySQLBackend(Backend):
    dialect = "mysql"

    def __init__(self, url, hmac_key=None, statement_timeout_ms=5000, install=True):
        u = urlparse(url)
        self.default_schema = u.path.lstrip("/") or "bank"
        self.conn = _mysql_connect(url)
        self.lock = threading.Lock()
        key = hmac_key if hmac_key is not None else masks._key().decode()
        with self.lock, self.conn.cursor() as c:
            c.execute("SET SESSION sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')")  # "ident" like the other engines
            c.execute("SET @maskguard_hmac_key = %s", (key,))
            c.execute(f"SET SESSION max_execution_time = {int(statement_timeout_ms)}")
            # materialise each masked view once instead of merging it into the outer query; otherwise masking
            # functions re-run per row of every join/cross product
            c.execute("SET SESSION optimizer_switch = 'derived_merge=off'")
            if install:
                _mysql_install(c)
        if not install:
            self._require_functions(MYSQL_PROBE)

    def privilege_problems(self):
        """Parse SHOW GRANTS: only read privileges are allowed, scoped to this database."""
        problems = []
        for (line,) in self.admin_query("SHOW GRANTS")[1]:
            m = re.match(r"GRANT (.+?) ON (.+?) TO ", line)
            if not m:  # e.g. GRANT `role`@`%` TO ...: inherited privileges this check can't see
                problems.append("database account inherits a role; grant SELECT/EXECUTE directly so they can be checked")
                continue
            obj = m.group(2)
            for priv in re.split(r",\s*(?![^()]*\))", m.group(1)):  # commas inside "SELECT (a, b)" don't split
                base = priv.split("(")[0].strip().upper()
                if base not in MYSQL_READ_PRIVILEGES:
                    problems.append(f"database account has {base} on {obj}")
                elif obj == "*.*" and base != "USAGE":
                    problems.append(f"database account has {base} on *.* (grant it on this database only)")
        return problems

    def _run(self, sql, params=None):
        with self.conn.cursor() as c:
            c.execute(sql, params)
            cols = [d[0] for d in c.description] if c.description else []
            return cols, (list(c.fetchall()) if c.description else [])

    def execute(self, sql):
        with self.lock:
            with self.conn.cursor() as c:
                c.execute("START TRANSACTION READ ONLY")
            try:
                return self._run(sql)
            finally:
                with self.conn.cursor() as c:
                    c.execute("ROLLBACK")

    def admin_query(self, sql, params=None):
        with self.lock:
            return self._run(sql, params)

    def admin_script(self, sql):
        with self.lock, self.conn.cursor() as c:
            for stmt in [x.strip() for x in sql.split(";") if x.strip()]:
                c.execute(stmt)

    def insert_many(self, table, rows):
        if rows:
            with self.lock, self.conn.cursor() as c:
                c.executemany(f'INSERT INTO "{table}" VALUES ({",".join(["%s"] * len(rows[0]))})', rows)

    def tables(self):
        return [r[0] for r in self.admin_query(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() "
            "AND table_type = 'BASE TABLE' ORDER BY table_name")[1]]

    def columns(self, table):
        return [(r[0], r[1].upper()) for r in self.admin_query(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = DATABASE() "
            "AND table_name = %s ORDER BY ordinal_position", (table,))[1]]


def _mysql_connect(url):
    import pymysql
    u = urlparse(url)
    return pymysql.connect(host=u.hostname or "127.0.0.1", port=u.port or 3306, user=u.username,
                           password=u.password or "", database=u.path.lstrip("/") or "bank", autocommit=True,
                           charset="utf8mb4")


def _mysql_install(cursor):
    cursor.execute("SET SESSION sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')")
    for name in MYSQL_FUNCTION_NAMES:
        cursor.execute(f"DROP FUNCTION IF EXISTS {name}")
    for ddl in MYSQL_FUNCTIONS + [mysql_redact_function()]:
        cursor.execute(ddl)


def install_functions(url):
    """Create or replace the masking functions with an owner/admin account (`maskguard db-install`)."""
    scheme = urlparse(url).scheme
    if scheme in ("postgres", "postgresql"):
        import psycopg
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(PG_FUNCTIONS)
            conn.execute(pg_function_sql())
        return "postgres"
    if scheme in ("mysql", "mysql+pymysql"):
        conn = _mysql_connect(url)
        try:
            with conn.cursor() as c:
                _mysql_install(c)
        finally:
            conn.close()
        return "mysql"
    raise ValueError("db-install supports PostgreSQL and MySQL URLs")


def is_numeric(sql_type):
    base = (sql_type or "").upper().split("(")[0].strip()
    return base in NUMERIC_TYPES


def connect(url, install=True):
    """sqlite:///path/to.db, sqlite:///:memory:, postgresql://user:pw@host:port/db or mysql://user:pw@host:port/db.
    install=False: don't create the masking functions, require them (production, read-only account)."""
    scheme = urlparse(url).scheme
    if scheme == "sqlite":
        return SQLiteBackend(url[len("sqlite:///"):] or ":memory:")
    if scheme in ("postgres", "postgresql"):
        return PostgresBackend(url, install=install)
    if scheme in ("mysql", "mysql+pymysql"):
        return MySQLBackend(url, install=install)
    raise ValueError(f"unsupported database URL: {url}")
