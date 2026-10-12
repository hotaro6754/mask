"""Database abstraction: one interface over SQLite and PostgreSQL.

Gateway queries always run read-only: SQLite through an authorizer that only allows reads, PostgreSQL inside
a READ ONLY transaction with a statement timeout. Seeding and scanning use the admin paths.
"""
import hashlib, sqlite3, threading
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
        return [r[0] for r in self.admin_query(f'SELECT "{column}" FROM {self._qualified(table)} LIMIT {int(n)}')[1]]

    def checksum(self, table):
        cols, rows = self.admin_query(f"SELECT * FROM {self._qualified(table)} ORDER BY 1")
        h = hashlib.sha256(repr(cols).encode())
        for r in rows:
            h.update(repr(tuple(str(v) for v in r)).encode())
        return h.hexdigest()

    def _qualified(self, table):
        return f'"{self.default_schema}"."{table}"'


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

    def execute(self, sql):
        with self.lock:
            self.conn.set_authorizer(self._readonly)
            try:
                cur = self.conn.execute(sql)
                return [d[0] for d in cur.description or []], cur.fetchall()
            finally:
                self.conn.set_authorizer(None)

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


class PostgresBackend(Backend):
    dialect, default_schema = "postgres", "public"

    def __init__(self, url, hmac_key=None, statement_timeout_ms=5000):
        import psycopg
        self.url = url
        self.conn = psycopg.connect(url, autocommit=True)
        self.lock = threading.Lock()
        with self.lock:
            self.conn.execute(PG_FUNCTIONS)
            self.conn.execute(pg_function_sql())
            key = hmac_key if hmac_key is not None else masks._key().decode()
            self.conn.execute("SELECT set_config('maskguard.hmac_key', %s, false)", (key,))
            self.conn.execute(f"SET statement_timeout = {int(statement_timeout_ms)}")

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

    def __init__(self, url, hmac_key=None, statement_timeout_ms=5000):
        import pymysql
        u = urlparse(url)
        self.default_schema = u.path.lstrip("/") or "bank"
        self.conn = pymysql.connect(host=u.hostname or "127.0.0.1", port=u.port or 3306, user=u.username,
                                    password=u.password or "", database=self.default_schema, autocommit=True,
                                    charset="utf8mb4")
        self.lock = threading.Lock()
        key = hmac_key if hmac_key is not None else masks._key().decode()
        with self.lock, self.conn.cursor() as c:
            c.execute("SET SESSION sql_mode = CONCAT(@@sql_mode, ',ANSI_QUOTES')")  # "ident" like the other engines
            c.execute("SET @maskguard_hmac_key = %s", (key,))
            c.execute(f"SET SESSION max_execution_time = {int(statement_timeout_ms)}")
            # materialise each masked view once instead of merging it into the outer query; otherwise masking
            # functions re-run per row of every join/cross product
            c.execute("SET SESSION optimizer_switch = 'derived_merge=off'")
            for name in ("mg_partial", "mg_email", "mg_hmac", "mg_bucket", "mg_redact_text"):
                c.execute(f"DROP FUNCTION IF EXISTS {name}")
            for ddl in MYSQL_FUNCTIONS + [mysql_redact_function()]:
                c.execute(ddl)

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


def is_numeric(sql_type):
    base = (sql_type or "").upper().split("(")[0].strip()
    return base in NUMERIC_TYPES


def connect(url):
    """sqlite:///path/to.db, sqlite:///:memory:, postgresql://user:pw@host:port/db or mysql://user:pw@host:port/db"""
    scheme = urlparse(url).scheme
    if scheme == "sqlite":
        return SQLiteBackend(url[len("sqlite:///"):] or ":memory:")
    if scheme in ("postgres", "postgresql"):
        return PostgresBackend(url)
    if scheme in ("mysql", "mysql+pymysql"):
        return MySQLBackend(url)
    raise ValueError(f"unsupported database URL: {url}")
