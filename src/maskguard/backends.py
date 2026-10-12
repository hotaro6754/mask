"""Database abstraction: one interface over SQLite and PostgreSQL.

Gateway queries always run read-only: SQLite through an authorizer that only allows reads, PostgreSQL inside
a READ ONLY transaction with a statement timeout. Seeding and scanning use the admin paths.
"""
import hashlib, sqlite3, threading
from urllib.parse import urlparse

from . import masks

NUMERIC_TYPES = {"INTEGER", "INT", "BIGINT", "SMALLINT", "REAL", "NUMERIC", "FLOAT", "DOUBLE", "DECIMAL",
                 "DOUBLE PRECISION"}

PG_FUNCTIONS = r"""
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION mg_partial(v text, pre int, suf int) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE total int; seen int := 0; res text := ''; ch text; p int := pre; s int := suf;
BEGIN
  IF v IS NULL THEN RETURN NULL; END IF;
  total := length(regexp_replace(v, '[^[:alnum:]]', '', 'g'));
  IF p + s >= total THEN p := 0; s := 0; END IF;
  FOREACH ch IN ARRAY regexp_split_to_array(v, '') LOOP
    IF ch ~ '^[[:alnum:]]$' THEN
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


def is_numeric(sql_type):
    base = (sql_type or "").upper().split("(")[0].strip()
    return base in NUMERIC_TYPES


def connect(url):
    """sqlite:///path/to.db, sqlite:///:memory:, or postgresql://user:pw@host:port/db"""
    scheme = urlparse(url).scheme
    if scheme == "sqlite":
        return SQLiteBackend(url[len("sqlite:///"):] or ":memory:")
    if scheme in ("postgres", "postgresql"):
        return PostgresBackend(url)
    raise ValueError(f"unsupported database URL: {url}")
