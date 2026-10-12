"""PostgreSQL wire-protocol proxy, exercised with real clients: psycopg (extended protocol) and psql (simple)."""
import asyncio, shutil, socket, subprocess, threading

import psycopg
import pytest

from maskguard.pgwire import serve


@pytest.fixture
def proxy(sqlite_env):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    ready = threading.Event()
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    fut = asyncio.run_coroutine_threadsafe(serve(sqlite_env.app, "127.0.0.1", port, ready), loop)
    assert ready.wait(10)
    yield sqlite_env, port
    loop.call_soon_threadsafe(fut.cancel)
    try:
        fut.result(5)
    except BaseException:  # cancelled: expected
        pass
    loop.call_soon_threadsafe(loop.stop)
    t.join(5)
    loop.close()


def connect(port, user, pw):
    return psycopg.connect(f"host=127.0.0.1 port={port} user={user} password={pw} dbname=bank sslmode=disable",
                           autocommit=True)


def test_psycopg_masks_per_role_with_parameters(proxy):
    env, port = proxy
    sup = connect(port, "support.sam", "support123").cursor()
    sup.execute("SELECT ssn, credit_card FROM users u JOIN accounts a ON a.user_id = u.id WHERE u.id = %s", (1,))
    ssn, card = sup.fetchone()
    assert ssn.startswith("XXX-XX-") and "X" in card
    ana = connect(port, "analyst.ali", "analyst123").cursor()
    ana.execute("SELECT ssn FROM users WHERE id = %s", (1,))
    assert len(ana.fetchone()[0]) == 16  # keyed token


def test_auto_prepared_statements_keep_masking(proxy):
    env, port = proxy
    cur = connect(port, "support.sam", "support123").cursor()
    for i in range(1, 9):  # psycopg switches to server-side prepared statements after 5 runs
        cur.execute("SELECT email FROM users WHERE id = %s", (i,))
        assert "***@" in cur.fetchone()[0]


def test_errors_are_postgres_errors_and_connection_recovers(proxy):
    env, port = proxy
    cur = connect(port, "support.sam", "support123").cursor()
    with pytest.raises(psycopg.Error, match="MaskGuard"):
        cur.execute("DROP TABLE users")
    with pytest.raises(psycopg.Error, match="MaskGuard"):
        cur.execute("SELECT * FROM pg_catalog.pg_user")
    cur.execute("SELECT count(*) FROM users")
    assert cur.fetchone()[0] == 300
    assert env.backend.admin_query("SELECT count(*) FROM users")[1][0][0] == 300  # nothing dropped


def test_bad_password_is_refused(proxy):
    env, port = proxy
    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        connect(port, "support.sam", "nope")


def test_queries_through_proxy_are_audited(proxy):
    env, port = proxy
    connect(port, "support.sam", "support123").cursor().execute("SELECT name FROM users WHERE id = %s", (3,))
    log = open(env.gw.audit.path).read()
    assert '"user": "support.sam"' in log and "WHERE id = ?" in log


@pytest.mark.skipif(not shutil.which("psql"), reason="psql not installed")
def test_psql_simple_protocol(proxy):
    env, port = proxy
    out = subprocess.run(["psql", f"host=127.0.0.1 port={port} user=support.sam dbname=bank sslmode=disable", "-At",
                          "-c", "SELECT ssn FROM users ORDER BY id LIMIT 1"], env={"PGPASSWORD": "support123", "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, timeout=30)
    assert out.returncode == 0 and out.stdout.startswith("XXX-XX-"), out.stderr
