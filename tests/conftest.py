"""
pytest fixtures for library-demo

- Creates/uses a test database (session-scoped) via TEST_DATABASE_URL or by creating
  a temporary DB using DATABASE_URL's server.
- Provides db_conn as a function-scoped psycopg2 connection that is rolled back/closed
  after each test to avoid transaction-aborted state.
"""

import os
import uuid
import time
from urllib.parse import urlparse, urlunparse

import pytest
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

TEST_DB_PREFIX = "test_lib_"


def _replace_dbname_in_url(url: str, dbname: str) -> str:
    p = urlparse(url)
    new_path = "/" + dbname
    new = p._replace(path=new_path)
    return urlunparse(new)


@pytest.fixture(scope="session")
def test_database_url():
    """
    Create a fresh database for the pytest session and return its DATABASE_URL.

    If TEST_DATABASE_URL env var is set, it's used as-is (no create/drop).
    Otherwise, DATABASE_URL must be set and we will create a temp DB on the same server.
    """
    provided = os.environ.get("TEST_DATABASE_URL")
    if provided:
        yield provided
        return

    base = os.environ.get("DATABASE_URL")
    if not base:
        raise RuntimeError(
            "DATABASE_URL env var must be set (or set TEST_DATABASE_URL). "
            "Example: postgresql://postgres:pass@db:5432/postgres"
        )

    parsed = urlparse(base)
    admin_dbname = "postgres"
    admin_url = _replace_dbname_in_url(base, admin_dbname)

    test_dbname = TEST_DB_PREFIX + uuid.uuid4().hex[:8]
    test_url = _replace_dbname_in_url(base, test_dbname)

    # create the test db
    admin_conn = psycopg2.connect(admin_url)
    admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    admin_cur = admin_conn.cursor()
    try:
        admin_cur.execute(f"CREATE DATABASE {test_dbname}")
    except Exception:
        admin_cur.close()
        admin_conn.close()
        raise
    admin_cur.close()
    admin_conn.close()

    # wait until ready
    for _ in range(30):
        try:
            conn = psycopg2.connect(test_url)
            conn.close()
            break
        except Exception:
            time.sleep(0.2)
    else:
        # cleanup if not ready
        admin_conn = psycopg2.connect(admin_url)
        admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        admin_cur = admin_conn.cursor()
        admin_cur.execute(f"DROP DATABASE IF EXISTS {test_dbname};")
        admin_cur.close()
        admin_conn.close()
        raise RuntimeError("Timed out waiting for test database to become available")

    prev_database_url = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = test_url

    # Try to initialize schema via application helper if available
    try:
        from app import ensure_tables  # noqa: WPS433,F401
        ensure_tables()
    except ImportError:
        # No ensure_tables available — tests must set up schema themselves or use existing DB
        pass
    except Exception:
        # cleanup on failure
        admin_conn = psycopg2.connect(admin_url)
        admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        admin_cur = admin_conn.cursor()
        admin_cur.execute(f"DROP DATABASE IF EXISTS {test_dbname};")
        admin_cur.close()
        admin_conn.close()
        if prev_database_url is not None:
            os.environ["DATABASE_URL"] = prev_database_url
        else:
            os.environ.pop("DATABASE_URL", None)
        raise

    try:
        yield test_url
    finally:
        # restore previous DATABASE_URL
        if prev_database_url is not None:
            os.environ["DATABASE_URL"] = prev_database_url
        else:
            os.environ.pop("DATABASE_URL", None)

        # drop the test DB (terminate connections first)
        admin_conn = psycopg2.connect(admin_url)
        admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        admin_cur = admin_conn.cursor()
        try:
            admin_cur.execute(
                "SELECT pid FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid();",
                (test_dbname,),
            )
            pids = [r[0] for r in admin_cur.fetchall()]
            for pid in pids:
                try:
                    admin_cur.execute("SELECT pg_terminate_backend(%s);", (pid,))
                except Exception:
                    pass
            admin_cur.execute(f"DROP DATABASE IF EXISTS {test_dbname};")
        finally:
            admin_cur.close()
            admin_conn.close()


@pytest.fixture(scope="function")
def db_conn(test_database_url):
    """
    Provide a fresh psycopg2 connection for each test function.
    Ensures rollback and close after each test to avoid transaction-aborted state.
    """
    conn = psycopg2.connect(test_database_url)
    try:
        yield conn
    finally:
        # on teardown, rollback any open transaction (clears aborted state) and close
        try:
            conn.rollback()
        except Exception:
            pass
        conn.close()
