import pytest

def _table_exists(conn, table_name):
    cur = conn.cursor()
    cur.execute("SELECT to_regclass(%s);", (f"public.{table_name}",))
    exists = cur.fetchone()[0] is not None
    cur.close()
    return exists

def test_create_and_query_user(db_conn):
    """
    Insert a user row and read it back.

    This test will be skipped if a `users` table is not present in the test DB.
    """
    if not _table_exists(db_conn, "users"):
        pytest.skip("users table not present")

    cur = db_conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, role, email) VALUES (%s,%s,%s,%s) RETURNING id;",
        ("pytest_user", "pw", "member", "pytest@example.com"),
    )
    user_id = cur.fetchone()[0]
    db_conn.commit()

    cur.execute("SELECT username, role, email FROM users WHERE id = %s;", (user_id,))
    row = cur.fetchone()
    cur.close()

    assert row is not None
    assert row[0] == "pytest_user"
    assert row[1] == "member"
    assert row[2] == "pytest@example.com"
