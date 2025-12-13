import pytest

def _table_exists(conn, table_name):
    cur = conn.cursor()
    cur.execute("SELECT to_regclass(%s);", (f"public.{table_name}",))
    exists = cur.fetchone()[0] is not None
    cur.close()
    return exists

def test_create_and_query_book(db_conn):
    """
    Insert a book row and read it back.

    This test will be skipped if a `books` table is not present in the test DB.
    """
    if not _table_exists(db_conn, "books"):
        pytest.skip("books table not present")

    cur = db_conn.cursor()
    cur.execute(
        "INSERT INTO books (title, author, copies_total) VALUES (%s,%s,%s) RETURNING id;",
        ("PyTest Book", "PyTester", 2),
    )
    book_id = cur.fetchone()[0]
    db_conn.commit()

    cur.execute("SELECT title, author, copies_total FROM books WHERE id = %s;", (book_id,))
    row = cur.fetchone()
    cur.close()

    assert row is not None
    assert row[0] == "PyTest Book"
    assert row[1] == "PyTester"
    assert row[2] == 2
    

