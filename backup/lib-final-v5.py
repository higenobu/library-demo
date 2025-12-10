# Full app with:
# - Combined confirm / table callbacks (single writers) to avoid duplicate outputs
# - Multi-select borrow with confirmation modal
# - Simple inventory: books.copies_total and books.copies_available with transactional updates
# - Single-process run recommended: debug=False, use_reloader=False
#
# Replace your current lib-final-v3.py with this file, then run:
#   python lib-final-v3.py --run
#
# Notes:
# - ensure_tables() will create the base tables and add copies_* columns if missing.
# - If you already have books data, ensure you run the migration step shown in the logs or run the ALTER/UPDATE SQL manually.
# - This file is a standalone runnable Dash + Flask app.

import os
import time
from datetime import date
from flask import Flask, redirect, url_for, has_request_context, request, render_template_string, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
from psycopg2 import errors
from psycopg2 import IntegrityError

import dash
from dash import html, dcc, no_update, callback_context
from dash import dash_table
from dash.dependencies import Input, Output, State

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://matsuo:masanobu@localhost:5432/emr_sample")
SECRET_KEY = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# -----------------------------------------------------------------------------
# Flask + Login
# -----------------------------------------------------------------------------
server = Flask(__name__)
server.secret_key = SECRET_KEY
server.logger.setLevel("DEBUG")

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = "/login"

# -----------------------------------------------------------------------------
# DB helpers
# -----------------------------------------------------------------------------
def get_db_conn():
    return psycopg2.connect(DATABASE_URL)
'''
def ensure_tables():
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # core tables
                cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    role TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
                );
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS books (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    author TEXT,
                    isbn TEXT,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
                );
                """)
                cur.execute("""
                CREATE TABLE IF NOT EXISTS rent (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
                    rent_date DATE DEFAULT (CURRENT_DATE),
                    return_date DATE NULL
                );
                """)
                # inventory columns (add if missing)
                cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_total INTEGER DEFAULT 1 NOT NULL;")
                cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_available INTEGER DEFAULT 1 NOT NULL;")
                # ensure non-negative constraint exists (attempt add; ignore if exists)
                try:
                    cur.execute("ALTER TABLE books ADD CONSTRAINT copies_available_nonnegative CHECK (copies_available >= 0);")
                except Exception:
                    # constraint may already exist
                    pass
                # backfill copies_available based on active rents if needed
                cur.execute("""
                    UPDATE books b
                    SET copies_available = GREATEST(b.copies_total - COALESCE(ar.cnt, 0), 0)
                    FROM (
                        SELECT book_id, COUNT(*) AS cnt
                        FROM rent
                        WHERE return_date IS NULL
                        GROUP BY book_id
                    ) AS ar
                    WHERE b.id = ar.book_id
                """)
    finally:
        conn.close()
'''
def ensure_tables():
    """
    Ensure core tables & inventory columns exist.
    Run DDL statements in autocommit mode to avoid a failed statement aborting subsequent ones,
    then run the backfill update in a normal transaction.
    """
    # 1) Run DDL / schema changes in autocommit so a single failing DDL doesn't leave conn aborted.
    conn = get_db_conn()
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS books (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                author TEXT,
                isbn TEXT,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
            );
            """)
            cur.execute("""
            CREATE TABLE IF NOT EXISTS rent (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                book_id INTEGER NOT NULL REFERENCES books(id) ON DELETE CASCADE,
                rent_date DATE DEFAULT (CURRENT_DATE),
                return_date DATE NULL
            );
            """)
            # inventory columns (safe with IF NOT EXISTS)
            cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_total INTEGER DEFAULT 1 NOT NULL;")
            cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_available INTEGER DEFAULT 1 NOT NULL;")
            # add constraint if not exists (catch duplicate object)
            try:
                cur.execute("ALTER TABLE books ADD CONSTRAINT copies_available_nonnegative CHECK (copies_available >= 0);")
            except psycopg2.errors.DuplicateObject:
                # constraint already exists — ignore
                pass
    finally:
        try:
            conn.autocommit = False
        except Exception:
            pass
        conn.close()

    # 2) Run backfill/update in a proper transaction (so errors here will rollback cleanly)
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE books b
                    SET copies_available = GREATEST(b.copies_total - COALESCE(ar.cnt, 0), 0)
                    FROM (
                        SELECT book_id, COUNT(*) AS cnt
                        FROM rent
                        WHERE return_date IS NULL
                        GROUP BY book_id
                    ) AS ar
                    WHERE b.id = ar.book_id
                """)
    finally:
        conn.close()
def get_all_books():
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title, author, copies_total, copies_available FROM books ORDER BY title")
            rows = cur.fetchall()
            return [
                {
                    "id": r[0],
                    "title": r[1] or "",
                    "author": r[2] or "",
                    "copies_total": r[3] if r[3] is not None else 1,
                    "copies_available": r[4] if r[4] is not None else (r[3] if r[3] is not None else 1)
                } for r in rows
            ]
    finally:
        conn.close()

def get_books_by_ids(book_ids):
    if not book_ids:
        return {}
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title, author, copies_total, copies_available FROM books WHERE id = ANY(%s)", (book_ids,))
            rows = cur.fetchall()
            return {r[0]: {"id": r[0], "title": r[1] or "", "author": r[2] or "", "copies_total": r[3], "copies_available": r[4]} for r in rows}
    finally:
        conn.close()

def get_user_row(username=None, user_id=None):
    q = None
    params = None
    if username is not None:
        q = "SELECT id, username, password_hash, role FROM users WHERE username = %s"
        params = (username,)
    elif user_id is not None:
        q = "SELECT id, username, password_hash, role FROM users WHERE id = %s"
        params = (user_id,)
    else:
        return None
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(q, params)
            return cur.fetchone()
    finally:
        conn.close()

def create_user(username, password, role="doctor", email=None):
    password_hash = generate_password_hash(password)
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, email, role) VALUES (%s, %s, %s, %s) RETURNING id",
                    (username, password_hash, email, role),
                )
                return cur.fetchone()[0]
    except IntegrityError as e:
        server.logger.debug("create_user IntegrityError: %s", e)
        raise ValueError("username exists")
    finally:
        conn.close()

def create_book(title, author=None, isbn=None, copies=1):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO books (title, author, isbn, copies_total, copies_available) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (title, author, isbn, copies, copies)
                )
                bid = cur.fetchone()[0]
                server.logger.debug("create_book created id=%s title=%s copies=%s", bid, title, copies)
                return bid
    finally:
        conn.close()

# Basic rent create (kept for compatibility but not used if inventory enabled)
def create_rent(user_id, book_id, rent_date=None):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                if rent_date:
                    cur.execute(
                        "INSERT INTO rent (user_id, book_id, rent_date) VALUES (%s, %s, %s) RETURNING id",
                        (user_id, book_id, rent_date)
                    )
                else:
                    cur.execute(
                        "INSERT INTO rent (user_id, book_id) VALUES (%s, %s) RETURNING id",
                        (user_id, book_id)
                    )
                rid = cur.fetchone()[0]
                server.logger.debug("create_rent created id=%s user_id=%s book_id=%s", rid, user_id, book_id)
                return rid
    finally:
        conn.close()

# Inventory-aware rent creation (transactional)
def create_rent_with_inventory(user_id, book_id, rent_date=None):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # lock the book row to avoid races
                cur.execute("SELECT copies_available FROM books WHERE id = %s FOR UPDATE", (book_id,))
                row = cur.fetchone()
                if not row:
                    server.logger.debug("Book not found id=%s", book_id)
                    return None
                copies_available = row[0] or 0
                if copies_available <= 0:
                    server.logger.debug("No copies available for book_id=%s", book_id)
                    return None
                # decrement available
                cur.execute("UPDATE books SET copies_available = copies_available - 1 WHERE id = %s", (book_id,))
                # insert rent
                if rent_date:
                    cur.execute(
                        "INSERT INTO rent (user_id, book_id, rent_date) VALUES (%s, %s, %s) RETURNING id",
                        (user_id, book_id, rent_date)
                    )
                else:
                    cur.execute(
                        "INSERT INTO rent (user_id, book_id) VALUES (%s, %s) RETURNING id",
                        (user_id, book_id)
                    )
                rid = cur.fetchone()[0]
                server.logger.debug("create_rent_with_inventory created id=%s user_id=%s book_id=%s", rid, user_id, book_id)
                return rid
    except Exception:
        server.logger.exception("Error in create_rent_with_inventory")
        return None
    finally:
        conn.close()

def has_active_rent(user_id, book_id):
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM rent WHERE user_id = %s AND book_id = %s AND return_date IS NULL LIMIT 1",
                (user_id, book_id)
            )
            row = cur.fetchone()
            return row is not None
    finally:
        conn.close()

def mark_rent_returned_with_inventory(rent_id):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # ensure rent exists and is not returned, lock row
                cur.execute("SELECT book_id FROM rent WHERE id = %s AND return_date IS NULL FOR UPDATE", (rent_id,))
                row = cur.fetchone()
                if not row:
                    return False
                book_id = row[0]
                # mark returned
                cur.execute("UPDATE rent SET return_date = CURRENT_DATE WHERE id = %s AND return_date IS NULL RETURNING id", (rent_id,))
                rr = cur.fetchone()
                if not rr:
                    return False
                # increment available
                cur.execute("UPDATE books SET copies_available = copies_available + 1 WHERE id = %s", (book_id,))
                return True
    except Exception:
        server.logger.exception("Error in mark_rent_returned_with_inventory")
        return False
    finally:
        conn.close()

def delete_rent_with_inventory(rent_id):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # find active rent and lock
                cur.execute("SELECT book_id FROM rent WHERE id = %s AND return_date IS NULL FOR UPDATE", (rent_id,))
                row = cur.fetchone()
                if not row:
                    # if already returned or not found, just attempt delete
                    cur.execute("DELETE FROM rent WHERE id = %s RETURNING id", (rent_id,))
                    return cur.fetchone() is not None
                book_id = row[0]
                cur.execute("DELETE FROM rent WHERE id = %s RETURNING id", (rent_id,))
                deleted = cur.fetchone()
                if deleted:
                    cur.execute("UPDATE books SET copies_available = copies_available + 1 WHERE id = %s", (book_id,))
                    return True
                return False
    except Exception:
        server.logger.exception("Error in delete_rent_with_inventory")
        return False
    finally:
        conn.close()

def get_rented_books_for_user(user_id):
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT r.id, b.id, b.title, b.author, r.rent_date, r.return_date
                FROM rent r
                JOIN books b ON r.book_id = b.id
                WHERE r.user_id = %s
                ORDER BY r.rent_date DESC, r.id DESC
            """, (user_id,))
            rows = cur.fetchall()
            result = []
            for row in rows:
                rent_id, book_id, title, author, rent_date, return_date = row
                result.append({
                    "rent_id": rent_id,
                    "book_id": book_id,
                    "title": title,
                    "author": author or "",
                    "rent_date": rent_date.strftime("%Y-%m-%d") if rent_date else "",
                    "return_date": return_date.strftime("%Y-%m-%d") if return_date else "",
                    "return_action": "返却" if not return_date else "",
                    "cancel_action": "キャンセル" if not return_date else ""
                })
            return result
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# User model
# -----------------------------------------------------------------------------
class User(UserMixin):
    def __init__(self, id_, username, password_hash, role):
        self.id = id_
        self.username = username
        self.password_hash = password_hash
        self.role = role

    @staticmethod
    def get_by_username(username):
        row = get_user_row(username=username)
        if not row:
            return None
        id_, uname, passwd_hash, role = row
        return User(id_, uname, passwd_hash, role)

    @staticmethod
    def get_by_id(user_id):
        row = get_user_row(user_id=user_id)
        if not row:
            return None
        id_, uname, passwd_hash, role = row
        return User(id_, uname, passwd_hash, role)

@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(int(user_id))

# -----------------------------------------------------------------------------
# Dash app
# -----------------------------------------------------------------------------
app = dash.Dash(__name__, server=server, url_base_pathname="/", suppress_callback_exceptions=True)

def serve_layout():
    if not has_request_context():
        return html.Div([dcc.Location(id='url'), html.Div("Loading...")])

    if current_user.is_authenticated:
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.H3(f"こんにちは、{current_user.username}さん（{current_user.role}）"),
            html.A("ログアウト", href="/logout"),
            html.Hr(),
            html.H4("あなたのレンタル中の本（表形式）"),
            html.Div([
                html.Button("再読み込み", id='refresh-rents', n_clicks=0),
                dcc.Store(id='rents-refresh', data=0),
            ], style={'marginBottom': '8px'}),
            dcc.Interval(id='load-once', interval=200, n_intervals=0, max_intervals=1),

            # --- Books -> Rent UI (multi + summary + confirm modal) ---
            html.H4("本を借りる"),
            html.Div([
                dcc.Dropdown(id='books-dropdown', options=[], placeholder='本を選択してください', multi=True),
                html.Button("借りる", id='rent-book-btn', n_clicks=0, style={'marginTop': '6px'}),
                html.Div(id='rent-book-result', style={'marginTop': '8px', 'color': 'green'}),
                html.Div(id='books-selection-summary', style={'marginTop': '8px'}),
                dcc.Store(id='confirm-selection', data=None),
                # confirmation modal (hidden by default)
                html.Div(id='confirm-modal',
                         style={'display': 'none', 'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%',
                                'backgroundColor': 'rgba(0,0,0,0.5)', 'zIndex': 1000},
                         children=html.Div([
                             html.Div(id='confirm-modal-body',
                                      style={'backgroundColor': 'white', 'padding': '20px', 'maxWidth': '700px',
                                             'margin': '80px auto', 'borderRadius': '6px', 'boxShadow': '0 2px 10px rgba(0,0,0,0.2)'}),
                             html.Div([
                                 html.Button('確定して借りる', id='confirm-rent-btn', n_clicks=0, style={'backgroundColor': '#28a745', 'color': 'white'}),
                                 html.Button('キャンセル', id='cancel-rent-btn', n_clicks=0, style={'marginLeft': '8px'})
                             ], style={'textAlign': 'right', 'marginTop': '12px', 'maxWidth': '700px', 'margin': '12px auto 40px auto'})
                         ])
                ),
            ], style={'marginBottom': '12px'}),
            # --- end added ---

            dash_table.DataTable(
                id='rents-table',
                columns=[
                    {"name": "Rent ID", "id": "rent_id", "hidden": True},
                    {"name": "Book ID", "id": "book_id", "hidden": True},
                    {"name": "タイトル", "id": "title"},
                    {"name": "著者", "id": "author"},
                    {"name": "借用日", "id": "rent_date"},
                    {"name": "返却日", "id": "return_date"},
                    {"name": "返却", "id": "return_action"},
                    {"name": "キャンセル", "id": "cancel_action"},
                ],
                data=[],
                style_cell={'textAlign': 'left', 'padding': '6px'},
                style_header={'fontWeight': 'bold'},
                page_action='none',
                style_table={'overflowX': 'auto', 'maxHeight': '400px'},
                style_data_conditional=[
                    {
                        'if': {'column_id': 'return_action'},
                        'color': 'white',
                        'backgroundColor': '#28a745',
                        'cursor': 'pointer',
                    },
                    {
                        'if': {'column_id': 'cancel_action'},
                        'color': 'white',
                        'backgroundColor': '#dc3545',
                        'cursor': 'pointer',
                    },
                    {
                        'if': {'filter_query': '{return_action} = ""', 'column_id': 'return_action'},
                        'backgroundColor': '#f8f9fa',
                        'color': '#6c757d',
                        'cursor': 'default',
                    },
                    {
                        'if': {'filter_query': '{cancel_action} = ""', 'column_id': 'cancel_action'},
                        'backgroundColor': '#f8f9fa',
                        'color': '#6c757d',
                        'cursor': 'default',
                    },
                ],
                style_cell_conditional=[
                    {'if': {'column_id': 'title'}, 'width': '35%'},
                    {'if': {'column_id': 'author'}, 'width': '25%'},
                    {'if': {'column_id': 'return_action'}, 'width': '8%'},
                    {'if': {'column_id': 'cancel_action'}, 'width': '10%'},
                ],
            ),
            html.Div(id='rents-action-result', style={'marginTop': '12px', 'color': 'green'}),
            html.Hr(),
        ], style={'maxWidth': '1000px', 'margin': 'auto'})

    else:
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.H2("ログインが必要です"),
            html.P(html.A("ログインページへ", href="/login")),
            html.Hr(),
            html.H4("新規ユーザ作成（Dashで可能）"),
            dcc.Input(id='signup-username', type='text', placeholder='ユーザー名'),
            dcc.Input(id='signup-email', type='email', placeholder='メールアドレス (任意)'),
            dcc.Input(id='signup-password', type='password', placeholder='パスワード'),
            dcc.Dropdown(id='signup-role', options=[
                {'label': 'Doctor', 'value': 'doctor'},
                {'label': 'Admin', 'value': 'admin'}
            ], value='doctor'),
            html.Button("登録", id='signup-btn'),
            html.Div(id='signup-message', style={'color': 'green', 'marginTop': '10px'})
        ], style={'maxWidth': '700px', 'margin': 'auto'})

app.layout = serve_layout

# -----------------------------------------------------------------------------
# Flask routes (login etc.)
# -----------------------------------------------------------------------------
LOGIN_PAGE_HTML = """
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body>
  <h2>ログイン</h2>
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      <ul>
      {% for m in messages %}
        <li style="color:red;">{{ m }}</li>
      {% endfor %}
      </ul>
    {% endif %}
  {% endwith %}
  <form method="post" action="/do_login">
    <label>ユーザー名: <input type="text" name="username" required></label><br>
    <label>パスワード: <input type="password" name="password" required></label><br>
    <button type="submit">ログイン</button>
  </form>
  <hr>
  <p><a href="/">トップに戻る</a></p>
</body>
</html>
"""

@server.route("/auth")
def auth_status():
    return jsonify({
        "authenticated": bool(getattr(current_user, "is_authenticated", False)),
        "user_id": getattr(current_user, "id", None),
        "username": getattr(current_user, "username", None),
        "cookie_sent": request.headers.get("Cookie"),
        "session_contents": dict(session)
    })

@server.route("/login", methods=["GET"])
def login_page():
    return render_template_string(LOGIN_PAGE_HTML)

@server.route("/do_login", methods=["POST"])
def do_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    server.logger.debug("do_login called for username=%s", username)
    if not username or not password:
        server.logger.debug("do_login missing credentials")
        flash("ユーザー名とパスワードを入力してください")
        return redirect(url_for("login_page"))

    user = User.get_by_username(username)
    if user:
        server.logger.debug("Found user id=%s username=%s", user.id, user.username)
    else:
        server.logger.debug("User not found: %s", username)

    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        server.logger.debug("login_user succeeded for username=%s", username)
        return redirect(url_for("index"))
    else:
        server.logger.debug("login_user failed for username=%s", username)
        flash("認証失敗: ユーザー名またはパスワードが正しくありません")
        return redirect(url_for("login_page"))

@server.route("/logout")
def do_logout():
    logout_user()
    return redirect(url_for("index"))

@server.route("/")
def index():
    return redirect("/")
@server.route("/debug/my_rents")
def debug_my_rents():
    if not getattr(current_user, "is_authenticated", False):
        return jsonify({"error": "not authenticated", "session": dict(session)}), 401
    try:
        rows = get_rented_books_for_user(current_user.id)
        return jsonify({"user_id": current_user.id, "username": current_user.username, "rents": rows})
    except Exception as e:
        server.logger.exception("Error in debug_my_rents")
        return jsonify({"error": "server error", "detail": str(e)}), 500

# -----------------------------------------------------------------------------
# Dash callbacks
# -----------------------------------------------------------------------------

from dash import callback_context
from dash import callback_context

@app.callback(
    Output('rents-table', 'data'),
    Input('rents-refresh', 'data'),
    Input('refresh-rents', 'n_clicks'),
    Input('load-once', 'n_intervals'),
    prevent_initial_call=False
)
def load_rents_table(refresh_token, refresh_clicks, n_intervals):
    """
    Ensure the rents-table gets the current user's rented books.
    Triggered on initial load (load-once), explicit refresh button, and rents-refresh token.
    """
    server.logger.debug(
        "load_rents_table called; user=%s refresh_token=%s refresh_clicks=%s n_intervals=%s",
        getattr(current_user, "id", None), refresh_token, refresh_clicks, n_intervals
    )
    # If layout rendered outside a request context or not authenticated, return empty list
    if not has_request_context() or not getattr(current_user, "is_authenticated", False):
        server.logger.debug("Not authenticated in load_rents_table or no request context")
        return []
    try:
        rows = get_rented_books_for_user(current_user.id)
        server.logger.debug("get_rented_books_for_user returned %d rows for user=%s", len(rows), current_user.id)
        return rows
    except Exception:
        server.logger.exception("Error loading rents in load_rents_table")
        return []
@app.callback(
    Output('books-selection-summary', 'children'),
    Output('confirm-modal-body', 'children'),
    Input('books-dropdown', 'value'),
    prevent_initial_call=False
)
def update_selection_summary(selected_values):
    if not has_request_context() or not current_user.is_authenticated:
        return html.Div(""), html.Div("")

    if not selected_values:
        return html.Div("選択されていません"), html.Div("選択されていません")

    if isinstance(selected_values, (str, int)):
        ids = [selected_values]
    else:
        ids = list(selected_values)

    try:
        ids_int = []
        for v in ids:
            try:
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("Invalid selection value: %s", v)
        books_map = get_books_by_ids(ids_int)
        inline_children = []
        modal_children = [html.H4("確認: 選択した本")]
        for bid in ids_int:
            b = books_map.get(bid)
            title = b.get('title') if b else str(bid)
            author = b.get('author') if b else ""
            active = has_active_rent(current_user.id, bid)
            status = html.Span("既にレンタル中", style={'color': 'red'}) if active else html.Span("利用可能", style={'color': 'green'})
            inline_children.append(html.Div([html.Strong(title), html.Span(f" / {author}" if author else ""), html.Span(" — "), status]))
            modal_children.append(html.Div([html.Strong(title), html.Span(f" / {author}" if author else ""), html.Span(" — "), status]))
        return html.Div(inline_children), html.Div(modal_children)
    except Exception:
        server.logger.exception("Error building selection summary")
        return html.Div("エラー"), html.Div("エラー")
'''
@app.callback(
    Output('confirm-selection', 'data'),
    Input('rent-book-btn', 'n_clicks'),
    State('books-dropdown', 'value'),
    prevent_initial_call=True
)
def open_confirm_modal(n_clicks, selected_values):
    """Open the confirmation selection store only. Combined handler will show/hide the modal."""
    if not has_request_context() or not current_user.is_authenticated:
        return None
    if not selected_values:
        return None
    # normalize
    if isinstance(selected_values, (str, int)):
        ids = [selected_values]
    else:
        ids = list(selected_values)
    normalized = []
    for v in ids:
        try:
            normalized.append(int(v))
        except Exception:
            server.logger.debug("Invalid book id selected: %s", v)
    if not normalized:
        return None
    # store the selection; combined_confirm_or_table will handle showing the modal
    return normalized
'''

# Replace the combined_confirm_or_table callback block with the version below.
# Also remove or comment out the open_confirm_modal() function (it becomes unused).
from dash import callback_context

@app.callback(
    Output('rent-book-result', 'children'),
    Output('rents-action-result', 'children'),
    Output('rents-refresh', 'data'),
    Output('confirm-modal', 'style'),
    Input('rent-book-btn', 'n_clicks'),
    Input('confirm-rent-btn', 'n_clicks'),
    Input('cancel-rent-btn', 'n_clicks'),
    Input('rents-table', 'active_cell'),
    State('books-dropdown', 'value'),
    State('rents-table', 'data'),
    prevent_initial_call=True
)
def combined_confirm_or_table(rent_btn_clicks, confirm_clicks, cancel_clicks, active_cell, selected_values, table_data):
    """
    Single callback handling:
      - rent-book-btn: show confirmation modal (uses current selection from books-dropdown)
      - confirm-rent-btn: perform bulk create (reads selected_values)
      - cancel-rent-btn: hide modal
      - rents-table active_cell: return/cancel actions
    This callback is the UNIQUE writer for rent-book-result and confirm-modal.style.
    """
    if not has_request_context() or not current_user.is_authenticated:
        return "ログインが必要です", "ログインしてください", no_update, {'display': 'none'}

    trig = callback_context.triggered
    if not trig:
        raise dash.exceptions.PreventUpdate
    prop = trig[0].get('prop_id', '')

    rent_msg = no_update
    action_msg = no_update
    refresh_token = no_update
    modal_style = no_update

    try:
        # 1) Show modal when user clicks "借りる"
        if prop.startswith('rent-book-btn'):
            if not selected_values:
                return "本を選んでください", no_update, no_update, no_update
            # normalize selection to list of ints
            if isinstance(selected_values, (str, int)):
                ids = [selected_values]
            else:
                ids = list(selected_values)
            normalized = []
            for v in ids:
                try:
                    normalized.append(int(v))
                except Exception:
                    server.logger.debug("Invalid book id selected (rent-book-btn): %s", v)
            if not normalized:
                return "有効な本が選択されていません", no_update, no_update, no_update
            # show modal overlay
            modal_style = {'display': 'block', 'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%',
                           'backgroundColor': 'rgba(0,0,0,0.5)', 'zIndex': 1000}
            return no_update, no_update, no_update, modal_style

        # 2) Confirm: perform bulk create
        elif prop.startswith('confirm-rent-btn'):
            if not selected_values:
                return "選択が無効です", no_update, no_update, {'display': 'none'}
            if isinstance(selected_values, (str, int)):
                ids = [selected_values]
            else:
                ids = list(selected_values)
            # cast to ints
            ids_int = []
            for v in ids:
                try:
                    ids_int.append(int(v))
                except Exception:
                    server.logger.debug("Invalid id in selection when confirming: %s", v)
            if not ids_int:
                return "有効な本が選択されていません", no_update, no_update, {'display': 'none'}

            # perform inventory-aware creates (use create_rent_with_inventory if available)
            created = []
            skipped = []
            for bid in ids_int:
                # prefer inventory-aware function if present
                try:
                    rid = None
                    if 'create_rent_with_inventory' in globals():
                        rid = create_rent_with_inventory(current_user.id, bid)
                    else:
                        rid = create_rent(current_user.id, bid)
                    if rid:
                        created.append(rid)
                    else:
                        books_map = get_books_by_ids([bid])
                        if books_map and books_map.get(bid, {}).get('copies_available') is not None and books_map.get(bid)['copies_available'] <= 0:
                            skipped.append({"book_id": bid, "reason": "在庫なし"})
                        elif has_active_rent(current_user.id, bid):
                            skipped.append({"book_id": bid, "reason": "既にレンタル中"})
                        else:
                            skipped.append({"book_id": bid, "reason": "作成失敗"})
                except Exception:
                    server.logger.exception("Error creating rent for book_id=%s user_id=%s", bid, current_user.id)
                    skipped.append({"book_id": bid, "reason": "サーバエラー"})

            parts = []
            if created:
                parts.append(f"{len(created)} 件レンタル登録しました")
            if skipped:
                books_map = get_books_by_ids(ids_int)
                sk_msgs = []
                for s in skipped:
                    bid = s.get('book_id')
                    title = books_map.get(bid, {}).get('title') if isinstance(bid, int) else None
                    if title:
                        sk_msgs.append(f"'{title}': {s.get('reason')}")
                    else:
                        sk_msgs.append(f"{bid}: {s.get('reason')}")
                parts.append("スキップ: " + "; ".join(sk_msgs))
            rent_msg = " / ".join(parts) if parts else "レンタルに失敗しました"
            if created:
                refresh_token = int(time.time())
            # hide modal
            modal_style = {'display': 'none'}
            return rent_msg, no_update, refresh_token, modal_style

        # 3) Cancel button (hide modal)
        elif prop.startswith('cancel-rent-btn'):
            return no_update, no_update, no_update, {'display': 'none'}

        # 4) Table actions (return/cancel) remain unchanged
        elif prop.startswith('rents-table'):
            if not active_cell:
                raise dash.exceptions.PreventUpdate
            row = active_cell.get('row')
            col_id = active_cell.get('column_id')
            if row is None or col_id is None:
                raise dash.exceptions.PreventUpdate
            row_data = table_data[row]
            rent_id = row_data.get('rent_id')
            if col_id == 'return_action':
                if row_data.get('return_date'):
                    action_msg = "既に返却済みです"
                    return no_update, action_msg, no_update, no_update
                ok = None
                if 'mark_rent_returned_with_inventory' in globals():
                    ok = mark_rent_returned_with_inventory(rent_id)
                else:
                    ok = mark_rent_returned(rent_id)
                if ok:
                    action_msg = "返却しました"
                    refresh_token = int(time.time())
                else:
                    action_msg = "返却に失敗しました"
                return no_update, action_msg, refresh_token, no_update
            elif col_id == 'cancel_action':
                ok = None
                if 'delete_rent_with_inventory' in globals():
                    ok = delete_rent_with_inventory(rent_id)
                else:
                    ok = delete_rent(rent_id)
                if ok:
                    action_msg = "レンタルをキャンセルしました"
                    refresh_token = int(time.time())
                else:
                    action_msg = "キャンセルに失敗しました"
                return no_update, action_msg, refresh_token, no_update
            else:
                raise dash.exceptions.PreventUpdate

        else:
            raise dash.exceptions.PreventUpdate

    except Exception:
        server.logger.exception("Error in combined confirm/table callback")
        return "エラーが発生しました", "エラーが発生しました", no_update, {'display': 'none'}
@app.callback(
    Output('books-dropdown', 'options'),
    Input('load-once', 'n_intervals'),
    Input('rents-refresh', 'data'),
    prevent_initial_call=False
)
def load_books_dropdown(n_intervals, refresh_token):
    if not has_request_context() or not current_user.is_authenticated:
        return []
    try:
        books = get_all_books()
        options = [
            {"label": f"{b['title']} / {b['author']}" + (f" ({b['copies_available']} available)" if b.get('copies_available') is not None else ""), "value": str(b['id'])}
            for b in books
        ]
        return options
    except Exception:
        server.logger.exception("Error loading books for dropdown")
        return []

# -----------------------------------------------------------------------------
# CLI helpers
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-user", nargs=4, metavar=("USERNAME", "PASSWORD", "ROLE", "EMAIL"), help="Create a new user (email optional)")
    #parser.add_argument("--create-book", nargs='+', metavar=("TITLE", "AUTHOR", "ISBN", "COPIES"), help="Create a book record (quote args as needed). Optionally add copies number as 4th arg.")
    #parser.add_argument("--create-book", nargs='+', metavar=("TITLE", "AUTHOR", "ISBN", "COPIES"), help="Create a book record (quote args as needed). Optionally add copies number as 4th arg.")
    parser.add_argument("--create-book", nargs='+', metavar='BOOK_ARGS', help="Create a book record (quote args as needed). Optionally add copies number as 4th arg.")
    parser.add_argument("--create-rent", nargs=3, metavar=("USER_ID", "BOOK_ID", "RENT_DATE"), help="Create a rent record (RENT_DATE optional: YYYY-MM-DD or 'None')")
    parser.add_argument("--run", action="store_true", help="Run server (Flask + Dash)")
    args = parser.parse_args()

    ensure_tables()

    if args.create_user:
        u, p, r, e = args.create_user
        try:
            uid = create_user(u, p, r, email=e if e != "None" else None)
            print(f"Created user id={uid} username={u} role={r} email={e}")
        except ValueError:
            print("username already exists")
        except Exception as ex:
            print("error:", ex)
    elif args.create_book:
        # accept either 3 args (title author isbn) or 4th copies
        parts = args.create_book
        title = parts[0]
        author = parts[1] if len(parts) > 1 else None
        isbn = parts[2] if len(parts) > 2 else None
        copies = int(parts[3]) if len(parts) > 3 else 1
        try:
            bid = create_book(title, author if author != "None" else None, isbn if isbn != "None" else None, copies=copies)
            print(f"Created book id={bid} title={title} copies={copies}")
        except Exception as ex:
            print("error creating book:", ex)
    elif args.create_rent:
        user_id_s, book_id_s, rent_date = args.create_rent
        try:
            user_id = int(user_id_s)
            book_id = int(book_id_s)
            rid = create_rent_with_inventory(user_id, book_id, rent_date if rent_date != "None" else None)
            print(f"Created rent id={rid} for user_id={user_id} book_id={book_id} rent_date={rent_date}")
        except Exception as ex:
            print("error creating rent:", ex)
    elif args.run:
        # single-process run to avoid double-registration during development
        server.run(host="0.0.0.0", port=8050, debug=False, use_reloader=False)
    else:
        parser.print_help()