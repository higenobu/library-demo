#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lib-final-v5-search-full.py
Full implementation with:
 - rents-table single-writer callback (existing)
 - instant search: input changes are picked up and applied automatically (debounced server-side)
 - search normalization: full-width spaces -> half-width, collapse spaces, trim
 - search tokenization: multiple tokens are ANDed for title search and ANDed for author search; combined via OR
 - search result highlight: matching terms wrapped with html.Mark in a result list under dropdown
 - click-to-select not implemented (user selects from dropdown) to keep UI simple and robust
 - Uses a small debounce implemented with a client-side quick update to a store and a server-side Interval-driven search trigger
Run:
  python lib-final-v5-search-full.py --run
"""
import os
import time
import re
from datetime import date
from flask import Flask, redirect, url_for, has_request_context, request, render_template_string, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
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

def ensure_tables():
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
            cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_total INTEGER DEFAULT 1 NOT NULL;")
            cur.execute("ALTER TABLE books ADD COLUMN IF NOT EXISTS copies_available INTEGER DEFAULT 1 NOT NULL;")
            try:
                cur.execute("ALTER TABLE books ADD CONSTRAINT copies_available_nonnegative CHECK (copies_available >= 0);")
            except Exception:
                pass
    finally:
        try:
            conn.autocommit = False
        except Exception:
            pass
        conn.close()

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

def get_books_by_search_tokens(title_tokens, author_tokens):
    """
    Search books by tokens (lists). We create a SQL query that ANDs tokens for title and ANDs tokens for author,
    then combines them with OR. If tokens list is empty for a side, we treat it as wildcard for that side.
    """
    # Normalize tokens to non-empty strings
    title_tokens = [t for t in title_tokens if t]
    author_tokens = [t for t in author_tokens if t]

    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            # If no tokens at all, return all
            if not title_tokens and not author_tokens:
                cur.execute("SELECT id, title, author, copies_total, copies_available FROM books ORDER BY title")
                rows = cur.fetchall()
            else:
                where_clauses = []
                params = []
                # Build title clause (AND tokens)
                if title_tokens:
                    title_and = []
                    for tok in title_tokens:
                        title_and.append("title ILIKE %s")
                        params.append(f"%{tok}%")
                    where_clauses.append("(" + " AND ".join(title_and) + ")")
                # Build author clause (AND tokens)
                if author_tokens:
                    author_and = []
                    for tok in author_tokens:
                        author_and.append("COALESCE(author,'') ILIKE %s")
                        params.append(f"%{tok}%")
                    where_clauses.append("(" + " AND ".join(author_and) + ")")
                # Combine with OR: (title_matches) OR (author_matches)
                sql_where = " OR ".join(where_clauses)
                sql = f"SELECT id, title, author, copies_total, copies_available FROM books WHERE {sql_where} ORDER BY title"
                cur.execute(sql, tuple(params))
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

def create_rent_with_inventory(user_id, book_id, rent_date=None):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SELECT copies_available FROM books WHERE id = %s FOR UPDATE", (book_id,))
                row = cur.fetchone()
                if not row:
                    server.logger.debug("Book not found id=%s", book_id)
                    return None
                copies_available = row[0] or 0
                if copies_available <= 0:
                    server.logger.debug("No copies available for book_id=%s", book_id)
                    return None
                cur.execute("UPDATE books SET copies_available = copies_available - 1 WHERE id = %s", (book_id,))
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
                cur.execute("SELECT book_id FROM rent WHERE id = %s AND return_date IS NULL FOR UPDATE", (rent_id,))
                row = cur.fetchone()
                if not row:
                    return False
                book_id = row[0]
                cur.execute("UPDATE rent SET return_date = CURRENT_DATE WHERE id = %s AND return_date IS NULL RETURNING id", (rent_id,))
                rr = cur.fetchone()
                if not rr:
                    return False
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
                cur.execute("SELECT book_id FROM rent WHERE id = %s AND return_date IS NULL FOR UPDATE", (rent_id,))
                row = cur.fetchone()
                if not row:
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
# Helpers for search normalization and highlighting
# -----------------------------------------------------------------------------
def normalize_search_text(s):
    """Normalize: convert full-width spaces to half-width, collapse whitespace, trim."""
    if not s:
        return ""
    # Replace full-width spaces (U+3000) with normal space
    s = s.replace("\u3000", " ")
    # Collapse any whitespace sequence into single space and strip
    s = re.sub(r"\s+", " ", s).strip()
    return s

def split_tokens(s):
    if not s:
        return []
    return [t for t in s.split(" ") if t]

def highlight_text_nodes(text, tokens):
    """
    Return a list of html nodes with matched tokens wrapped in html.Mark.
    Case-insensitive.
    """
    if not tokens or not text:
        return [text]
    # Build regex to match any token (longer tokens first to avoid partial overlaps)
    tokens_sorted = sorted(set(tokens), key=lambda x: -len(x))
    pattern = "(" + "|".join(re.escape(t) for t in tokens_sorted) + ")"
    parts = []
    last_end = 0
    for m in re.finditer(pattern, text, flags=re.IGNORECASE):
        if m.start() > last_end:
            parts.append(text[last_end:m.start()])
        parts.append(html.Mark(m.group(0)))
        last_end = m.end()
    if last_end < len(text):
        parts.append(text[last_end:])
    return parts

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
# Dash app + layout
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

            html.H4("本を借りる"),
            # Search inputs + instant search store + interval
            html.Div([
                dcc.Input(id='search-title', type='text', placeholder='タイトルで検索', style={'width': '40%'}),
                dcc.Input(id='search-author', type='text', placeholder='著者で検索', style={'width': '40%', 'marginLeft': '8px'}),
                html.Button('検索 (手動)', id='books-search-btn', n_clicks=0, style={'marginLeft': '8px'}),
                html.Button('クリア', id='books-clear-btn', n_clicks=0, style={'marginLeft': '8px'}),
            ], style={'marginBottom': '8px'}),

            # Stores for debouncing and tracking last search
            dcc.Store(id='search-store', data={'title': '', 'author': '', 'last_input_ts': 0}),
            dcc.Store(id='search-last-searched', data=0),
            dcc.Interval(id='search-interval', interval=600, n_intervals=0),  # server-side debounce timer

            # Books dropdown + modal UI
            html.Div([

                dcc.Dropdown(id='books-dropdown', options=[], placeholder='本を選択してください', multi=True),
                html.Button("借りる", id='rent-book-btn', n_clicks=0, style={'marginTop': '6px'}),
                html.Div(id='rent-book-result', style={'marginTop': '8px', 'color': 'green'}),
                html.Div(id='books-selection-summary', style={'marginTop': '8px'}),
                dcc.Store(id='confirm-selection', data=None),
                dcc.Store(id='books-selected-store', data=[]),
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
                # Search result highlighted list
                html.Div(id='search-results', style={'marginTop': '8px', 'maxHeight': '200px', 'overflowY': 'auto', 'border': '1px solid #eee', 'padding': '6px'}),
            ], style={'marginBottom': '12px'}),

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
#--------------------------------
# Add this to the top-level of your app module (e.g. near other imports / before callbacks).
# It logs and keeps the last POST body for /_dash-update-component so you can inspect
# what the client sent when the error happens.
from flask import request, jsonify

# Store last dash request body in module-global variable for quick inspection.
_last_dash_request_body = None

@server.before_request
def _capture_dash_request_body():
    global _last_dash_request_body
    # Only capture the dash update component requests (XHR)
    if request.path and "_dash-update-component" in request.path and request.method.upper() == "POST":
        try:
            body = request.get_data(as_text=True)
            server.logger.debug("Captured /_dash-update-component body (truncated 4000 chars): %s", body[:4000])
            _last_dash_request_body = body
        except Exception:
            server.logger.exception("Failed to capture dash update request body")

@server.route("/debug/last_dash_request", methods=["GET"])
def debug_last_dash_request():
    """
    Returns the last captured /_dash-update-component POST body as plain text.
    Use this after you reproduce the error in the browser.
    """
    global _last_dash_request_body
    if not _last_dash_request_body:
        return jsonify({"error": "no dash request captured yet"}), 404
    # return as text for easy copy/paste
    return _last_dash_request_body, 200, {"Content-Type": "text/plain; charset=utf-8"}
    #----------------------------------------------
    #-------------------------------------------

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

# Replace the two callbacks that wrote to 'search-store' with this single callback.
# It handles:
#  - input changes on search-title / search-author (instant update + timestamp)
#  - clear button clicks (resets search-store)
# Keeps prevent_initial_call=False so initial load is handled consistently.

from dash import callback_context

@app.callback(
    Output('search-store', 'data'),
    Input('search-title', 'value'),
    Input('search-author', 'value'),
    Input('books-clear-btn', 'n_clicks'),
    State('search-store', 'data'),
    prevent_initial_call=False
)
def update_search_store_combined(title_val, author_val, clear_n, current_store):
    """
    Single writer for search-store:
      - If clear button is the trigger, reset to empty search and update timestamp.
      - Otherwise (title/author change or initial call), normalize inputs and store timestamp.
    """
    try:
        trig = callback_context.triggered
        triggered_id = trig[0]['prop_id'] if trig else ''

        # If clear button triggered -> reset store immediately
        if triggered_id.startswith('books-clear-btn'):
            return {"title": "", "author": "", "last_input_ts": time.time()}

        # Otherwise treat as input change / initial load
        title_norm = normalize_search_text(title_val or "")
        author_norm = normalize_search_text(author_val or "")
        ts = time.time()
        return {"title": title_norm, "author": author_norm, "last_input_ts": ts}

    except Exception:
        server.logger.exception("Error updating search-store (combined)")
        # Fallback to previous value or empty store
        return current_store or {"title": "", "author": "", "last_input_ts": 0}

# The main loader: populates dropdown options AND search result highlight list.
# It is driven by:
# - load-once (initial load)
# - rents-refresh (after rent/return)
# - manual search button (books-search-btn)
# - search-interval (debounced automatic search)
'''
@app.callback(
    Output('books-dropdown', 'options'),
    Output('search-results', 'children'),
    Output('search-last-searched', 'data'),
    Input('load-once', 'n_intervals'),
    Input('rents-refresh', 'data'),
    Input('books-search-btn', 'n_clicks'),
    Input('search-interval', 'n_intervals'),
    State('search-store', 'data'),
    State('search-last-searched', 'data'),
    prevent_initial_call=False
)
def load_books_dropdown(n_intervals, refresh_token, manual_search_clicks, interval_ticks, search_store, last_searched_ts):
    trig = callback_context.triggered
    triggered_id = trig[0]['prop_id'] if trig else ''
    try:
        # If no search store present, load all
        search_store = search_store or {"title": "", "author": "", "last_input_ts": 0}
        title_q = search_store.get('title', '') or ""
        author_q = search_store.get('author', '') or ""
        last_input_ts = search_store.get('last_input_ts', 0)

        do_search = False
        # manual search button - always perform search using current store
        if triggered_id.startswith('books-search-btn'):
            do_search = True
        # interval tick - perform search only if there's a newer input timestamp
        elif triggered_id.startswith('search-interval'):
            if last_input_ts and last_input_ts > (last_searched_ts or 0):
                do_search = True
        # initial load or after rents refreshed: if search terms exist, apply them; otherwise load all
        elif triggered_id.startswith('load-once') or triggered_id.startswith('rents-refresh'):
            do_search = bool(title_q or author_q)

        if do_search:
            # tokenize
            title_tokens = split_tokens(title_q)
            author_tokens = split_tokens(author_q)
            books = get_books_by_search_tokens(title_tokens, author_tokens)
            # build options and highlighted result list
            options = [
                {"label": f"{b['title']} / {b['author']}" + (f" ({b['copies_available']} available)" if b.get('copies_available') is not None else ""), "value": str(b['id'])}
                for b in books
            ]
            # build highlighted children for display (limit to 50 items for perf)
            children = []
            max_show = 50
            for b in books[:max_show]:
                # highlight using title tokens + author tokens combined
                tokens = title_tokens + author_tokens
                title_nodes = highlight_text_nodes(b['title'], tokens)
                author_nodes = highlight_text_nodes(b['author'], tokens)
                children.append(html.Div([
                    html.Div(title_nodes, style={'fontWeight': '600'}),
                    html.Div(author_nodes, style={'fontSize': '0.9em', 'color': '#666'})
                ], style={'padding': '6px', 'borderBottom': '1px solid #f1f1f1'}))
            # update last searched timestamp to avoid repeating searches
            return options, children, last_input_ts or int(time.time())
        else:
            # default: show all books (or maintain current options)
            books = get_all_books()
            options = [
                {"label": f"{b['title']} / {b['author']}" + (f" ({b['copies_available']} available)" if b.get('copies_available') is not None else ""), "value": str(b['id'])}
                for b in books
            ]
            # no highlighted results when not searching
            return options, [], last_searched_ts or 0
    except Exception:
        server.logger.exception("Error loading books for dropdown (search)")
        return [], [], last_searched_ts or 0
'''
@app.callback(
    Output('books-dropdown', 'options'),
    Input('load-once', 'n_intervals'),
    Input('rents-refresh', 'data'),
    Input('books-search-btn', 'n_clicks'),
    Input('search-interval', 'n_intervals'),
    State('search-store', 'data'),
    State('search-last-searched', 'data'),
    State('books-dropdown', 'value'),
    prevent_initial_call=False
)
def load_books_dropdown(n_intervals, refresh_token, manual_search_clicks, interval_ticks,
                        search_store, last_searched_ts, current_selected):
    """
    Populate books-dropdown.options while preserving any currently selected values even if
    they are outside the current search results. Ensure option 'value' is a string.
    """
    trig = callback_context.triggered
    triggered_id = trig[0]['prop_id'] if trig else ''
    try:
        search_store = search_store or {"title": "", "author": "", "last_input_ts": 0}
        title_q = search_store.get('title', '') or ""
        author_q = search_store.get('author', '') or ""
        last_input_ts = search_store.get('last_input_ts', 0)

        do_search = False
        if triggered_id.startswith('books-search-btn'):
            do_search = True
        elif triggered_id.startswith('search-interval'):
            if last_input_ts and last_input_ts > (last_searched_ts or 0):
                do_search = True
        elif triggered_id.startswith('load-once') or triggered_id.startswith('rents-refresh'):
            do_search = bool(title_q or author_q)

        if do_search:
            title_tokens = split_tokens(title_q)
            author_tokens = split_tokens(author_q)
            books = get_books_by_search_tokens(title_tokens, author_tokens)
        else:
            books = get_all_books()

        # Normalize current_selected to list of ints (if any)
        selected_ids = []
        if current_selected is not None:
            if isinstance(current_selected, (str, int)):
                selected_ids = [current_selected]
            else:
                selected_ids = list(current_selected)
        # Convert to int if possible and dedupe
        sel_ints = []
        for v in selected_ids:
            try:
                sel_ints.append(int(v))
            except Exception:
                # ignore non-int values
                pass
        sel_ints = list(dict.fromkeys(sel_ints))  # preserve order, dedupe

        # Build map for results and ensure selected items are included
        books_map = {b['id']: b for b in books}
        # For any selected id not in current results, fetch details and append
        missing_selected = [sid for sid in sel_ints if sid not in books_map]
        if missing_selected:
            extra = get_books_by_ids(missing_selected)
            # merge extras into books_map and append to books list (so dropdown shows them)
            for sid in missing_selected:
                b = extra.get(sid)
                if b:
                    books_map[sid] = b
                    books.append(b)

        # Build options ensuring value is string
        options = []
        seen = set()
        for b in books:
            bid = b['id']
            if bid in seen:
                continue
            seen.add(bid)
            label = f"{b['title']} / {b['author']}" + (f" ({b['copies_available']} available)" if b.get('copies_available') is not None else "")
            options.append({"label": label, "value": str(bid)})
        return options, [], last_searched_ts or 0
    except Exception:
        server.logger.exception("Error loading books for dropdown (preserve selection)")
        return [], [], last_searched_ts or 0
#---------------------------------------added
@app.callback(
    Output('books-selected-store', 'data'),
    Input('books-dropdown', 'value'),
    Input('books-clear-btn', 'n_clicks'),
    State('books-dropdown', 'options'),
    State('books-selected-store', 'data'),
    prevent_initial_call=False
)
def sync_selected_store(selected_values, clear_n, current_options, current_store):
    """
    Robust sync of canonical selected ids.
    - Avoid treating transient dropdown.value == None as a user clear.
    - Only clear selection when the clear button is pressed.
    - Read options as State (not Input) to avoid client-side payload ordering issues.
    """
    try:
        trig = callback_context.triggered
        triggered_id = trig[0]['prop_id'] if trig else ''
        server.logger.debug("sync_selected_store triggered by=%s selected_values=%s current_options=%s current_store=%s",
                            triggered_id, repr(selected_values), repr(current_options)[:500], repr(current_store))

        # Explicit clear button -> user intent to clear
        if triggered_id.startswith('books-clear-btn'):
            server.logger.debug("books-clear-btn pressed -> clearing stored selection")
            return []

        # If selected_values is falsy/null -> treat as transient and preserve stored selection
        if not selected_values:
            server.logger.debug("Dropdown value empty/None (transient) -> preserving stored selection")
            return current_store or []

        # Normalize selected_values into flat list
        vals = []
        if isinstance(selected_values, (str, int)):
            vals = [selected_values]
        elif isinstance(selected_values, list):
            # flatten one level
            flat = []
            for v in selected_values:
                if isinstance(v, list):
                    flat.extend(v)
                else:
                    flat.append(v)
            vals = flat
        else:
            try:
                vals = list(selected_values)
            except Exception:
                vals = []

        ids_int = []
        for v in vals:
            try:
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("sync_selected_store: ignoring invalid selected value: %s", repr(v))

        # dedupe preserving order
        seen = set()
        out = []
        for i in ids_int:
            if i not in seen:
                seen.add(i)
                out.append(i)

        server.logger.debug("sync_selected_store normalized -> %s", out)
        return out
    except Exception:
        server.logger.exception("Error in sync_selected_store")
        return current_store or []
        
'''
@app.callback(
    Output('books-selected-store', 'data'),
    Input('books-dropdown', 'value'),
    Input('books-dropdown', 'options'),
    Input('books-clear-btn', 'n_clicks'),
    State('books-selected-store', 'data'),
    prevent_initial_call=False
)
def sync_selected_store(selected_values, current_options, clear_n, current_store):
    """
    Robust synchronization of canonical selection list.
    Handles malformed current_options (nested lists / mixed payloads) and avoids
    clearing stored selection on transient value=None caused by options updates.
    """
    try:
        trig = callback_context.triggered
        triggered_id = trig[0]['prop_id'] if trig else ''
        server.logger.debug("sync_selected_store triggered by=%s selected_values=%s current_options=%s current_store=%s",
                            triggered_id, repr(selected_values), repr(current_options)[:1000], repr(current_store))

        # 1) Explicit clear button: user intends to clear selection
        if triggered_id.startswith('books-clear-btn'):
            server.logger.debug("books-clear-btn pressed -> clearing stored selection")
            return []

        # 2) Normalize current_options to a sane list-of-dicts if possible.
        options_list = None
        try:
            # If it's already a list of dicts (normal case)
            if isinstance(current_options, list) and current_options and isinstance(current_options[0], dict):
                options_list = current_options
            # If it's nested like [[{...}], [], 0] (observed), try to find first element that looks like list-of-dicts
            elif isinstance(current_options, list):
                for item in current_options:
                    if isinstance(item, list) and item and isinstance(item[0], dict):
                        options_list = item
                        break
                # fallback: if any element is dict, collect them
                if options_list is None:
                    dicts = [x for x in current_options if isinstance(x, dict)]
                    if dicts:
                        options_list = dicts
            # If it's a tuple-like or string, ignore
        except Exception:
            server.logger.exception("Error normalizing current_options")

        # 3) If options updated and value empty -> preserve stored selection
        if triggered_id.startswith('books-dropdown.options') and (not selected_values):
            server.logger.debug("Options update detected and dropdown.value empty -> preserving stored selection")
            return current_store or []

        # 4) If value is None/empty but not a clear action -> preserve (avoid transient overwrite)
        if not selected_values:
            server.logger.debug("Dropdown value empty (transient) -> preserving stored selection")
            return current_store or []

        # 5) Otherwise treat as a real selection update: normalize values and store ints
        # selected_values may be str, int, list, or even nested; handle carefully
        vals = []
        if isinstance(selected_values, (str, int)):
            vals = [selected_values]
        elif isinstance(selected_values, list):
            # flatten one level if necessary (sometimes UI might send nested lists)
            flat = []
            for v in selected_values:
                if isinstance(v, list):
                    flat.extend(v)
                else:
                    flat.append(v)
            vals = flat
        else:
            # unknown type — try to stringify then parse ints
            try:
                vals = list(selected_values)
            except Exception:
                vals = []

        ids_int = []
        for v in vals:
            try:
                # sometimes value is numeric string "6" or int 6
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("sync_selected_store: ignoring invalid selected value: %s", repr(v))

        # remove duplicates while preserving order
        seen = set()
        out = []
        for i in ids_int:
            if i not in seen:
                seen.add(i)
                out.append(i)

        server.logger.debug("sync_selected_store normalized -> %s", out)
        return out
    except Exception:
        server.logger.exception("Unexpected error in sync_selected_store")

@app.callback(
    Output('books-selected-store', 'data'),
    Input('books-dropdown', 'value'),
    Input('books-dropdown', 'options'),
    Input('books-clear-btn', 'n_clicks'),
    State('books-selected-store', 'data'),
    prevent_initial_call=False
)
def sync_selected_store(selected_values, current_options, clear_n, current_store):
    """
    Keep canonical selected ids in books-selected-store while avoiding
    overwriting the store with an empty selection when options are being replaced.
    Rules:
      - If clear button triggered -> clear the stored selection (user intent).
      - If options were updated and value is empty/None -> preserve stored selection.
      - If value is empty/None but not a clear action -> preserve stored selection (transient).
      - Otherwise (user selected some values) -> normalize and store them.
    """
    try:
        trig = callback_context.triggered
        triggered_id = trig[0]['prop_id'] if trig else ''
        server.logger.debug("sync_selected_store triggered by=%s selected_values=%s current_store=%s",
                            triggered_id, repr(selected_values), repr(current_store))

        # 1) Explicit clear button: user intends to clear selection
        if triggered_id.startswith('books-clear-btn'):
            server.logger.debug("books-clear-btn pressed -> clearing stored selection")
            return []

        # 2) If options updated and value is empty -> preserve stored selection
        if triggered_id.startswith('books-dropdown.options') and (not selected_values):
            server.logger.debug("Options update: preserving existing stored selection")
            return current_store or []

        # 3) If value is None/empty but not a clear action -> preserve (avoid transient overwrite)
        if not selected_values:
            server.logger.debug("Value empty (transient) -> preserving stored selection")
            return current_store or []

        # 4) Otherwise treat as a real selection update: normalize values and store ints
        if isinstance(selected_values, (str, int)):
            vals = [selected_values]
        else:
            vals = list(selected_values)

        ids_int = []
        for v in vals:
            try:
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("sync_selected_store: ignoring invalid selected value: %s", repr(v))

        # remove duplicates while preserving order
        seen = set()
        out = []
        for i in ids_int:
            if i not in seen:
                seen.add(i)
                out.append(i)

        server.logger.debug("sync_selected_store -> %s", out)
        return out
    except Exception:
        server.logger.exception("Error in sync_selected_store")
        return current_store or []
#------------------------------delete

@app.callback(
    Output('books-selected-store', 'data'),
    Input('books-dropdown', 'value'),
    Input('books-dropdown', 'options'),
    State('books-selected-store', 'data'),
    prevent_initial_call=False
)
def sync_selected_store(selected_values, current_options, current_store):
    """
    Keep canonical selected ids in books-selected-store while avoiding
    overwriting the store with an empty selection when options are being replaced.
    Behavior:
      - If triggered by options update (prop_id contains 'books-dropdown.options')
        and selected_values is empty/None, return current_store (preserve selection).
      - Otherwise (user changed selection), normalize and store the selection (list of ints).
    """
    try:
        trig = callback_context.triggered
        triggered_id = trig[0]['prop_id'] if trig else ''
        server.logger.debug("sync_selected_store triggered by=%s selected_values=%s current_store=%s",
                            triggered_id, repr(selected_values), repr(current_store))

        # If options were updated and the value is empty, it's likely a transient reset:
        if triggered_id.startswith('books-dropdown.options') and (not selected_values):
            server.logger.debug("Options update: preserving existing stored selection")
            return current_store or []

        # Otherwise treat as a user-driven (or real) selection update:
        if not selected_values:
            # user cleared selection explicitly
            server.logger.debug("Dropdown value empty -> clearing stored selection")
            return []

        # Normalize to list
        if isinstance(selected_values, (str, int)):
            vals = [selected_values]
        else:
            vals = list(selected_values)

        ids_int = []
        for v in vals:
            try:
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("sync_selected_store: ignoring invalid selected value: %s", repr(v))

        # remove duplicates while preserving order
        seen = set()
        out = []
        for i in ids_int:
            if i not in seen:
                seen.add(i)
                out.append(i)

        server.logger.debug("sync_selected_store -> %s", out)
        return out
    except Exception:
        server.logger.exception("Error in sync_selected_store")
        return current_store or []

'''
# -------------------------------------------------------------------------
# Replace update_selection_summary with this version that falls back to store
# -------------------------------------------------------------------------
@app.callback(
    Output('books-selection-summary', 'children'),
    Output('confirm-modal-body', 'children'),
    Input('books-dropdown', 'value'),
    State('books-selected-store', 'data'),
    prevent_initial_call=False
)
def update_selection_summary(selected_values, stored_selected):
    """
    Build selection summary from either the current dropdown value (preferred)
    or from the stored canonical selection (fallback). This prevents the summary
    from disappearing when options are refreshed and the dropdown.value temporarily
    becomes empty due to options replacement.
    """
    server.logger.debug("update_selection_summary called; dropdown_value=%s stored_selected=%s",
                        repr(selected_values), repr(stored_selected))

    if not has_request_context() or not current_user.is_authenticated:
        return html.Div(""), html.Div("")

    # Determine the effective selected ids (list of ints)
    ids_int = []
    # Prefer the live dropdown value if present
    if selected_values:
        if isinstance(selected_values, (str, int)):
            vals = [selected_values]
        else:
            vals = list(selected_values)
        for v in vals:
            try:
                ids_int.append(int(v))
            except Exception:
                server.logger.debug("update_selection_summary: invalid value in dropdown: %s", repr(v))
    else:
        # Fallback to stored selection (already list of ints)
        if stored_selected:
            try:
                ids_int = [int(x) for x in stored_selected]
            except Exception:
                server.logger.debug("update_selection_summary: invalid data in stored_selected: %s", repr(stored_selected))
                ids_int = []

    if not ids_int:
        return html.Div("選択されていません"), html.Div("選択されていません")

    try:
        books_map = get_books_by_ids(ids_int)
        inline_children = []
        modal_children = [html.H4("確認: 選択した本")]
        for bid in ids_int:
            b = books_map.get(bid)
            title = b.get('title') if b else str(bid)
            author = b.get('author') if b else ""
            active = False
            try:
                active = has_active_rent(current_user.id, bid)
            except Exception:
                server.logger.exception("Error checking active rent for user=%s book=%s", current_user.id, bid)
            status = html.Span("既にレンタル中", style={'color': 'red'}) if active else html.Span("利用可能", style={'color': 'green'})
            inline_children.append(html.Div([html.Strong(title), html.Span(f" / {author}" if author else ""), html.Span(" — "), status]))
            modal_children.append(html.Div([html.Strong(title), html.Span(f" / {author}" if author else ""), html.Span(" — "), status]))
        return html.Div(inline_children), html.Div(modal_children)
    except Exception:
        server.logger.exception("Error building selection summary")
        return html.Div("エラー"), html.Div("エラー")

#-----------------------------------

# Combined confirm/table callback
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
        if prop.startswith('rent-book-btn'):
            if not selected_values:
                return "本を選んでください", no_update, no_update, no_update
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
            modal_style = {'display': 'block', 'position': 'fixed', 'top': 0, 'left': 0, 'width': '100%', 'height': '100%',
                           'backgroundColor': 'rgba(0,0,0,0.5)', 'zIndex': 1000}
            return no_update, no_update, no_update, modal_style

        elif prop.startswith('confirm-rent-btn'):
            if not selected_values:
                return "選択が無効です", no_update, no_update, {'display': 'none'}
            if isinstance(selected_values, (str, int)):
                ids = [selected_values]
            else:
                ids = list(selected_values)
            ids_int = []
            for v in ids:
                try:
                    ids_int.append(int(v))
                except Exception:
                    server.logger.debug("Invalid id in selection when confirming: %s", v)
            if not ids_int:
                return "有効な本が選択されていません", no_update, no_update, {'display': 'none'}

            created = []
            skipped = []
            for bid in ids_int:
                try:
                    rid = None
                    rid = create_rent_with_inventory(current_user.id, bid) if 'create_rent_with_inventory' in globals() else create_rent(current_user.id, bid)
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
            modal_style = {'display': 'none'}
            return rent_msg, no_update, refresh_token, modal_style

        elif prop.startswith('cancel-rent-btn'):
            return no_update, no_update, no_update, {'display': 'none'}

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
                ok = mark_rent_returned_with_inventory(rent_id) if 'mark_rent_returned_with_inventory' in globals() else False
                if ok:
                    action_msg = "返却しました"
                    refresh_token = int(time.time())
                else:
                    action_msg = "返却に失敗しました"
                return no_update, action_msg, refresh_token, no_update
            elif col_id == 'cancel_action':
                ok = delete_rent_with_inventory(rent_id) if 'delete_rent_with_inventory' in globals() else False
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

# -----------------------------------------------------------------------------
# Rents table loader (single writer)
# -----------------------------------------------------------------------------
@app.callback(
    Output('rents-table', 'data'),
    Input('rents-refresh', 'data'),
    Input('refresh-rents', 'n_clicks'),
    Input('load-once', 'n_intervals'),
    prevent_initial_call=False
)
def load_rents_table(refresh_token, refresh_clicks, n_intervals):
    server.logger.debug(
        "load_rents_table called; user=%s refresh_token=%s refresh_clicks=%s n_intervals=%s",
        getattr(current_user, "id", None), refresh_token, refresh_clicks, n_intervals
    )
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
#------debug code
# Temporary debug helpers — paste into your app (near the other callbacks) and restart server.
# Shows current dropdown.value and books-selected-store data on the page to help trace selection mismatch.

# Add these two Divs somewhere near the dropdown in serve_layout (e.g. below books-selection-summary):
# html.Div(id='debug-dropdown-value', style={'marginTop': '6px', 'color': '#333'}),
# html.Div(id='debug-books-selected-store', style={'marginTop': '6px', 'color': '#666', 'fontSize': '0.9em'}),

@app.callback(
    Output('debug-dropdown-value', 'children'),
    Output('debug-books-selected-store', 'children'),
    Input('books-dropdown', 'value'),
    Input('books-selected-store', 'data'),
    prevent_initial_call=False
)
def debug_show_selection(dropdown_value, stored_selected):
    """
    Render short textual debug info about the dropdown.value and the canonical stored selection.
    """
    try:
        dv = repr(dropdown_value)
        ss = repr(stored_selected)
        return (
            html.Div([html.Strong("DEBUG: dropdown.value:"), html.Span(f" {dv}")]),
            html.Div([html.Strong("DEBUG: books-selected-store:"), html.Span(f" {ss}")])
        )
    except Exception as e:
        return "debug error", str(e)

# -----------------------------------------------------------------------------
# CLI helpers
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-user", nargs=4, metavar=("USERNAME", "PASSWORD", "ROLE", "EMAIL"), help="Create a new user (email optional)")
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