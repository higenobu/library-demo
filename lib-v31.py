# Full app.py (cleaned and with Books -> Rent UI + fixes)
# Replace your current app.py with this file, then run:
#   python app.py --run
# and test via browser: http://localhost:8050

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
from dash import html, dcc, no_update
import dash_table
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

# enable debug logging to console
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
        with conn:
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
    finally:
        conn.close()

def get_all_books():
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, title, author FROM books ORDER BY title")
            rows = cur.fetchall()
            return [{"id": r[0], "title": r[1] or "", "author": r[2] or ""} for r in rows]
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
        # unique violation -> user exists
        server.logger.debug("create_user IntegrityError: %s", e)
        raise ValueError("username exists")
    finally:
        conn.close()

def create_book(title, author=None, isbn=None):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO books (title, author, isbn) VALUES (%s, %s, %s) RETURNING id",
                    (title, author, isbn)
                )
                bid = cur.fetchone()[0]
                server.logger.debug("create_book created id=%s title=%s", bid, title)
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

def mark_rent_returned(rent_id):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE rent SET return_date = CURRENT_DATE WHERE id = %s AND return_date IS NULL RETURNING id", (rent_id,))
                row = cur.fetchone()
                return row is not None
    finally:
        conn.close()

def delete_rent(rent_id):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM rent WHERE id = %s RETURNING id", (rent_id,))
                row = cur.fetchone()
                return row is not None
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
                dcc.Store(id='rents-refresh-aux', data=0),  
                dcc.Store(id='rents-refresh-aux2', data=0),# <-- NEW aux store to avoid duplicate output collisions
            ], style={'marginBottom': '8px'}),
            dcc.Interval(id='load-once', interval=200, n_intervals=0, max_intervals=1),

            # --- Books -> Rent UI (added) ---
            html.H4("本を借りる"),
            html.Div([
                dcc.Dropdown(id='books-dropdown', options=[], placeholder='本を選択してください'),
                html.Button("借りる", id='rent-book-btn', n_clicks=0, style={'marginTop': '6px'}),
                html.Div(id='rent-book-result', style={'marginTop': '8px', 'color': 'green'})
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
# Flask routes
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

# -----------------------------------------------------------------------------
# Dash callbacks
# -----------------------------------------------------------------------------
@app.callback(
    Output('signup-message', 'children'),
    Input('signup-btn', 'n_clicks'),
    State('signup-username', 'value'),
    State('signup-email', 'value'),
    State('signup-password', 'value'),
    State('signup-role', 'value'),
    prevent_initial_call=True
)
def handle_signup(n_clicks, username, email, password, role):
    if not username or not password:
        return "ユーザー名とパスワードを入力してください"
    try:
        create_user(username.strip(), password, role or "doctor", email=email)
        return "ユーザー作成に成功しました。ログインしてください。"
    except ValueError:
        return "ユーザー名は既に存在します。別の名前を選んでください。"
    except Exception:
        return "ユーザー作成に失敗しました（サーバエラー）"

@app.callback(
    Output('rents-table', 'data'),
    Input('rents-refresh', 'data'),
    Input('rents-refresh-aux', 'data'),
    Input('rents-refresh-aux2', 'data'),
    Input('refresh-rents', 'n_clicks'),
    Input('load-once', 'n_intervals'),
    prevent_initial_call=False
)
def load_rents_table(refresh_token, refresh_aux_token, refresh_aux2_token, n_clicks, _n_intervals):
    server.logger.debug(
        "load_rents_table called; user=%s refresh_token=%s refresh_aux=%s refresh_aux2=%s n_clicks=%s n_intervals=%s",
        getattr(current_user, "id", None),
        refresh_token,
        refresh_aux_token,
        refresh_aux2_token,
        n_clicks,
        _n_intervals
    )
    if not has_request_context() or not current_user.is_authenticated:
        server.logger.debug("Not authenticated in load_rents_table")
        return []
    try:
        rows = get_rented_books_for_user(current_user.id)
        server.logger.debug("get_rented_books_for_user returned %d rows", len(rows))
        return rows
    except Exception:
        server.logger.exception("Error loading rents")
        return []
@app.callback(
    Output('rents-action-result', 'children'),
    Output('rents-refresh-aux', 'data'),   # <-- was 'rents-refresh'
    #Output('rents-refresh', 'data'),
    Input('rents-table', 'active_cell'),
    State('rents-table', 'data'),
    prevent_initial_call=True
  
    
)
def handle_table_click(active_cell, table_data):
    server.logger.debug("handle_table_click triggered: active_cell=%s", active_cell)
    if not has_request_context() or not current_user.is_authenticated:
        return "ログインしてください", dash.no_update
    if not active_cell:
        raise dash.exceptions.PreventUpdate

    row = active_cell.get('row')
    col_id = active_cell.get('column_id')
    if row is None or col_id is None:
        raise dash.exceptions.PreventUpdate

    try:
        row_data = table_data[row]
        rent_id = row_data.get('rent_id')
        if col_id == 'return_action':
            if row_data.get('return_date'):
                return "既に返却済みです", dash.no_update
            ok = mark_rent_returned(rent_id)
            if ok:
                return "返却しました", int(time.time())
            else:
                return "返却に失敗しました", dash.no_update
        elif col_id == 'cancel_action':
            ok = delete_rent(rent_id)
            if ok:
                return "レンタルをキャンセルしました", int(time.time())
            else:
                return "キャンセルに失敗しました", dash.no_update
        else:
            raise dash.exceptions.PreventUpdate
    except Exception:
        server.logger.exception("Error handling table click")
        return "操作中にエラーが発生しました", dash.no_update

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
            {"label": f"{b['title']} / {b['author']}" if b['author'] else b['title'], "value": str(b['id'])}
            for b in books
        ]
        return options
    except Exception:
        server.logger.exception("Error loading books for dropdown")
        return []

@app.callback(
    Output('rent-book-result', 'children'),
    Output('rents-refresh-aux2', 'data'),   # <-- was 'rents-refresh'
    Input('rent-book-btn', 'n_clicks'),
    State('books-dropdown', 'value'),
    prevent_initial_call=True
    
)
def handle_rent_book(n_clicks, selected_book_id):
    if not has_request_context() or not current_user.is_authenticated:
        return "ログインが必要です", no_update
    if not selected_book_id:
        return "本を選んでください", no_update
    try:
        book_id = int(selected_book_id)
        rid = create_rent(current_user.id, book_id)
        if rid:
            return "レンタル登録しました", int(time.time())
        else:
            return "レンタルに失敗しました", no_update
    except Exception:
        server.logger.exception("Error creating rent")
        return "レンタル中にエラーが発生しました", no_update

# -----------------------------------------------------------------------------
# CLI helpers
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-user", nargs=4, metavar=("USERNAME", "PASSWORD", "ROLE", "EMAIL"), help="Create a new user (email optional)")
    parser.add_argument("--create-book", nargs=3, metavar=("TITLE", "AUTHOR", "ISBN"), help="Create a book record (quote args as needed)")
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
        title, author, isbn = args.create_book
        try:
            bid = create_book(title, author if author != "None" else None, isbn if isbn != "None" else None)
            print(f"Created book id={bid} title={title}")
        except Exception as ex:
            print("error creating book:", ex)
    elif args.create_rent:
        user_id_s, book_id_s, rent_date = args.create_rent
        try:
            user_id = int(user_id_s)
            book_id = int(book_id_s)
            rid = create_rent(user_id, book_id, rent_date if rent_date != "None" else None)
            print(f"Created rent id={rid} for user_id={user_id} book_id={book_id} rent_date={rent_date}")
        except Exception as ex:
            print("error creating rent:", ex)
    elif args.run:
        server.run(host="0.0.0.0", port=8050, debug=False, use_reloader=False)
    else:
        parser.print_help()