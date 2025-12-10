import os
from flask import Flask, redirect, url_for, has_request_context
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
from psycopg2 import errors

import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State
import logging
# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://matsuo:masanobu@localhost:5432/emr_sample"
)
SECRET_KEY = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# -----------------------------------------------------------------------------
# Flask + Login manager
# -----------------------------------------------------------------------------
server = Flask(__name__)
server.secret_key = SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(server)
login_manager.login_view = "/"

# -----------------------------------------------------------------------------
# DB helpers (psycopg2)
# -----------------------------------------------------------------------------
def get_db_conn():
    return psycopg2.connect(DATABASE_URL)

def ensure_tables():
    """
    Ensure users and rent tables exist. If you already have these tables with other schema,
    adjust/migrate as appropriate.
    """
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
                CREATE TABLE IF NOT EXISTS rent (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    book_id INTEGER NOT NULL,
                    rent_date DATE DEFAULT (CURRENT_DATE)
                );
                """)
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
    except errors.UniqueViolation:
        raise ValueError("username exists")
    finally:
        conn.close()

def create_rent(user_id, book_id, rent_date=None):
    """
    Helper to insert a rent record (used for CLI/testing).
    rent_date: string 'YYYY-MM-DD' or None to use default/current_date
    """
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
                return cur.fetchone()[0]
    finally:
        conn.close()

def get_users_page(page=1, per_page=10):
    """
    Return (rows, total_count)
    rows: list of tuples (id, username, email, role, created_at)
    """
    offset = (page - 1) * per_page
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id DESC LIMIT %s OFFSET %s", (per_page, offset))
            rows = cur.fetchall()
            cur.execute("SELECT COUNT(*) FROM users")
            total = cur.fetchone()[0]
            return rows, total
    finally:
        conn.close()

def get_rented_books_for_user(user_id):
    """
    Return list of tuples (book_id, rent_date) for given user_id ordered by rent_date desc.
    """
    conn = get_db_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT book_id, rent_date FROM rent WHERE user_id = %s ORDER BY rent_date DESC", (user_id,))
            return cur.fetchall()
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# User model for Flask-Login
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
# Dash app (mounted on Flask server)
# -----------------------------------------------------------------------------
app = dash.Dash(__name__, server=server, url_base_pathname="/")

def serve_layout():
    # Dash may call this during init when no request context exists.
    if not has_request_context():
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.Div("Loading...", id='page-content')
        ])

    if current_user.is_authenticated:
        # Authenticated layout: include users table, pagination controls, and my-rents section
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.H3(f"こんにちは、{current_user.username}さん（{current_user.role}）"),
            html.A("ログアウト", href="/logout"),
            html.Hr(),
            html.H4("保護されたダッシュボード"),
            html.Ul([
                html.Li("ダッシュボードの内容 A"),
                html.Li("ダッシュボードの内容 B"),
            ]),
            html.Hr(),
            html.H4("あなたのレンタル中の本"),
            html.Div([
                html.Button("レンタル一覧更新", id="refresh-my-rents", n_clicks=0),
                # load once on entry
                dcc.Interval(id='load-my-rents-once', interval=200, n_intervals=0, max_intervals=1),
            ], style={'marginBottom': '8px'}),
            html.Ul(id='my-rents-list'),
            html.Hr(),
            html.H4("ユーザー一覧"),
            html.Div([
                html.Button("前へ", id='prev-page', n_clicks=0),
                html.Button("次へ", id='next-page', n_clicks=0),
                html.Span("  ページ: "),
                html.Span(id='page-indicator'),
                html.Span("  |  表示件数: "),
                dcc.Dropdown(
                    id='per-page',
                    options=[
                        {'label': '10', 'value': 10},
                        {'label': '25', 'value': 25},
                        {'label': '50', 'value': 50}
                    ],
                    value=10,
                    clearable=False,
                    style={'width': '100px', 'display': 'inline-block', 'verticalAlign': 'middle', 'marginLeft': '8px'}
                ),
                html.Button("更新", id="refresh-users", n_clicks=0, style={'marginLeft': '12px'})
            ], style={'marginBottom': '12px'}),
            # store page state: dict with page, per_page, total
            dcc.Store(id='users-page', data={'page': 1, 'per_page': 10, 'total': 0}),
            html.Div(id='users-table-container')
        ], style={'maxWidth': '1000px', 'margin': 'auto'})
    else:
        # Login / signup layout (signup includes email)
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.H2("ログイン"),
            dcc.Input(id='login-username', type='text', placeholder='ユーザー名'),
            dcc.Input(id='login-password', type='password', placeholder='パスワード'),
            html.Button("ログイン", id='login-btn'),
            html.Div(id='login-message', style={'color': 'red', 'marginTop': '10px'}),
            html.Hr(),
            html.H4("新規ユーザ作成（テスト用）"),
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
# Callbacks: login, signup
# -----------------------------------------------------------------------------
@app.callback(
    Output('login-message', 'children'),
    Output('url', 'pathname'),
    Input('login-btn', 'n_clicks'),
    State('login-username', 'value'),
    State('login-password', 'value'),
    prevent_initial_call=True
)
# 例: コールバック冒頭に入れる（app.py）

#server.logger.setLevel(logging.DEBUG)

def debug_trigger():
    server.logger.debug("callback triggered: %s", dash.callback_context.triggered)
    server.logger.debug("inputs: %s", dash.callback_context.inputs)
    server.logger.debug("states: %s", dash.callback_context.states)

# callback の最初で
#debug_trigger()
def handle_login(n_clicks, username, password):
    if not username or not password:
        return "ユーザー名とパスワードを入力してください", dash.no_update

    user = User.get_by_username(username)
    if user and check_password_hash(user.password_hash, password):
        login_user(user)
        # redirect to root so layout re-evaluates and authenticated view is shown
        return "", "/"
    else:
        return "認証失敗: ユーザー名またはパスワードが正しくありません", dash.no_update

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

# -----------------------------------------------------------------------------
# My rents callbacks: auto-load on entry and manual refresh
# -----------------------------------------------------------------------------
@app.callback(
    Output('my-rents-list', 'children'),
    Input('load-my-rents-once', 'n_intervals'),
    Input('refresh-my-rents', 'n_clicks'),
    prevent_initial_call=False
)
def load_my_rents(n_intervals, n_clicks):
    # Only fetch when authenticated in a request context
    if not has_request_context() or not current_user.is_authenticated:
        return [html.Li("ログインしてください")]

    try:
        rows = get_rented_books_for_user(current_user.id)
        if not rows:
            return [html.Li("レンタル中の本はありません")]
        items = []
        for r in rows:
            book_id = r[0]
            rent_date = r[1].strftime("%Y-%m-%d") if r[1] is not None else ""
            items.append(html.Li(f"Book ID: {book_id} — Rent date: {rent_date}"))
        return items
    except Exception:
        return [html.Li("レンタル一覧の取得に失敗しました")]

# -----------------------------------------------------------------------------
# Pagination helpers / callbacks for users table (unchanged logic)
# -----------------------------------------------------------------------------
@app.callback(
    Output('users-page', 'data'),
    Input('prev-page', 'n_clicks'),
    Input('next-page', 'n_clicks'),
    Input('per-page', 'value'),
    State('users-page', 'data'),
    prevent_initial_call=False
)
def update_page_state(prev_clicks, next_clicks, per_page_value, store):
    if store is None:
        store = {'page': 1, 'per_page': per_page_value or 10, 'total': 0}

    if per_page_value is not None and per_page_value != store.get('per_page'):
        store['per_page'] = per_page_value
        store['page'] = 1
        return store

    prev = prev_clicks or 0
    nxt = next_clicks or 0
    if prev == 0 and nxt == 0:
        return store

    if nxt > prev:
        store['page'] = store.get('page', 1) + 1
    elif prev > nxt:
        store['page'] = max(1, store.get('page', 1) - 1)
    return store

@app.callback(
    Output('users-table-container', 'children'),
    Output('users-page', 'data'),
    Output('page-indicator', 'children'),
    Input('users-page', 'data'),
    Input('refresh-users', 'n_clicks'),
    Input('load-once', 'n_intervals'),
    prevent_initial_call=False
)
def load_users_table(store, refresh_clicks, _n_intervals):
    if not has_request_context() or not current_user.is_authenticated:
        return html.Div("ログインしてください"), store or {'page':1,'per_page':10,'total':0}, "0/0"

    if store is None:
        store = {'page': 1, 'per_page': 10, 'total': 0}

    page = int(store.get('page', 1))
    per_page = int(store.get('per_page', 10))

    try:
        rows, total = get_users_page(page=page, per_page=per_page)
    except Exception:
        return html.Div("ユーザー一覧の取得に失敗しました"), store, f"{page}/?"

    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    header = html.Thead(html.Tr([
        html.Th("ID"), html.Th("ユーザー名"), html.Th("メール"), html.Th("役割"), html.Th("作成日時")
    ]))
    body_rows = []
    for r in rows:
        created = r[4].strftime("%Y-%m-%d %H:%M:%S") if r[4] is not None else ""
        body_rows.append(html.Tr([
            html.Td(r[0]),
            html.Td(r[1]),
            html.Td(r[2] or ""),
            html.Td(r[3]),
            html.Td(created)
        ]))
    table = html.Table([header, html.Tbody(body_rows)], style={'width': '100%', 'borderCollapse': 'collapse'})

    store['page'] = page
    store['per_page'] = per_page
    store['total'] = total

    page_indicator = f"{page} / {total_pages} (合計: {total})"
    return table, store, page_indicator

# -----------------------------------------------------------------------------
# Flask logout route
# -----------------------------------------------------------------------------
@server.route("/logout")
def do_logout():
    logout_user()
    return redirect(url_for('index'))

# Provide an index route that simply redirects to Dash root
@server.route("/")
def index():
    return redirect("/")

# -----------------------------------------------------------------------------
# CLI helpers
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-user", nargs=4, metavar=("USERNAME", "PASSWORD", "ROLE", "EMAIL"), help="Create a new user (email optional)")
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
        except Exception as e:
            print("error:", e)
    elif args.create_rent:
        user_id_s, book_id_s, rent_date = args.create_rent
        try:
            user_id = int(user_id_s)
            book_id = int(book_id_s)
            rid = create_rent(user_id, book_id, rent_date if rent_date != "None" else None)
            print(f"Created rent id={rid} for user_id={user_id} book_id={book_id} rent_date={rent_date}")
        except Exception as e:
            print("error creating rent:", e)
    elif args.run:
        server.run(host="0.0.0.0", port=8050, debug=True)
    else:
        parser.print_help()