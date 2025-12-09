import os
from flask import Flask, redirect, url_for, has_request_context
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
from psycopg2 import sql, errors

import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State

def logout_and_redirect(n_clicks):
    # n_clicks が押されたらブラウザを /logout に遷移させる
    # Flask 側の /logout ルートで logout_user() → redirect('/') をしている想定
    return "/logout"
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
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
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

def create_user(username, password, role="doctor"):
    password_hash = generate_password_hash(password)
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                    (username, password_hash, role),
                )
                return cur.fetchone()[0]
    except errors.UniqueViolation:
        raise ValueError("username exists")
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
    # IMPORTANT: Dash may call this during app initialization when there's no
    # Flask request context. Avoid accessing current_user unless a request
    # context exists.
    if not has_request_context():
        # return a minimal placeholder layout during initialization
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.Div("Loading...", id='page-content')
        ])

    # Now it's safe to reference current_user
    if current_user.is_authenticated:
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
            html.Div(id='login-message')
        ], style={'maxWidth': '700px', 'margin': 'auto'})
    else:
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
# Callbacks: login, signup, logout (logout handled by Flask route below too)
# -----------------------------------------------------------------------------
@app.callback(
    Output('login-message', 'children'),
    Output('url', 'pathname'),
    Input('login-btn', 'n_clicks'),
    State('login-username', 'value'),
    State('login-password', 'value'),
    prevent_initial_call=True
)
def handle_login(n_clicks, username, password):
    if not username or not password:
        return "ユーザー名とパスワードを入力してください", dash.no_update

    user = User.get_by_username(username)
    if user and check_password_hash(user.password_hash, password):
        # login_user sets session cookie
        login_user(user)
        # redirect to root so serve_layout will render authenticated view
        return "", "/"
    else:
        return "認証失敗: ユーザー名またはパスワードが正しくありません", dash.no_update

@app.callback(
    Output('signup-message', 'children'),
    Input('signup-btn', 'n_clicks'),
    State('signup-username', 'value'),
    State('signup-password', 'value'),
    State('signup-role', 'value'),
    prevent_initial_call=True
)
def handle_signup(n_clicks, username, password, role):
    if not username or not password:
        return "ユーザー名とパスワードを入力してください"
    try:
        create_user(username.strip(), password, role or "doctor")
        return "ユーザー作成に成功しました。ログインしてください。"
    except ValueError:
        return "ユーザー名は既に存在します。別の名前を選んでください。"
    except Exception:
        return "ユーザー作成に失敗しました（サーバエラー）"

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
    parser.add_argument("--create-user", nargs=3, metavar=("USERNAME", "PASSWORD", "ROLE"), help="Create a new user")
    parser.add_argument("--run", action="store_true", help="Run server (Flask + Dash)")
    args = parser.parse_args()

    ensure_tables()

    if args.create_user:
        u, p, r = args.create_user
        try:
            uid = create_user(u, p, r)
            print(f"Created user id={uid} username={u} role={r}")
        except ValueError:
            print("username already exists")
        except Exception as e:
            print("error:", e)
    elif args.run:
        # Run Flask dev server (which serves Dash)
        server.run(host="0.0.0.0", port=8050, debug=True)
    else:
        parser.print_help()