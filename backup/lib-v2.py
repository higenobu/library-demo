import os
import time
from datetime import date
from flask import Flask, redirect, url_for, has_request_context, request, render_template_string, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

import psycopg2
from psycopg2 import errors

import dash
from dash import html, dcc
import dash_table
from dash.dependencies import Input, Output, State

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://myuser:secret@localhost:5432/mydb")
SECRET_KEY = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

# -----------------------------------------------------------------------------
# Flask + Login
# -----------------------------------------------------------------------------
server = Flask(__name__)
server.secret_key = SECRET_KEY

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

def create_book(title, author=None, isbn=None):
    conn = get_db_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO books (title, author, isbn) VALUES (%s, %s, %s) RETURNING id",
                    (title, author, isbn)
                )
                return cur.fetchone()[0]
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
                return cur.fetchone()[0]
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
                    # action columns: display labels; clicking cells triggers operations
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
app = dash.Dash(__name__, server=server, url_base_pathname="/")

# serve_layout: returns different layouts depending on authentication
def serve_layout():
    if not has_request_context():
        return html.Div([dcc.Location(id='url'), html.Div("Loading...")])

    if current_user.is_authenticated:
        # authenticated layout: include DataTable
        return html.Div([
            dcc.Location(id='url', refresh=True),
            html.H3(f"こんにちは、{current_user.username}さん（{current_user.role}）"),
            html.A("ログアウト", href="/logout"),
            html.Hr(),
            html.H4("あなたのレンタル中の本（表形式）"),
            html.Div([
                html.Button("再読み込み", id='refresh-rents', n_clicks=0),
                dcc.Store(id='rents-refresh', data=0)
            ], style={'marginBottom': '8px'}),
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
                data=[],  # populated by callback
                style_cell={'textAlign': 'left', 'padding': '6px'},
                style_header={'fontWeight': 'bold'},
                page_action='none',
                style_table={'overflowX': 'auto', 'maxHeight': '400px'},
                # make action cells look clickable
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
        # unauthenticated: link to login form (Flask)
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
            html.Button("
