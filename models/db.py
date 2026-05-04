import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "database.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    with conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id),
                FOREIGN KEY (receiver_id) REFERENCES users (id)
            );
        ''')
    conn.close()

def create_user(username, password):
    conn = get_db()
    password_hash = generate_password_hash(password)
    try:
        with conn:
            conn.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def verify_user(username, password):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password_hash'], password):
        return dict(user)
    return None

def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute('SELECT id, username FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def get_all_users(exclude_id=None):
    conn = get_db()
    if exclude_id:
        users = conn.execute('SELECT id, username FROM users WHERE id != ?', (exclude_id,)).fetchall()
    else:
        users = conn.execute('SELECT id, username FROM users').fetchall()
    conn.close()
    return [dict(u) for u in users]

def save_message(sender_id, receiver_id, content):
    conn = get_db()
    with conn:
        conn.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
                     (sender_id, receiver_id, content))
    conn.close()

def get_messages(user1_id, user2_id):
    conn = get_db()
    messages = conn.execute('''
        SELECT * FROM messages 
        WHERE (sender_id = ? AND receiver_id = ?) 
           OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (user1_id, user2_id, user2_id, user1_id)).fetchall()
    conn.close()
    return [dict(m) for m in messages]
