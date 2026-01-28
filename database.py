from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    make_response,
    abort,
    g,
)
import jwt, datetime, sqlite3, bcrypt
from functools import wraps

DB = "users.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = sqlite3.connect(DB)
    cur = db.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB,
            role TEXT
        )
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS books (
            id INT PRIMARY KEY,
            title TEXT,
            author TEXT,
            available INT
        )
"""
    )
    db.commit()

    users = [("admin", "admin123", "admin"), ("india", "india123", "user")]

    for u, p, r in users:
        hashed = bcrypt.hashpw(p.encode(), bcrypt.gensalt())
        cur.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?)", (u, hashed, r))
    db.commit()
    db.close()
