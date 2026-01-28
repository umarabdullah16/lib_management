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
from app import app

app.config["SECRET_KEY"] = "super-secret-key"


def decode_jwt(token):
    try:
        return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return None


def require_role(role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.cookies.get("access_token")
            if not token:
                return redirect(url_for("login"))
            decoded = decode_jwt(token)
            if not decoded or decoded["role"] != role:
                abort(403)
            return fn(decoded, *args, **kwargs)

        return wrapper

    return decorator
