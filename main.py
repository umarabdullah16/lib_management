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

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-key"
DB = "users.db"
token_store = []


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e):
    db = g.pop("db", None)
    if db:
        db.close()


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


def create_jwt(user, role):
    payload = {
        "user": user,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
    }

    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    token_store.append(token)
    return token


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


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"].encode()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()

        if user and bcrypt.checkpw(password, user["password"]):
            token = create_jwt(user["username"], user["role"])
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie("access_token", token, httponly=True, samesite="Lax")
            return resp

        return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/insert_books", methods=["GET", "POST"])
@require_role("admin")
def insert_books(decoded):
    if request.method == "POST":
        book_id = request.form["id"]
        title = request.form["title"]
        author = request.form["author"]
        available = request.form["available"]

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT OR IGNORE INTO books VALUES (?, ?, ?, ?)",
            (book_id, title, author, available),
        )
        db.commit()
        db.close()
    return render_template("insert_books.html", user=decoded["user"])


@app.route("/books")
def books():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM books")
    rows = cur.fetchall()
    cur.close()
    return render_template("books.html", books=rows)


@app.route("/dashboard")
def dashboard():
    token = request.cookies.get("access_token")
    decoded = decode_jwt(token) if token else None
    if not decoded:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=decoded["user"], role=decoded["role"])


@app.route("/admin")
@require_role("admin")
def admin_panel(decoded):
    return render_template("admin.html", user=decoded["user"])


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("access_token")
    return resp


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
