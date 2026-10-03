import os
import sqlite3
import secrets
import uuid

from flask import Flask, request, render_template, redirect, url_for, session, g, jsonify

APP_DIR = os.path.dirname(os.path.abspath(__file__))

# PERUBAHAN 1: Ubah lokasi database ke folder /tmp/ yang diizinkan Vercel
DB_PATH = "/tmp/taskhub.db"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_time = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    if first_time:
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("judy", "judy123", "user"),
        )
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("mike", "mike2024", "user"),
        )
        db.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ("admin", secrets.token_hex(16), "admin"),
        )

        judy_id = db.execute("SELECT id FROM users WHERE username='judy'").fetchone()[0]
        mike_id = db.execute("SELECT id FROM users WHERE username='mike'").fetchone()[0]
        admin_id = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]

        db.execute(
            "INSERT INTO tickets (id, user_id, title, body) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), judy_id, "VPN keeps dropping",
             "My VPN disconnects every ~20 minutes on the new office wifi."),
        )
        db.execute(
            "INSERT INTO tickets (id, user_id, title, body) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), judy_id, "Laptop fan is loud",
             "Started last week, might just need a clean."),
        )
        db.execute(
            "INSERT INTO tickets (id, user_id, title, body) VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), mike_id, "Can't access shared drive",
             "Permission denied on \\\\fileserver\\team since Monday."),
        )
        db.execute(
            "INSERT INTO tickets (id, user_id, title, body) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                admin_id,
                "Launch checklist follow-ups",
                "Reminders to self before go-live:\n"
                "- Rotate the QA demo flag, CTF{not_the_real_one_keep_looking} "
                "is still sitting in the seed data, swap it out.\n"
                "- Double-check who can reach the internal settings panel "
                "at /admin/settings -- it should NOT be reachable by regular "
                "staff accounts, only us. Low priority, nobody knows the URL anyway.\n"
                "- Remove the ?support=1 override on ticket viewing once the "
                "real support-role system ships.",
            ),
        )
        db.commit()
    db.close()


# PERUBAHAN 2: Panggil init_db() di sini agar Vercel mengeksekusinya saat server menyala
init_db()


def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute(
        "SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute(
            "SELECT id, username FROM users WHERE username = ? AND password = ?",
            (username, password),
        ).fetchone()
        if row:
            session["user_id"] = row["id"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    db = get_db()
    tickets = db.execute(
        "SELECT id, title FROM tickets WHERE user_id = ?", (user["id"],)
    ).fetchall()
    return render_template("dashboard.html", user=user, tickets=tickets)


@app.route("/api/activity")
def api_activity():
    if "user_id" not in session:
        return jsonify({"error": "unauthorized"}), 401
    db = get_db()
    rows = db.execute(
        """
        SELECT tickets.id as id, tickets.title as title, users.username as author
        FROM tickets JOIN users ON tickets.user_id = users.id
        ORDER BY tickets.id
        """
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/ticket/<ticket_id>")
def view_ticket(ticket_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    db = get_db()
    ticket = db.execute(
        "SELECT tickets.*, users.username as owner FROM tickets "
        "JOIN users ON tickets.user_id = users.id WHERE tickets.id = ?",
        (ticket_id,),
    ).fetchone()
    if not ticket:
        return render_template("ticket.html", ticket=None, error="Ticket not found."), 404

    is_support_override = request.args.get("support") == "1"
    if ticket["user_id"] != user["id"] and not is_support_override:
        return render_template(
            "ticket.html", ticket=None,
            error="403: this isn't your ticket."
        ), 403

    return render_template("ticket.html", ticket=ticket, error=None)


@app.route("/admin/settings")
def admin_settings():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    flag = os.environ.get("FLAG", "CTF{this_is_a_placeholder_flag}")
    return render_template("admin_settings.html", user=user, flag=flag)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
