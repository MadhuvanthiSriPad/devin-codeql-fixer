"""
INTENTIONALLY VULNERABLE — for CodeQL demo purposes only.

This Flask app contains real-world vulnerability patterns that
CodeQL's Python queries will flag. DO NOT deploy to production.
"""

import os
import re
import subprocess
import sqlite3

from flask import Flask, request, redirect, render_template_string

app = Flask(__name__)

DATABASE = "app.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# VULN 1: SQL Injection — f-string in query
# CodeQL rule: py/sql-injection
# ---------------------------------------------------------------------------
@app.route("/api/users")
def search_users():
    search = request.args.get("search", "")
    conn = get_db()
    query = f"SELECT * FROM users WHERE username LIKE '%{search}%'"
    cursor = conn.execute(query)
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"users": users}


# ---------------------------------------------------------------------------
# VULN 2: Reflected XSS via template injection
# CodeQL rule: py/reflective-xss
# ---------------------------------------------------------------------------
@app.route("/search")
def search_page():
    query = request.args.get("q", "")
    html = f"""
    <html>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <p>No results found.</p>
      </body>
    </html>
    """
    return render_template_string(html)


# ---------------------------------------------------------------------------
# VULN 3: Command Injection — user input in shell command
# CodeQL rule: py/command-line-injection
# ---------------------------------------------------------------------------
@app.route("/api/ping", methods=["POST"])
def ping_host():
    host = request.json.get("host", "")
    if not re.match(r'^[a-zA-Z0-9._-]+$', host):
        return {"error": "Invalid host"}, 400
    try:
        result = subprocess.check_output(
            ["ping", "-c", "1", host], text=True
        )
        return {"output": result}
    except subprocess.CalledProcessError:
        return {"error": "Ping failed"}, 500


# ---------------------------------------------------------------------------
# VULN 4: Path Traversal — user-controlled file path
# CodeQL rule: py/path-injection
# ---------------------------------------------------------------------------
@app.route("/api/files")
def read_file():
    filename = request.args.get("name", "")
    file_path = os.path.join("/uploads", filename)
    try:
        with open(file_path) as f:
            return {"content": f.read()}
    except FileNotFoundError:
        return {"error": "File not found"}, 404


# ---------------------------------------------------------------------------
# VULN 5: Open Redirect
# CodeQL rule: py/url-redirection
# ---------------------------------------------------------------------------
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url", "/")
    return redirect(target)


# ---------------------------------------------------------------------------
# VULN 6: Hardcoded credentials
# CodeQL rule: py/hardcoded-credentials
# ---------------------------------------------------------------------------
DB_PASSWORD = "super_secret_password_123"
API_SECRET = "sk-live-abc123def456ghi789"


@app.route("/api/config")
def get_config():
    return {
        "database": {"host": "db.example.com", "password": DB_PASSWORD},
        "api_secret": API_SECRET,
    }


if __name__ == "__main__":
    app.run(debug=True, port=3000)
