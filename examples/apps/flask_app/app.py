"""Runnable Flask example app using the authority library.

A real web app: server-rendered HTML pages (``/``, ``/login``, ``/register``,
``/dashboard``) plus a JSON API (``/login``, ``/register``, ``/me``,
``/admin``). Logging in through the web UI sets an ``HttpOnly`` ``access_token``
cookie; the dashboard is rendered server-side from the verified token.

Run from the repository root with:

    python -m examples.apps.flask_app.app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, url_for

from authority.core import AuthManager
from authority.exceptions import AuthError, InvalidCredentialsError, UserExistsError
from authority.flask import FlaskAuth, current_user, init_auth
from authority.storage.sqlite import SQLiteStorage

from .._common import default_config, seed_demo_sync

DB_PATH = "flask_auth.db"
APP_NAME = "Authority Flask Example"
_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "_templates"

app = Flask(__name__, template_folder=str(_TEMPLATES_DIR))
app.secret_key = "flask-example-session-secret-change-me"


@app.before_request
def _cookie_to_bearer():
    """Treat the access_token cookie as a Bearer token when no header is sent.

    This lets the browser (which only has the cookie) use the header-based
    ``@auth.login_required`` / ``@auth.require_permission`` decorators unchanged.
    """
    if "Authorization" not in request.headers:
        token = request.cookies.get("access_token")
        if token:
            request.environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"


manager = AuthManager(default_config(DB_PATH), SQLiteStorage(DB_PATH))
init_auth(manager)
auth = FlaskAuth(app, manager)
seed_demo_sync(manager)


@app.get("/")
def index():
    return render_template(
        "index.html",
        app_name=APP_NAME,
        endpoints=["/register", "/login", "/me", "/admin", "/dashboard"],
        docs_url=url_for("index"),
    )


@app.get("/login")
def login_page():
    return render_template("login.html", app_name=APP_NAME)


@app.get("/register")
def register_page():
    return render_template("register.html", app_name=APP_NAME)


def _current_user_from_cookie():
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = manager.verify_access_token(token)
        return manager.get_user(payload["user_id"])
    except AuthError:
        return None


@app.get("/dashboard")
def dashboard():
    user = _current_user_from_cookie()
    if user is None:
        return redirect(url_for("login_page"), code=303)
    permissions = manager.get_user_permissions(user["id"])
    return render_template(
        "dashboard.html", app_name=APP_NAME, user=user, permissions=permissions
    )


@app.post("/logout")
def logout():
    response = redirect(url_for("login_page"), code=303)
    response.delete_cookie("access_token")
    return response


@app.post("/register")
def register():
    data = request.get_json(force=True)
    try:
        user = manager.register(
            data["name"],
            data["email"],
            data["password"],
            auto_verify=True,
        )
    except UserExistsError:
        return jsonify({"error": "Email already registered"}), 409
    return jsonify({"user_id": user["id"], "email": user["email"]})


@app.post("/login")
def login():
    data = request.get_json(force=True)
    try:
        result = manager.login(data["email"], data["password"])
    except InvalidCredentialsError:
        return jsonify({"error": "Invalid credentials"}), 401
    response = jsonify(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )
    response.set_cookie(
        "access_token",
        result["access_token"],
        httponly=True,
        samesite="lax",
        max_age=manager.config.jwt_access_token_expiry_minutes * 60,
    )
    return response


@app.get("/me")
@auth.login_required
def me():
    user = current_user()
    if user is None:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"id": user["id"], "name": user["name"], "email": user["email"]})


@app.get("/admin")
@auth.require_permission("admin.access")
def admin():
    return jsonify({"message": "Welcome, admin!"})


if __name__ == "__main__":
    app.run()
