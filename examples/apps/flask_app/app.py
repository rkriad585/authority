"""Runnable Flask example app using the authority library.

Run from the repository root with:

    python -m examples.apps.flask_app.app

The demo admin account is seeded on first startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

from flask import Flask, jsonify, request

from authority.core import AuthManager
from authority.exceptions import InvalidCredentialsError, UserExistsError
from authority.flask import FlaskAuth, current_user, init_auth
from authority.storage.sqlite import SQLiteStorage

from .._common import default_config, seed_demo_sync

DB_PATH = "flask_auth.db"

app = Flask(__name__)
app.secret_key = "flask-example-session-secret-change-me"

manager = AuthManager(default_config(DB_PATH), SQLiteStorage(DB_PATH))
init_auth(manager)
auth = FlaskAuth(app, manager)
seed_demo_sync(manager)


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
    return jsonify(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )


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
