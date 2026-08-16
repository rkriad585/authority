"""Runnable bare-WSGI example app using the authority middleware.

This is a plain WSGI application (no framework) wrapped in
:class:`authority.wsgi.AuthorityWSGIMiddleware`.

Run from the repository root with:

    python -m examples.apps.wsgi_app.app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

import json
from typing import Any

from authority.core import AuthManager
from authority.exceptions import (
    InvalidCredentialsError,
    UserExistsError,
    ValidationError,
)
from authority.storage.sqlite import SQLiteStorage
from authority.wsgi import (
    AuthorityWSGIMiddleware,
    get_current_user,
    get_user_state,
    user_id_from_environ,
)

from .._common import default_config, seed_demo_sync

DB_PATH = "wsgi_auth.db"

manager = AuthManager(default_config(DB_PATH), SQLiteStorage(DB_PATH))
seed_demo_sync(manager)

STATUS_OK = "200 OK"
STATUS_CREATED = "201 Created"
STATUS_BAD_REQUEST = "400 Bad Request"
STATUS_UNAUTHORIZED = "401 Unauthorized"
STATUS_CONFLICT = "409 Conflict"


def _json_response(
    start_response: Any, status: str, body: dict[str, Any]
) -> list[bytes]:
    payload = json.dumps(body).encode("utf-8")
    start_response(
        status,
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


def _read_body(environ: dict[str, Any]) -> dict[str, Any]:
    length = int(environ.get("CONTENT_LENGTH") or 0)
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    return json.loads(raw) if raw else {}


def application(environ: dict[str, Any], start_response: Any) -> list[bytes]:
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/register" and method == "POST":
        data = _read_body(environ)
        try:
            user = manager.register(
                data["name"], data["email"], data["password"], auto_verify=True
            )
        except UserExistsError:
            return _json_response(
                start_response, STATUS_CONFLICT, {"error": "Email already registered"}
            )
        except ValidationError as exc:
            return _json_response(
                start_response, STATUS_BAD_REQUEST, {"error": str(exc)}
            )
        return _json_response(
            start_response,
            STATUS_CREATED,
            {"user_id": user["id"], "email": user["email"]},
        )

    if path == "/login" and method == "POST":
        data = _read_body(environ)
        try:
            result = manager.login(data["email"], data["password"])
        except InvalidCredentialsError:
            return _json_response(
                start_response, STATUS_UNAUTHORIZED, {"error": "Invalid credentials"}
            )
        return _json_response(
            start_response,
            STATUS_OK,
            {
                "access_token": result["access_token"],
                "refresh_token": result["refresh_token"],
                "token_type": "Bearer",
            },
        )

    if path == "/me":
        user = get_current_user(environ, manager)
        if user is None:
            return _json_response(
                start_response, STATUS_UNAUTHORIZED, {"error": "Not authenticated"}
            )
        return _json_response(
            start_response,
            STATUS_OK,
            {"id": user["id"], "name": user["name"], "email": user["email"]},
        )

    state = get_user_state(environ)
    return _json_response(
        start_response,
        STATUS_OK,
        {
            "authenticated": state.get("authenticated"),
            "user_id": user_id_from_environ(environ),
            "path": path,
        },
    )


app = AuthorityWSGIMiddleware(application, manager)

if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    server = make_server("127.0.0.1", 8080, app)
    print("Serving WSGI app on http://127.0.0.1:8080")
    server.serve_forever()
