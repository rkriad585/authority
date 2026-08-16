"""Runnable bare-ASGI example app using the authority middleware.

This is a plain ASGI application (no framework) wrapped in
:class:`authority.asgi.AuthorityASGIMiddleware`.

Run from the repository root with:

    pip install uvicorn
    uvicorn examples.apps.asgi_app.app:wrapped_app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

import json
from typing import Any

from authority.asgi import (
    AuthorityASGIMiddleware,
    get_current_user,
    get_user_state,
    is_authenticated,
    user_id_from_scope,
)
from authority.async_core import AsyncAuthManager
from authority.exceptions import InvalidCredentialsError, UserExistsError
from authority.storage.aiosqlite import AsyncSQLiteStorage

from .._common import default_config, seed_demo_async

DB_PATH = "asgi_auth.db"

storage = AsyncSQLiteStorage(DB_PATH)
manager = AsyncAuthManager(default_config(DB_PATH), storage)


async def _json_response(send: Any, status: int, body: dict[str, Any]) -> None:
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


async def _read_body(receive: Any) -> dict[str, Any]:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    raw = b"".join(chunks)
    return json.loads(raw) if raw else {}


async def _lifespan(receive: Any, send: Any) -> None:
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await storage.connect()
            await seed_demo_async(manager)
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await manager.close()
            await send({"type": "lifespan.shutdown.complete"})
            return


async def app(scope: Any, receive: Any, send: Any) -> None:
    if scope["type"] == "lifespan":
        await _lifespan(receive, send)
        return

    if scope["type"] != "http":
        return

    path = scope.get("path", "/")
    method = scope.get("method", "GET")

    if path == "/register" and method == "POST":
        data = await _read_body(receive)
        try:
            user = await manager.register(
                data["name"], data["email"], data["password"], auto_verify=True
            )
        except UserExistsError:
            await _json_response(send, 409, {"error": "Email already registered"})
            return
        await _json_response(send, 201, {"user_id": user["id"], "email": user["email"]})
        return

    if path == "/login" and method == "POST":
        data = await _read_body(receive)
        try:
            result = await manager.login(data["email"], data["password"])
        except InvalidCredentialsError:
            await _json_response(send, 401, {"error": "Invalid credentials"})
            return
        await _json_response(
            send,
            200,
            {
                "access_token": result["access_token"],
                "refresh_token": result["refresh_token"],
                "token_type": "Bearer",
            },
        )
        return

    if path == "/me":
        user = await get_current_user(scope, manager)
        if user is None:
            await _json_response(send, 401, {"error": "Not authenticated"})
            return
        await _json_response(
            send,
            200,
            {"id": user["id"], "name": user["name"], "email": user["email"]},
        )
        return

    state = get_user_state(scope)
    await _json_response(
        send,
        200,
        {
            "authenticated": is_authenticated(scope),
            "user_id": user_id_from_scope(scope),
            "path": path,
            "authority": state,
        },
    )


wrapped_app = AuthorityASGIMiddleware(app, manager)
