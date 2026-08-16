"""Framework-agnostic ASGI authentication middleware for the Authority library.

Works with any ASGI application (Starlette, FastAPI, Quart, Django/ASGI,
bare ASGI apps) that speaks the ASGI protocol. On every HTTP request it
reads the ``Authorization: Bearer <token>`` header, verifies it with the
:class:`authority.AsyncAuthManager`, and exposes the result on the scope
under ``scope["authority"]``::

    {
        "authenticated": True,
        "user_id": 1,
        "token": "<jwt>",
        "payload": {"user_id": 1, "jti": "...", ...},
    }

Usage::

    from authority.asgi import AuthorityASGIMiddleware

    app = AuthorityASGIMiddleware(raw_asgi_app, manager)
    app = AuthorityASGIMiddleware(starlette_app, manager, auth_required=True)

Set ``auth_required=True`` to reject unauthenticated HTTP requests with a
401 JSON response before they reach the application.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any, TypedDict

from .async_core import AsyncAuthManager
from .exceptions import AuthError

logger = logging.getLogger("authority.asgi")

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

AUTHORITY_SCOPE_KEY = "authority"


class AuthorityState(TypedDict, total=False):
    """State exposed on the ASGI scope by the middleware."""

    authenticated: bool
    user_id: int
    token: str
    payload: dict[str, Any]


def _extract_bearer_token(headers: list[tuple[bytes, bytes]]) -> str | None:
    """Extract a Bearer token from ASGI raw header pairs."""
    for name, value in headers:
        if name.lower() == b"authorization":
            text = value.decode("latin-1").strip()
            if text.lower().startswith("bearer "):
                return text[7:].strip()
    return None


async def _send_json_response(
    send: Send, status_code: int, body: dict[str, Any]
) -> None:
    """Send a complete JSON HTTP response."""
    payload = json.dumps(body).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": payload})


class AuthorityASGIMiddleware:
    """ASGI middleware that authenticates requests with a Bearer token."""

    def __init__(
        self,
        app: ASGIApp,
        manager: AsyncAuthManager,
        *,
        auth_required: bool = False,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The inner ASGI application.
            manager: The AsyncAuthManager used to verify tokens.
            auth_required: If True, unauthenticated HTTP requests are rejected
                with a 401 before reaching the app.
        """
        self.app = app
        self.manager = manager
        self.auth_required = auth_required

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        """Wrap the ASGI application.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive callable.
            send: The ASGI send callable.
        """
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers") or []
        token = _extract_bearer_token(headers)

        state: AuthorityState = {"authenticated": False}
        if token:
            try:
                payload = await self.manager.verify_access_token(token)
            except AuthError:
                payload = None
            if payload:
                state = {
                    "authenticated": True,
                    "user_id": payload["user_id"],
                    "token": token,
                    "payload": payload,
                }

        if self.auth_required and not state.get("authenticated"):
            await _send_json_response(send, 401, {"detail": "Authentication required."})
            return

        scope[AUTHORITY_SCOPE_KEY] = state
        await self.app(scope, receive, send)


def get_user_state(scope: Scope) -> AuthorityState:
    """Return the authority state attached to an ASGI scope.

    Args:
        scope: The ASGI connection scope.

    Returns:
        The authority state dict (always present after the middleware runs).
    """
    return scope.get(AUTHORITY_SCOPE_KEY, {"authenticated": False})


def is_authenticated(scope: Scope) -> bool:
    """Return True if the scope carries an authenticated user.

    Args:
        scope: The ASGI connection scope.
    """
    return bool(get_user_state(scope).get("authenticated"))


def user_id_from_scope(scope: Scope) -> int | None:
    """Return the authenticated user id from an ASGI scope, or None.

    Args:
        scope: The ASGI connection scope.
    """
    return get_user_state(scope).get("user_id")


async def get_current_user(
    scope: Scope, manager: AsyncAuthManager
) -> dict[str, Any] | None:
    """Return the full user dict for an ASGI scope, or None.

    Args:
        scope: The ASGI connection scope.
        manager: The AsyncAuthManager instance.

    Returns:
        The user dict, or None if the scope is not authenticated.
    """
    state = get_user_state(scope)
    user_id = state.get("user_id")
    if user_id is None:
        return None
    try:
        return await manager.get_user(user_id)
    except AuthError:
        return None
