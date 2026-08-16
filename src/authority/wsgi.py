"""Framework-agnostic WSGI authentication middleware for the Authority library.

Works with any WSGI application (Flask, Django, plain WSGI apps). On every
request it reads the ``Authorization: Bearer <token>`` header, verifies it
with the :class:`authority.AuthManager`, and exposes the result on the WSGI
environ under ``environ["authority"]``::

    {
        "authenticated": True,
        "user_id": 1,
        "token": "<jwt>",
        "payload": {"user_id": 1, "jti": "...", ...},
    }

Usage::

    from authority.wsgi import AuthorityWSGIMiddleware

    app = AuthorityWSGIMiddleware(wsgi_app, manager)
    app = AuthorityWSGIMiddleware(flask_app, manager, auth_required=True)

Set ``auth_required=True`` to reject unauthenticated requests with a 401
JSON response before they reach the application.
"""

from __future__ import annotations

import http.client
import json
import logging
from collections.abc import Callable
from typing import Any

from .core import AuthManager
from .exceptions import AuthError

logger = logging.getLogger("authority.wsgi")

Environ = dict[str, Any]
StartResponse = Callable[..., Any]
WSGIApp = Callable[..., Any]

AUTHORITY_ENVIRON_KEY = "authority"


def _extract_bearer_token(environ: Environ) -> str | None:
    """Extract a Bearer token from a WSGI environ."""
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _json_response(
    start_response: StartResponse, status_code: int, body: dict[str, Any]
) -> list[bytes]:
    """Build a WSGI JSON response."""
    payload = json.dumps(body).encode("utf-8")
    reason = http.client.responses.get(status_code, "Unknown")
    start_response(
        f"{status_code} {reason}",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


class AuthorityWSGIMiddleware:
    """WSGI middleware that authenticates requests with a Bearer token."""

    def __init__(
        self,
        app: WSGIApp,
        manager: AuthManager,
        *,
        auth_required: bool = False,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The inner WSGI application.
            manager: The AuthManager used to verify tokens.
            auth_required: If True, unauthenticated requests are rejected with
                a 401 before reaching the app.
        """
        self.app = app
        self.manager = manager
        self.auth_required = auth_required

    def __call__(self, environ: Environ, start_response: StartResponse) -> list[bytes]:
        """Wrap the WSGI application.

        Args:
            environ: The WSGI environment.
            start_response: The WSGI start_response callable.

        Returns:
            The application's response iterable.
        """
        token = _extract_bearer_token(environ)

        state: dict[str, Any] = {"authenticated": False}
        if token:
            try:
                payload = self.manager.verify_access_token(token)
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
            return _json_response(
                start_response, 401, {"detail": "Authentication required."}
            )

        environ[AUTHORITY_ENVIRON_KEY] = state
        return self.app(environ, start_response)


def get_user_state(environ: Environ) -> dict[str, Any]:
    """Return the authority state attached to a WSGI environ.

    Args:
        environ: The WSGI environment.

    Returns:
        The authority state dict (always present after the middleware runs).
    """
    return environ.get(AUTHORITY_ENVIRON_KEY, {"authenticated": False})


def is_authenticated(environ: Environ) -> bool:
    """Return True if the environ carries an authenticated user.

    Args:
        environ: The WSGI environment.
    """
    return bool(get_user_state(environ).get("authenticated"))


def user_id_from_environ(environ: Environ) -> int | None:
    """Return the authenticated user id from a WSGI environ, or None.

    Args:
        environ: The WSGI environment.
    """
    return get_user_state(environ).get("user_id")


def get_current_user(environ: Environ, manager: AuthManager) -> dict[str, Any] | None:
    """Return the full user dict for a WSGI environ, or None.

    Args:
        environ: The WSGI environment.
        manager: The AuthManager instance.

    Returns:
        The user dict, or None if the environ is not authenticated.
    """
    state = get_user_state(environ)
    user_id = state.get("user_id")
    if user_id is None:
        return None
    try:
        return manager.get_user(user_id)
    except AuthError:
        return None
