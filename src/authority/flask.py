"""Flask integration helpers for the Authority authentication library.

Synchronous integration for WSGI Flask apps backed by :class:`authority.AuthManager`.

Usage::

    from flask import Flask, render_template
    from authority import AuthConfig, AuthManager
    from authority.storage.sqlite import SQLiteStorage
    from authority.flask import FlaskAuth

    app = Flask(__name__)
    app.secret_key = "app-session-secret"

    manager = AuthManager(
        AuthConfig(jwt_secret_key="...", fernet_key="..."),
        SQLiteStorage("auth.db"),
    )
    auth = FlaskAuth(app, manager)

    @app.route("/dashboard")
    @auth.login_required
    def dashboard():
        return render_template("dashboard.html", user=auth.current_user())

    @app.route("/admin")
    @auth.require_permission("admin.access")
    def admin():
        return "Welcome, admin!"
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from flask import abort, g, request, session

from .core import AuthManager
from .exceptions import (
    AuthError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
)

logger = logging.getLogger("authority.flask")

_global_auth_manager: AuthManager | None = None


def init_auth(manager: AuthManager) -> None:
    """Initialize the global auth manager for Flask apps.

    This is required before using the module-level :func:`login_required`,
    :func:`require_permission`, or :func:`require_role` helpers.

    Args:
        manager: The AuthManager instance to use.
    """
    global _global_auth_manager
    _global_auth_manager = manager


def get_auth_manager() -> AuthManager:
    """Get the global auth manager instance.

    Returns:
        The AuthManager instance.

    Raises:
        RuntimeError: If init_auth() has not been called.
    """
    if _global_auth_manager is None:
        raise RuntimeError(
            "AuthManager not initialized. Call init_auth(manager) first."
        )
    return _global_auth_manager


def extract_bearer_token() -> str | None:
    """Extract a Bearer token from the current request.

    The ``Authorization: Bearer <token>`` header is checked first; if absent,
    the token stored in the Flask session under ``access_token`` is used.

    Returns:
        The token string, or None if no token is present.
    """
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return session.get("access_token")


def _authenticate_or_abort() -> dict[str, Any]:
    """Verify the request token and return its payload, aborting on failure.

    Raises:
        flask.exceptions.HTTPException: 401 if the token is missing, expired, or invalid.
    """
    manager = get_auth_manager()
    token = extract_bearer_token()
    if not token:
        abort(401, description="Authentication required.")
    try:
        payload = manager.verify_access_token(token)
    except TokenExpiredError:
        abort(401, description="Token has expired.")
    except (InvalidTokenError, InvalidCredentialsError) as exc:
        abort(401, description=f"Invalid token: {exc}")
    g.authority_user_id = payload["user_id"]
    g.authority_user_payload = payload
    return payload


def current_user() -> dict[str, Any] | None:
    """Return the full user dict for the current request, or None if unauthenticated.

    The result is cached on the Flask request context.
    """
    cached = getattr(g, "_authority_current_user", None)
    if cached is not None:
        return cached
    manager = get_auth_manager()
    token = extract_bearer_token()
    if not token:
        return None
    try:
        payload = manager.verify_access_token(token)
        user = manager.get_user(payload["user_id"])
    except AuthError:
        return None
    g._authority_current_user = user
    return user


def login_required(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator requiring a valid access token on the current request.

    On success, ``g.authority_user_id`` and ``g.authority_user_payload`` are set.
    Use :func:`current_user` inside the view to fetch the full user dict.

    Raises:
        flask.exceptions.HTTPException: 401 if no valid token is provided.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _authenticate_or_abort()
        return func(*args, **kwargs)

    return wrapper


def require_permission(
    permission_code: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory requiring the current user to hold a permission.

    Usage::

        @app.route("/admin")
        @require_permission("admin.access")
        def admin():
            return "Welcome, admin!"

    Args:
        permission_code: The permission code to check (e.g. "admin.access").

    Raises:
        flask.exceptions.HTTPException: 401 if unauthenticated, 403 if the
            permission is missing.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = _authenticate_or_abort()
            manager = get_auth_manager()
            if not manager.has_permission(payload["user_id"], permission_code):
                abort(403, description=f"Permission '{permission_code}' required.")
            return func(*args, **kwargs)

        return wrapper

    return decorator


def require_role(role_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory requiring the current user to hold a role.

    Usage::

        @app.route("/admin")
        @require_role("admin")
        def admin():
            return "Welcome, admin!"

    Args:
        role_name: The role name to check (e.g. "admin").

    Raises:
        flask.exceptions.HTTPException: 401 if unauthenticated, 403 if the role
            is missing.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = _authenticate_or_abort()
            manager = get_auth_manager()
            roles = [r["name"] for r in manager.get_user_roles(payload["user_id"])]
            if role_name not in roles:
                abort(403, description=f"Role '{role_name}' required.")
            return func(*args, **kwargs)

        return wrapper

    return decorator


class FlaskAuth:
    """Instance-based Flask integration helper.

    Unlike the module-level helpers, this keeps a reference to both the Flask
    app (so the manager can be registered for ``current_app``-style usage) and
    the auth manager, which is useful when running multiple Flask apps in one
    process.
    """

    def __init__(
        self, app: Any | None = None, manager: AuthManager | None = None
    ) -> None:
        """Initialize the FlaskAuth helper.

        Args:
            app: Optional Flask app to bind the manager to.
            manager: The AuthManager instance to use.
        """
        self._manager = manager
        if app is not None and manager is not None:
            self.init_app(app, manager)

    @property
    def manager(self) -> AuthManager:
        """The auth manager instance."""
        if self._manager is None:
            raise RuntimeError(
                "AuthManager not initialized. Call init_app() or pass manager."
            )
        return self._manager

    def init_app(self, app: Any, manager: AuthManager) -> None:
        """Bind the auth manager to a Flask app.

        Args:
            app: The Flask app instance.
            manager: The AuthManager instance to use.
        """
        self._manager = manager
        app.extensions["authority_auth"] = self

    def current_user(self) -> dict[str, Any] | None:
        """Return the full user dict for the current request, or None."""
        return current_user()

    def login_required(self, func: Callable[..., Any]) -> Callable[..., Any]:
        """See :func:`login_required` (instance version)."""
        return login_required(func)

    def require_permission(
        self, permission_code: str
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """See :func:`require_permission` (instance version)."""
        return require_permission(permission_code)

    def require_role(
        self, role_name: str
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """See :func:`require_role` (instance version)."""
        return require_role(role_name)
