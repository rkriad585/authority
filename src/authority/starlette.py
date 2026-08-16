"""Starlette integration helpers for the Authority authentication library.

Asynchronous integration for ASGI Starlette apps backed by
:class:`authority.AsyncAuthManager`.

Usage::

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from authority import AuthConfig, AsyncAuthManager
    from authority.storage.aiosqlite import AsyncSQLiteStorage
    from authority.starlette import StarletteAuth

    storage = AsyncSQLiteStorage("auth.db")
    await storage.connect()
    manager = AsyncAuthManager(AuthConfig(jwt_secret_key="...", fernet_key="..."), storage)
    auth = StarletteAuth(manager)

    async def me(request: Request):
        return JSONResponse({"user": await auth.current_user(request)})

    @auth.login_required
    async def dashboard(request: Request):
        return JSONResponse({"message": "Hello"})

    app = Starlette(routes=[Route("/me", me), Route("/dashboard", dashboard)])
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import TYPE_CHECKING, Any

from starlette.exceptions import HTTPException

from .async_core import AsyncAuthManager
from .exceptions import AuthError

if TYPE_CHECKING:
    from starlette.requests import Request

logger = logging.getLogger("authority.starlette")


def extract_bearer_token(request: Request) -> str | None:
    """Extract a Bearer token from the request's Authorization header.

    Args:
        request: The Starlette Request.

    Returns:
        The token string, or None if no Bearer token is present.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


class StarletteAuth:
    """Starlette integration helper wrapping an :class:`AsyncAuthManager`."""

    def __init__(self, manager: AsyncAuthManager) -> None:
        """Initialize the StarletteAuth helper.

        Args:
            manager: The AsyncAuthManager instance to use.
        """
        self._manager = manager

    @property
    def manager(self) -> AsyncAuthManager:
        """The auth manager instance."""
        return self._manager

    async def user_payload(self, request: Request) -> dict[str, Any] | None:
        """Return the verified JWT payload for a request, or None.

        Args:
            request: The Starlette Request.

        Returns:
            The token payload dict, or None if the token is invalid.
        """
        token = extract_bearer_token(request)
        if not token:
            return None
        try:
            return await self._manager.verify_access_token(token)
        except AuthError:
            return None

    async def current_user(self, request: Request) -> dict[str, Any] | None:
        """Return the full user dict for a request, or None.

        Args:
            request: The Starlette Request.

        Returns:
            The user dict, or None if the token is missing or invalid.
        """
        payload = await self.user_payload(request)
        if payload is None:
            return None
        try:
            return await self._manager.get_user(payload["user_id"])
        except AuthError:
            return None

    async def authenticate(self, request: Request) -> dict[str, Any]:
        """Return the verified token payload or raise a 401.

        Args:
            request: The Starlette Request.

        Returns:
            The token payload dict.

        Raises:
            starlette.exceptions.HTTPException: 401 if the token is missing
                or invalid.
        """
        payload = await self.user_payload(request)
        if payload is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        return payload

    def login_required(
        self, func: Callable[..., Awaitable[Any]]
    ) -> Callable[..., Awaitable[Any]]:
        """Decorator requiring a valid access token on the request.

        The decorated function must accept ``request`` as its first argument.

        Raises:
            starlette.exceptions.HTTPException: 401 if unauthenticated.
        """

        @wraps(func)
        async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Any:
            await self.authenticate(request)
            return await func(request, *args, **kwargs)

        return wrapper

    def require_permission(
        self, permission_code: str
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Decorator factory requiring the current user to hold a permission.

        Usage::

            @auth.require_permission("admin.access")
            async def admin(request: Request):
                return JSONResponse({"ok": True})

        Args:
            permission_code: The permission code to check (e.g. "admin.access").

        Raises:
            starlette.exceptions.HTTPException: 401 if unauthenticated, 403 if
                the permission is missing.
        """

        def decorator(
            func: Callable[..., Awaitable[Any]],
        ) -> Callable[..., Awaitable[Any]]:
            @wraps(func)
            async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Any:
                payload = await self.authenticate(request)
                if not await self._manager.has_permission(
                    payload["user_id"], permission_code
                ):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Permission '{permission_code}' required.",
                    )
                return await func(request, *args, **kwargs)

            return wrapper

        return decorator

    def require_role(
        self, role_name: str
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Decorator factory requiring the current user to hold a role.

        Usage::

            @auth.require_role("admin")
            async def admin(request: Request):
                return JSONResponse({"ok": True})

        Args:
            role_name: The role name to check (e.g. "admin").

        Raises:
            starlette.exceptions.HTTPException: 401 if unauthenticated, 403 if
                the role is missing.
        """

        def decorator(
            func: Callable[..., Awaitable[Any]],
        ) -> Callable[..., Awaitable[Any]]:
            @wraps(func)
            async def wrapper(request: Request, *args: Any, **kwargs: Any) -> Any:
                payload = await self.authenticate(request)
                roles = [
                    r["name"]
                    for r in await self._manager.get_user_roles(payload["user_id"])
                ]
                if role_name not in roles:
                    raise HTTPException(
                        status_code=403, detail=f"Role '{role_name}' required."
                    )
                return await func(request, *args, **kwargs)

            return wrapper

        return decorator
