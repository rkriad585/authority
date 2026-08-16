"""FastAPI integration helpers for the Authority authentication library."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .async_core import AsyncAuthManager
from .exceptions import (
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
)

logger = logging.getLogger("authority.fastapi")

_bearer_scheme = HTTPBearer()

_global_auth_manager: AsyncAuthManager | None = None


def init_auth(manager: AsyncAuthManager) -> None:
    """Initialize the global auth manager for FastAPI dependency injection.

    Args:
        manager: The AsyncAuthManager instance to use.
    """
    global _global_auth_manager
    _global_auth_manager = manager


def get_auth_manager() -> AsyncAuthManager:
    """Get the global auth manager instance.

    Returns:
        The AsyncAuthManager instance.

    Raises:
        RuntimeError: If init_auth() has not been called.
    """
    if _global_auth_manager is None:
        raise RuntimeError(
            "AuthManager not initialized. Call init_auth(manager) first."
        )
    return _global_auth_manager


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),  # noqa: B008
) -> dict[str, Any]:
    """FastAPI dependency that extracts and validates the current user from a JWT.

    Use this as a dependency in your route handlers:

        @app.get("/me")
        async def get_me(user=Depends(get_current_user)):
            return user

    Args:
        credentials: The Bearer token from the Authorization header.

    Returns:
        Dict with user_id, jti, exp, iat, iss, typ.

    Raises:
        HTTPException: 401 if token is invalid or expired.
    """
    manager = get_auth_manager()
    try:
        payload = await manager.verify_access_token(credentials.credentials)
        return payload
    except TokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None


async def require_permission(permission_code: str):
    """FastAPI dependency factory that checks if the current user has a specific permission.

    Usage:

        @app.delete("/items/{item_id}")
        async def delete_item(
            item_id: int,
            user=Depends(require_permission("items.delete")),
        ):
            return {"deleted": item_id}

    Args:
        permission_code: The permission code to check (e.g., "items.delete").

    Returns:
        A dependency function that returns the current user if authorized.

    Raises:
        HTTPException: 403 if user lacks the permission.
    """

    async def _check_permission(
        credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),  # noqa: B008
    ) -> dict[str, Any]:
        manager = get_auth_manager()
        try:
            payload = await manager.verify_access_token(credentials.credentials)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

        user_id = payload["user_id"]
        permissions = await manager.get_user_permissions(user_id)
        if permission_code not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission_code}' required.",
            )

        return payload

    return _check_permission


async def require_role(role_name: str):
    """FastAPI dependency factory that checks if the current user has a specific role.

    Usage:

        @app.get("/admin")
        async def admin_only(user=Depends(require_role("admin"))):
            return {"message": "Welcome, admin"}

    Args:
        role_name: The role name to check (e.g., "admin").

    Returns:
        A dependency function that returns the current user if authorized.

    Raises:
        HTTPException: 403 if user lacks the role.
    """

    async def _check_role(
        credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),  # noqa: B008
    ) -> dict[str, Any]:
        manager = get_auth_manager()
        try:
            payload = await manager.verify_access_token(credentials.credentials)
        except TokenExpiredError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None
        except InvalidTokenError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from None

        user_id = payload["user_id"]
        roles = await manager.get_user_roles(user_id)
        role_names = [r["name"] for r in roles]
        if role_name not in role_names:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' required.",
            )

        return payload

    return _check_role
