"""Django integration helpers for the Authority authentication library.

Synchronous integration for Django apps backed by :class:`authority.AuthManager`.

It provides:

* :class:`AuthorityBackend` — a ``django.contrib.auth`` authentication backend
  so the standard ``authenticate()`` / ``login()`` Django session flow works.
* JWT decorators (:func:`login_required`, :func:`require_permission`,
  :func:`require_role`) for API-style Authorization-header auth.

Usage::

    # settings.py
    AUTHENTICATION_BACKENDS = ["authority.django.AuthorityBackend"]

    # views.py
    from django.contrib.auth import authenticate, login
    from authority.django import init_auth, require_permission

    init_auth(manager)  # during app setup

    def login_view(request):
        user = authenticate(request, email=..., password=...)
        if user is not None:
            login(request, user)

    @require_permission("admin.access")
    def admin(request):
        return HttpResponse("Welcome, admin!")
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpRequest, HttpResponse

from .core import AuthManager
from .exceptions import AuthError

logger = logging.getLogger("authority.django")

_global_auth_manager: AuthManager | None = None


def init_auth(manager: AuthManager) -> None:
    """Initialize the global auth manager for Django.

    Call this once during application setup, before handling any requests.

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


def authority_user_to_django_user(authority_user: dict[str, Any]) -> User:
    """Get (or create) the Django User mirroring an authority user.

    The Django user uses the same primary key as the authority user, so
    :meth:`AuthorityBackend.get_user` can map sessions directly.

    Args:
        authority_user: A user dict from the authority manager.

    Returns:
        The mirrored Django User instance.
    """
    user_id = int(authority_user["id"])
    email = authority_user["email"]
    user, created = User.objects.get_or_create(
        id=user_id,
        defaults={
            "username": email,
            "email": email,
            "first_name": authority_user.get("name", ""),
        },
    )
    if created:
        user.set_unusable_password()
        user.save(update_fields=["password"])
    return user


class AuthorityBackend:
    """Django authentication backend backed by Authority.

    Authenticates against the authority manager and returns a mirrored
    :class:`django.contrib.auth.models.User` on success.
    """

    def authenticate(
        self,
        request: HttpRequest | None = None,
        email: str | None = None,
        password: str | None = None,
        access_token: str | None = None,
        **kwargs: Any,
    ) -> User | None:
        """Authenticate using email+password or an access token.

        Args:
            request: The current HTTP request (optional).
            email: The user's email address.
            password: The user's password.
            access_token: Alternatively, a valid authority access token.

        Returns:
            The mirrored Django User, or None if authentication failed.
        """
        manager = get_auth_manager()
        try:
            if access_token:
                payload = manager.verify_access_token(access_token)
                authority_user = manager.get_user(payload["user_id"])
            elif email and password:
                result = manager.login(email, password)
                if result.get("mfa_required"):
                    return None
                authority_user = result["user"]
            else:
                return None
        except AuthError:
            return None
        return authority_user_to_django_user(authority_user)

    def get_user(self, user_id: int) -> User | None:
        """Fetch the Django user for the given primary key.

        Args:
            user_id: The Django user primary key (matches the authority user id).

        Returns:
            The Django User, or None if not found.
        """
        try:
            return User.objects.get(pk=user_id)
        except ObjectDoesNotExist:
            return None


def extract_bearer_token(request: HttpRequest) -> str | None:
    """Extract a Bearer token from the request's Authorization header.

    Args:
        request: The Django HttpRequest.

    Returns:
        The token string, or None if no Bearer token is present.
    """
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _verify_request_token(request: HttpRequest) -> dict[str, Any] | None:
    """Return the verified token payload for a request, or None."""
    manager = get_auth_manager()
    token = extract_bearer_token(request)
    if not token:
        return None
    try:
        return manager.verify_access_token(token)
    except AuthError:
        return None


def get_current_user(request: HttpRequest) -> dict[str, Any] | None:
    """Return the full authority user dict for the request, or None.

    Args:
        request: The Django HttpRequest.

    Returns:
        The user dict, or None if the token is missing or invalid.
    """
    payload = _verify_request_token(request)
    if payload is None:
        return None
    try:
        return get_auth_manager().get_user(payload["user_id"])
    except AuthError:
        return None


def _unauthorized() -> HttpResponse:
    """Return a plain-text 401 response."""
    return HttpResponse(
        b"Authentication required.", status=401, content_type="text/plain"
    )


def _forbidden(detail: str) -> HttpResponse:
    """Return a plain-text 403 response."""
    return HttpResponse(detail.encode(), status=403, content_type="text/plain")


def login_required(view_func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator requiring a valid access token on the request.

    The view can call :func:`get_current_user` to load the full user.

    Raises:
        HttpResponse: 401 if no valid token is provided.
    """

    @wraps(view_func)
    def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        if _verify_request_token(request) is None:
            return _unauthorized()
        return view_func(request, *args, **kwargs)

    return wrapper


def require_permission(
    permission_code: str,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory requiring the current user to hold a permission.

    Usage::

        @require_permission("admin.access")
        def admin(request):
            return HttpResponse("Welcome, admin!")

    Args:
        permission_code: The permission code to check (e.g. "admin.access").

    Raises:
        HttpResponse: 401 if unauthenticated, 403 if the permission is missing.
    """

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            payload = _verify_request_token(request)
            if payload is None:
                return _unauthorized()
            manager = get_auth_manager()
            if not manager.has_permission(payload["user_id"], permission_code):
                return _forbidden(f"Permission '{permission_code}' required.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_role(role_name: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory requiring the current user to hold a role.

    Usage::

        @require_role("admin")
        def admin(request):
            return HttpResponse("Welcome, admin!")

    Args:
        role_name: The role name to check (e.g. "admin").

    Raises:
        HttpResponse: 401 if unauthenticated, 403 if the role is missing.
    """

    def decorator(view_func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            payload = _verify_request_token(request)
            if payload is None:
                return _unauthorized()
            manager = get_auth_manager()
            roles = [r["name"] for r in manager.get_user_roles(payload["user_id"])]
            if role_name not in roles:
                return _forbidden(f"Role '{role_name}' required.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator
