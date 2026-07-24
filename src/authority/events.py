"""Typed event bus for authority library lifecycle events."""

from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Callable, Coroutine
from enum import Enum
from typing import Any

logger = logging.getLogger("authority.events")


class Event(str, Enum):
    """All supported authority lifecycle events."""

    # User lifecycle
    USER_REGISTERED = "user.registered"
    USER_LOGIN_SUCCESS = "user.login_success"
    USER_LOGIN_FAILED = "user.login_failed"
    USER_LOGOUT = "user.logout"
    USER_PASSWORD_CHANGED = "user.password_changed"
    USER_PASSWORD_RESET = "user.password_reset_requested"
    USER_EMAIL_CHANGED = "user.email_changed"
    USER_DELETED = "user.deleted"

    # MFA
    MFA_SETUP_INITIATED = "mfa.setup_initiated"
    MFA_ENABLED = "mfa.enabled"
    MFA_DISABLED = "mfa.disabled"
    MFA_FAILED = "mfa.failed"

    # Tokens
    TOKEN_REFRESHED = "token.refreshed"
    TOKEN_REUSE_DETECTED = "token.reuse_detected"

    # WebAuthn
    WEBAUTHN_CREDENTIAL_ADDED = "webauthn.credential_added"
    WEBAUTHN_CREDENTIAL_REMOVED = "webauthn.credential_removed"

    # RBAC
    RBAC_ROLE_ASSIGNED = "rbac.role_assigned"
    RBAC_ROLE_REVOKED = "rbac.role_revoked"

    # API Keys
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"

    # Audit
    AUDIT_EVENT_LOGGED = "audit.event_logged"


# Handler types
SyncHandler = Callable[[dict[str, Any]], None]
AsyncHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]
Handler = SyncHandler | AsyncHandler


class EventBus:
    """Simple typed event bus supporting sync and async handlers.

    Usage::

        bus = EventBus()
        bus.on(Event.USER_REGISTERED, my_handler)
        bus.emit(Event.USER_REGISTERED, {"user_id": 1, "email": "a@b.com"})
    """

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = {}

    def on(self, event: Event | str, handler: Handler) -> None:
        """Register *handler* for *event*."""
        key = event.value if isinstance(event, Event) else event
        self._handlers.setdefault(key, []).append(handler)

    def off(self, event: Event | str, handler: Handler) -> None:
        """Remove *handler* from *event*."""
        key = event.value if isinstance(event, Event) else event
        handlers = self._handlers.get(key, [])
        try:
            handlers.remove(handler)
        except ValueError:
            logger.warning("Tried to remove non-existent handler for '%s'", key)

    def emit(self, event: Event | str, data: dict[str, Any] | None = None) -> None:
        """Fire all handlers for *event* synchronously.

        Async handlers are scheduled on the running event loop if one exists,
        otherwise they are logged and skipped.
        """
        key = event.value if isinstance(event, Event) else event
        payload = data or {}

        for handler in self._handlers.get(key, []):
            try:
                if inspect.iscoroutinefunction(handler):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(handler(payload))  # type: ignore[arg-type]
                    except RuntimeError:
                        logger.warning(
                            "Async handler for '%s' skipped: no running event loop", key
                        )
                else:
                    handler(payload)
            except Exception:
                logger.exception("Handler error for event '%s'", key)

    async def emit_async(
        self, event: Event | str, data: dict[str, Any] | None = None
    ) -> None:
        """Fire all handlers for *event*, awaiting each one."""
        key = event.value if isinstance(event, Event) else event
        payload = data or {}

        for handler in self._handlers.get(key, []):
            try:
                if inspect.iscoroutinefunction(handler):
                    await handler(payload)
                else:
                    handler(payload)
            except Exception:
                logger.exception("Handler error for event '%s'", key)

    def clear(self) -> None:
        """Remove all handlers."""
        self._handlers.clear()
