"""Shared configuration and demo-data helpers for the example apps.

All example apps seed the same demo admin account on startup:

    email:    demo@example.com
    password: SecureP@ss1234!

so you can log in and hit the protected endpoints immediately.
"""

from __future__ import annotations

import os

from cryptography.fernet import Fernet

from authority import AuthConfig
from authority.async_core import AsyncAuthManager
from authority.core import AuthManager
from authority.exceptions import AuthError

DEMO_NAME = "Demo Admin"
DEMO_EMAIL = "demo@example.com"
DEMO_PASSWORD = "SecureP@ss1234!"
DEMO_ROLE = "admin"
DEMO_PERMISSION = "admin.access"


def default_config(db_path: str) -> AuthConfig:
    """Build an AuthConfig for local development.

    Secrets are read from the environment when present so the examples work in
    production-ish settings too, and fall back to a throwaway local value.

    Args:
        db_path: SQLite database path used by the app.
    """
    return AuthConfig(
        jwt_secret_key=os.getenv(
            "AUTHORITY_JWT_SECRET_KEY", "dev-only-secret-key-change-me-32chars!"
        ),
        fernet_key=os.getenv("AUTHORITY_FERNET_KEY") or Fernet.generate_key().decode(),
        db_path=db_path,
    )


def seed_demo_sync(manager: AuthManager) -> None:
    """Idempotently create the demo role, permission, and admin user."""
    try:
        permission = manager.create_permission(DEMO_PERMISSION, "Full admin access")
    except AuthError:
        permission = None
    try:
        role = manager.create_role(DEMO_ROLE, "Administrator")
    except AuthError:
        role = None
    try:
        user = manager.register(DEMO_NAME, DEMO_EMAIL, DEMO_PASSWORD, auto_verify=True)
    except AuthError:
        user = None
    if permission is not None and role is not None:
        try:
            manager.assign_permission_to_role(role["id"], permission["id"])
        except AuthError:
            pass
    if user is not None and role is not None:
        try:
            manager.assign_role_to_user(user["id"], role["id"])
        except AuthError:
            pass


async def seed_demo_async(manager: AsyncAuthManager) -> None:
    """Idempotently create the demo role, permission, and admin user."""
    try:
        permission = await manager.create_permission(
            DEMO_PERMISSION, "Full admin access"
        )
    except AuthError:
        permission = None
    try:
        role = await manager.create_role(DEMO_ROLE, "Administrator")
    except AuthError:
        role = None
    try:
        user = await manager.register(
            DEMO_NAME, DEMO_EMAIL, DEMO_PASSWORD, auto_verify=True
        )
    except AuthError:
        user = None
    if permission is not None and role is not None:
        try:
            await manager.assign_permission_to_role(role["id"], permission["id"])
        except AuthError:
            pass
    if user is not None and role is not None:
        try:
            await manager.assign_role_to_user(user["id"], role["id"])
        except AuthError:
            pass
