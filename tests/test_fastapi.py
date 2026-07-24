"""Tests for authority.fastapi — FastAPI integration helpers."""

from __future__ import annotations

import datetime

import jwt as pyjwt
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from authority.async_core import AsyncAuthManager
from authority.config import AuthConfig
from authority.fastapi import (
    get_auth_manager,
    get_current_user,
    init_auth,
    require_permission,
    require_role,
)
from authority.storage.aiosqlite import AsyncSQLiteStorage
from authority.utils import generate_secure_token

# ── Helpers ─────────────────────────────────────────────────


def _make_token(
    secret: str,
    sub: str = "1",
    jti: str | None = None,
    exp_minutes: int = 15,
    iss: str = "authority",
    typ: str = "access",
    algorithm: str = "HS256",
) -> str:
    """Create a JWT for testing."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload: dict = {
        "sub": sub,
        "jti": jti or generate_secure_token(16),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=exp_minutes),
        "iss": iss,
        "typ": typ,
    }
    return pyjwt.encode(payload, secret, algorithm=algorithm)


def _make_expired_token(secret: str, sub: str = "1") -> str:
    """Create an expired JWT for testing."""
    return _make_token(secret, sub=sub, exp_minutes=-10)


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture()
async def mem_db() -> AsyncSQLiteStorage:
    """Create an in-memory async SQLite database."""
    storage = AsyncSQLiteStorage(":memory:")
    await storage.connect()
    yield storage
    await storage.close()


@pytest.fixture()
def fernet_key() -> str:
    """Return a valid Fernet key."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


@pytest.fixture()
def test_config(fernet_key: str) -> AuthConfig:
    """Return a valid AuthConfig."""
    return AuthConfig(
        jwt_secret_key="test-secret-key-for-testing-only-32chars!",
        fernet_key=fernet_key,
        db_path=":memory:",
    )


@pytest.fixture()
async def auth_manager(
    test_config: AuthConfig, mem_db: AsyncSQLiteStorage
) -> AsyncAuthManager:
    """Return an AsyncAuthManager with in-memory storage."""
    test_config.refresh_token_reuse_grace_seconds = 0
    return AsyncAuthManager(test_config, mem_db)


@pytest.fixture()
async def registered_user(auth_manager: AsyncAuthManager) -> dict:
    """Register a user and return the user dict."""
    return await auth_manager.register(
        name="Test User",
        email="test@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
def valid_token(auth_manager: AsyncAuthManager) -> str:
    """Return a valid access token."""
    return _make_token(auth_manager.config.jwt_secret_key)


@pytest.fixture()
def expired_token(auth_manager: AsyncAuthManager) -> str:
    """Return an expired access token."""
    return _make_expired_token(auth_manager.config.jwt_secret_key)


# ── init_auth / get_auth_manager ────────────────────────────


class TestInitAuth:
    def test_init_and_get(self, auth_manager: AsyncAuthManager):
        init_auth(auth_manager)
        assert get_auth_manager() is auth_manager

    def test_get_before_init_raises(self):
        import authority.fastapi as mod

        mod._global_auth_manager = None
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_manager()


# ── get_current_user ────────────────────────────────────────


class TestGetCurrentUser:
    @pytest.fixture(autouse=True)
    def _init(self, auth_manager: AsyncAuthManager):
        init_auth(auth_manager)

    def _creds(self, token: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    async def test_valid_token(self, auth_manager, valid_token):
        payload = await get_current_user(self._creds(valid_token))
        assert payload["user_id"] == 1
        assert payload["typ"] == "access"

    async def test_expired_token(self, auth_manager, expired_token):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(self._creds(expired_token))
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    async def test_invalid_token(self, auth_manager):
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(self._creds("garbage.token.value"))
        assert exc_info.value.status_code == 401
        assert "invalid token" in exc_info.value.detail.lower()

    async def test_wrong_secret(self, auth_manager):
        token = _make_token("wrong-secret-key-that-is-long-enough-for-hmac!")
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user(self._creds(token))
        assert exc_info.value.status_code == 401


# ── require_permission ──────────────────────────────────────


class TestRequirePermission:
    @pytest.fixture(autouse=True)
    def _init(self, auth_manager: AsyncAuthManager):
        init_auth(auth_manager)

    def _creds(self, token: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    async def test_has_permission(self, auth_manager, registered_user):
        perm = await auth_manager.create_permission(
            code="items.delete", description="Delete items"
        )
        role = await auth_manager.create_role(name="admin", description="Admin role")
        await auth_manager.assign_permission_to_role(role["id"], perm["id"])
        await auth_manager.assign_role_to_user(registered_user["id"], role["id"])

        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        dep = await require_permission("items.delete")
        result = await dep(self._creds(token))
        assert result["user_id"] == registered_user["id"]

    async def test_lacks_permission(self, auth_manager, registered_user):
        await auth_manager.create_permission(
            code="items.delete", description="Delete items"
        )
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        dep = await require_permission("items.delete")
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds(token))
        assert exc_info.value.status_code == 403
        assert "items.delete" in exc_info.value.detail

    async def test_expired_token(self, auth_manager, registered_user):
        dep = await require_permission("items.delete")
        token = _make_expired_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds(token))
        assert exc_info.value.status_code == 401

    async def test_invalid_token(self, auth_manager):
        dep = await require_permission("items.delete")
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds("bad.token.here"))
        assert exc_info.value.status_code == 401


# ── require_role ────────────────────────────────────────────


class TestRequireRole:
    @pytest.fixture(autouse=True)
    def _init(self, auth_manager: AsyncAuthManager):
        init_auth(auth_manager)

    def _creds(self, token: str) -> HTTPAuthorizationCredentials:
        return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)

    async def test_has_role(self, auth_manager, registered_user):
        role = await auth_manager.create_role(name="admin", description="Admin role")
        await auth_manager.assign_role_to_user(registered_user["id"], role["id"])

        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        dep = await require_role("admin")
        result = await dep(self._creds(token))
        assert result["user_id"] == registered_user["id"]

    async def test_lacks_role(self, auth_manager, registered_user):
        await auth_manager.create_role(name="admin", description="Admin role")
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        dep = await require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds(token))
        assert exc_info.value.status_code == 403
        assert "admin" in exc_info.value.detail

    async def test_expired_token(self, auth_manager, registered_user):
        dep = await require_role("admin")
        token = _make_expired_token(
            auth_manager.config.jwt_secret_key, sub=str(registered_user["id"])
        )
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds(token))
        assert exc_info.value.status_code == 401

    async def test_invalid_token(self, auth_manager):
        dep = await require_role("admin")
        with pytest.raises(HTTPException) as exc_info:
            await dep(self._creds("bad.token.here"))
        assert exc_info.value.status_code == 401
