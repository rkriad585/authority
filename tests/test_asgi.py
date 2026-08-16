"""Tests for authority.asgi — framework-agnostic ASGI authentication middleware."""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator

import pytest
from starlette.testclient import TestClient

from authority.asgi import (
    AuthorityASGIMiddleware,
    get_current_user,
    get_user_state,
    is_authenticated,
    user_id_from_scope,
)
from authority.async_core import AsyncAuthManager
from authority.config import AuthConfig
from authority.storage.aiosqlite import AsyncSQLiteStorage

# ── Helpers ─────────────────────────────────────────────────


async def _state_app(scope, receive, send) -> None:
    """Echo the authority state from the scope as JSON."""
    if scope["type"] == "lifespan":
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    state = get_user_state(scope)
    body = json.dumps(state).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture()
async def mem_db() -> AsyncGenerator[AsyncSQLiteStorage, None]:
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
async def registered_user(auth_manager: AsyncAuthManager, access_token: str) -> dict:
    """Return the already-registered user from the access_token fixture."""
    user = await auth_manager.get_user(1)
    assert user is not None
    return user


@pytest.fixture()
async def access_token(auth_manager: AsyncAuthManager) -> str:
    """Return a real access token for the registered user."""
    await auth_manager.register(
        name="ASGI User",
        email="asgi@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )
    result = await auth_manager.login("asgi@example.com", "SecureP@ss1234!")
    return result["access_token"]


# ── Middleware behaviour ─────────────────────────────────────


class TestMiddleware:
    def test_authenticated_request(
        self, auth_manager: AsyncAuthManager, access_token: str
    ):
        app = AuthorityASGIMiddleware(_state_app, auth_manager)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 200
        state = resp.json()
        assert state["authenticated"] is True
        assert state["user_id"] == 1
        assert state["token"] == access_token
        assert state["payload"]["user_id"] == 1

    def test_lowercase_scheme(self, auth_manager: AsyncAuthManager, access_token: str):
        app = AuthorityASGIMiddleware(_state_app, auth_manager)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": f"bearer {access_token}"})
        assert resp.json()["authenticated"] is True

    def test_unauthenticated_request(self, auth_manager: AsyncAuthManager):
        app = AuthorityASGIMiddleware(_state_app, auth_manager)
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is False

    def test_invalid_token(self, auth_manager: AsyncAuthManager):
        app = AuthorityASGIMiddleware(_state_app, auth_manager)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": "Bearer garbage.token"})
        assert resp.json()["authenticated"] is False

    def test_auth_required_without_token(self, auth_manager: AsyncAuthManager):
        app = AuthorityASGIMiddleware(_state_app, auth_manager, auth_required=True)
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Authentication required."}

    def test_auth_required_invalid_token(self, auth_manager: AsyncAuthManager):
        app = AuthorityASGIMiddleware(_state_app, auth_manager, auth_required=True)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": "Bearer bad.token"})
        assert resp.status_code == 401

    def test_auth_required_valid_token(
        self, auth_manager: AsyncAuthManager, access_token: str
    ):
        app = AuthorityASGIMiddleware(_state_app, auth_manager, auth_required=True)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 200
        assert resp.json()["authenticated"] is True

    def test_lifespan_passthrough(self, auth_manager: AsyncAuthManager):
        received: dict = {}

        async def life_app(scope, receive, send) -> None:
            received["type"] = scope["type"]
            if scope["type"] == "lifespan":
                while True:
                    message = await receive()
                    if message["type"] == "lifespan.startup":
                        await send({"type": "lifespan.startup.complete"})
                    elif message["type"] == "lifespan.shutdown":
                        await send({"type": "lifespan.shutdown.complete"})
                        return

        app = AuthorityASGIMiddleware(life_app, auth_manager)
        with TestClient(app):
            pass
        assert received["type"] == "lifespan"


# ── Scope helpers ────────────────────────────────────────────


class TestScopeHelpers:
    def test_get_user_state_default(self):
        assert get_user_state({}) == {"authenticated": False}

    def test_authenticated_scope_with_token(self, auth_manager: AsyncAuthManager):
        state = {
            "authenticated": True,
            "user_id": 1,
            "payload": {"user_id": 1},
        }
        assert is_authenticated({"authority": state}) is True
        assert user_id_from_scope({"authority": state}) == 1

    def test_unauthenticated_scope(self):
        assert is_authenticated({}) is False
        assert user_id_from_scope({}) is None

    async def test_websocket_passthrough(self, auth_manager: AsyncAuthManager):
        received: dict = {}

        async def ws_app(scope, receive, send) -> None:
            received["type"] = scope["type"]

        app = AuthorityASGIMiddleware(ws_app, auth_manager)
        await app(
            {"type": "websocket", "headers": [], "path": "/ws"},
            lambda: None,
            lambda msg: None,
        )
        assert received["type"] == "websocket"

    async def test_get_current_user(
        self,
        auth_manager: AsyncAuthManager,
        access_token: str,
        registered_user: dict,
    ):
        app = AuthorityASGIMiddleware(_state_app, auth_manager)
        with TestClient(app) as client:
            resp = client.get("/", headers={"Authorization": f"Bearer {access_token}"})
        assert resp.status_code == 200
        state = resp.json()
        user = await get_current_user({"authority": state}, auth_manager)
        assert user is not None
        assert user["email"] == "asgi@example.com"

    async def test_get_current_user_unauthenticated(
        self, auth_manager: AsyncAuthManager
    ):
        user = await get_current_user({}, auth_manager)
        assert user is None
