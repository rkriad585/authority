"""Shared fixtures for authority tests."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator

import pytest

from authority.config import AuthConfig
from authority.core import AuthManager
from authority.events import EventBus
from authority.storage.sqlite import SQLiteStorage


@pytest.fixture()
def tmp_db() -> Generator[SQLiteStorage, None, None]:
    """Create a temporary SQLite database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    storage = SQLiteStorage(path)
    yield storage
    storage.close()
    os.unlink(path)


@pytest.fixture()
def mem_db() -> Generator[SQLiteStorage, None, None]:
    """Create an in-memory SQLite database for testing."""
    storage = SQLiteStorage(":memory:")
    yield storage
    storage.close()


@pytest.fixture()
def fernet_key() -> str:
    """Return a valid Fernet key for testing."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


@pytest.fixture()
def test_config(fernet_key: str) -> AuthConfig:
    """Return a valid AuthConfig for testing."""
    return AuthConfig(
        jwt_secret_key="test-secret-key-for-testing-only-32chars!",
        fernet_key=fernet_key,
        db_path=":memory:",
    )


@pytest.fixture()
def auth_manager(test_config: AuthConfig, mem_db: SQLiteStorage) -> AuthManager:
    """Return an AuthManager with in-memory storage for testing."""
    test_config.refresh_token_reuse_grace_seconds = 0
    return AuthManager(test_config, mem_db)


@pytest.fixture()
def event_bus() -> EventBus:
    """Return a fresh EventBus."""
    return EventBus()


@pytest.fixture()
def registered_user(auth_manager: AuthManager) -> dict:
    """Register a user and return the user dict."""
    return auth_manager.register(
        name="Test User",
        email="test@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
def verified_user(auth_manager: AuthManager) -> dict:
    """Register a verified user and return the user dict."""
    return auth_manager.register(
        name="Verified User",
        email="verified@example.com",
        password="AuthP@ss12345!",
        auto_verify=True,
    )
