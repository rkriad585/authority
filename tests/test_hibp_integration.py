"""Tests for HIBP integration through AuthManager.register."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from authority.async_core import AsyncAuthManager
from authority.config import AuthConfig
from authority.core import AuthManager
from authority.exceptions import PasswordPwnedError
from authority.storage.aiosqlite import AsyncSQLiteStorage
from authority.storage.sqlite import SQLiteStorage


class TestSyncHIBPIntegration:
    def test_register_rejects_pwned_password(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="reject",
        )
        manager = AuthManager(config, storage)

        with (
            patch("authority.core.check_password_pwned", return_value=100),
            pytest.raises(PasswordPwnedError),
        ):
            manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
        storage.close()

    def test_register_warns_pwned_password(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="warn",
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned", return_value=50):
            # Should succeed (not raise)
            user = manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "test@example.com"
        storage.close()

    def test_register_ignores_pwned_password(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="ignore",
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned", return_value=200):
            user = manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "test@example.com"
        storage.close()

    def test_hibp_not_checked_when_disabled(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=False,
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned") as mock_hibp:
            manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
            mock_hibp.assert_not_called()
        storage.close()

    def test_password_history_depth_zero_skips_check(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_history_depth=0,
        )
        manager = AuthManager(config, storage)

        user = manager.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        # Change password
        manager.change_password(user["id"], "SecureP@ss1234!", "NewP@ss12345!")
        # Change back to original - should succeed because depth=0
        manager.change_password(user["id"], "NewP@ss12345!", "SecureP@ss1234!")
        storage.close()


class TestAsyncHIBPIntegration:
    @pytest.mark.asyncio
    async def test_register_rejects_pwned_password(self):
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="reject",
        )
        manager = AsyncAuthManager(config, storage)

        with (
            patch("authority.async_core.check_password_pwned", return_value=100),
            pytest.raises(PasswordPwnedError),
        ):
            await manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
        await storage.close()

    @pytest.mark.asyncio
    async def test_register_warns_pwned_password(self):
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="warn",
        )
        manager = AsyncAuthManager(config, storage)

        with patch("authority.async_core.check_password_pwned", return_value=50):
            user = await manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "test@example.com"
        await storage.close()

    @pytest.mark.asyncio
    async def test_register_ignores_pwned_password(self):
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="ignore",
        )
        manager = AsyncAuthManager(config, storage)

        with patch("authority.async_core.check_password_pwned", return_value=200):
            user = await manager.register(
                name="Test",
                email="test@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "test@example.com"
        await storage.close()

    @pytest.mark.asyncio
    async def test_password_history_depth_zero_skips_check(self):
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_history_depth=0,
        )
        manager = AsyncAuthManager(config, storage)

        user = await manager.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        await manager.change_password(user["id"], "SecureP@ss1234!", "NewP@ss12345!")
        await manager.change_password(user["id"], "NewP@ss12345!", "SecureP@ss1234!")
        await storage.close()
