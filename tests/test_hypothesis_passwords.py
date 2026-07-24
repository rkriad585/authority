"""Property-based tests for password validation using Hypothesis."""

from __future__ import annotations

from unittest.mock import patch

from hypothesis import given, settings
from hypothesis import strategies as st

from authority.async_core import AsyncAuthManager
from authority.config import AuthConfig
from authority.core import AuthManager
from authority.exceptions import ValidationError
from authority.storage.aiosqlite import AsyncSQLiteStorage
from authority.storage.sqlite import SQLiteStorage


class TestPasswordValidationSync:
    """Hypothesis-driven tests for password validation rules."""

    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=100, deadline=None)
    def test_password_min_length_enforced(self, password: str):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_min_length=12,
            hibp_check_enabled=False,
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned", return_value=0):
            if len(password) < 12:
                try:
                    manager.register(
                        name="Test", email="test@example.com", password=password
                    )
                    raise AssertionError("Should have raised ValidationError")
                except ValidationError:
                    pass  # Expected
            else:
                # Passwords >= 12 chars may pass length check
                # (other rules may still reject)
                try:
                    manager.register(
                        name="Test", email="test@example.com", password=password
                    )
                except ValidationError:
                    pass  # Other validation rules may reject
        storage.close()

    @given(st.text(min_size=12, max_size=100))
    @settings(max_examples=100, deadline=None)
    def test_password_complexity_regex_enforced(self, password: str):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_min_length=12,
            password_require_complexity=True,
            hibp_check_enabled=False,
        )
        manager = AuthManager(config, storage)

        import re

        pattern = re.compile(config.password_complexity_regex)

        with patch("authority.core.check_password_pwned", return_value=0):
            try:
                manager.register(
                    name="Test", email="test@example.com", password=password
                )
                # If registration succeeds, password must match complexity regex
                assert pattern.match(password), (
                    f"Password '{password}' passed but shouldn't match regex"
                )
            except ValidationError:
                pass  # Expected for non-matching passwords
        storage.close()

    def test_password_rejects_email_username(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_prevent_email_username_use=True,
            hibp_check_enabled=False,
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned", return_value=0):
            try:
                manager.register(
                    name="Test",
                    email="test@example.com",
                    password="SecureP@ss1234test!",
                )
                raise AssertionError("Should have raised ValidationError")
            except ValidationError:
                pass
        storage.close()

    def test_password_rejects_name_in_password(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_prevent_email_username_use=True,
            hibp_check_enabled=False,
        )
        manager = AuthManager(config, storage)

        with patch("authority.core.check_password_pwned", return_value=0):
            try:
                manager.register(
                    name="Alice",
                    email="test@example.com",
                    password="SecureAlice123!",
                )
                raise AssertionError("Should have raised ValidationError")
            except ValidationError:
                pass
        storage.close()


class TestPasswordValidationAsync:
    """Async hypothesis-driven tests for password validation rules."""

    @given(st.text(min_size=1, max_size=200))
    @settings(max_examples=100, deadline=None)
    async def test_password_min_length_enforced(self, password: str):
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
            password_min_length=12,
            hibp_check_enabled=False,
        )
        manager = AsyncAuthManager(config, storage)

        with patch("authority.async_core.check_password_pwned", return_value=0):
            if len(password) < 12:
                try:
                    await manager.register(
                        name="Test", email="test@example.com", password=password
                    )
                    raise AssertionError("Should have raised ValidationError")
                except ValidationError:
                    pass
            else:
                try:
                    await manager.register(
                        name="Test", email="test@example.com", password=password
                    )
                except ValidationError:
                    pass
        await storage.close()
