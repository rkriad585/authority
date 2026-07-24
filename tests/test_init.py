"""Tests for authority.__init__ (public API surface)."""

from __future__ import annotations

import authority


class TestPublicAPI:
    def test_version_exists(self):
        assert hasattr(authority, "__version__")
        assert isinstance(authority.__version__, str)

    def test_core_exports(self):
        assert hasattr(authority, "AuthConfig")
        assert hasattr(authority, "Event")
        assert hasattr(authority, "EventBus")

    def test_exception_exports(self):
        assert hasattr(authority, "AuthError")
        assert hasattr(authority, "UserNotFoundError")
        assert hasattr(authority, "InvalidCredentialsError")

    def test_storage_exports(self):
        assert hasattr(authority, "StorageInterface")
        assert hasattr(authority, "AsyncStorageInterface")
        assert hasattr(authority, "SQLiteStorage")

    def test_util_exports(self):
        assert hasattr(authority, "validate_email_format")
        assert hasattr(authority, "generate_secure_token")
        assert hasattr(authority, "hash_token")
        assert hasattr(authority, "encrypt_data")
        assert hasattr(authority, "decrypt_data")
        assert hasattr(authority, "check_password_pwned")
