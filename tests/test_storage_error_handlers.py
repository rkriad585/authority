"""Tests for storage error handlers — both sync and async."""

from __future__ import annotations

import datetime

import pytest

from authority.exceptions import DatabaseError
from authority.storage.aiosqlite import AsyncSQLiteStorage
from authority.storage.sqlite import SQLiteStorage

# ── Sync Storage Error Handlers ──────────────────────────────


class TestSQLiteStorageErrorHandlers:
    def _make_storage(self):
        return SQLiteStorage(":memory:")

    def test_create_user_integrity_error(self):
        storage = self._make_storage()
        storage.create_user("Test", "a@b.com", "hash1", True, None, None)
        with pytest.raises(DatabaseError):
            storage.create_user("Test", "a@b.com", "hash2", True, None, None)
        storage.close()

    def test_update_user_empty_dict(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = storage.update_user(user_id, {})
        assert result is True
        storage.close()

    def test_update_user_protected_fields_only(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = storage.update_user(user_id, {"id": 999, "created_at": "x"})
        assert result is True
        storage.close()

    def test_get_password_history_limit_zero(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = storage.get_password_history(user_id, limit=0)
        assert result == []
        storage.close()

    def test_rotate_refresh_token_nonexistent(self):
        storage = self._make_storage()
        result = storage.rotate_refresh_token(
            99999,
            "new_hash",
            datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
        )
        assert result is False
        storage.close()

    def test_create_role_integrity_error_wrapped(self):
        storage = self._make_storage()
        storage.create_role("admin", "Admin role")
        with pytest.raises(DatabaseError):
            storage.create_role("admin", "Admin role duplicate")
        storage.close()

    def test_create_permission_integrity_error_wrapped(self):
        storage = self._make_storage()
        storage.create_permission("users.read", "Read users")
        with pytest.raises(DatabaseError):
            storage.create_permission("users.read", "Read users dup")
        storage.close()

    def test_get_webauthn_credentials_bad_transports_json(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        storage._execute(
            """INSERT INTO webauthn_credentials
               (user_id, user_handle, credential_id, public_key, sign_count, rp_id, transports, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                b"handle",
                b"cred1",
                b"pubkey",
                0,
                "localhost",
                "{invalid json",
                "test",
            ),
        )
        storage._commit()
        creds = storage.get_webauthn_credentials_for_user(user_id)
        assert len(creds) == 1
        assert creds[0]["transports"] == []
        storage.close()

    def test_list_api_keys_bad_scopes_json(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        storage.store_api_key(
            user_id,
            "ak_test_",
            "hash1",
            "key1",
            "{invalid",
            datetime.datetime(2030, 1, 1),
        )
        keys = storage.list_api_keys_for_user(user_id)
        assert len(keys) == 1
        assert keys[0]["scopes"] == []
        storage.close()

    def test_get_user_custom_profile_corrupt_json(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        storage._execute(
            "UPDATE users SET custom_profile = ? WHERE id = ?",
            ("{invalid json", user_id),
        )
        storage._commit()
        result = storage.get_user_custom_profile(user_id)
        assert result is None
        storage.close()

    def test_get_webauthn_credential_by_id_bad_transports(self):
        storage = self._make_storage()
        user_id = storage.create_user("Test", "a@b.com", "hash", True, None, None)
        storage._execute(
            """INSERT INTO webauthn_credentials
               (user_id, user_handle, credential_id, public_key, sign_count, rp_id, transports, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                b"handle",
                b"cred2",
                b"pubkey",
                0,
                "localhost",
                "{bad json",
                "test",
            ),
        )
        storage._commit()
        cred = storage.get_webauthn_credential_by_id(b"cred2")
        assert cred is not None
        assert cred["transports"] == []
        storage.close()

    def test_execute_no_connection_raises(self):
        storage = self._make_storage()
        storage.close()
        with pytest.raises(DatabaseError):
            storage._execute("SELECT 1")


# ── Async Storage Error Handlers ─────────────────────────────


class TestAsyncSQLiteStorageErrorHandlers:
    @pytest.fixture()
    async def storage(self):
        s = AsyncSQLiteStorage(":memory:")
        await s.connect()
        yield s
        await s.close()

    async def test_double_connect_is_noop(self):
        s = AsyncSQLiteStorage(":memory:")
        await s.connect()
        await s.connect()
        await s.close()

    async def test_create_user_integrity_error(self, storage: AsyncSQLiteStorage):
        await storage.create_user("Test", "a@b.com", "hash1", True, None, None)
        with pytest.raises(DatabaseError):
            await storage.create_user("Test", "a@b.com", "hash2", True, None, None)

    async def test_update_user_empty_dict(self, storage: AsyncSQLiteStorage):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = await storage.update_user(user_id, {})
        assert result is True

    async def test_update_user_protected_fields_only(self, storage: AsyncSQLiteStorage):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = await storage.update_user(user_id, {"id": 999, "created_at": "x"})
        assert result is True

    async def test_get_password_history_limit_zero(self, storage: AsyncSQLiteStorage):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        result = await storage.get_password_history(user_id, limit=0)
        assert result == []

    async def test_rotate_refresh_token_nonexistent(self, storage: AsyncSQLiteStorage):
        result = await storage.rotate_refresh_token(
            99999,
            "new_hash",
            datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc),
        )
        assert result is False

    async def test_create_role_integrity_error_wrapped(
        self, storage: AsyncSQLiteStorage
    ):
        await storage.create_role("admin", "Admin role")
        with pytest.raises(DatabaseError):
            await storage.create_role("admin", "Admin role duplicate")

    async def test_create_permission_integrity_error_wrapped(
        self, storage: AsyncSQLiteStorage
    ):
        await storage.create_permission("users.read", "Read users")
        with pytest.raises(DatabaseError):
            await storage.create_permission("users.read", "Read users dup")

    async def test_get_webauthn_credentials_bad_transports_json(
        self, storage: AsyncSQLiteStorage
    ):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        await storage._execute(
            """INSERT INTO webauthn_credentials
               (user_id, user_handle, credential_id, public_key, sign_count, rp_id, transports, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                b"handle",
                b"cred1",
                b"pubkey",
                0,
                "localhost",
                "{invalid json",
                "test",
            ),
        )
        await storage._commit()
        creds = await storage.get_webauthn_credentials_for_user(user_id)
        assert len(creds) == 1
        assert creds[0]["transports"] == []

    async def test_list_api_keys_bad_scopes_json(self, storage: AsyncSQLiteStorage):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        await storage.store_api_key(
            user_id,
            "ak_test_",
            "hash1",
            "key1",
            "{invalid",
            datetime.datetime(2030, 1, 1),
        )
        keys = await storage.list_api_keys_for_user(user_id)
        assert len(keys) == 1
        assert keys[0]["scopes"] == []

    async def test_get_user_custom_profile_corrupt_json(
        self, storage: AsyncSQLiteStorage
    ):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        await storage._execute(
            "UPDATE users SET custom_profile = ? WHERE id = ?",
            ("{invalid json", user_id),
        )
        await storage._commit()
        result = await storage.get_user_custom_profile(user_id)
        assert result is None

    async def test_get_webauthn_credential_by_id_bad_transports(
        self, storage: AsyncSQLiteStorage
    ):
        user_id = await storage.create_user("Test", "a@b.com", "hash", True, None, None)
        await storage._execute(
            """INSERT INTO webauthn_credentials
               (user_id, user_handle, credential_id, public_key, sign_count, rp_id, transports, description)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                b"handle",
                b"cred2",
                b"pubkey",
                0,
                "localhost",
                "{bad json",
                "test",
            ),
        )
        await storage._commit()
        cred = await storage.get_webauthn_credential_by_id(b"cred2")
        assert cred is not None
        assert cred["transports"] == []

    async def test_auto_connect_on_first_query(self):
        s = AsyncSQLiteStorage(":memory:")
        user_id = await s.create_user("Test", "a@b.com", "hash", True, None, None)
        assert user_id > 0
        await s.close()
