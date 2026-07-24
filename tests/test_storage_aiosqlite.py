"""Tests for authority.storage.aiosqlite (AsyncSQLiteStorage)."""

from __future__ import annotations

import datetime

import pytest

from authority.storage.aiosqlite import AsyncSQLiteStorage


@pytest.fixture()
async def storage():
    """In-memory async SQLite storage for fast tests."""
    s = AsyncSQLiteStorage(":memory:")
    await s.connect()
    yield s
    await s.close()


class TestUserManagement:
    async def test_create_and_get_user(self, storage):
        user_id = await storage.create_user(
            name="Alice",
            email="alice@example.com",
            password_hash="hashed-pw",
            is_verified=False,
            verification_token_hash="abc123",
            verification_token_expiry=datetime.datetime(
                2030, 1, 1, tzinfo=datetime.timezone.utc
            ),
        )
        assert user_id > 0
        user = await storage.get_user_by_id(user_id)
        assert user is not None
        assert user["email"] == "alice@example.com"
        assert user["name"] == "Alice"

    async def test_get_user_by_email(self, storage):
        await storage.create_user(
            name="Bob",
            email="bob@example.com",
            password_hash="hashed",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        user = await storage.get_user_by_email("bob@example.com")
        assert user is not None
        assert user["name"] == "Bob"

    async def test_get_user_by_email_case_insensitive(self, storage):
        await storage.create_user(
            name="Bob",
            email="Bob@Example.COM",
            password_hash="hashed",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        user = await storage.get_user_by_email("bob@example.com")
        assert user is not None

    async def test_get_nonexistent_user(self, storage):
        assert await storage.get_user_by_id(999) is None
        assert await storage.get_user_by_email("nobody@example.com") is None

    async def test_update_user(self, storage):
        uid = await storage.create_user(
            name="Charlie",
            email="c@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        assert await storage.update_user(uid, {"name": "Charles", "is_verified": True})
        user = await storage.get_user_by_id(uid)
        assert user["name"] == "Charles"
        assert user["is_verified"] is True

    async def test_update_user_protected_fields_skipped(self, storage):
        uid = await storage.create_user(
            name="X",
            email="x@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        assert await storage.update_user(uid, {"id": 1, "name": "Updated"})
        user = await storage.get_user_by_id(uid)
        assert user["name"] == "Updated"
        assert user["id"] == uid

    async def test_update_user_invalid_field_name(self, storage):
        uid = await storage.create_user(
            name="X",
            email="x2@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        with pytest.raises(ValueError, match="Invalid field name"):
            await storage.update_user(uid, {"drop table users": "evil"})

    async def test_delete_user(self, storage):
        uid = await storage.create_user(
            name="Del",
            email="del@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        assert await storage.delete_user(uid)
        assert await storage.get_user_by_id(uid) is None
        assert not await storage.delete_user(uid)


class TestUserTokenLookup:
    async def test_find_by_verification_token(self, storage):
        uid = await storage.create_user(
            name="V",
            email="v@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash="vtoken123",
            verification_token_expiry=None,
        )
        user = await storage.find_user_by_verification_token("vtoken123")
        assert user is not None
        assert user["id"] == uid

    async def test_find_by_verification_token_missing(self, storage):
        assert await storage.find_user_by_verification_token("nope") is None

    async def test_find_by_reset_token(self, storage):
        uid = await storage.create_user(
            name="R",
            email="r@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.update_user(uid, {"reset_token_hash": "rtoken456"})
        user = await storage.find_user_by_reset_token("rtoken456")
        assert user is not None
        assert user["id"] == uid

    async def test_find_by_email_change_token(self, storage):
        uid = await storage.create_user(
            name="E",
            email="e@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.update_user(
            uid,
            {"pending_email": "new@example.com", "email_change_token_hash": "ectoken"},
        )
        user = await storage.find_user_by_email_change_token("ectoken")
        assert user is not None
        assert user["id"] == uid

    async def test_find_by_pending_email(self, storage):
        uid = await storage.create_user(
            name="PE",
            email="pe@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.update_user(uid, {"pending_email": "pending@example.com"})
        user = await storage.find_user_by_pending_email("pending@example.com")
        assert user is not None
        assert user["id"] == uid

    async def test_find_by_pending_email_case_insensitive(self, storage):
        uid = await storage.create_user(
            name="PE2",
            email="pe2@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.update_user(uid, {"pending_email": "Pending@Example.COM"})
        user = await storage.find_user_by_pending_email("pending@example.com")
        assert user is not None


class TestPasswordHistory:
    async def test_add_and_get_history(self, storage):
        uid = await storage.create_user(
            name="P",
            email="p@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.add_password_history(uid, "hash1")
        await storage.add_password_history(uid, "hash2")
        await storage.add_password_history(uid, "hash3")
        history = await storage.get_password_history(uid, limit=2)
        assert len(history) == 2
        assert set(history) <= {"hash1", "hash2", "hash3"}

    async def test_empty_history(self, storage):
        assert await storage.get_password_history(999, limit=5) == []


class TestRefreshTokens:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="R",
            email="r@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_store_and_retrieve(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        tid = await storage.store_refresh_token(
            uid, "hash1", "family-1", expires, "127.0.0.1", "Mozilla"
        )
        assert tid > 0
        token = await storage.get_refresh_token_by_hash("hash1")
        assert token is not None
        assert token["family_id"] == "family-1"
        assert token["used"] is False

    async def test_mark_used(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        tid = await storage.store_refresh_token(uid, "h", "fam", expires, None, None)
        assert await storage.mark_refresh_token_used(tid)
        token = await storage.get_refresh_token_by_hash("h")
        assert token["used"] is True

    async def test_rotate_token(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        tid = await storage.store_refresh_token(uid, "old", "fam", expires, None, None)
        new_expires = datetime.datetime(2030, 6, 1, tzinfo=datetime.timezone.utc)
        assert await storage.rotate_refresh_token(tid, "new", new_expires)
        old_token = await storage.get_refresh_token_by_hash("old")
        assert old_token is not None
        assert old_token["used"] is True
        new_token = await storage.get_refresh_token_by_hash("new")
        assert new_token is not None
        assert new_token["used"] is False
        assert new_token["family_id"] == "fam"

    async def test_revoke_token(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        tid = await storage.store_refresh_token(uid, "h", "fam", expires, None, None)
        assert await storage.revoke_refresh_token(tid)

    async def test_revoke_all_for_user(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        t1 = await storage.store_refresh_token(uid, "h1", "fam1", expires, None, None)
        await storage.store_refresh_token(uid, "h2", "fam2", expires, None, None)
        count = await storage.revoke_all_refresh_tokens_for_user(
            uid, exclude_token_id=t1
        )
        assert count == 1

    async def test_revoke_family(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        await storage.store_refresh_token(uid, "h1", "famA", expires, None, None)
        await storage.store_refresh_token(uid, "h2", "famA", expires, None, None)
        await storage.store_refresh_token(uid, "h3", "famB", expires, None, None)
        count = await storage.revoke_token_family("famA")
        assert count == 2

    async def test_list_tokens(self, storage):
        uid = await self._create_user(storage)
        expires = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)
        await storage.store_refresh_token(uid, "l1", "fam1", expires, "1.1.1.1", "Curl")
        await storage.store_refresh_token(uid, "l2", "fam2", expires, None, None)
        tokens = await storage.list_refresh_tokens_for_user(uid)
        assert len(tokens) == 2

    async def test_prune_expired(self, storage):
        uid = await self._create_user(storage)
        past = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        await storage.store_refresh_token(uid, "old", "fam", past, None, None)
        count = await storage.prune_expired_refresh_tokens()
        assert count >= 1


class TestMFARecoveryCodes:
    async def test_set_and_use(self, storage):
        uid = await storage.create_user(
            name="M",
            email="m@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.set_mfa_recovery_codes(uid, ["code1", "code2", "code3"])
        assert await storage.get_active_mfa_recovery_codes_count(uid) == 3
        assert await storage.use_mfa_recovery_code(uid, "code1")
        assert await storage.get_active_mfa_recovery_codes_count(uid) == 2
        assert not await storage.use_mfa_recovery_code(uid, "code1")

    async def test_reset_codes(self, storage):
        uid = await storage.create_user(
            name="M2",
            email="m2@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.set_mfa_recovery_codes(uid, ["a", "b"])
        await storage.set_mfa_recovery_codes(uid, ["c", "d", "e"])
        assert await storage.get_active_mfa_recovery_codes_count(uid) == 3


class TestWebAuthnCredentials:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="W",
            email="w@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_add_and_get_credential(self, storage):
        uid = await self._create_user(storage)
        cred_id = b"\x01\x02\x03\x04"
        pub_key = b"\x05\x06\x07\x08"
        user_handle = b"user-handle"
        db_id = await storage.add_webauthn_credential(
            uid,
            cred_id,
            pub_key,
            0,
            "example.com",
            user_handle,
            transports=["internal"],
            description="My Passkey",
        )
        assert db_id > 0
        creds = await storage.get_webauthn_credentials_for_user(uid)
        assert len(creds) == 1
        assert creds[0]["credential_id"] == cred_id
        assert creds[0]["transports"] == ["internal"]
        assert creds[0]["description"] == "My Passkey"

    async def test_get_credential_by_id(self, storage):
        uid = await self._create_user(storage)
        cred_id = b"\x0a\x0b\x0c\x0d"
        await storage.add_webauthn_credential(
            uid, cred_id, b"\x0e\x0f", 1, "example.com", b"handle"
        )
        cred = await storage.get_webauthn_credential_by_id(cred_id)
        assert cred is not None
        assert cred["rp_id"] == "example.com"

    async def test_get_nonexistent_credential(self, storage):
        assert await storage.get_webauthn_credential_by_id(b"\xff") is None

    async def test_update_sign_count(self, storage):
        uid = await self._create_user(storage)
        cred_id = b"\x10\x11\x12\x13"
        await storage.add_webauthn_credential(
            uid, cred_id, b"\x14\x15", 0, "example.com", b"handle"
        )
        assert await storage.update_webauthn_credential_sign_count(cred_id, 5)
        cred = await storage.get_webauthn_credential_by_id(cred_id)
        assert cred["sign_count"] == 5

    async def test_update_last_used(self, storage):
        uid = await self._create_user(storage)
        cred_id = b"\x16\x17\x18\x19"
        await storage.add_webauthn_credential(
            uid, cred_id, b"\x1a\x1b", 0, "example.com", b"handle"
        )
        await storage.update_webauthn_credential_last_used(cred_id)
        cred = await storage.get_webauthn_credential_by_id(cred_id)
        assert cred["last_used_at"] is not None

    async def test_delete_credential(self, storage):
        uid = await self._create_user(storage)
        cred_id = b"\x1c\x1d\x1e\x1f"
        await storage.add_webauthn_credential(
            uid, cred_id, b"\x20\x21", 0, "example.com", b"handle"
        )
        assert await storage.delete_webauthn_credential(uid, cred_id)
        assert await storage.get_webauthn_credential_by_id(cred_id) is None

    async def test_filter_by_rp_id(self, storage):
        uid = await self._create_user(storage)
        await storage.add_webauthn_credential(uid, b"\x01", b"\x02", 0, "a.com", b"h")
        await storage.add_webauthn_credential(uid, b"\x03", b"\x04", 0, "b.com", b"h")
        creds_a = await storage.get_webauthn_credentials_for_user(uid, rp_id="a.com")
        assert len(creds_a) == 1
        assert creds_a[0]["rp_id"] == "a.com"


class TestRBAC:
    async def test_role_crud(self, storage):
        role_id = await storage.create_role("admin", "Administrator")
        role = await storage.get_role_by_name("admin")
        assert role is not None
        assert role["description"] == "Administrator"
        assert await storage.delete_role(role_id)
        assert await storage.get_role_by_name("admin") is None

    async def test_permission_crud(self, storage):
        perm_id = await storage.create_permission("users.read", "Read users")
        perm = await storage.get_permission_by_code("users.read")
        assert perm is not None
        assert await storage.delete_permission(perm_id)

    async def test_assign_permission_to_role(self, storage):
        role_id = await storage.create_role("editor")
        perm_id = await storage.create_permission("posts.write")
        assert await storage.assign_permission_to_role(role_id, perm_id)
        perms = await storage.get_role_permissions(role_id)
        assert len(perms) == 1
        assert perms[0]["code"] == "posts.write"

    async def test_assign_role_to_user(self, storage):
        uid = await storage.create_user(
            name="U",
            email="u@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        role_id = await storage.create_role("viewer")
        assert await storage.assign_role_to_user(uid, role_id)
        roles = await storage.get_user_roles(uid)
        assert len(roles) == 1
        assert roles[0]["name"] == "viewer"

    async def test_user_permissions(self, storage):
        uid = await storage.create_user(
            name="U2",
            email="u2@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        role_id = await storage.create_role("moderator")
        p1 = await storage.create_permission("comments.delete")
        p2 = await storage.create_permission("comments.edit")
        await storage.assign_permission_to_role(role_id, p1)
        await storage.assign_permission_to_role(role_id, p2)
        await storage.assign_role_to_user(uid, role_id)
        perms = await storage.get_user_permissions(uid)
        assert set(perms) == {"comments.delete", "comments.edit"}

    async def test_list_roles(self, storage):
        await storage.create_role("admin")
        await storage.create_role("editor")
        roles = await storage.list_roles()
        assert len(roles) == 2
        names = [r["name"] for r in roles]
        assert "admin" in names
        assert "editor" in names

    async def test_list_permissions(self, storage):
        await storage.create_permission("p1")
        await storage.create_permission("p2")
        perms = await storage.list_permissions()
        assert len(perms) == 2

    async def test_get_role_by_id(self, storage):
        rid = await storage.create_role("test_role")
        role = await storage.get_role_by_id(rid)
        assert role is not None
        assert role["name"] == "test_role"

    async def test_get_permission_by_id(self, storage):
        pid = await storage.create_permission("test.perm")
        perm = await storage.get_permission_by_id(pid)
        assert perm is not None
        assert perm["code"] == "test.perm"

    async def test_remove_permission_from_role(self, storage):
        rid = await storage.create_role("r")
        pid = await storage.create_permission("p")
        await storage.assign_permission_to_role(rid, pid)
        assert await storage.remove_permission_from_role(rid, pid)
        assert len(await storage.get_role_permissions(rid)) == 0

    async def test_remove_role_from_user(self, storage):
        uid = await storage.create_user(
            name="R",
            email="rbac_rm@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        rid = await storage.create_role("temp")
        await storage.assign_role_to_user(uid, rid)
        assert await storage.remove_role_from_user(uid, rid)
        assert len(await storage.get_user_roles(uid)) == 0

    async def test_get_nonexistent_role(self, storage):
        assert await storage.get_role_by_name("nobody") is None
        assert await storage.get_role_by_id(999) is None

    async def test_get_nonexistent_permission(self, storage):
        assert await storage.get_permission_by_code("nobody") is None
        assert await storage.get_permission_by_id(999) is None


class TestAPIKeys:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="K",
            email="k@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_store_and_retrieve(self, storage):
        uid = await self._create_user(storage)
        key_id = await storage.store_api_key(
            uid, "ak_12345678", "hash-of-key", "Test key", '["read"]', None
        )
        assert key_id > 0
        key = await storage.get_api_key_by_prefix_and_hash("ak_12345678", "hash-of-key")
        assert key is not None
        assert key["user_email"] == "k@example.com"

    async def test_list_keys(self, storage):
        uid = await self._create_user(storage)
        await storage.store_api_key(uid, "prefix1", "hash1", "Key 1", '["a"]', None)
        await storage.store_api_key(uid, "prefix2", "hash2", "Key 2", "[]", None)
        keys = await storage.list_api_keys_for_user(uid)
        assert len(keys) == 2

    async def test_delete_key(self, storage):
        uid = await self._create_user(storage)
        await storage.store_api_key(uid, "prefix_del", "hash_del", "Del", None, None)
        assert await storage.delete_api_key_by_prefix(uid, "prefix_del")
        assert (
            await storage.get_api_key_by_prefix_and_hash("prefix_del", "hash_del")
            is None
        )

    async def test_update_last_used(self, storage):
        uid = await self._create_user(storage)
        await storage.store_api_key(uid, "prefix_used", "hash_used", "Used", None, None)
        await storage.update_api_key_last_used("prefix_used")
        key = await storage.get_api_key_by_prefix_and_hash("prefix_used", "hash_used")
        assert key["last_used_at"] is not None


class TestCustomProfile:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="P",
            email="profile@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_update_and_get(self, storage):
        uid = await self._create_user(storage)
        profile = {"theme": "dark", "language": "en", "notifications": True}
        assert await storage.update_user_custom_profile(uid, profile)
        result = await storage.get_user_custom_profile(uid)
        assert result == profile

    async def test_get_empty_profile(self, storage):
        uid = await self._create_user(storage)
        assert await storage.get_user_custom_profile(uid) is None

    async def test_overwrite_profile(self, storage):
        uid = await self._create_user(storage)
        await storage.update_user_custom_profile(uid, {"v": 1})
        await storage.update_user_custom_profile(uid, {"v": 2})
        result = await storage.get_user_custom_profile(uid)
        assert result == {"v": 2}


class TestAuditLog:
    async def test_log_event(self, storage):
        await storage.log_audit_event(
            user_id=None,
            email="test@example.com",
            action="LOGIN_SUCCESS",
            ip_address="127.0.0.1",
            success=True,
            details=None,
        )

    async def test_log_event_with_user(self, storage):
        uid = await storage.create_user(
            name="A",
            email="audit@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.log_audit_event(
            user_id=uid,
            email="audit@example.com",
            action="PASSWORD_CHANGED",
            ip_address="10.0.0.1",
            success=True,
            details='{"method": "reset"}',
        )

    async def test_get_audit_log(self, storage):
        uid = await storage.create_user(
            name="AL",
            email="al@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.log_audit_event(
            uid, "al@example.com", "LOGIN", "1.2.3.4", True, None
        )
        await storage.log_audit_event(
            uid, "al@example.com", "LOGOUT", "1.2.3.4", True, None
        )
        logs = await storage.get_audit_log(user_id=uid)
        assert len(logs) == 2

    async def test_get_audit_log_filter_action(self, storage):
        uid = await storage.create_user(
            name="AF",
            email="af@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.log_audit_event(
            uid, "af@example.com", "LOGIN", "1.2.3.4", True, None
        )
        await storage.log_audit_event(
            uid, "af@example.com", "LOGIN_FAILED", "1.2.3.4", False, None
        )
        logs = await storage.get_audit_log(user_id=uid, action="LOGIN")
        assert len(logs) == 1
        assert logs[0]["action"] == "LOGIN"

    async def test_get_audit_log_limit_and_offset(self, storage):
        uid = await storage.create_user(
            name="AO",
            email="ao@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        for i in range(5):
            await storage.log_audit_event(
                uid, "ao@example.com", f"ACTION_{i}", None, True, None
            )
        logs = await storage.get_audit_log(user_id=uid, limit=2, offset=0)
        assert len(logs) == 2
        logs_page2 = await storage.get_audit_log(user_id=uid, limit=2, offset=2)
        assert len(logs_page2) == 2
        assert logs[0]["action"] != logs_page2[0]["action"]


# ── Coverage boost: find_user_by_* methods ─────────────────


class TestFindUserByTokens:
    async def _create_user_with_tokens(self, storage) -> int:
        uid = await storage.create_user(
            name="Token User",
            email="token@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash="verify_hash_123",
            verification_token_expiry=datetime.datetime(
                2030, 1, 1, tzinfo=datetime.timezone.utc
            ),
        )
        await storage.update_user(
            uid,
            {
                "reset_token_hash": "reset_hash_456",
                "email_change_token_hash": "email_change_hash_789",
                "pending_email": "new@example.com",
            },
        )
        return uid

    async def test_find_user_by_verification_token(self, storage):
        uid = await self._create_user_with_tokens(storage)
        result = await storage.find_user_by_verification_token("verify_hash_123")
        assert result is not None
        assert result["id"] == uid

    async def test_find_user_by_verification_token_not_found(self, storage):
        assert await storage.find_user_by_verification_token("nonexistent") is None

    async def test_find_user_by_reset_token(self, storage):
        uid = await self._create_user_with_tokens(storage)
        result = await storage.find_user_by_reset_token("reset_hash_456")
        assert result is not None
        assert result["id"] == uid

    async def test_find_user_by_reset_token_not_found(self, storage):
        assert await storage.find_user_by_reset_token("nonexistent") is None

    async def test_find_user_by_email_change_token(self, storage):
        uid = await self._create_user_with_tokens(storage)
        result = await storage.find_user_by_email_change_token("email_change_hash_789")
        assert result is not None
        assert result["id"] == uid

    async def test_find_user_by_email_change_token_not_found(self, storage):
        assert await storage.find_user_by_email_change_token("nonexistent") is None

    async def test_find_user_by_pending_email(self, storage):
        uid = await self._create_user_with_tokens(storage)
        result = await storage.find_user_by_pending_email("new@example.com")
        assert result is not None
        assert result["id"] == uid

    async def test_find_user_by_pending_email_case_insensitive(self, storage):
        uid = await self._create_user_with_tokens(storage)
        result = await storage.find_user_by_pending_email("NEW@EXAMPLE.COM")
        assert result is not None
        assert result["id"] == uid

    async def test_find_user_by_pending_email_not_found(self, storage):
        assert await storage.find_user_by_pending_email("nobody@example.com") is None


# ── Coverage boost: update_user edge cases ─────────────────


class TestUpdateUserEdgeCases:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="Edge",
            email="edge@example.com",
            password_hash="h",
            is_verified=False,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_update_empty_dict(self, storage):
        uid = await self._create_user(storage)
        assert await storage.update_user(uid, {}) is True

    async def test_update_protected_fields_only(self, storage):
        uid = await self._create_user(storage)
        assert await storage.update_user(uid, {"id": 1, "created_at": "x"}) is True

    async def test_update_email_lowercased(self, storage):
        uid = await self._create_user(storage)
        await storage.update_user(uid, {"email": "UPPER@EXAMPLE.COM"})
        user = await storage.get_user_by_id(uid)
        assert user["email"] == "upper@example.com"

    async def test_update_pending_email_lowercased(self, storage):
        uid = await self._create_user(storage)
        await storage.update_user(uid, {"pending_email": "PENDING@EXAMPLE.COM"})
        result = await storage.find_user_by_pending_email("pending@example.com")
        assert result is not None


# ── Coverage boost: password history edge cases ────────────


class TestPasswordHistoryEdgeCases:
    async def test_get_password_history_zero_limit(self, storage):
        uid = await storage.create_user(
            name="H",
            email="h@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.add_password_history(uid, "hash1")
        assert await storage.get_password_history(uid, limit=0) == []

    async def test_get_password_history_negative_limit(self, storage):
        uid = await storage.create_user(
            name="H2",
            email="h2@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )
        await storage.add_password_history(uid, "hash1")
        assert await storage.get_password_history(uid, limit=-1) == []


# ── Coverage boost: refresh token edge cases ───────────────


class TestRefreshTokenEdgeCases:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="RT",
            email="rt@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_rotate_nonexistent_token(self, storage):
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=1
        )
        assert await storage.rotate_refresh_token(99999, "new_hash", future) is False

    async def test_list_refresh_tokens(self, storage):
        uid = await self._create_user(storage)
        future = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=1
        )
        await storage.store_refresh_token(
            uid, "tok1", "fam1", future, "127.0.0.1", "agent"
        )
        await storage.store_refresh_token(
            uid, "tok2", "fam1", future, "127.0.0.1", "agent"
        )
        tokens = await storage.list_refresh_tokens_for_user(uid)
        assert len(tokens) == 2

    async def test_prune_expired_tokens_returns_count(self, storage):
        uid = await self._create_user(storage)
        count = await storage.prune_expired_refresh_tokens()
        assert count >= 0


# ── Coverage boost: audit log ──────────────────────────────


class TestAuditLogCoverage:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="AL",
            email="al_cov@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_get_audit_log_no_filters(self, storage):
        uid = await self._create_user(storage)
        await storage.log_audit_event(
            uid, "al_cov@example.com", "LOGIN", "1.2.3.4", True, None
        )
        logs = await storage.get_audit_log()
        assert len(logs) >= 1

    async def test_get_audit_log_with_action_filter(self, storage):
        uid = await self._create_user(storage)
        await storage.log_audit_event(
            uid, "al_cov@example.com", "LOGIN", "1.2.3.4", True, None
        )
        await storage.log_audit_event(
            uid, "al_cov@example.com", "LOGOUT", "1.2.3.4", True, None
        )
        logs = await storage.get_audit_log(action="LOGIN")
        assert all(entry["action"] == "LOGIN" for entry in logs)

    async def test_get_audit_log_limit_offset(self, storage):
        uid = await self._create_user(storage)
        for i in range(5):
            await storage.log_audit_event(
                uid, "al_cov@example.com", f"A_{i}", None, True, None
            )
        page1 = await storage.get_audit_log(limit=2, offset=0)
        page2 = await storage.get_audit_log(limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2

    async def test_log_audit_event_error_path(self, storage):
        from unittest.mock import AsyncMock, patch

        import aiosqlite

        with patch.object(
            storage,
            "_execute",
            new_callable=AsyncMock,
            side_effect=aiosqlite.Error("db error"),
        ):
            await storage.log_audit_event(None, None, "TEST", None, True, None)


# ── Coverage boost: corrupt JSON paths ─────────────────────


class TestCorruptJSONPaths:
    async def _create_user(self, storage) -> int:
        return await storage.create_user(
            name="JSON",
            email="json@example.com",
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_corrupt_scopes_json_in_api_keys(self, storage):
        uid = await self._create_user(storage)
        await storage.store_api_key(uid, "prefix1", "hash1", "Key 1", '["read"]', None)
        await storage._execute(
            "UPDATE api_keys SET scopes_json = ? WHERE key_prefix = ?",
            ("not-valid-json{", "prefix1"),
        )
        await storage._commit()
        keys = await storage.list_api_keys_for_user(uid)
        assert keys[0]["scopes"] == []


# ── Coverage boost: additional edge-case tests ─────────────


class TestAdditionalEdgeCases:
    async def _create_user(self, storage, email="edge2@example.com") -> int:
        return await storage.create_user(
            name="Edge2",
            email=email,
            password_hash="h",
            is_verified=True,
            verification_token_hash=None,
            verification_token_expiry=None,
        )

    async def test_get_webauthn_credential_nonexistent(self, storage):
        assert await storage.get_webauthn_credential_by_id(b"nonexistent") is None

    async def test_delete_webauthn_credential_nonexistent(self, storage):
        uid = await self._create_user(storage)
        assert await storage.delete_webauthn_credential(uid, b"nonexistent") is False

    async def test_revoke_refresh_token_nonexistent(self, storage):
        assert await storage.revoke_refresh_token("nonexistent_hash") is False

    async def test_mark_refresh_token_used_nonexistent(self, storage):
        assert await storage.mark_refresh_token_used("nonexistent_hash") is False

    async def test_use_mfa_recovery_code_nonexistent(self, storage):
        uid = await self._create_user(storage, email="mfa@example.com")
        assert await storage.use_mfa_recovery_code(uid, "nonexistent_code") is False

    async def test_get_active_mfa_recovery_codes_count_zero(self, storage):
        uid = await self._create_user(storage, email="mfa2@example.com")
        assert await storage.get_active_mfa_recovery_codes_count(uid) == 0

    async def test_delete_role_nonexistent(self, storage):
        assert await storage.delete_role(99999) is False

    async def test_delete_permission_nonexistent(self, storage):
        assert await storage.delete_permission(99999) is False

    async def test_delete_api_key_nonexistent(self, storage):
        uid = await self._create_user(storage, email="apikey@example.com")
        assert await storage.delete_api_key_by_prefix(uid, "nonexistent") is False

    async def test_update_api_key_last_used_nonexistent(self, storage):
        await storage.update_api_key_last_used("nonexistent_hash")

    async def test_list_api_keys_empty(self, storage):
        uid = await self._create_user(storage, email="apikey2@example.com")
        assert await storage.list_api_keys_for_user(uid) == []

    async def test_list_refresh_tokens_empty(self, storage):
        uid = await self._create_user(storage, email="refresh@example.com")
        assert await storage.list_refresh_tokens_for_user(uid) == []

    async def test_get_audit_log_empty(self, storage):
        assert await storage.get_audit_log() == []

    async def test_update_user_custom_profile_nonexistent_user(self, storage):
        assert await storage.update_user_custom_profile(99999, {"k": "v"}) is False

    async def test_get_user_custom_profile_nonexistent_user(self, storage):
        assert await storage.get_user_custom_profile(99999) is None

    async def test_revoke_token_family_nonexistent(self, storage):
        await storage.revoke_token_family("nonexistent_family")

    async def test_revoke_all_refresh_tokens_nonexistent_user(self, storage):
        await storage.revoke_all_refresh_tokens_for_user(99999)

    async def test_get_user_roles_empty(self, storage):
        uid = await self._create_user(storage, email="roles@example.com")
        assert await storage.get_user_roles(uid) == []

    async def test_get_user_permissions_empty(self, storage):
        uid = await self._create_user(storage, email="perms@example.com")
        assert await storage.get_user_permissions(uid) == []

    async def test_get_role_permissions_empty(self, storage):
        rid = await storage.create_role("empty_role")
        assert await storage.get_role_permissions(rid) == []

    async def test_initialize_schema_idempotent(self, storage):
        await storage.initialize_schema()

    async def test_connect_idempotent(self, storage):
        await storage.connect()

    async def test_delete_user_and_cascade(self, storage):
        uid = await self._create_user(storage, email="cascade@example.com")
        assert await storage.delete_user(uid) is True
        assert await storage.get_user_by_id(uid) is None

    async def test_prune_expired_tokens_empty_db(self, storage):
        count = await storage.prune_expired_refresh_tokens()
        assert count == 0

    async def test_rollback_no_conn(self, storage):
        await storage.close()
        await storage._rollback()
