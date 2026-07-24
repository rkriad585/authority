"""Tests for authority API Keys."""

from __future__ import annotations

import pytest

from authority.core import AuthManager
from authority.exceptions import InvalidAPIKeyError


class TestCreateAPIKey:
    def test_create_api_key(self, auth_manager: AuthManager, verified_user: dict):
        result = auth_manager.create_api_key(
            verified_user["id"],
            description="Test key",
            scopes=["read", "write"],
        )
        assert "key" in result
        assert result["prefix"] == result["key"][:8]
        assert result["description"] == "Test key"
        assert result["scopes"] == ["read", "write"]
        assert result["expires_at"] is None

    def test_create_api_key_with_expiry(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.create_api_key(
            verified_user["id"],
            expires_in_days=30,
        )
        assert result["expires_at"] is not None

    def test_create_api_key_no_scopes(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.create_api_key(verified_user["id"])
        assert result["scopes"] == []


class TestVerifyAPIKey:
    def test_verify_valid_key(self, auth_manager: AuthManager, verified_user: dict):
        create_result = auth_manager.create_api_key(
            verified_user["id"],
            scopes=["read"],
        )
        verified = auth_manager.verify_api_key(create_result["key"])
        assert verified["user_id"] == verified_user["id"]
        assert verified["scopes"] == ["read"]

    def test_verify_invalid_key(self, auth_manager: AuthManager):
        with pytest.raises(InvalidAPIKeyError, match="Invalid API key"):
            auth_manager.verify_api_key("invalid-key-here")

    def test_verify_expired_key(self, auth_manager: AuthManager, verified_user: dict):
        create_result = auth_manager.create_api_key(
            verified_user["id"],
            expires_in_days=-1,  # Already expired
        )
        with pytest.raises(InvalidAPIKeyError, match="expired"):
            auth_manager.verify_api_key(create_result["key"])

    def test_verify_updates_last_used(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        create_result = auth_manager.create_api_key(verified_user["id"])
        auth_manager.verify_api_key(create_result["key"])

        keys = auth_manager.list_api_keys(verified_user["id"])
        assert keys[0]["last_used_at"] is not None


class TestListAPIKeys:
    def test_list_empty(self, auth_manager: AuthManager, verified_user: dict):
        assert auth_manager.list_api_keys(verified_user["id"]) == []

    def test_list_keys(self, auth_manager: AuthManager, verified_user: dict):
        auth_manager.create_api_key(verified_user["id"], description="Key 1")
        auth_manager.create_api_key(verified_user["id"], description="Key 2")
        keys = auth_manager.list_api_keys(verified_user["id"])
        assert len(keys) == 2
        # Full key should not be in the list
        for k in keys:
            assert "key" not in k or k.get("key") is None


class TestRevokeAPIKey:
    def test_revoke_key(self, auth_manager: AuthManager, verified_user: dict):
        create_result = auth_manager.create_api_key(
            verified_user["id"], description="To revoke"
        )
        prefix = create_result["prefix"]
        assert auth_manager.revoke_api_key(verified_user["id"], prefix)

        # Key should no longer be valid
        with pytest.raises(InvalidAPIKeyError):
            auth_manager.verify_api_key(create_result["key"])

    def test_revoke_emits_event(self, auth_manager: AuthManager, verified_user: dict):
        events: list[dict] = []
        auth_manager.events.on("api_key.revoked", lambda d: events.append(d))

        create_result = auth_manager.create_api_key(verified_user["id"])
        auth_manager.revoke_api_key(verified_user["id"], create_result["prefix"])
        assert len(events) == 1
