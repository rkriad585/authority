"""Tests for authority WebAuthn — server-side methods."""

from __future__ import annotations

import pytest

from authority.core import AuthManager
from authority.exceptions import (
    UserNotFoundError,
    WebAuthnVerificationError,
)


class TestWebAuthnRegistration:
    def test_start_registration(self, auth_manager: AuthManager, verified_user: dict):
        result = auth_manager.start_webauthn_registration(verified_user["id"])
        assert "challenge" in result
        assert "options_json" in result
        assert result["rp_id"] == auth_manager.config.webauthn_rp_id

    def test_start_registration_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.start_webauthn_registration(99999)

    def test_complete_registration(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "test-cred-id-123",
                "public_key": "test-public-key",
                "sign_count": 0,
                "description": "My Security Key",
            },
        )
        assert result["description"] == "My Security Key"
        assert result["credential_id"] == "test-cred-id-123"

    def test_complete_registration_invalid_data(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        from authority.exceptions import WebAuthnRegistrationError

        with pytest.raises(WebAuthnRegistrationError, match="Invalid credential"):
            auth_manager.complete_webauthn_registration(
                verified_user["id"],
                {"credential_id": "", "public_key": ""},
            )


class TestWebAuthnAuthentication:
    def test_start_authentication(self, auth_manager: AuthManager):
        result = auth_manager.start_webauthn_authentication()
        assert "challenge" in result
        assert "options_json" in result

    def test_start_authentication_with_user(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "cred-123",
                "public_key": "pk-123",
                "sign_count": 0,
            },
        )
        result = auth_manager.start_webauthn_authentication(verified_user["id"])
        assert "challenge" in result

    def test_complete_authentication(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "auth-cred-123",
                "public_key": "auth-pk-123",
                "sign_count": 0,
            },
        )
        result = auth_manager.complete_webauthn_authentication(
            {
                "credential_id": "auth-cred-123",
                "sign_count": 1,
            },
        )
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"]["id"] == verified_user["id"]

    def test_complete_authentication_unknown_credential(
        self, auth_manager: AuthManager
    ):
        with pytest.raises(WebAuthnVerificationError, match="Unknown credential"):
            auth_manager.complete_webauthn_authentication(
                {"credential_id": "nonexistent", "sign_count": 0},
            )


class TestWebAuthnCredentialManagement:
    def test_list_credentials_empty(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        creds = auth_manager.list_webauthn_credentials(verified_user["id"])
        assert creds == []

    def test_list_credentials(self, auth_manager: AuthManager, verified_user: dict):
        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "cred-1",
                "public_key": "pk-1",
                "sign_count": 0,
                "description": "Key 1",
            },
        )
        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "cred-2",
                "public_key": "pk-2",
                "sign_count": 0,
                "description": "Key 2",
            },
        )
        creds = auth_manager.list_webauthn_credentials(verified_user["id"])
        assert len(creds) == 2
        # Public key should not be exposed
        for c in creds:
            assert "public_key" not in c

    def test_delete_credential(self, auth_manager: AuthManager, verified_user: dict):
        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "to-delete",
                "public_key": "pk-del",
                "sign_count": 0,
            },
        )
        assert auth_manager.delete_webauthn_credential(verified_user["id"], "to-delete")
        creds = auth_manager.list_webauthn_credentials(verified_user["id"])
        assert len(creds) == 0

    def test_delete_credential_emits_event(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(
            "webauthn.credential_removed", lambda d: events.append(d)
        )

        auth_manager.complete_webauthn_registration(
            verified_user["id"],
            {
                "credential_id": "del-event",
                "public_key": "pk",
                "sign_count": 0,
            },
        )
        auth_manager.delete_webauthn_credential(verified_user["id"], "del-event")
        assert len(events) == 1
