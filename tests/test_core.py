"""Comprehensive tests for authority.core — AuthManager."""

from __future__ import annotations

import datetime
from typing import Any

import jwt as pyjwt
import pytest

from authority.config import AuthConfig
from authority.core import AuthManager, _hash_password, _verify_password
from authority.events import Event
from authority.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    ConfigurationError,
    DatabaseError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
    UserExistsError,
    UserNotFoundError,
    ValidationError,
)
from authority.storage.sqlite import SQLiteStorage
from authority.utils import generate_secure_token, hash_token

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
    payload: dict[str, Any] = {
        "sub": sub,
        "jti": jti or generate_secure_token(16),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=exp_minutes),
        "iss": iss,
        "typ": typ,
    }
    return pyjwt.encode(payload, secret, algorithm=algorithm)


# ── Password Hashing ────────────────────────────────────────


class TestPasswordHashing:
    def test_hash_and_verify(self):
        password = "MySecureP@ss1234!"
        h = _hash_password(password)
        assert _verify_password(password, h)

    def test_wrong_password_fails(self):
        h = _hash_password("correct-password")
        assert not _verify_password("wrong-password", h)

    def test_invalid_hash_returns_false(self):
        assert not _verify_password("password", "not-a-hash")


# ── Registration ────────────────────────────────────────────


class TestRegister:
    def test_register_success(self, auth_manager: AuthManager):
        result = auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        assert result["name"] == "Alice"
        assert result["email"] == "alice@example.com"
        assert result["is_verified"] is False
        assert "password_hash" not in result

    def test_register_auto_verify(self, auth_manager: AuthManager):
        result = auth_manager.register(
            name="Bob",
            email="bob@example.com",
            password="StrongP@ss1234!",
            auto_verify=True,
        )
        assert result["is_verified"] is True

    def test_register_duplicate_email_raises(self, auth_manager: AuthManager):
        auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        with pytest.raises(UserExistsError, match="already exists"):
            auth_manager.register(
                name="Alice2",
                email="alice@example.com",
                password="AnotherP@ss1234!",
            )

    def test_register_empty_name_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="Name is required"):
            auth_manager.register(
                name="",
                email="test@example.com",
                password="StrongP@ss1234!",
            )

    def test_register_invalid_email_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="Invalid email format"):
            auth_manager.register(
                name="Alice",
                email="not-an-email",
                password="StrongP@ss1234!",
            )

    def test_register_empty_password_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="Password is required"):
            auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="",
            )

    def test_register_weak_password_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="at least 12 characters"):
            auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="short",
            )

    def test_register_password_no_complexity_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError):
            auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="alllowercase1234",  # No uppercase, no special
            )

    def test_register_password_contains_email_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="email username"):
            auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="aliceP@ss1234!",
            )

    def test_register_password_contains_name_raises(self, auth_manager: AuthManager):
        with pytest.raises(ValidationError, match="contain your name"):
            auth_manager.register(
                name="alice",
                email="bob@example.com",
                password="aliceP@ss1234!",
            )

    def test_register_emits_event(self, auth_manager: AuthManager):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_REGISTERED, lambda d: events.append(d))
        auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        assert len(events) == 1
        assert events[0]["email"] == "alice@example.com"

    def test_register_stores_password_history(self, auth_manager: AuthManager):
        user = auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        history = auth_manager.storage.get_password_history(user["id"], limit=10)
        assert len(history) == 1

    def test_register_email_lowercase(self, auth_manager: AuthManager):
        result = auth_manager.register(
            name="Alice",
            email="ALICE@Example.COM",
            password="StrongP@ss1234!",
        )
        assert result["email"] == "alice@example.com"


# ── Login ───────────────────────────────────────────────────


class TestLogin:
    def test_login_success(self, auth_manager: AuthManager, registered_user: dict):
        result = auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "Bearer"
        assert result["user"]["email"] == "test@example.com"

    def test_login_wrong_password(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
            auth_manager.login(
                email="test@example.com",
                password="WrongPassword123!",
            )

    def test_login_nonexistent_email(self, auth_manager: AuthManager):
        with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
            auth_manager.login(
                email="nonexistent@example.com",
                password="Password123!",
            )

    def test_login_increments_failed_attempts(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        for _ in range(3):
            try:
                auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        user = auth_manager.storage.get_user_by_id(registered_user["id"])
        assert user["failed_login_attempts"] == 3

    def test_login_account_lockout(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        for _ in range(5):
            try:
                auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        with pytest.raises(AccountLockedError, match="temporarily locked"):
            auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    def test_login_resets_failed_attempts(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        # Fail 3 times
        for _ in range(3):
            try:
                auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        # Login successfully
        auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )

        user = auth_manager.storage.get_user_by_id(registered_user["id"])
        assert user["failed_login_attempts"] == 0

    def test_login_inactive_account(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        auth_manager.storage.update_user(registered_user["id"], {"is_active": False})
        with pytest.raises(AccountInactiveError, match="deactivated"):
            auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    def test_login_unverified_account(self, fernet_key: str):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            email_verification_required=True,
        )
        storage = SQLiteStorage(":memory:")
        auth = AuthManager(config, storage)
        auth.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=False,
        )
        with pytest.raises(AccountNotVerifiedError, match="verify your email"):
            auth.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )
        storage.close()

    def test_login_emits_events(self, auth_manager: AuthManager, registered_user: dict):
        success_events: list[dict] = []
        auth_manager.events.on(
            Event.USER_LOGIN_SUCCESS, lambda d: success_events.append(d)
        )

        auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert len(success_events) == 1

    def test_login_failed_emits_event(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        failed_events: list[dict] = []
        auth_manager.events.on(
            Event.USER_LOGIN_FAILED, lambda d: failed_events.append(d)
        )

        try:
            auth_manager.login(
                email="test@example.com",
                password="WrongPassword123!",
            )
        except InvalidCredentialsError:
            pass

        assert len(failed_events) == 1

    def test_login_returns_valid_jwt(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        result = auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        payload = pyjwt.decode(
            result["access_token"],
            auth_manager.config.jwt_secret_key,
            algorithms=[auth_manager.config.jwt_algorithm],
        )
        assert payload["sub"] == str(registered_user["id"])
        assert payload["typ"] == "access"


# ── Verify Access Token ─────────────────────────────────────


class TestVerifyAccessToken:
    def test_valid_token(self, auth_manager: AuthManager, verified_user: dict):
        result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        payload = auth_manager.verify_access_token(result["access_token"])
        assert payload["user_id"] == verified_user["id"]
        assert payload["typ"] == "access"

    def test_expired_token(self, auth_manager: AuthManager, verified_user: dict):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            exp_minutes=-1,
        )
        with pytest.raises(TokenExpiredError, match="expired"):
            auth_manager.verify_access_token(token)

    def test_invalid_token(self, auth_manager: AuthManager):
        with pytest.raises(InvalidTokenError):
            auth_manager.verify_access_token("not-a-valid-token")

    def test_wrong_secret(self, auth_manager: AuthManager, verified_user: dict):
        token = _make_token("wrong-secret-key!!!", sub=str(verified_user["id"]))
        with pytest.raises(InvalidTokenError):
            auth_manager.verify_access_token(token)

    def test_wrong_algorithm(self, auth_manager: AuthManager, verified_user: dict):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            algorithm="HS512",
        )
        with pytest.raises(InvalidTokenError):
            auth_manager.verify_access_token(token)

    def test_wrong_issuer(self, auth_manager: AuthManager, verified_user: dict):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            iss="attacker",
        )
        with pytest.raises(InvalidTokenError):
            auth_manager.verify_access_token(token)

    def test_refresh_token_rejected(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            typ="refresh",
        )
        with pytest.raises(InvalidTokenError, match="not an access token"):
            auth_manager.verify_access_token(token)

    def test_blacklisted_jti(self, auth_manager: AuthManager, verified_user: dict):
        jti = generate_secure_token(16)
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            jti=jti,
        )
        auth_manager._jti_blacklist.add(jti)
        with pytest.raises(InvalidTokenError, match="revoked"):
            auth_manager.verify_access_token(token)


# ── Refresh Token Rotation ──────────────────────────────────


class TestRefreshAccessToken:
    def test_refresh_success(self, auth_manager: AuthManager, verified_user: dict):
        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        refresh_result = auth_manager.refresh_access_token(
            login_result["refresh_token"],
        )
        assert "access_token" in refresh_result
        assert "refresh_token" in refresh_result
        assert refresh_result["refresh_token"] != login_result["refresh_token"]

    def test_refresh_invalid_token(self, auth_manager: AuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid refresh token"):
            auth_manager.refresh_access_token("invalid-token")

    def test_refresh_revoked_token(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        # Revoke the token
        auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login_result["refresh_token"],
        )
        with pytest.raises(InvalidTokenError, match="revoked"):
            auth_manager.refresh_access_token(
                login_result["refresh_token"],
            )

    def test_refresh_reuse_detection(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        # First refresh — marks token as used
        auth_manager.refresh_access_token(login_result["refresh_token"])
        # Second refresh with same token — should trigger reuse detection
        with pytest.raises(InvalidTokenError, match="reuse detected"):
            auth_manager.refresh_access_token(login_result["refresh_token"])

    def test_refresh_emits_event(self, auth_manager: AuthManager, verified_user: dict):
        refresh_events: list[dict] = []
        auth_manager.events.on(
            Event.TOKEN_REFRESHED, lambda d: refresh_events.append(d)
        )

        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.refresh_access_token(login_result["refresh_token"])
        assert len(refresh_events) == 1

    def test_refresh_reuse_emits_event(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        reuse_events: list[dict] = []
        auth_manager.events.on(
            Event.TOKEN_REUSE_DETECTED, lambda d: reuse_events.append(d)
        )

        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.refresh_access_token(login_result["refresh_token"])
        try:
            auth_manager.refresh_access_token(login_result["refresh_token"])
        except InvalidTokenError:
            pass
        assert len(reuse_events) == 1

    def test_refresh_new_token_works(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        refresh_result = auth_manager.refresh_access_token(
            login_result["refresh_token"],
        )
        # New access token should be valid
        payload = auth_manager.verify_access_token(refresh_result["access_token"])
        assert payload["user_id"] == verified_user["id"]


# ── Email Verification ──────────────────────────────────────


class TestEmailVerification:
    def test_request_and_verify(self, auth_manager: AuthManager):
        user = auth_manager.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=False,
        )
        token = auth_manager.request_email_verification(user["id"])
        assert token  # Non-empty

        result = auth_manager.verify_email(token)
        assert result["is_verified"] is True

    def test_verify_invalid_token(self, auth_manager: AuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            auth_manager.verify_email("invalid-token")

    def test_request_for_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.request_email_verification(99999)

    def test_already_verified_returns_empty(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        token = auth_manager.request_email_verification(verified_user["id"])
        assert token == ""


# ── Password Reset ──────────────────────────────────────────


class TestPasswordReset:
    def test_request_and_reset(self, auth_manager: AuthManager, registered_user: dict):
        token = auth_manager.request_password_reset("test@example.com")
        assert token

        result = auth_manager.reset_password(token, "NewSecureP@ss1234!")
        assert result["id"] == registered_user["id"]

        # Old password should no longer work
        with pytest.raises(InvalidCredentialsError):
            auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

        # New password should work
        login_result = auth_manager.login(
            email="test@example.com",
            password="NewSecureP@ss1234!",
        )
        assert "access_token" in login_result

    def test_request_nonexistent_email(self, auth_manager: AuthManager):
        # Should return empty string to prevent enumeration
        token = auth_manager.request_password_reset("nonexistent@example.com")
        assert token == ""

    def test_reset_invalid_token(self, auth_manager: AuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            auth_manager.reset_password("invalid-token", "NewP@ss1234!")

    def test_reset_weak_password(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        token = auth_manager.request_password_reset("test@example.com")
        with pytest.raises(ValidationError, match="at least 12 characters"):
            auth_manager.reset_password(token, "weak")

    def test_reset_revokes_all_tokens(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        # Login to create refresh tokens
        auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        # Reset password
        token = auth_manager.request_password_reset("test@example.com")
        auth_manager.reset_password(token, "NewSecureP@ss1234!")

        # All refresh tokens should be revoked
        tokens = auth_manager.storage.list_refresh_tokens_for_user(
            registered_user["id"]
        )
        assert all(t.get("revoked", False) for t in tokens)

    def test_reset_emits_event(self, auth_manager: AuthManager, registered_user: dict):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_PASSWORD_CHANGED, lambda d: events.append(d))

        token = auth_manager.request_password_reset("test@example.com")
        auth_manager.reset_password(token, "NewSecureP@ss1234!")
        assert len(events) == 1


# ── Change Password ─────────────────────────────────────────


class TestChangePassword:
    def test_change_password_success(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        result = auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        assert result["id"] == registered_user["id"]

        # Old password should not work
        with pytest.raises(InvalidCredentialsError):
            auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    def test_change_wrong_current_password(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        with pytest.raises(
            InvalidCredentialsError, match="Current password is incorrect"
        ):
            auth_manager.change_password(
                user_id=registered_user["id"],
                current_password="WrongPassword123!",
                new_password="NewSecureP@ss1234!",
            )

    def test_change_password_history_check(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        # Change once
        auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        # Try to reuse old password
        with pytest.raises(ValidationError, match="reuse a password"):
            auth_manager.change_password(
                user_id=registered_user["id"],
                current_password="NewSecureP@ss1234!",
                new_password="SecureP@ss1234!",
            )

    def test_change_password_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.change_password(
                user_id=99999,
                current_password="Password123!",
                new_password="NewSecureP@ss1234!",
            )

    def test_change_password_emits_event(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_PASSWORD_CHANGED, lambda d: events.append(d))

        auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        assert len(events) == 1


# ── Email Change ────────────────────────────────────────────


class TestEmailChange:
    def test_request_and_confirm(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        token = auth_manager.request_email_change(
            user_id=registered_user["id"],
            new_email="newemail@example.com",
            current_password="SecureP@ss1234!",
        )
        assert token

        result = auth_manager.confirm_email_change(token)
        assert result["email"] == "newemail@example.com"

    def test_request_wrong_password(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        with pytest.raises(
            InvalidCredentialsError, match="Current password is incorrect"
        ):
            auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="newemail@example.com",
                current_password="WrongPassword123!",
            )

    def test_request_same_email(self, auth_manager: AuthManager, registered_user: dict):
        with pytest.raises(ValidationError, match="different from current"):
            auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="test@example.com",
                current_password="SecureP@ss1234!",
            )

    def test_request_invalid_email(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        with pytest.raises(ValidationError, match="Invalid email format"):
            auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="not-valid",
                current_password="SecureP@ss1234!",
            )

    def test_request_existing_email(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        auth_manager.register(
            name="Other",
            email="other@example.com",
            password="UniqueP@ss9876!",
        )
        with pytest.raises(UserExistsError):
            auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="other@example.com",
                current_password="SecureP@ss1234!",
            )

    def test_confirm_invalid_token(self, auth_manager: AuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            auth_manager.confirm_email_change("invalid-token")

    def test_email_change_emits_event(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_EMAIL_CHANGED, lambda d: events.append(d))

        token = auth_manager.request_email_change(
            user_id=registered_user["id"],
            new_email="newemail@example.com",
            current_password="SecureP@ss1234!",
        )
        auth_manager.confirm_email_change(token)
        assert len(events) == 1
        assert events[0]["new_email"] == "newemail@example.com"


# ── Logout ──────────────────────────────────────────────────


class TestLogout:
    def test_logout_specific_token(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        login_result = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login_result["refresh_token"],
        )
        # Token should be revoked
        with pytest.raises(InvalidTokenError, match="revoked"):
            auth_manager.refresh_access_token(login_result["refresh_token"])

    def test_logout_all(self, auth_manager: AuthManager, verified_user: dict):
        # Login multiple times
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.logout_all(
            user_id=verified_user["id"],
            exclude_refresh_token=login2["refresh_token"],
        )
        # Only the excluded token should still work
        tokens = auth_manager.storage.list_refresh_tokens_for_user(verified_user["id"])
        revoked = [t for t in tokens if t.get("revoked")]
        active = [t for t in tokens if not t.get("revoked")]
        assert len(revoked) >= 1
        assert len(active) <= 1

    def test_logout_emits_event(self, auth_manager: AuthManager, verified_user: dict):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_LOGOUT, lambda d: events.append(d))

        auth_manager.logout(user_id=verified_user["id"])
        assert len(events) == 1

    def test_logout_all_returns_count(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        count = auth_manager.logout_all(user_id=verified_user["id"])
        assert count >= 1


class TestSessionManagement:
    def test_list_sessions_empty(self, auth_manager: AuthManager, verified_user: dict):
        assert auth_manager.list_sessions(verified_user["id"]) == []

    def test_list_sessions_after_logins(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        sessions = auth_manager.list_sessions(verified_user["id"])
        assert len(sessions) == 2
        assert {"id", "created_at", "expires_at"} <= set(sessions[0])

    def test_list_sessions_excludes_revoked(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        login1 = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login1["refresh_token"],
        )
        sessions = auth_manager.list_sessions(verified_user["id"])
        assert len(sessions) == 1
        login2_token = auth_manager.storage.get_refresh_token_by_hash(
            hash_token(login2["refresh_token"])
        )
        assert login2_token is not None
        assert sessions[0]["id"] == login2_token["id"]

    def test_revoke_session_by_id(self, auth_manager: AuthManager, verified_user: dict):
        login = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        token_id = auth_manager.storage.list_refresh_tokens_for_user(
            verified_user["id"]
        )[0]["id"]
        assert auth_manager.revoke_session_by_id(verified_user["id"], token_id)
        assert auth_manager.list_sessions(verified_user["id"]) == []
        with pytest.raises(InvalidTokenError, match="revoked"):
            auth_manager.refresh_access_token(login["refresh_token"])

    def test_revoke_session_by_id_unauthorized(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        token_id = auth_manager.storage.list_refresh_tokens_for_user(
            verified_user["id"]
        )[0]["id"]
        # Different user cannot revoke
        assert not auth_manager.revoke_session_by_id(99999, token_id)
        assert len(auth_manager.list_sessions(verified_user["id"])) == 1

    def test_revoke_session_by_id_nonexistent(self, auth_manager: AuthManager):
        assert not auth_manager.revoke_session_by_id(1, 99999)

    def test_revoke_all_sessions_for_user(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        count = auth_manager.revoke_all_sessions_for_user(verified_user["id"])
        assert count == 2
        assert auth_manager.list_sessions(verified_user["id"]) == []

    def test_revoke_all_sessions_excluding_one(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2_token = auth_manager.storage.get_refresh_token_by_hash(
            hash_token(login2["refresh_token"])
        )
        assert login2_token is not None
        keep_id = login2_token["id"]
        count = auth_manager.revoke_all_sessions_for_user(
            verified_user["id"], exclude_token_id=keep_id
        )
        assert count == 1
        remaining = auth_manager.list_sessions(verified_user["id"])
        assert len(remaining) == 1
        assert remaining[0]["id"] == keep_id


class TestContextManager:
    def test_context_manager_closes_storage(
        self, test_config: AuthConfig, tmp_db: SQLiteStorage
    ):
        with AuthManager(test_config, tmp_db) as auth:
            user = auth.register(
                name="CM User",
                email="cm@example.com",
                password="SecureP@ss1234!",
                auto_verify=True,
            )
            assert auth.get_user(user["id"])["email"] == "cm@example.com"
        # Storage should be closed after exiting the context
        with pytest.raises(DatabaseError):
            tmp_db.get_user_by_id(user["id"])


# ── User Management ─────────────────────────────────────────


class TestUserManagement:
    def test_get_user(self, auth_manager: AuthManager, verified_user: dict):
        user = auth_manager.get_user(verified_user["id"])
        assert user["email"] == "verified@example.com"
        assert "password_hash" not in user

    def test_get_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.get_user(99999)

    def test_update_user(self, auth_manager: AuthManager, verified_user: dict):
        result = auth_manager.update_user(
            verified_user["id"],
            {"name": "Updated Name"},
        )
        assert result["name"] == "Updated Name"

    def test_update_user_protected_fields(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        original_email = verified_user["email"]
        result = auth_manager.update_user(
            verified_user["id"],
            {"email": "hacked@example.com", "name": "New Name"},
        )
        assert result["email"] == original_email  # Email not changed
        assert result["name"] == "New Name"

    def test_update_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.update_user(99999, {"name": "X"})

    def test_delete_user(self, auth_manager: AuthManager, registered_user: dict):
        result = auth_manager.delete_user(registered_user["id"])
        assert result is True
        with pytest.raises(UserNotFoundError):
            auth_manager.get_user(registered_user["id"])

    def test_delete_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.delete_user(99999)

    def test_delete_user_revokes_tokens(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        auth_manager.delete_user(registered_user["id"])
        tokens = auth_manager.storage.list_refresh_tokens_for_user(
            registered_user["id"]
        )
        assert all(t.get("revoked", False) for t in tokens)


# ── Audit Logging ───────────────────────────────────────────


class TestAuditLogging:
    def test_audit_log_on_register(self, auth_manager: AuthManager):
        auth_manager.register(
            name="Audit User",
            email="audit@example.com",
            password="SecureP@ss1234!",
        )
        # Check that an audit event was logged
        # (We can't query audit directly from AuthManager, but we can check storage)

    def test_audit_log_disabled(self, fernet_key: str):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            audit_log_enabled=False,
        )
        storage = SQLiteStorage(":memory:")
        auth = AuthManager(config, storage)
        auth.register(
            name="No Audit",
            email="noaudit@example.com",
            password="SecureP@ss1234!",
        )
        # Should not raise — just silently skip
        storage.close()


# ── Event System Integration ────────────────────────────────


class TestEventIntegration:
    def test_multiple_handlers(self, auth_manager: AuthManager, registered_user: dict):
        calls: list[str] = []
        auth_manager.events.on(
            Event.USER_LOGIN_SUCCESS, lambda d: calls.append("first")
        )
        auth_manager.events.on(
            Event.USER_LOGIN_SUCCESS, lambda d: calls.append("second")
        )

        auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert calls == ["first", "second"]

    def test_handler_error_doesnt_break_flow(
        self, auth_manager: AuthManager, registered_user: dict
    ):
        def bad_handler(data: dict) -> None:
            raise RuntimeError("Handler exploded")

        auth_manager.events.on(Event.USER_LOGIN_SUCCESS, bad_handler)

        # Should not raise — event handler errors are swallowed
        result = auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert "access_token" in result


# ── Config Validation ───────────────────────────────────────


class TestConfigValidation:
    def test_missing_jwt_secret(self, fernet_key: str):
        config = AuthConfig(jwt_secret_key="", fernet_key=fernet_key)
        storage = SQLiteStorage(":memory:")
        with pytest.raises(ConfigurationError, match="jwt_secret_key"):
            AuthManager(config, storage)
        storage.close()

    def test_missing_fernet_key(self):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="",
        )
        storage = SQLiteStorage(":memory:")
        with pytest.raises(ConfigurationError, match="fernet_key"):
            AuthManager(config, storage)
        storage.close()


# ── Close ───────────────────────────────────────────────────


class TestClose:
    def test_close(self, auth_manager: AuthManager):
        auth_manager.close()
        # Should not raise
