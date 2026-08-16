"""Comprehensive async tests for authority.async_core — AsyncAuthManager."""

from __future__ import annotations

import datetime
from typing import Any

import jwt as pyjwt
import pytest

from authority.async_core import AsyncAuthManager, _hash_password, _verify_password
from authority.config import AuthConfig
from authority.events import Event
from authority.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    ConfigurationError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidTokenError,
    TokenExpiredError,
    UserExistsError,
    UserNotFoundError,
    ValidationError,
)
from authority.storage.aiosqlite import AsyncSQLiteStorage
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


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture()
async def mem_db() -> AsyncSQLiteStorage:
    """Create an in-memory async SQLite database for testing."""
    storage = AsyncSQLiteStorage(":memory:")
    await storage.connect()
    yield storage
    await storage.close()


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
async def auth_manager(
    test_config: AuthConfig, mem_db: AsyncSQLiteStorage
) -> AsyncAuthManager:
    """Return an AsyncAuthManager with in-memory storage for testing."""
    test_config.refresh_token_reuse_grace_seconds = 0
    return AsyncAuthManager(test_config, mem_db)


@pytest.fixture()
async def registered_user(auth_manager: AsyncAuthManager) -> dict:
    """Register a user and return the user dict."""
    return await auth_manager.register(
        name="Test User",
        email="test@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
async def verified_user(auth_manager: AsyncAuthManager) -> dict:
    """Register a verified user and return the user dict."""
    return await auth_manager.register(
        name="Verified User",
        email="verified@example.com",
        password="AuthP@ss12345!",
        auto_verify=True,
    )


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


class TestRegistration:
    async def test_register_success(self, auth_manager: AsyncAuthManager):
        result = await auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        assert result["name"] == "Alice"
        assert result["email"] == "alice@example.com"
        assert result["is_verified"] is False
        assert "password_hash" not in result

    async def test_register_auto_verify(self, auth_manager: AsyncAuthManager):
        result = await auth_manager.register(
            name="Bob",
            email="bob@example.com",
            password="StrongP@ss1234!",
            auto_verify=True,
        )
        assert result["is_verified"] is True

    async def test_register_duplicate_email_raises(
        self, auth_manager: AsyncAuthManager
    ):
        await auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        with pytest.raises(UserExistsError, match="already exists"):
            await auth_manager.register(
                name="Alice2",
                email="alice@example.com",
                password="AnotherP@ss1234!",
            )

    async def test_register_empty_name_raises(self, auth_manager: AsyncAuthManager):
        with pytest.raises(ValidationError, match="Name is required"):
            await auth_manager.register(
                name="",
                email="test@example.com",
                password="StrongP@ss1234!",
            )

    async def test_register_invalid_email_raises(self, auth_manager: AsyncAuthManager):
        with pytest.raises(ValidationError, match="Invalid email format"):
            await auth_manager.register(
                name="Alice",
                email="not-an-email",
                password="StrongP@ss1234!",
            )

    async def test_register_empty_password_raises(self, auth_manager: AsyncAuthManager):
        with pytest.raises(ValidationError, match="Password is required"):
            await auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="",
            )

    async def test_register_weak_password_raises(self, auth_manager: AsyncAuthManager):
        with pytest.raises(ValidationError, match="at least 12 characters"):
            await auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="short",
            )

    async def test_register_password_no_complexity_raises(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(ValidationError):
            await auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="alllowercase1234",
            )

    async def test_register_password_contains_email_raises(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(ValidationError, match="email username"):
            await auth_manager.register(
                name="Alice",
                email="alice@example.com",
                password="aliceP@ss1234!",
            )

    async def test_register_password_contains_name_raises(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(ValidationError, match="contain your name"):
            await auth_manager.register(
                name="alice",
                email="bob@example.com",
                password="aliceP@ss1234!",
            )

    async def test_register_emits_event(self, auth_manager: AsyncAuthManager):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_REGISTERED, lambda d: events.append(d))
        await auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        assert len(events) == 1
        assert events[0]["email"] == "alice@example.com"

    async def test_register_stores_password_history(
        self, auth_manager: AsyncAuthManager
    ):
        user = await auth_manager.register(
            name="Alice",
            email="alice@example.com",
            password="StrongP@ss1234!",
        )
        history = await auth_manager.storage.get_password_history(user["id"], limit=10)
        assert len(history) == 1

    async def test_register_email_lowercase(self, auth_manager: AsyncAuthManager):
        result = await auth_manager.register(
            name="Alice",
            email="ALICE@Example.COM",
            password="StrongP@ss1234!",
        )
        assert result["email"] == "alice@example.com"


# ── Login ───────────────────────────────────────────────────


class TestLogin:
    async def test_login_success(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["token_type"] == "Bearer"
        assert result["user"]["email"] == "test@example.com"

    async def test_login_wrong_password(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
            await auth_manager.login(
                email="test@example.com",
                password="WrongPassword123!",
            )

    async def test_login_nonexistent_email(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidCredentialsError, match="Invalid email or password"):
            await auth_manager.login(
                email="nonexistent@example.com",
                password="Password123!",
            )

    async def test_login_increments_failed_attempts(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        for _ in range(3):
            try:
                await auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        user = await auth_manager.storage.get_user_by_id(registered_user["id"])
        assert user["failed_login_attempts"] == 3

    async def test_login_account_lockout(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        for _ in range(5):
            try:
                await auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        with pytest.raises(AccountLockedError, match="temporarily locked"):
            await auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    async def test_login_resets_failed_attempts(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        for _ in range(3):
            try:
                await auth_manager.login(
                    email="test@example.com",
                    password="WrongPassword123!",
                )
            except InvalidCredentialsError:
                pass

        await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )

        user = await auth_manager.storage.get_user_by_id(registered_user["id"])
        assert user["failed_login_attempts"] == 0

    async def test_login_inactive_account(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        await auth_manager.storage.update_user(
            registered_user["id"], {"is_active": False}
        )
        with pytest.raises(AccountInactiveError, match="deactivated"):
            await auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    async def test_login_unverified_account(self, fernet_key: str):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            email_verification_required=True,
        )
        storage = AsyncSQLiteStorage(":memory:")
        await storage.connect()
        auth = AsyncAuthManager(config, storage)
        await auth.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=False,
        )
        with pytest.raises(AccountNotVerifiedError, match="verify your email"):
            await auth.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )
        await storage.close()

    async def test_login_emits_events(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        success_events: list[dict] = []
        auth_manager.events.on(
            Event.USER_LOGIN_SUCCESS, lambda d: success_events.append(d)
        )

        await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        assert len(success_events) == 1

    async def test_login_failed_emits_event(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        failed_events: list[dict] = []
        auth_manager.events.on(
            Event.USER_LOGIN_FAILED, lambda d: failed_events.append(d)
        )

        try:
            await auth_manager.login(
                email="test@example.com",
                password="WrongPassword123!",
            )
        except InvalidCredentialsError:
            pass

        assert len(failed_events) == 1

    async def test_login_returns_valid_jwt(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.login(
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


class TestAccessToken:
    async def test_valid_token(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        payload = await auth_manager.verify_access_token(result["access_token"])
        assert payload["user_id"] == verified_user["id"]
        assert payload["typ"] == "access"

    async def test_expired_token(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            exp_minutes=-1,
        )
        with pytest.raises(TokenExpiredError, match="expired"):
            await auth_manager.verify_access_token(token)

    async def test_invalid_token(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidTokenError):
            await auth_manager.verify_access_token("not-a-valid-token")

    async def test_wrong_secret(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = _make_token("wrong-secret-key!!!", sub=str(verified_user["id"]))
        with pytest.raises(InvalidTokenError):
            await auth_manager.verify_access_token(token)

    async def test_wrong_algorithm(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            algorithm="HS512",
        )
        with pytest.raises(InvalidTokenError):
            await auth_manager.verify_access_token(token)

    async def test_wrong_issuer(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            iss="attacker",
        )
        with pytest.raises(InvalidTokenError):
            await auth_manager.verify_access_token(token)

    async def test_refresh_token_rejected(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            typ="refresh",
        )
        with pytest.raises(InvalidTokenError, match="not an access token"):
            await auth_manager.verify_access_token(token)

    async def test_blacklisted_jti(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        jti = generate_secure_token(16)
        token = _make_token(
            auth_manager.config.jwt_secret_key,
            sub=str(verified_user["id"]),
            jti=jti,
        )
        auth_manager._jti_blacklist.add(jti)
        with pytest.raises(InvalidTokenError, match="revoked"):
            await auth_manager.verify_access_token(token)


# ── Refresh Token Rotation ──────────────────────────────────


class TestRefreshToken:
    async def test_refresh_success(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        refresh_result = await auth_manager.refresh_access_token(
            login_result["refresh_token"],
        )
        assert "access_token" in refresh_result
        assert "refresh_token" in refresh_result
        assert refresh_result["refresh_token"] != login_result["refresh_token"]

    async def test_refresh_invalid_token(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid refresh token"):
            await auth_manager.refresh_access_token("invalid-token")

    async def test_refresh_revoked_token(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login_result["refresh_token"],
        )
        with pytest.raises(InvalidTokenError, match="revoked"):
            await auth_manager.refresh_access_token(
                login_result["refresh_token"],
            )

    async def test_refresh_reuse_detection(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.refresh_access_token(login_result["refresh_token"])
        with pytest.raises(InvalidTokenError, match="reuse detected"):
            await auth_manager.refresh_access_token(login_result["refresh_token"])

    async def test_refresh_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        refresh_events: list[dict] = []
        auth_manager.events.on(
            Event.TOKEN_REFRESHED, lambda d: refresh_events.append(d)
        )

        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.refresh_access_token(login_result["refresh_token"])
        assert len(refresh_events) == 1

    async def test_refresh_reuse_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        reuse_events: list[dict] = []
        auth_manager.events.on(
            Event.TOKEN_REUSE_DETECTED, lambda d: reuse_events.append(d)
        )

        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.refresh_access_token(login_result["refresh_token"])
        try:
            await auth_manager.refresh_access_token(login_result["refresh_token"])
        except InvalidTokenError:
            pass
        assert len(reuse_events) == 1

    async def test_refresh_new_token_works(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        refresh_result = await auth_manager.refresh_access_token(
            login_result["refresh_token"],
        )
        payload = await auth_manager.verify_access_token(refresh_result["access_token"])
        assert payload["user_id"] == verified_user["id"]


# ── Email Verification ──────────────────────────────────────


class TestEmailVerification:
    async def test_request_and_verify(self, auth_manager: AsyncAuthManager):
        user = await auth_manager.register(
            name="Test",
            email="test@example.com",
            password="SecureP@ss1234!",
            auto_verify=False,
        )
        token = await auth_manager.request_email_verification(user["id"])
        assert token

        result = await auth_manager.verify_email(token)
        assert result["is_verified"] is True

    async def test_verify_invalid_token(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            await auth_manager.verify_email("invalid-token")

    async def test_request_for_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.request_email_verification(99999)

    async def test_already_verified_returns_empty(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        token = await auth_manager.request_email_verification(verified_user["id"])
        assert token == ""


# ── Password Reset ──────────────────────────────────────────


class TestPasswordReset:
    async def test_request_and_reset(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        token = await auth_manager.request_password_reset("test@example.com")
        assert token

        result = await auth_manager.reset_password(token, "NewSecureP@ss1234!")
        assert result["id"] == registered_user["id"]

        with pytest.raises(InvalidCredentialsError):
            await auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

        login_result = await auth_manager.login(
            email="test@example.com",
            password="NewSecureP@ss1234!",
        )
        assert "access_token" in login_result

    async def test_request_nonexistent_email(self, auth_manager: AsyncAuthManager):
        token = await auth_manager.request_password_reset("nonexistent@example.com")
        assert token == ""

    async def test_reset_invalid_token(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            await auth_manager.reset_password("invalid-token", "NewP@ss1234!")

    async def test_reset_weak_password(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        token = await auth_manager.request_password_reset("test@example.com")
        with pytest.raises(ValidationError, match="at least 12 characters"):
            await auth_manager.reset_password(token, "weak")

    async def test_reset_revokes_all_tokens(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        token = await auth_manager.request_password_reset("test@example.com")
        await auth_manager.reset_password(token, "NewSecureP@ss1234!")

        tokens = await auth_manager.storage.list_refresh_tokens_for_user(
            registered_user["id"]
        )
        assert all(t.get("revoked", False) for t in tokens)

    async def test_reset_emits_event(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_PASSWORD_CHANGED, lambda d: events.append(d))

        token = await auth_manager.request_password_reset("test@example.com")
        await auth_manager.reset_password(token, "NewSecureP@ss1234!")
        assert len(events) == 1


# ── Change Password ─────────────────────────────────────────


class TestChangePassword:
    async def test_change_password_success(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        assert result["id"] == registered_user["id"]

        with pytest.raises(InvalidCredentialsError):
            await auth_manager.login(
                email="test@example.com",
                password="SecureP@ss1234!",
            )

    async def test_change_wrong_current_password(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        with pytest.raises(
            InvalidCredentialsError, match="Current password is incorrect"
        ):
            await auth_manager.change_password(
                user_id=registered_user["id"],
                current_password="WrongPassword123!",
                new_password="NewSecureP@ss1234!",
            )

    async def test_change_password_history_check(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        await auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        with pytest.raises(ValidationError, match="reuse a password"):
            await auth_manager.change_password(
                user_id=registered_user["id"],
                current_password="NewSecureP@ss1234!",
                new_password="SecureP@ss1234!",
            )

    async def test_change_password_nonexistent_user(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(UserNotFoundError):
            await auth_manager.change_password(
                user_id=99999,
                current_password="Password123!",
                new_password="NewSecureP@ss1234!",
            )

    async def test_change_password_emits_event(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_PASSWORD_CHANGED, lambda d: events.append(d))

        await auth_manager.change_password(
            user_id=registered_user["id"],
            current_password="SecureP@ss1234!",
            new_password="NewSecureP@ss1234!",
        )
        assert len(events) == 1


# ── Email Change ────────────────────────────────────────────


class TestEmailChange:
    async def test_request_and_confirm(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        token = await auth_manager.request_email_change(
            user_id=registered_user["id"],
            new_email="newemail@example.com",
            current_password="SecureP@ss1234!",
        )
        assert token

        result = await auth_manager.confirm_email_change(token)
        assert result["email"] == "newemail@example.com"

    async def test_request_wrong_password(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        with pytest.raises(
            InvalidCredentialsError, match="Current password is incorrect"
        ):
            await auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="newemail@example.com",
                current_password="WrongPassword123!",
            )

    async def test_request_same_email(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        with pytest.raises(ValidationError, match="different from current"):
            await auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="test@example.com",
                current_password="SecureP@ss1234!",
            )

    async def test_request_invalid_email(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        with pytest.raises(ValidationError, match="Invalid email format"):
            await auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="not-valid",
                current_password="SecureP@ss1234!",
            )

    async def test_request_existing_email(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        await auth_manager.register(
            name="Other",
            email="other@example.com",
            password="UniqueP@ss9876!",
        )
        with pytest.raises(UserExistsError):
            await auth_manager.request_email_change(
                user_id=registered_user["id"],
                new_email="other@example.com",
                current_password="SecureP@ss1234!",
            )

    async def test_confirm_invalid_token(self, auth_manager: AsyncAuthManager):
        with pytest.raises(InvalidTokenError, match="Invalid or expired"):
            await auth_manager.confirm_email_change("invalid-token")

    async def test_email_change_emits_event(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_EMAIL_CHANGED, lambda d: events.append(d))

        token = await auth_manager.request_email_change(
            user_id=registered_user["id"],
            new_email="newemail@example.com",
            current_password="SecureP@ss1234!",
        )
        await auth_manager.confirm_email_change(token)
        assert len(events) == 1
        assert events[0]["new_email"] == "newemail@example.com"


# ── Logout ──────────────────────────────────────────────────


class TestLogout:
    async def test_logout_specific_token(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login_result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login_result["refresh_token"],
        )
        with pytest.raises(InvalidTokenError, match="revoked"):
            await auth_manager.refresh_access_token(login_result["refresh_token"])

    async def test_logout_all(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.logout_all(
            user_id=verified_user["id"],
            exclude_refresh_token=login2["refresh_token"],
        )
        tokens = await auth_manager.storage.list_refresh_tokens_for_user(
            verified_user["id"]
        )
        revoked = [t for t in tokens if t.get("revoked")]
        active = [t for t in tokens if not t.get("revoked")]
        assert len(revoked) >= 1
        assert len(active) <= 1

    async def test_logout_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on(Event.USER_LOGOUT, lambda d: events.append(d))

        await auth_manager.logout(user_id=verified_user["id"])
        assert len(events) == 1

    async def test_logout_all_returns_count(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        count = await auth_manager.logout_all(user_id=verified_user["id"])
        assert count >= 1


class TestSessionManagement:
    async def test_list_sessions_empty(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        assert await auth_manager.list_sessions(verified_user["id"]) == []

    async def test_list_sessions_after_logins(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        sessions = await auth_manager.list_sessions(verified_user["id"])
        assert len(sessions) == 2
        assert {"id", "created_at", "expires_at"} <= set(sessions[0])

    async def test_list_sessions_excludes_revoked(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login1 = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.logout(
            user_id=verified_user["id"],
            refresh_token=login1["refresh_token"],
        )
        sessions = await auth_manager.list_sessions(verified_user["id"])
        assert len(sessions) == 1
        login2_token = await auth_manager.storage.get_refresh_token_by_hash(
            hash_token(login2["refresh_token"])
        )
        assert login2_token is not None
        assert sessions[0]["id"] == login2_token["id"]

    async def test_revoke_session_by_id(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        login = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        token_id = (
            await auth_manager.storage.list_refresh_tokens_for_user(verified_user["id"])
        )[0]["id"]
        assert await auth_manager.revoke_session_by_id(verified_user["id"], token_id)
        assert await auth_manager.list_sessions(verified_user["id"]) == []
        with pytest.raises(InvalidTokenError, match="revoked"):
            await auth_manager.refresh_access_token(login["refresh_token"])

    async def test_revoke_session_by_id_unauthorized(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        token_id = (
            await auth_manager.storage.list_refresh_tokens_for_user(verified_user["id"])
        )[0]["id"]
        # Different user cannot revoke
        assert not await auth_manager.revoke_session_by_id(99999, token_id)
        assert len(await auth_manager.list_sessions(verified_user["id"])) == 1

    async def test_revoke_session_by_id_nonexistent(
        self, auth_manager: AsyncAuthManager
    ):
        assert not await auth_manager.revoke_session_by_id(1, 99999)

    async def test_revoke_all_sessions_for_user(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        count = await auth_manager.revoke_all_sessions_for_user(verified_user["id"])
        assert count == 2
        assert await auth_manager.list_sessions(verified_user["id"]) == []

    async def test_revoke_all_sessions_excluding_one(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2 = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        login2_token = await auth_manager.storage.get_refresh_token_by_hash(
            hash_token(login2["refresh_token"])
        )
        assert login2_token is not None
        keep_id = login2_token["id"]
        count = await auth_manager.revoke_all_sessions_for_user(
            verified_user["id"], exclude_token_id=keep_id
        )
        assert count == 1
        remaining = await auth_manager.list_sessions(verified_user["id"])
        assert len(remaining) == 1
        assert remaining[0]["id"] == keep_id


class TestAsyncContextManager:
    async def test_async_context_manager_closes_storage(
        self, test_config: AuthConfig, mem_db: AsyncSQLiteStorage
    ):
        async with AsyncAuthManager(test_config, mem_db) as auth:
            user = await auth.register(
                name="CM User",
                email="cm@example.com",
                password="SecureP@ss1234!",
                auto_verify=True,
            )
            assert (await auth.get_user(user["id"]))["email"] == "cm@example.com"
        # Storage connection should be closed after exiting the context
        assert mem_db._conn is None


# ── User Management ─────────────────────────────────────────


class TestUserManagement:
    async def test_get_user(self, auth_manager: AsyncAuthManager, verified_user: dict):
        user = await auth_manager.get_user(verified_user["id"])
        assert user["email"] == "verified@example.com"
        assert "password_hash" not in user

    async def test_get_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.get_user(99999)

    async def test_update_user(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.update_user(
            verified_user["id"],
            {"name": "Updated Name"},
        )
        assert result["name"] == "Updated Name"

    async def test_update_user_protected_fields(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        original_email = verified_user["email"]
        result = await auth_manager.update_user(
            verified_user["id"],
            {"email": "hacked@example.com", "name": "New Name"},
        )
        assert result["email"] == original_email
        assert result["name"] == "New Name"

    async def test_update_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.update_user(99999, {"name": "X"})

    async def test_delete_user(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.delete_user(registered_user["id"])
        assert result is True
        with pytest.raises(UserNotFoundError):
            await auth_manager.get_user(registered_user["id"])

    async def test_delete_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.delete_user(99999)

    async def test_delete_user_revokes_tokens(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        await auth_manager.delete_user(registered_user["id"])
        tokens = await auth_manager.storage.list_refresh_tokens_for_user(
            registered_user["id"]
        )
        assert all(t.get("revoked", False) for t in tokens)


# ── RBAC ────────────────────────────────────────────────────


class TestRBAC:
    async def test_create_role(self, auth_manager: AsyncAuthManager):
        role = await auth_manager.create_role("admin", "Administrator role")
        assert role["name"] == "admin"
        assert role["description"] == "Administrator role"
        assert "id" in role

    async def test_create_role_no_description(self, auth_manager: AsyncAuthManager):
        role = await auth_manager.create_role("viewer")
        assert role["name"] == "viewer"
        assert role["description"] is None

    async def test_list_roles_empty(self, auth_manager: AsyncAuthManager):
        assert await auth_manager.list_roles() == []

    async def test_list_roles(self, auth_manager: AsyncAuthManager):
        await auth_manager.create_role("admin")
        await auth_manager.create_role("editor")
        roles = await auth_manager.list_roles()
        assert len(roles) == 2
        names = {r["name"] for r in roles}
        assert names == {"admin", "editor"}

    async def test_delete_role(self, auth_manager: AsyncAuthManager):
        role = await auth_manager.create_role("temp")
        assert await auth_manager.delete_role(role["id"])
        assert await auth_manager.list_roles() == []

    async def test_create_permission(self, auth_manager: AsyncAuthManager):
        perm = await auth_manager.create_permission("users:read", "Read users")
        assert perm["code"] == "users:read"
        assert perm["description"] == "Read users"
        assert "id" in perm

    async def test_list_permissions(self, auth_manager: AsyncAuthManager):
        await auth_manager.create_permission("users:read")
        await auth_manager.create_permission("users:write")
        perms = await auth_manager.list_permissions()
        assert len(perms) == 2

    async def test_delete_permission(self, auth_manager: AsyncAuthManager):
        perm = await auth_manager.create_permission("temp:perm")
        assert await auth_manager.delete_permission(perm["id"])
        assert await auth_manager.list_permissions() == []

    async def test_assign_and_remove_permission(self, auth_manager: AsyncAuthManager):
        role = await auth_manager.create_role("admin")
        perm = await auth_manager.create_permission("users:manage")

        assert await auth_manager.assign_permission_to_role(role["id"], perm["id"])

        role_perms = await auth_manager.get_role_permissions(role["id"])
        assert len(role_perms) == 1
        assert role_perms[0]["code"] == "users:manage"

        assert await auth_manager.remove_permission_from_role(role["id"], perm["id"])
        assert await auth_manager.get_role_permissions(role["id"]) == []

    async def test_assign_and_remove_role(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        role = await auth_manager.create_role("admin")
        assert await auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        user_roles = await auth_manager.get_user_roles(verified_user["id"])
        assert len(user_roles) == 1
        assert user_roles[0]["name"] == "admin"

        assert await auth_manager.remove_role_from_user(verified_user["id"], role["id"])
        assert await auth_manager.get_user_roles(verified_user["id"]) == []

    async def test_user_permissions_from_roles(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        role = await auth_manager.create_role("editor")
        perm1 = await auth_manager.create_permission("posts:read")
        perm2 = await auth_manager.create_permission("posts:write")

        await auth_manager.assign_permission_to_role(role["id"], perm1["id"])
        await auth_manager.assign_permission_to_role(role["id"], perm2["id"])
        await auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        perms = await auth_manager.get_user_permissions(verified_user["id"])
        assert set(perms) == {"posts:read", "posts:write"}

    async def test_has_permission(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        role = await auth_manager.create_role("viewer")
        perm = await auth_manager.create_permission("content:read")
        await auth_manager.assign_permission_to_role(role["id"], perm["id"])
        await auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        assert await auth_manager.has_permission(verified_user["id"], "content:read")
        assert not await auth_manager.has_permission(
            verified_user["id"], "content:write"
        )

    async def test_no_permissions(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        assert await auth_manager.get_user_permissions(verified_user["id"]) == []
        assert not await auth_manager.has_permission(verified_user["id"], "anything")


class TestAsyncRequirePermission:
    async def test_require_permission_passes(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        role = await auth_manager.create_role("viewer")
        perm = await auth_manager.create_permission("content:read")
        await auth_manager.assign_permission_to_role(role["id"], perm["id"])
        await auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        await auth_manager.require_permission(verified_user["id"], "content:read")

    async def test_require_permission_denied(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        role = await auth_manager.create_role("viewer")
        perm = await auth_manager.create_permission("content:read")
        await auth_manager.assign_permission_to_role(role["id"], perm["id"])
        await auth_manager.assign_role_to_user(verified_user["id"], role["id"])

        with pytest.raises(InsufficientPermissionsError, match="content:write"):
            await auth_manager.require_permission(verified_user["id"], "content:write")

    async def test_require_permission_no_permissions(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        with pytest.raises(InsufficientPermissionsError):
            await auth_manager.require_permission(verified_user["id"], "anything")


# ── API Keys ────────────────────────────────────────────────


class TestAPIKeys:
    async def test_create_api_key(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.create_api_key(
            verified_user["id"],
            description="Test key",
            scopes=["read", "write"],
        )
        assert "key" in result
        assert result["prefix"] == result["key"][:8]
        assert result["description"] == "Test key"
        assert result["scopes"] == ["read", "write"]
        assert result["expires_at"] is None

    async def test_create_api_key_with_expiry(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.create_api_key(
            verified_user["id"],
            expires_in_days=30,
        )
        assert result["expires_at"] is not None

    async def test_create_api_key_no_scopes(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.create_api_key(verified_user["id"])
        assert result["scopes"] == []

    async def test_verify_valid_key(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        create_result = await auth_manager.create_api_key(
            verified_user["id"],
            scopes=["read"],
        )
        verified = await auth_manager.verify_api_key(create_result["key"])
        assert verified["user_id"] == verified_user["id"]
        assert verified["scopes"] == ["read"]

    async def test_verify_invalid_key(self, auth_manager: AsyncAuthManager):
        from authority.exceptions import InvalidAPIKeyError

        with pytest.raises(InvalidAPIKeyError, match="Invalid API key"):
            await auth_manager.verify_api_key("invalid-key-here")

    async def test_verify_expired_key(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import InvalidAPIKeyError

        create_result = await auth_manager.create_api_key(
            verified_user["id"],
            expires_in_days=-1,
        )
        with pytest.raises(InvalidAPIKeyError, match="expired"):
            await auth_manager.verify_api_key(create_result["key"])

    async def test_verify_updates_last_used(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        create_result = await auth_manager.create_api_key(verified_user["id"])
        await auth_manager.verify_api_key(create_result["key"])

        keys = await auth_manager.list_api_keys(verified_user["id"])
        assert keys[0]["last_used_at"] is not None

    async def test_list_empty(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        assert await auth_manager.list_api_keys(verified_user["id"]) == []

    async def test_list_keys(self, auth_manager: AsyncAuthManager, verified_user: dict):
        await auth_manager.create_api_key(verified_user["id"], description="Key 1")
        await auth_manager.create_api_key(verified_user["id"], description="Key 2")
        keys = await auth_manager.list_api_keys(verified_user["id"])
        assert len(keys) == 2
        for k in keys:
            assert "key" not in k or k.get("key") is None

    async def test_revoke_key(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import InvalidAPIKeyError

        create_result = await auth_manager.create_api_key(
            verified_user["id"], description="To revoke"
        )
        prefix = create_result["prefix"]
        assert await auth_manager.revoke_api_key(verified_user["id"], prefix)

        with pytest.raises(InvalidAPIKeyError):
            await auth_manager.verify_api_key(create_result["key"])

    async def test_revoke_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("api_key.revoked", lambda d: events.append(d))

        create_result = await auth_manager.create_api_key(verified_user["id"])
        await auth_manager.revoke_api_key(verified_user["id"], create_result["prefix"])
        assert len(events) == 1


# ── Audit Log ───────────────────────────────────────────────


class TestAuditLog:
    async def test_audit_log_empty(self, auth_manager: AsyncAuthManager):
        logs = await auth_manager.get_audit_log()
        assert logs == []

    async def test_audit_log_after_register(self, auth_manager: AsyncAuthManager):
        await auth_manager.register(
            name="Audit User",
            email="audit@example.com",
            password="SecureP@ss1234!",
        )
        logs = await auth_manager.get_audit_log()
        assert len(logs) >= 1
        assert logs[0]["action"] == "user.registered"

    async def test_audit_log_filter_by_user(self, auth_manager: AsyncAuthManager):
        user1 = await auth_manager.register(
            name="User 1", email="u1@example.com", password="SecureP@ss1234!"
        )
        await auth_manager.register(
            name="User 2", email="u2@example.com", password="SecureP@ss1234!"
        )
        logs = await auth_manager.get_audit_log(user_id=user1["id"])
        for log in logs:
            assert log["user_id"] == user1["id"]

    async def test_audit_log_filter_by_action(self, auth_manager: AsyncAuthManager):
        await auth_manager.register(
            name="Test", email="test@example.com", password="SecureP@ss1234!"
        )
        logs = await auth_manager.get_audit_log(action="user.registered")
        assert len(logs) >= 1
        assert all(entry["action"] == "user.registered" for entry in logs)

    async def test_audit_log_pagination(self, auth_manager: AsyncAuthManager):
        for i in range(5):
            await auth_manager.register(
                name=f"User {i}",
                email=f"user{i}@example.com",
                password="SecureP@ss1234!",
            )
        logs_page1 = await auth_manager.get_audit_log(limit=2, offset=0)
        logs_page2 = await auth_manager.get_audit_log(limit=2, offset=2)
        assert len(logs_page1) == 2
        assert len(logs_page2) == 2
        assert logs_page1[0]["id"] != logs_page2[0]["id"]


# ── Profile ─────────────────────────────────────────────────


class TestProfile:
    async def test_get_profile_empty(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        profile = await auth_manager.get_profile(verified_user["id"])
        assert profile == {}

    async def test_update_profile(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark", "language": "en"},
        )
        assert result == {"theme": "dark", "language": "en"}

    async def test_get_profile(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark"},
        )
        profile = await auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "dark"}

    async def test_update_profile_merges(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark", "language": "en"},
        )
        await auth_manager.update_profile(
            verified_user["id"],
            {"theme": "light"},
        )
        profile = await auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "light", "language": "en"}

    async def test_update_profile_adds_new_fields(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        await auth_manager.update_profile(
            verified_user["id"],
            {"theme": "dark"},
        )
        await auth_manager.update_profile(
            verified_user["id"],
            {"notifications": True},
        )
        profile = await auth_manager.get_profile(verified_user["id"])
        assert profile == {"theme": "dark", "notifications": True}


# ── MFA (Async) ────────────────────────────────────────────


def _make_totp_code(secret: str) -> str:
    """Generate a valid TOTP code from a secret."""
    import pyotp

    return pyotp.TOTP(secret).now()


class TestAsyncSetupMFA:
    async def test_setup_mfa_returns_secret_and_uri(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.setup_mfa(verified_user["id"])
        assert "secret" in result
        assert "provisioning_uri" in result
        assert result["recovery_code_count"] == 10
        assert len(result["secret"]) == 32

    async def test_setup_mfa_stores_encrypted_secret(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.setup_mfa(verified_user["id"])
        user = await auth_manager.storage.get_user_by_id(verified_user["id"])
        assert user["mfa_secret_encrypted"] is not None
        assert user["mfa_secret_encrypted"] != result["secret"]

    async def test_setup_mfa_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.setup_mfa(99999)

    async def test_setup_mfa_already_enabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import MFANotEnabledError

        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(verified_user["id"], code)
        with pytest.raises(MFANotEnabledError, match="already enabled"):
            await auth_manager.setup_mfa(verified_user["id"])

    async def test_setup_mfa_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.setup_initiated", lambda d: events.append(d))
        await auth_manager.setup_mfa(verified_user["id"])
        assert len(events) == 1

    async def test_provisioning_uri_format(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.setup_mfa(verified_user["id"])
        uri = result["provisioning_uri"]
        assert uri.startswith("otpauth://totp/")
        assert "verified%40example.com" in uri or "verified@example.com" in uri


class TestAsyncVerifyAndEnableMFA:
    async def test_verify_and_enable_success(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        result = await auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        assert "recovery_codes" in result
        assert len(result["recovery_codes"]) == 10
        assert result["recovery_code_count"] == 10

        user = await auth_manager.storage.get_user_by_id(verified_user["id"])
        assert user["mfa_enabled"] is True

    async def test_verify_and_enable_wrong_code(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import MFAFailedError

        await auth_manager.setup_mfa(verified_user["id"])
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            await auth_manager.verify_and_enable_mfa(verified_user["id"], "000000")

    async def test_verify_and_enable_no_setup(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        with pytest.raises(ValidationError, match="MFA secret not found"):
            await auth_manager.verify_and_enable_mfa(verified_user["id"], "123456")

    async def test_verify_and_enable_nonexistent_user(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(UserNotFoundError):
            await auth_manager.verify_and_enable_mfa(99999, "123456")

    async def test_verify_and_enable_stores_hashed_recovery_codes(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        count = await auth_manager.storage.get_active_mfa_recovery_codes_count(
            verified_user["id"]
        )
        assert count == 10

    async def test_verify_and_enable_emits_event(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.enabled", lambda d: events.append(d))

        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(verified_user["id"], code)
        assert len(events) == 1


class TestAsyncMFALogin:
    @pytest.fixture()
    async def mfa_user(self, auth_manager: AsyncAuthManager) -> dict:
        user = await auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = await auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(user["id"], code)
        return {"user": user, "secret": setup["secret"]}

    async def test_login_returns_mfa_required(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        result = await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        assert result.get("mfa_required") is True
        assert "access_token" not in result
        assert "refresh_token" not in result

    async def test_mfa_login_with_totp(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        code = _make_totp_code(mfa_user["secret"])
        result = await auth_manager.verify_mfa_login(mfa_user["user"]["id"], code)
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"]["mfa_enabled"] is True

    async def test_mfa_login_with_recovery_code(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        result = await auth_manager.regenerate_recovery_codes(
            mfa_user["user"]["id"], "SecureP@ss1234!"
        )
        recovery_code = result["recovery_codes"][0]

        login_result = await auth_manager.verify_mfa_login(
            mfa_user["user"]["id"], recovery_code
        )
        assert "access_token" in login_result

    async def test_mfa_login_recovery_code_single_use(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        result = await auth_manager.regenerate_recovery_codes(
            mfa_user["user"]["id"], "SecureP@ss1234!"
        )
        recovery_code = result["recovery_codes"][0]

        await auth_manager.verify_mfa_login(mfa_user["user"]["id"], recovery_code)

        from authority.exceptions import MFAFailedError

        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            await auth_manager.verify_mfa_login(mfa_user["user"]["id"], recovery_code)

    async def test_mfa_login_invalid_code(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        from authority.exceptions import MFAFailedError

        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            await auth_manager.verify_mfa_login(mfa_user["user"]["id"], "000000")

    async def test_mfa_login_nonexistent_user(self, auth_manager: AsyncAuthManager):

        with pytest.raises(UserNotFoundError):
            await auth_manager.verify_mfa_login(99999, "123456")

    async def test_mfa_login_not_enabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import MFAFailedError

        with pytest.raises(MFAFailedError, match="MFA is not enabled"):
            await auth_manager.verify_mfa_login(verified_user["id"], "123456")

    async def test_mfa_login_emits_event_on_success(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("user.login_success", lambda d: events.append(d))

        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        code = _make_totp_code(mfa_user["secret"])
        await auth_manager.verify_mfa_login(mfa_user["user"]["id"], code)
        assert len(events) == 1

    async def test_mfa_login_emits_event_on_failure(
        self, auth_manager: AsyncAuthManager, mfa_user: dict
    ):
        from authority.exceptions import MFAFailedError

        events: list[dict] = []
        auth_manager.events.on("mfa.failed", lambda d: events.append(d))

        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        try:
            await auth_manager.verify_mfa_login(mfa_user["user"]["id"], "000000")
        except MFAFailedError:
            pass
        assert len(events) == 1


class TestAsyncDisableMFA:
    @pytest.fixture()
    async def mfa_enabled_user(self, auth_manager: AsyncAuthManager) -> dict:
        user = await auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = await auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(user["id"], code)
        return user

    async def test_disable_mfa_success(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        result = await auth_manager.disable_mfa(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )
        assert result["mfa_enabled"] is False

        user = await auth_manager.storage.get_user_by_id(mfa_enabled_user["id"])
        assert user["mfa_secret_encrypted"] is None
        assert user["mfa_enabled"] is False

    async def test_disable_mfa_wrong_password(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Password is incorrect"):
            await auth_manager.disable_mfa(mfa_enabled_user["id"], "WrongPassword123!")

    async def test_disable_mfa_not_enabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import MFANotEnabledError

        with pytest.raises(MFANotEnabledError, match="not enabled"):
            await auth_manager.disable_mfa(verified_user["id"], "SecureP@ss1234!")

    async def test_disable_mfa_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.disable_mfa(99999, "Password123!")

    async def test_disable_mfa_clears_recovery_codes(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        await auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        count = await auth_manager.storage.get_active_mfa_recovery_codes_count(
            mfa_enabled_user["id"]
        )
        assert count == 0

    async def test_disable_mfa_emits_event(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.disabled", lambda d: events.append(d))
        await auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        assert len(events) == 1

    async def test_login_after_disable_no_mfa_challenge(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        await auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        result = await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        assert "access_token" in result
        assert result.get("mfa_required") is not True


class TestAsyncRegenerateRecoveryCodes:
    @pytest.fixture()
    async def mfa_enabled_user(self, auth_manager: AsyncAuthManager) -> dict:
        user = await auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = await auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(user["id"], code)
        return user

    async def test_regenerate_success(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        result = await auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )
        assert "recovery_codes" in result
        assert len(result["recovery_codes"]) == 10
        assert result["recovery_code_count"] == 10

    async def test_regenerate_wrong_password(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Password is incorrect"):
            await auth_manager.regenerate_recovery_codes(
                mfa_enabled_user["id"], "WrongPassword123!"
            )

    async def test_regenerate_not_enabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        from authority.exceptions import MFANotEnabledError

        with pytest.raises(MFANotEnabledError, match="not enabled"):
            await auth_manager.regenerate_recovery_codes(
                verified_user["id"], "SecureP@ss1234!"
            )

    async def test_regenerate_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.regenerate_recovery_codes(99999, "Password123!")

    async def test_regenerate_invalidates_old_codes(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        old_result = await auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )
        old_code = old_result["recovery_codes"][0]

        await auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )

        await auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        from authority.exceptions import MFAFailedError

        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            await auth_manager.verify_mfa_login(mfa_enabled_user["id"], old_code)


class TestAsyncGetMFAStatus:
    async def test_status_mfa_disabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        status = await auth_manager.get_mfa_status(verified_user["id"])
        assert status["mfa_enabled"] is False
        assert status["recovery_codes_remaining"] == 0

    async def test_status_mfa_enabled(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        status = await auth_manager.get_mfa_status(verified_user["id"])
        assert status["mfa_enabled"] is True
        assert status["recovery_codes_remaining"] == 10

    async def test_status_nonexistent_user(self, auth_manager: AsyncAuthManager):
        with pytest.raises(UserNotFoundError):
            await auth_manager.get_mfa_status(99999)


class TestAsyncMFACodeFormats:
    async def test_recovery_code_format(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        result = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(result["secret"])
        enable_result = await auth_manager.verify_and_enable_mfa(
            verified_user["id"], code
        )

        for rc in enable_result["recovery_codes"]:
            parts = rc.split("-")
            assert len(parts) == 3
            assert all(len(p) == 4 for p in parts)
            assert all(p.isalnum() for p in parts)

    async def test_totp_code_is_6_digits(self):
        import pyotp

        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        assert len(code) == 6
        assert code.isdigit()


class TestAsyncVerifyRecoveryCode:
    @pytest.fixture()
    async def mfa_enabled_user(self, auth_manager: AsyncAuthManager) -> dict:
        user = await auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = await auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        result = await auth_manager.verify_and_enable_mfa(user["id"], code)
        return {**user, "recovery_codes": result["recovery_codes"]}

    async def test_verify_valid_recovery_code(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        code = mfa_enabled_user["recovery_codes"][0]
        assert await auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], code)

    async def test_verify_recovery_code_single_use(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        code = mfa_enabled_user["recovery_codes"][0]
        assert await auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], code)
        assert not await auth_manager.verify_mfa_recovery_code(
            mfa_enabled_user["id"], code
        )

    async def test_verify_invalid_recovery_code(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        assert not await auth_manager.verify_mfa_recovery_code(
            mfa_enabled_user["id"], "AAAA-AAAA-AAAA"
        )

    async def test_verify_empty_code(
        self, auth_manager: AsyncAuthManager, mfa_enabled_user: dict
    ):
        assert not await auth_manager.verify_mfa_recovery_code(
            mfa_enabled_user["id"], ""
        )


# ── Edge Cases (Async) ──────────────────────────────────────


class TestAsyncEdgeCases:
    async def test_login_mfa_enabled_returns_mfa_required(
        self, auth_manager: AsyncAuthManager, verified_user: dict
    ):
        setup = await auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        await auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        result = await auth_manager.login(
            email="verified@example.com",
            password="AuthP@ss12345!",
        )
        assert result.get("mfa_required") is True
        assert result.get("user_id") == verified_user["id"]
        assert "access_token" not in result

    async def test_refresh_token_expired(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        login_result = await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        refresh_token = login_result["refresh_token"]

        # Manually expire the token in storage
        user = await auth_manager.storage.get_user_by_id(registered_user["id"])
        tokens = await auth_manager.storage.list_refresh_tokens_for_user(
            registered_user["id"]
        )
        assert len(tokens) > 0

        async with auth_manager.storage._conn.execute(
            "UPDATE refresh_tokens SET expires_at = ? WHERE id = ?",
            (
                datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc),
                tokens[0]["id"],
            ),
        ):
            pass
        await auth_manager.storage._conn.commit()

        with pytest.raises(TokenExpiredError):
            await auth_manager.refresh_access_token(refresh_token)

    async def test_verify_email_expired_token(self, auth_manager: AsyncAuthManager):
        user = await auth_manager.register(
            name="Exp User",
            email="exp@example.com",
            password="SecureP@ss1234!",
            auto_verify=False,
        )
        await auth_manager.request_email_verification(user["id"])

        # Manually expire the token
        from authority.utils import hash_token

        token = "expired-token"
        token_hash = hash_token(token)
        await auth_manager.storage.update_user(
            user["id"],
            {
                "verification_token_hash": token_hash,
                "verification_token_expiry": datetime.datetime(2020, 1, 1),
            },
        )

        with pytest.raises(TokenExpiredError):
            await auth_manager.verify_email(token)

    async def test_reset_password_expired_token(self, auth_manager: AsyncAuthManager):
        user = await auth_manager.register(
            name="Reset User",
            email="reset@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        await auth_manager.request_password_reset("reset@example.com")

        token = "expired-reset-token"
        token_hash = hash_token(token)
        await auth_manager.storage.update_user(
            user["id"],
            {
                "reset_token_hash": token_hash,
                "reset_token_expiry": datetime.datetime(2020, 1, 1),
            },
        )

        with pytest.raises(TokenExpiredError):
            await auth_manager.reset_password(token, "NewP@ss1234!")

    async def test_logout_with_jti_blacklist(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        login_result = await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        access_token = login_result["access_token"]
        payload = pyjwt.decode(
            access_token,
            auth_manager._config.jwt_secret_key,
            algorithms=["HS256"],
        )
        jti = payload["jti"]

        await auth_manager.logout(registered_user["id"], access_token_jti=jti)

        assert jti in auth_manager._jti_blacklist
        with pytest.raises(InvalidTokenError):
            await auth_manager.verify_access_token(access_token)

    async def test_update_user_protected_fields(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.update_user(
            registered_user["id"],
            {"id": 999, "password_hash": "x", "email": "new@example.com"},
        )
        # Protected fields should not be changed
        assert result["email"] == "test@example.com"

    async def test_password_history_depth_zero(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        auth_manager._config.password_history_depth = 0
        await auth_manager.login(
            email="test@example.com",
            password="SecureP@ss1234!",
        )
        await auth_manager.change_password(
            registered_user["id"], "SecureP@ss1234!", "NewP@ss12345!"
        )
        # Change back to original - should succeed because depth=0 skips check
        await auth_manager.change_password(
            registered_user["id"], "NewP@ss12345!", "SecureP@ss1234!"
        )

    async def test_verify_api_key_naive_expiry(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.create_api_key(
            registered_user["id"],
            description="Test Key",
            expires_in_days=365,
        )
        full_key = result["key"]

        # Verify works
        verified = await auth_manager.verify_api_key(full_key)
        assert verified is not None
        assert verified["user_id"] == registered_user["id"]

    async def test_verify_api_key_malformed_scopes(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):

        # Create a key normally
        result = await auth_manager.create_api_key(
            registered_user["id"],
            description="Bad Scopes Key",
            scopes=["read"],
        )
        full_key = result["key"]

        # Now corrupt the scopes_json directly in storage
        prefix = full_key[:8]
        await auth_manager.storage._conn.execute(
            "UPDATE api_keys SET scopes_json = ? WHERE key_prefix = ?",
            ("not-valid-json{", prefix),
        )
        await auth_manager.storage._conn.commit()

        verified = await auth_manager.verify_api_key(full_key)
        assert verified is not None
        assert verified["scopes"] == []

    async def test_list_api_keys_malformed_scopes(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        result = await auth_manager.create_api_key(
            registered_user["id"],
            description="Bad Key",
        )
        full_key = result["key"]
        prefix = full_key[:8]

        # Corrupt scopes_json
        await auth_manager.storage._conn.execute(
            "UPDATE api_keys SET scopes_json = ? WHERE key_prefix = ?",
            ("invalid", prefix),
        )
        await auth_manager.storage._conn.commit()

        keys = await auth_manager.list_api_keys(registered_user["id"])
        bad_keys = [k for k in keys if k["key_prefix"] == prefix]
        assert len(bad_keys) == 1
        assert bad_keys[0]["scopes"] == []

    async def test_request_email_change_user_not_found(
        self, auth_manager: AsyncAuthManager
    ):
        with pytest.raises(UserNotFoundError):
            await auth_manager.request_email_change(
                99999, "new@example.com", "SecureP@ss1234!"
            )

    async def test_request_email_change_pending_conflict(
        self, auth_manager: AsyncAuthManager
    ):
        user_a = await auth_manager.register(
            name="User A",
            email="a@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        user_b = await auth_manager.register(
            name="User B",
            email="b@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )

        # User A requests change to new@example.com (don't confirm)
        await auth_manager.request_email_change(
            user_a["id"], "new@example.com", "SecureP@ss1234!"
        )

        # User B tries the same pending email
        with pytest.raises(UserExistsError, match="pending"):
            await auth_manager.request_email_change(
                user_b["id"], "new@example.com", "SecureP@ss1234!"
            )

    async def test_confirm_email_change_no_pending(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        from authority.utils import hash_token

        token = "some-valid-token"
        token_hash = hash_token(token)
        await auth_manager.storage.update_user(
            registered_user["id"],
            {
                "email_change_token_hash": token_hash,
                "email_change_token_expiry": datetime.datetime(2030, 1, 1),
                "pending_email": None,
            },
        )

        with pytest.raises(InvalidTokenError, match="No pending email change"):
            await auth_manager.confirm_email_change(token)

    async def test_confirm_email_change_expired(
        self, auth_manager: AsyncAuthManager, registered_user: dict
    ):
        from authority.utils import hash_token

        token = "expired-change-token"
        token_hash = hash_token(token)
        await auth_manager.storage.update_user(
            registered_user["id"],
            {
                "email_change_token_hash": token_hash,
                "email_change_token_expiry": datetime.datetime(2020, 1, 1),
                "pending_email": "new@example.com",
            },
        )

        with pytest.raises(TokenExpiredError):
            await auth_manager.confirm_email_change(token)

    async def test_close_delegates_to_storage(self, auth_manager: AsyncAuthManager):
        from unittest.mock import AsyncMock, patch

        with patch.object(
            auth_manager.storage, "close", new_callable=AsyncMock
        ) as mock_close:
            await auth_manager.close()
            mock_close.assert_called_once()

    async def test_audit_log_disabled(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            audit_log_enabled=False,
        )
        manager = AsyncAuthManager(config, mem_db)
        await manager.register(
            name="No Audit",
            email="noaudit@example.com",
            password="SecureP@ss1234!",
        )
        logs = await manager.get_audit_log()
        assert logs == []

    async def test_register_post_create_inconsistency(
        self, auth_manager: AsyncAuthManager
    ):
        from unittest.mock import AsyncMock, patch

        async def fake_create(*args, **kwargs):
            return 99999

        with (
            patch.object(auth_manager.storage, "create_user", fake_create),
            patch.object(
                auth_manager.storage,
                "get_user_by_email",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch.object(
                auth_manager.storage,
                "add_password_history",
                new_callable=AsyncMock,
            ),
            patch.object(
                auth_manager.storage,
                "get_user_by_id",
                new_callable=AsyncMock,
                return_value=None,
            ),
            pytest.raises(ConfigurationError, match="Failed to retrieve"),
        ):
            await auth_manager.register(
                name="Ghost",
                email="ghost@example.com",
                password="SecureP@ss1234!",
            )

    async def test_create_role_post_create_inconsistency(
        self, auth_manager: AsyncAuthManager
    ):
        from unittest.mock import AsyncMock, patch

        with (
            patch.object(
                auth_manager.storage,
                "create_role",
                new_callable=AsyncMock,
                return_value=1,
            ),
            patch.object(
                auth_manager.storage,
                "get_role_by_id",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            from authority.exceptions import ConfigurationError

            with pytest.raises(ConfigurationError, match="Failed to create role"):
                await auth_manager.create_role(name="ghost", description="Ghost role")

    async def test_create_permission_post_create_inconsistency(
        self, auth_manager: AsyncAuthManager
    ):
        from unittest.mock import AsyncMock, patch

        with (
            patch.object(
                auth_manager.storage,
                "create_permission",
                new_callable=AsyncMock,
                return_value=1,
            ),
            patch.object(
                auth_manager.storage,
                "get_permission_by_id",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            from authority.exceptions import ConfigurationError

            with pytest.raises(ConfigurationError, match="Failed to create permission"):
                await auth_manager.create_permission("ghost.perm", "Ghost perm")


class TestHIBPBranches:
    async def test_hibp_ignore_mode(self, mem_db: AsyncSQLiteStorage, fernet_key: str):
        from unittest.mock import patch

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="ignore",
        )
        manager = AsyncAuthManager(config, mem_db)
        with patch("authority.async_core.check_password_pwned", return_value=100):
            user = await manager.register(
                name="HIBP Ignore",
                email="hibp_ignore@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "hibp_ignore@example.com"

    async def test_hibp_warn_mode(self, mem_db: AsyncSQLiteStorage, fernet_key: str):
        from unittest.mock import patch

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="warn",
        )
        manager = AsyncAuthManager(config, mem_db)
        with patch("authority.async_core.check_password_pwned", return_value=50):
            user = await manager.register(
                name="HIBP Warn",
                email="hibp_warn@example.com",
                password="SecureP@ss1234!",
            )
            assert user["email"] == "hibp_warn@example.com"

    async def test_hibp_reject_mode(self, mem_db: AsyncSQLiteStorage, fernet_key: str):
        from unittest.mock import patch

        from authority.exceptions import PasswordPwnedError

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            hibp_check_enabled=True,
            hibp_failure_mode="reject",
        )
        manager = AsyncAuthManager(config, mem_db)
        with (
            patch("authority.async_core.check_password_pwned", return_value=200),
            pytest.raises(PasswordPwnedError, match="data breaches"),
        ):
            await manager.register(
                name="HIBP Reject",
                email="hibp_reject@example.com",
                password="SecureP@ss1234!",
            )


# ── Coverage boost: refresh token grace period ─────────────


class TestRefreshTokenGracePeriod:
    async def test_grace_period_reuse(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            refresh_token_reuse_grace_seconds=300,
        )
        manager = AsyncAuthManager(config, mem_db)
        await manager.register(
            name="Grace",
            email="grace@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        login_result = await manager.login("grace@example.com", "SecureP@ss1234!")
        old_refresh = login_result["refresh_token"]

        refresh_result = await manager.refresh_access_token(old_refresh)

        second_refresh = await manager.refresh_access_token(old_refresh)
        assert "access_token" in second_refresh


# ── Coverage boost: MFA decryption failure ─────────────────


class TestMFADecryptionFailure:
    async def test_verify_and_enable_mfa_wrong_key(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        from cryptography.fernet import Fernet

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="MFA Fail",
            email="mfa_fail@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = await manager.setup_mfa(user["id"])
        assert setup is not None

        config.fernet_key = Fernet.generate_key().decode()
        manager._config = config

        with pytest.raises(ValidationError, match="Failed to decrypt MFA secret"):
            await manager.verify_and_enable_mfa(user["id"], "123456")


# ── Coverage boost: verify_api_key naive datetime ──────────


class TestAPIKeyEdgeCases:
    async def test_verify_api_key_naive_expiry(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="APIK",
            email="apik@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        key_result = await manager.create_api_key(
            user["id"], "test_key", ["read"], expires_in_days=1
        )
        raw_key = key_result["key"]
        prefix = key_result["prefix"]

        from authority.utils import hash_token

        key_hash = hash_token(raw_key)

        naive_past = datetime.datetime(2020, 1, 1)
        await mem_db._execute(
            "UPDATE api_keys SET expires_at = ? WHERE key_prefix = ?",
            (naive_past, prefix),
        )
        await mem_db._commit()

        from authority.exceptions import InvalidAPIKeyError

        with pytest.raises(InvalidAPIKeyError, match="expired"):
            await manager.verify_api_key(raw_key)

    async def test_list_api_keys_malformed_scopes(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="Scope",
            email="scope@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        await manager.create_api_key(user["id"], "test_key", ["read"])

        await mem_db._execute(
            "UPDATE api_keys SET scopes_json = ? WHERE user_id = ?",
            ("not-valid-json{", user["id"]),
        )
        await mem_db._commit()

        keys = await manager.list_api_keys(user["id"])
        assert keys[0]["scopes"] == []


# ── Coverage boost: WebAuthn tests ─────────────────────────


class TestWebAuthnCoverage:
    async def test_start_registration_user_not_found(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        with pytest.raises(UserNotFoundError):
            await manager.start_webauthn_registration(99999)

    async def test_complete_registration_user_not_found(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        with pytest.raises(UserNotFoundError):
            await manager.complete_webauthn_registration(
                99999, {"credential_id": "c", "public_key": "p"}
            )

    async def test_complete_registration_invalid_credential(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        from authority.exceptions import WebAuthnRegistrationError

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="WA2",
            email="wa2@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        with pytest.raises(WebAuthnRegistrationError, match="Invalid credential"):
            await manager.complete_webauthn_registration(
                user["id"], {"credential_id": "", "public_key": ""}
            )

    async def test_complete_auth_unknown_credential(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        from authority.exceptions import WebAuthnVerificationError

        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        with pytest.raises(WebAuthnVerificationError, match="Unknown credential"):
            await manager.complete_webauthn_authentication(
                {"credential_id": "nonexistent"}
            )

    async def test_list_credentials_empty(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="WA3",
            email="wa3@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        creds = await manager.list_webauthn_credentials(user["id"])
        assert creds == []

    async def test_delete_credential_not_found(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="WA4",
            email="wa4@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        result = await manager.delete_webauthn_credential(
            user["id"], "nonexistent_cred"
        )
        assert result is False

    async def test_start_auth_with_user_id(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        user = await manager.register(
            name="WA5",
            email="wa5@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        result = await manager.start_webauthn_authentication(user_id=user["id"])
        assert "challenge" in result
        assert "options_json" in result

    async def test_start_auth_without_user_id(
        self, mem_db: AsyncSQLiteStorage, fernet_key: str
    ):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key=fernet_key,
            db_path=":memory:",
            webauthn_rp_id="example.com",
        )
        manager = AsyncAuthManager(config, mem_db)
        result = await manager.start_webauthn_authentication()
        assert "challenge" in result
