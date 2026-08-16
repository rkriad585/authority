"""Comprehensive tests for authority MFA — TOTP and recovery codes."""

from __future__ import annotations

import pyotp
import pytest

from authority.core import AuthManager
from authority.exceptions import (
    InvalidCredentialsError,
    MFAFailedError,
    MFANotEnabledError,
    UserNotFoundError,
    ValidationError,
)


def _make_totp_code(secret: str) -> str:
    """Generate a valid TOTP code from a secret."""
    return pyotp.TOTP(secret).now()


class TestSetupMFA:
    def test_setup_mfa_returns_secret_and_uri(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.setup_mfa(verified_user["id"])
        assert "secret" in result
        assert "provisioning_uri" in result
        assert result["recovery_code_count"] == 10
        assert len(result["secret"]) == 32  # Base32 encoded

    def test_setup_mfa_stores_encrypted_secret(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.setup_mfa(verified_user["id"])
        user = auth_manager.storage.get_user_by_id(verified_user["id"])
        assert user["mfa_secret_encrypted"] is not None
        assert user["mfa_secret_encrypted"] != result["secret"]

    def test_setup_mfa_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.setup_mfa(99999)

    def test_setup_mfa_already_enabled(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(auth_manager.setup_mfa(verified_user["id"])["secret"])
        auth_manager.verify_and_enable_mfa(verified_user["id"], code)
        with pytest.raises(MFANotEnabledError, match="already enabled"):
            auth_manager.setup_mfa(verified_user["id"])

    def test_setup_mfa_emits_event(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.setup_initiated", lambda d: events.append(d))
        auth_manager.setup_mfa(verified_user["id"])
        assert len(events) == 1

    def test_provisioning_uri_format(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        result = auth_manager.setup_mfa(verified_user["id"])
        uri = result["provisioning_uri"]
        assert uri.startswith("otpauth://totp/")
        assert "verified%40example.com" in uri or "verified@example.com" in uri


class TestVerifyAndEnableMFA:
    def test_verify_and_enable_success(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        setup = auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        result = auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        assert "recovery_codes" in result
        assert len(result["recovery_codes"]) == 10
        assert result["recovery_code_count"] == 10

        # MFA should now be enabled
        user = auth_manager.storage.get_user_by_id(verified_user["id"])
        assert user["mfa_enabled"] is True

    def test_verify_and_enable_wrong_code(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        auth_manager.setup_mfa(verified_user["id"])
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            auth_manager.verify_and_enable_mfa(verified_user["id"], "000000")

    def test_verify_and_enable_no_setup(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        with pytest.raises(ValidationError, match="MFA secret not found"):
            auth_manager.verify_and_enable_mfa(verified_user["id"], "123456")

    def test_verify_and_enable_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.verify_and_enable_mfa(99999, "123456")

    def test_verify_and_enable_stores_hashed_recovery_codes(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        setup = auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        # Check that recovery codes are stored as hashes
        count = auth_manager.storage.get_active_mfa_recovery_codes_count(
            verified_user["id"]
        )
        assert count == 10

    def test_verify_and_enable_emits_event(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.enabled", lambda d: events.append(d))

        setup = auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(verified_user["id"], code)
        assert len(events) == 1


class TestMFALogin:
    @pytest.fixture()
    def mfa_user(self, auth_manager: AuthManager) -> dict:
        """Register a user with MFA enabled."""
        user = auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(user["id"], code)
        return {"user": user, "secret": setup["secret"], "codes": []}

    def test_login_returns_mfa_required(
        self, auth_manager: AuthManager, mfa_user: dict
    ):
        result = auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        assert result.get("mfa_required") is True
        assert "access_token" not in result
        assert "refresh_token" not in result

    def test_mfa_login_with_totp(self, auth_manager: AuthManager, mfa_user: dict):
        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        code = _make_totp_code(mfa_user["secret"])
        result = auth_manager.verify_mfa_login(mfa_user["user"]["id"], code)
        assert "access_token" in result
        assert "refresh_token" in result
        assert result["user"]["mfa_enabled"] is True

    def test_mfa_login_with_recovery_code(
        self, auth_manager: AuthManager, mfa_user: dict
    ):
        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        # Regenerate recovery codes to get fresh ones
        result = auth_manager.regenerate_recovery_codes(
            mfa_user["user"]["id"], "SecureP@ss1234!"
        )
        recovery_code = result["recovery_codes"][0]

        login_result = auth_manager.verify_mfa_login(
            mfa_user["user"]["id"], recovery_code
        )
        assert "access_token" in login_result

    def test_mfa_login_recovery_code_single_use(
        self, auth_manager: AuthManager, mfa_user: dict
    ):
        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        result = auth_manager.regenerate_recovery_codes(
            mfa_user["user"]["id"], "SecureP@ss1234!"
        )
        recovery_code = result["recovery_codes"][0]

        # First use should succeed
        auth_manager.verify_mfa_login(mfa_user["user"]["id"], recovery_code)

        # Second use should fail
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            auth_manager.verify_mfa_login(mfa_user["user"]["id"], recovery_code)

    def test_mfa_login_invalid_code(self, auth_manager: AuthManager, mfa_user: dict):
        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            auth_manager.verify_mfa_login(mfa_user["user"]["id"], "000000")

    def test_mfa_login_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.verify_mfa_login(99999, "123456")

    def test_mfa_login_not_enabled(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        with pytest.raises(MFAFailedError, match="MFA is not enabled"):
            auth_manager.verify_mfa_login(verified_user["id"], "123456")

    def test_mfa_login_emits_event_on_success(
        self, auth_manager: AuthManager, mfa_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("user.login_success", lambda d: events.append(d))

        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        code = _make_totp_code(mfa_user["secret"])
        auth_manager.verify_mfa_login(mfa_user["user"]["id"], code)
        assert len(events) == 1

    def test_mfa_login_emits_event_on_failure(
        self, auth_manager: AuthManager, mfa_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.failed", lambda d: events.append(d))

        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        try:
            auth_manager.verify_mfa_login(mfa_user["user"]["id"], "000000")
        except MFAFailedError:
            pass
        assert len(events) == 1


class TestDisableMFA:
    @pytest.fixture()
    def mfa_enabled_user(self, auth_manager: AuthManager) -> dict:
        """Register a user with MFA enabled."""
        user = auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(user["id"], code)
        return user

    def test_disable_mfa_success(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        result = auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        assert result["mfa_enabled"] is False

        user = auth_manager.storage.get_user_by_id(mfa_enabled_user["id"])
        assert user["mfa_secret_encrypted"] is None
        assert user["mfa_enabled"] is False

    def test_disable_mfa_wrong_password(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Password is incorrect"):
            auth_manager.disable_mfa(mfa_enabled_user["id"], "WrongPassword123!")

    def test_disable_mfa_not_enabled(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        with pytest.raises(MFANotEnabledError, match="not enabled"):
            auth_manager.disable_mfa(verified_user["id"], "SecureP@ss1234!")

    def test_disable_mfa_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.disable_mfa(99999, "Password123!")

    def test_disable_mfa_clears_recovery_codes(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        count = auth_manager.storage.get_active_mfa_recovery_codes_count(
            mfa_enabled_user["id"]
        )
        assert count == 0

    def test_disable_mfa_emits_event(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        events: list[dict] = []
        auth_manager.events.on("mfa.disabled", lambda d: events.append(d))
        auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        assert len(events) == 1

    def test_login_after_disable_no_mfa_challenge(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        auth_manager.disable_mfa(mfa_enabled_user["id"], "SecureP@ss1234!")
        result = auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        assert "access_token" in result
        assert result.get("mfa_required") is not True


class TestRegenerateRecoveryCodes:
    @pytest.fixture()
    def mfa_enabled_user(self, auth_manager: AuthManager) -> dict:
        """Register a user with MFA enabled."""
        user = auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(user["id"], code)
        return user

    def test_regenerate_success(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        result = auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )
        assert "recovery_codes" in result
        assert len(result["recovery_codes"]) == 10
        assert result["recovery_code_count"] == 10

    def test_regenerate_wrong_password(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        with pytest.raises(InvalidCredentialsError, match="Password is incorrect"):
            auth_manager.regenerate_recovery_codes(
                mfa_enabled_user["id"], "WrongPassword123!"
            )

    def test_regenerate_not_enabled(
        self, auth_manager: AuthManager, verified_user: dict
    ):
        with pytest.raises(MFANotEnabledError, match="not enabled"):
            auth_manager.regenerate_recovery_codes(
                verified_user["id"], "SecureP@ss1234!"
            )

    def test_regenerate_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.regenerate_recovery_codes(99999, "Password123!")

    def test_regenerate_invalidates_old_codes(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        # Get old recovery codes
        old_result = auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )
        old_code = old_result["recovery_codes"][0]

        # Regenerate
        auth_manager.regenerate_recovery_codes(
            mfa_enabled_user["id"], "SecureP@ss1234!"
        )

        # Old code should not work
        auth_manager.login(
            email="mfa@example.com",
            password="SecureP@ss1234!",
        )
        with pytest.raises(MFAFailedError, match="Invalid MFA code"):
            auth_manager.verify_mfa_login(mfa_enabled_user["id"], old_code)


class TestGetMFAStatus:
    def test_status_mfa_disabled(self, auth_manager: AuthManager, verified_user: dict):
        status = auth_manager.get_mfa_status(verified_user["id"])
        assert status["mfa_enabled"] is False
        assert status["recovery_codes_remaining"] == 0

    def test_status_mfa_enabled(self, auth_manager: AuthManager, verified_user: dict):
        setup = auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(setup["secret"])
        auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        status = auth_manager.get_mfa_status(verified_user["id"])
        assert status["mfa_enabled"] is True
        assert status["recovery_codes_remaining"] == 10

    def test_status_nonexistent_user(self, auth_manager: AuthManager):
        with pytest.raises(UserNotFoundError):
            auth_manager.get_mfa_status(99999)


class TestMFACodeFormats:
    def test_recovery_code_format(self, auth_manager: AuthManager, verified_user: dict):
        """Recovery codes should be in XXXX-XXXX-XXXX format."""
        result = auth_manager.setup_mfa(verified_user["id"])
        code = _make_totp_code(result["secret"])
        enable_result = auth_manager.verify_and_enable_mfa(verified_user["id"], code)

        for rc in enable_result["recovery_codes"]:
            parts = rc.split("-")
            assert len(parts) == 3
            assert all(len(p) == 4 for p in parts)
            assert all(p.isalnum() for p in parts)

    def test_totp_code_is_6_digits(self):
        """TOTP codes should be 6 digits."""
        secret = pyotp.random_base32()
        code = pyotp.TOTP(secret).now()
        assert len(code) == 6
        assert code.isdigit()


class TestVerifyRecoveryCode:
    @pytest.fixture()
    def mfa_enabled_user(self, auth_manager: AuthManager) -> dict:
        """Register a user with MFA enabled."""
        user = auth_manager.register(
            name="MFA User",
            email="mfa@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        setup = auth_manager.setup_mfa(user["id"])
        code = _make_totp_code(setup["secret"])
        result = auth_manager.verify_and_enable_mfa(user["id"], code)
        return {**user, "recovery_codes": result["recovery_codes"]}

    def test_verify_valid_recovery_code(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        code = mfa_enabled_user["recovery_codes"][0]
        assert auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], code)

    def test_verify_recovery_code_single_use(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        code = mfa_enabled_user["recovery_codes"][0]
        assert auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], code)
        assert not auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], code)

    def test_verify_invalid_recovery_code(
        self, auth_manager: AuthManager, mfa_enabled_user: dict
    ):
        assert not auth_manager.verify_mfa_recovery_code(
            mfa_enabled_user["id"], "AAAA-AAAA-AAAA"
        )

    def test_verify_empty_code(self, auth_manager: AuthManager, mfa_enabled_user: dict):
        assert not auth_manager.verify_mfa_recovery_code(mfa_enabled_user["id"], "")
