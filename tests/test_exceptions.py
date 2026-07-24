"""Tests for authority.exceptions."""

import pytest

from authority.exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    AuthError,
    ConfigurationError,
    DatabaseError,
    InsufficientPermissionsError,
    InvalidAPIKeyError,
    InvalidCredentialsError,
    InvalidRecoveryCodeError,
    InvalidTokenError,
    MFAFailedError,
    MFANotEnabledError,
    MFARequiredError,
    PasswordPwnedError,
    PermissionError,
    RateLimitExceededError,
    TokenExpiredError,
    UserExistsError,
    UserNotFoundError,
    ValidationError,
    WebAuthnError,
    WebAuthnRegistrationError,
    WebAuthnVerificationError,
)


class TestExceptionHierarchy:
    def test_all_inherit_from_auth_error(self):
        exceptions = [
            ConfigurationError,
            DatabaseError,
            ValidationError,
            UserExistsError,
            UserNotFoundError,
            InvalidCredentialsError,
            AccountInactiveError,
            AccountNotVerifiedError,
            AccountLockedError,
            InvalidTokenError,
            TokenExpiredError,
            MFARequiredError,
            MFAFailedError,
            InvalidRecoveryCodeError,
            MFANotEnabledError,
            PasswordPwnedError,
            PermissionError,
            InsufficientPermissionsError,
            WebAuthnError,
            WebAuthnRegistrationError,
            WebAuthnVerificationError,
            InvalidAPIKeyError,
            RateLimitExceededError,
        ]
        for exc_cls in exceptions:
            assert issubclass(exc_cls, AuthError), (
                f"{exc_cls.__name__} should inherit from AuthError"
            )

    def test_inheritance_chains(self):
        assert issubclass(TokenExpiredError, InvalidTokenError)
        assert issubclass(MFAFailedError, MFARequiredError)
        assert issubclass(InvalidRecoveryCodeError, MFAFailedError)
        assert issubclass(InsufficientPermissionsError, PermissionError)
        assert issubclass(WebAuthnRegistrationError, WebAuthnError)
        assert issubclass(WebAuthnVerificationError, WebAuthnError)
        assert issubclass(UserExistsError, ValidationError)
        assert issubclass(PasswordPwnedError, ValidationError)

    def test_exceptions_are_raised_and_caught(self):
        with pytest.raises(AuthError):
            raise ConfigurationError("bad config")

    def test_exceptions_carry_message(self):
        exc = InvalidCredentialsError("wrong password")
        assert str(exc) == "wrong password"
