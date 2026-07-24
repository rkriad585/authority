"""Custom exception hierarchy for the authority library."""


class AuthError(Exception):
    """Base exception for all authority library errors."""


class ConfigurationError(AuthError):
    """Raised for configuration issues (missing keys, invalid values)."""


class DatabaseError(AuthError):
    """Raised for underlying storage/database issues."""


class ValidationError(AuthError):
    """Raised for general data validation errors."""


class UserExistsError(ValidationError):
    """Raised when registering an email that already exists."""


class UserNotFoundError(AuthError):
    """Raised when an operation targets a user that does not exist."""


class InvalidCredentialsError(AuthError):
    """Raised for incorrect identifier or password during login."""


class AccountInactiveError(AuthError):
    """Raised when trying to operate on an inactive account."""


class AccountNotVerifiedError(AuthError):
    """Raised when an action requires email verification that is pending."""


class AccountLockedError(AuthError):
    """Raised when an account is temporarily locked due to failed attempts."""


class InvalidTokenError(AuthError):
    """Raised when a provided token is invalid, malformed, or not found."""


class TokenExpiredError(InvalidTokenError):
    """Raised specifically when a token exists but has expired."""


class MFARequiredError(AuthError):
    """Raised during login when MFA is required but code not provided."""


class MFAFailedError(MFARequiredError):
    """Raised when MFA code verification fails."""


class InvalidRecoveryCodeError(MFAFailedError):
    """Raised when an invalid MFA recovery code is used."""


class MFANotEnabledError(AuthError):
    """Raised when MFA actions are attempted but MFA is not set up."""


class PasswordPwnedError(ValidationError):
    """Raised when a password is found in the HIBP database."""


class PermissionError(AuthError):
    """Base exception for permission-related errors."""


class InsufficientPermissionsError(PermissionError):
    """Raised when a user lacks specific permissions for an action."""


class WebAuthnError(AuthError):
    """Base exception for WebAuthn related errors."""


class WebAuthnRegistrationError(WebAuthnError):
    """Raised during WebAuthn registration issues."""


class WebAuthnVerificationError(WebAuthnError):
    """Raised during WebAuthn authentication/verification issues."""


class InvalidAPIKeyError(AuthError):
    """Raised when an invalid API key is provided."""


class RateLimitExceededError(AuthError):
    """Raised when a rate limit is exceeded."""
