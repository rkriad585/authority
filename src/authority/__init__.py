"""Authority — comprehensive, framework-agnostic Python authentication library."""

__version__ = "0.1.0"

from .async_core import AsyncAuthManager
from .config import AuthConfig
from .core import AuthManager
from .events import Event, EventBus
from .exceptions import (
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
from .storage import (
    AsyncSQLiteStorage,
    AsyncStorageInterface,
    SQLiteStorage,
    StorageInterface,
)
from .utils import (
    check_password_pwned,
    decrypt_data,
    encrypt_data,
    generate_secure_token,
    hash_token,
    reset_fernet_cache,
    validate_email_format,
)

__all__ = [
    "__version__",
    # Config
    "AuthConfig",
    # Core
    "AuthManager",
    "AsyncAuthManager",
    # Events
    "Event",
    "EventBus",
    # Exceptions
    "AuthError",
    "ConfigurationError",
    "DatabaseError",
    "ValidationError",
    "UserExistsError",
    "UserNotFoundError",
    "InvalidCredentialsError",
    "AccountInactiveError",
    "AccountNotVerifiedError",
    "AccountLockedError",
    "InvalidTokenError",
    "TokenExpiredError",
    "MFARequiredError",
    "MFAFailedError",
    "InvalidRecoveryCodeError",
    "MFANotEnabledError",
    "PasswordPwnedError",
    "PermissionError",
    "InsufficientPermissionsError",
    "WebAuthnError",
    "WebAuthnRegistrationError",
    "WebAuthnVerificationError",
    "InvalidAPIKeyError",
    "RateLimitExceededError",
    # Storage
    "StorageInterface",
    "AsyncStorageInterface",
    "SQLiteStorage",
    "AsyncSQLiteStorage",
    # Utils
    "validate_email_format",
    "generate_secure_token",
    "hash_token",
    "encrypt_data",
    "decrypt_data",
    "reset_fernet_cache",
    "check_password_pwned",
]
