# Exceptions

Every error raised by `authority-auth` is a subclass of `AuthError`
(itself an `Exception`), so a single `except AuthError` catches all library
errors. All exceptions are importable from `authority`:

```python
from authority import AuthError, InvalidCredentialsError
```

## Hierarchy

```
AuthError
├── ConfigurationError
├── DatabaseError
├── ValidationError
│   ├── UserExistsError
│   └── PasswordPwnedError
├── UserNotFoundError
├── InvalidCredentialsError
├── AccountInactiveError
├── AccountNotVerifiedError
├── AccountLockedError
├── InvalidTokenError
│   └── TokenExpiredError
├── MFARequiredError
│   └── MFAFailedError
│       └── InvalidRecoveryCodeError
├── MFANotEnabledError
├── PermissionError
│   └── InsufficientPermissionsError
├── WebAuthnError
│   ├── WebAuthnRegistrationError
│   └── WebAuthnVerificationError
├── InvalidAPIKeyError
└── RateLimitExceededError
```

## Reference

| Exception | Raised when |
|---|---|
| `AuthError` | Base class for all library errors |
| `ConfigurationError` | Configuration is invalid (e.g. empty `jwt_secret_key`) |
| `DatabaseError` | Underlying storage/database operation fails |
| `ValidationError` | General data validation fails |
| `UserExistsError` | Registering an email that already exists |
| `UserNotFoundError` | An operation targets a user that does not exist |
| `InvalidCredentialsError` | Wrong identifier or password during login |
| `AccountInactiveError` | Operating on an inactive account |
| `AccountNotVerifiedError` | An action requires pending email verification |
| `AccountLockedError` | Account is temporarily locked after failed attempts |
| `InvalidTokenError` | A token is invalid, malformed, or not found |
| `TokenExpiredError` | A token exists but has expired |
| `MFARequiredError` | Login requires MFA but no code was provided |
| `MFAFailedError` | MFA code verification fails |
| `InvalidRecoveryCodeError` | An invalid MFA recovery code is used |
| `MFANotEnabledError` | MFA actions attempted but MFA is not set up |
| `PasswordPwnedError` | Password found in the HIBP breach database |
| `PermissionError` | Base class for permission errors |
| `InsufficientPermissionsError` | User lacks a required permission |
| `WebAuthnError` | Base class for WebAuthn errors |
| `WebAuthnRegistrationError` | WebAuthn registration fails |
| `WebAuthnVerificationError` | WebAuthn authentication/verification fails |
| `InvalidAPIKeyError` | An invalid API key is presented |
| `RateLimitExceededError` | A rate limit is exceeded |

!!! note
    `authority.PermissionError` intentionally shadows the builtin
    `PermissionError` in the `authority` namespace. Import the builtin
    explicitly (e.g. `import builtins`) if you need both in one module.

## Example

```python
from authority import AuthManager, InvalidCredentialsError

try:
    result = auth.login(email, password)
except InvalidCredentialsError:
    return 401
```
