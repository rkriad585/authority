# API Reference

The full public surface of `authority-auth`. Every name below is importable
from the top-level `authority` package unless noted otherwise.

## Package layout

| Module | Contents |
|---|---|
| `authority` | Re-exports config, managers, events, exceptions, storage, utils |
| `authority.config` | `AuthConfig` |
| `authority.core` | `AuthManager` (sync) |
| `authority.async_core` | `AsyncAuthManager` (async) |
| `authority.events` | `Event`, `EventBus` |
| `authority.exceptions` | The exception hierarchy |
| `authority.storage.base` | `StorageInterface`, `AsyncStorageInterface` |
| `authority.storage.sqlite` | `SQLiteStorage` |
| `authority.storage.aiosqlite` | `AsyncSQLiteStorage` |
| `authority.fastapi` | FastAPI dependencies (`fastapi` extra) |
| `authority.flask` | `FlaskAuth` + helpers (`flask` extra) |
| `authority.django` | `AuthorityBackend` + helpers (`django` extra) |
| `authority.starlette` | `StarletteAuth` (`starlette` extra) |
| `authority.asgi` | `AuthorityASGIMiddleware` + helpers |
| `authority.wsgi` | `AuthorityWSGIMiddleware` + helpers |
| `authority.utils` | Standalone helpers |

## AuthConfig

`AuthConfig(**kwargs)` — dataclass. Values resolve as constructor kwargs >
environment variables (`AUTHORITY_*`) > defaults. See
[Configuration](configuration.md) for the full field table.

Constructing a config with an empty `jwt_secret_key` raises
`ConfigurationError`.

## AuthManager

`AuthManager(config, storage, event_bus=None)` — synchronous core manager.
Open the manager (and initialize storage) with `.open()`, close with
`.close()`.

`AsyncAuthManager` mirrors every method as a coroutine.

### User management

| Method | Signature |
|---|---|
| `register` | `register(name, email, password, ip_address=None, auto_verify=False)` |
| `get_user` | `get_user(user_id) -> dict` |
| `get_profile` | `get_profile(user_id) -> dict` |
| `update_user` | `update_user(user_id, updates, ip_address=None) -> dict` |
| `update_profile` | `update_profile(user_id, profile_data) -> dict` |
| `delete_user` | `delete_user(user_id, ip_address=None) -> bool` |
| `request_email_verification` | `request_email_verification(user_id, ip_address=None) -> str` |
| `verify_email` | `verify_email(token, ip_address=None) -> dict` |
| `request_email_change` | `request_email_change(user_id, new_email, current_password, ip_address=None) -> str` |
| `confirm_email_change` | `confirm_email_change(token, ip_address=None) -> dict` |
| `request_password_reset` | `request_password_reset(email, ip_address=None) -> str` |
| `reset_password` | `reset_password(token, new_password, ip_address=None) -> dict` |
| `change_password` | `change_password(user_id, current_password, new_password, ip_address=None) -> dict` |

### Authentication & tokens

| Method | Signature |
|---|---|
| `login` | `login(email, password, ip_address=None, user_agent=None) -> dict` |
| `logout` | `logout(user_id, refresh_token=None, access_token_jti=None, ip_address=None)` |
| `logout_all` | `logout_all(user_id, exclude_refresh_token=None, ip_address=None) -> int` |
| `verify_access_token` | `verify_access_token(token) -> dict` |
| `refresh_access_token` | `refresh_access_token(refresh_token, ip_address=None, user_agent=None) -> dict` |
| `require_permission` | `require_permission(user_id, permission_code)` |

`login()` returns `access_token`, `refresh_token`, `token_type` — or
`mfa_required: True` and `user_id` when MFA is enabled.

### Sessions

| Method | Signature |
|---|---|
| `list_sessions` | `list_sessions(user_id) -> list[dict]` |
| `revoke_session_by_id` | `revoke_session_by_id(user_id, session_token_id, ip_address=None) -> bool` |
| `revoke_all_sessions_for_user` | `revoke_all_sessions_for_user(user_id, exclude_token_id=None, ip_address=None) -> int` |

### Multi-factor authentication

| Method | Signature |
|---|---|
| `setup_mfa` | `setup_mfa(user_id) -> dict` |
| `verify_and_enable_mfa` | `verify_and_enable_mfa(user_id, code, ip_address=None) -> dict` |
| `get_mfa_status` | `get_mfa_status(user_id) -> dict` |
| `disable_mfa` | `disable_mfa(user_id, password, ip_address=None) -> dict` |
| `verify_mfa_login` | `verify_mfa_login(user_id, code, ip_address=None) -> dict` |
| `verify_mfa_recovery_code` | `verify_mfa_recovery_code(user_id, recovery_code) -> bool` |
| `regenerate_recovery_codes` | `regenerate_recovery_codes(user_id, password, ip_address=None) -> dict` |

`setup_mfa()` returns `secret` and `provisioning_uri`.
`verify_and_enable_mfa()` returns `recovery_codes` (plaintext, shown once).

### WebAuthn / passkeys

| Method | Signature |
|---|---|
| `start_webauthn_registration` | `start_webauthn_registration(user_id, ip_address=None) -> dict` |
| `complete_webauthn_registration` | `complete_webauthn_registration(user_id, credential_data, ip_address=None) -> dict` |
| `start_webauthn_authentication` | `start_webauthn_authentication(user_id=None, ip_address=None) -> dict` |
| `complete_webauthn_authentication` | `complete_webauthn_authentication(credential_data, ip_address=None) -> dict` |
| `list_webauthn_credentials` | `list_webauthn_credentials(user_id) -> list[dict]` |
| `delete_webauthn_credential` | `delete_webauthn_credential(user_id, credential_id, ip_address=None) -> bool` |

### RBAC

| Method | Signature |
|---|---|
| `create_role` | `create_role(name, description=None) -> dict` |
| `delete_role` | `delete_role(role_id) -> bool` |
| `list_roles` | `list_roles() -> list[dict]` |
| `create_permission` | `create_permission(code, description=None) -> dict` |
| `delete_permission` | `delete_permission(permission_id) -> bool` |
| `list_permissions` | `list_permissions() -> list[dict]` |
| `assign_permission_to_role` | `assign_permission_to_role(role_id, permission_id) -> bool` |
| `remove_permission_from_role` | `remove_permission_from_role(role_id, permission_id) -> bool` |
| `get_role_permissions` | `get_role_permissions(role_id) -> list[dict]` |
| `assign_role_to_user` | `assign_role_to_user(user_id, role_id) -> bool` |
| `remove_role_from_user` | `remove_role_from_user(user_id, role_id) -> bool` |
| `get_user_roles` | `get_user_roles(user_id) -> list[dict]` |
| `has_permission` | `has_permission(user_id, permission_code) -> bool` |
| `get_user_permissions` | `get_user_permissions(user_id) -> list[str]` |

### API keys

| Method | Signature |
|---|---|
| `create_api_key` | `create_api_key(user_id, description=None, scopes=None, expires_in_days=None, ip_address=None) -> dict` |
| `verify_api_key` | `verify_api_key(api_key) -> dict` |
| `list_api_keys` | `list_api_keys(user_id) -> list[dict]` |
| `revoke_api_key` | `revoke_api_key(user_id, key_prefix, ip_address=None) -> bool` |

`create_api_key()` returns `key` (plaintext, shown once) and `prefix`.

### Audit

| Method | Signature |
|---|---|
| `get_audit_log` | `get_audit_log(user_id=None, action=None, limit=100, offset=0) -> list[dict]` |

## Events

`Event(str, Enum)` — the 22 lifecycle events:

`USER_REGISTERED`, `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`, `USER_LOGOUT`,
`USER_PASSWORD_CHANGED`, `USER_PASSWORD_RESET`, `USER_EMAIL_CHANGED`,
`USER_DELETED`, `MFA_SETUP_INITIATED`, `MFA_ENABLED`, `MFA_DISABLED`,
`MFA_FAILED`, `TOKEN_REFRESHED`, `TOKEN_REUSE_DETECTED`, `TOKEN_REVOKED`,
`WEBAUTHN_CREDENTIAL_ADDED`, `WEBAUTHN_CREDENTIAL_REMOVED`,
`RBAC_ROLE_ASSIGNED`, `RBAC_ROLE_REVOKED`, `API_KEY_CREATED`,
`API_KEY_REVOKED`, `AUDIT_EVENT_LOGGED`.

`EventBus()` — register handlers with `.on(event, handler)`, fire with
`.emit(event, data)`. Handlers may be sync functions or coroutines.

## Exceptions

`AuthError(Exception)` is the base of the hierarchy.

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

All exceptions are importable from `authority`.

## Storage

### StorageInterface (sync)

Abstract contract; `SQLiteStorage` implements it. All methods:

```
create_user, get_user_by_id, get_user_by_email, find_user_by_verification_token,
find_user_by_reset_token, find_user_by_email_change_token,
find_user_by_pending_email, update_user, delete_user,
get_user_custom_profile, update_user_custom_profile,
add_password_history, get_password_history,
store_refresh_token, get_refresh_token_by_id, get_refresh_token_by_hash,
mark_refresh_token_used, rotate_refresh_token, revoke_refresh_token,
revoke_all_refresh_tokens_for_user, revoke_token_family,
prune_expired_refresh_tokens, list_refresh_tokens_for_user,
create_role, get_role_by_id, get_role_by_name, delete_role, list_roles,
create_permission, get_permission_by_id, get_permission_by_code,
delete_permission, list_permissions,
assign_permission_to_role, remove_permission_from_role, get_role_permissions,
assign_role_to_user, remove_role_from_user, get_user_roles, get_user_permissions,
set_mfa_recovery_codes, use_mfa_recovery_code, get_active_mfa_recovery_codes_count,
add_webauthn_credential, get_webauthn_credential_by_id,
get_webauthn_credentials_for_user, update_webauthn_credential_sign_count,
update_webauthn_credential_last_used, delete_webauthn_credential,
store_api_key, get_api_key_by_prefix_and_hash, list_api_keys_for_user,
delete_api_key_by_prefix, update_api_key_last_used,
log_audit_event, get_audit_log, initialize_schema, close
```

### AsyncStorageInterface (async)

Abstract contract with the same 58-method surface; `AsyncSQLiteStorage`
implements it using `aiosqlite`.

### Implementations

- `SQLiteStorage(db_path)` — sync SQLite backend
- `AsyncSQLiteStorage(db_path)` — async SQLite backend (requires `async` extra)

## Integrations

### FastAPI (`authority.fastapi`, extra: `fastapi`)

| Symbol | Purpose |
|---|---|
| `init_auth(manager)` | Bind the global `AsyncAuthManager` |
| `get_auth_manager()` | Retrieve it (raises `RuntimeError` if unset) |
| `get_current_user` | Dependency returning the verified token payload (`dict`) |
| `require_permission(permission_code)` | Dependency factory → 401/403 via `HTTPException` |
| `require_role(role_name)` | Dependency factory → 401/403 via `HTTPException` |

`get_current_user`, `require_permission(...)`, and `require_role(...)` are used
as `Depends(...)` arguments and return the verified token payload dict.

### Flask (`authority.flask`, extra: `flask`)

| Symbol | Purpose |
|---|---|
| `FlaskAuth(app, manager)` | Binds the manager to the app |
| `FlaskAuth.login_required` | Instance decorator (401 via `abort`) |
| `FlaskAuth.require_permission(code)` | Instance decorator (401/403) |
| `FlaskAuth.require_role(name)` | Instance decorator (401/403) |
| `FlaskAuth.current_user()` | Full user dict or `None` |
| `init_auth(manager)` | Module-level binding |
| `login_required` | Module-level decorator |
| `require_permission(code)` | Module-level decorator factory |
| `require_role(name)` | Module-level decorator factory |
| `current_user()` | Module-level user accessor |

Tokens are read from `Authorization: Bearer <token>` or
`session["access_token"]`.

### Django (`authority.django`, extra: `django`)

| Symbol | Purpose |
|---|---|
| `init_auth(manager)` | Bind the global `AuthManager` |
| `login_required` | View decorator (plain-text 401) |
| `require_permission(code)` | View decorator factory |
| `require_role(name)` | View decorator factory |
| `get_current_user(request)` | User dict from the request |
| `AuthorityBackend` | Django `BaseBackend` that authenticates against authority |
| `authority_user_to_django_user(user)` | Mirror an authority user into `django.contrib.auth.models.User` |

### Starlette (`authority.starlette`, extra: `starlette`)

| Symbol | Purpose |
|---|---|
| `StarletteAuth(manager)` | Binds an `AsyncAuthManager` |
| `StarletteAuth.login_required` | Instance decorator (401 via `HTTPException`) |
| `StarletteAuth.require_permission(code)` | Instance decorator |
| `StarletteAuth.require_role(name)` | Instance decorator |
| `StarletteAuth.current_user()` | User dict or `None` |

### ASGI middleware (`authority.asgi`)

| Symbol | Purpose |
|---|---|
| `AuthorityASGIMiddleware(app, manager, auth_required=False)` | Wraps any ASGI app |
| `get_user_state(scope)` | State dict at `scope["authority"]` |
| `is_authenticated(scope)` | Boolean |
| `user_id_from_scope(scope)` | `int | None` |
| `get_current_user(scope, manager)` | User dict or `None` |

### WSGI middleware (`authority.wsgi`)

| Symbol | Purpose |
|---|---|
| `AuthorityWSGIMiddleware(app, manager, auth_required=False)` | Wraps any WSGI app |
| `get_user_state(environ)` | State dict at `environ["authority"]` |
| `is_authenticated(environ)` | Boolean |
| `user_id_from_environ(environ)` | `int | None` |
| `get_current_user(environ, manager)` | User dict or `None` |

## Utils (`authority.utils`)

| Symbol | Purpose |
|---|---|
| `generate_secure_token(length=32)` | Cryptographically secure random token |
| `hash_token(token)` | SHA-256 hex digest of a token |
| `encrypt_data(plaintext)` | Fernet-encrypt data |
| `decrypt_data(token)` | Fernet-decrypt data |
| `reset_fernet_cache()` | Clear the cached Fernet instance |
| `check_password_pwned(password, api_key=None, timeout=5)` | HIBP k-anonymity check |
| `estimate_password_strength(password)` | Heuristic strength estimate |
| `validate_email_format(email)` | Email format validation |
