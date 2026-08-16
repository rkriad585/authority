# AuthManager

`AuthManager` is the synchronous core of `authority-auth`. It implements all
authentication flows: registration, login, tokens, sessions, MFA, WebAuthn,
RBAC, API keys, and audit logging.

```python
from authority import AuthConfig
from authority.core import AuthManager
from authority.storage.sqlite import SQLiteStorage

config = AuthConfig(jwt_secret_key="your-secret-key-min-32-chars")
storage = SQLiteStorage("authority_data.db")
auth = AuthManager(config, storage)

# SQLite connects lazily — just start using the manager.
try:
    user = auth.register("Alice", "alice@example.com", "SecureP@ss1234!")
finally:
    auth.close()
```

The manager can also be used as a context manager, which closes the storage
connection when the block exits:

```python
with AuthManager(config, SQLiteStorage("authority_data.db")) as auth:
    user = auth.register("Alice", "alice@example.com", "SecureP@ss1234!")
```

`AsyncAuthManager` mirrors every method as a coroutine — see
[AsyncAuthManager](async-auth-manager.md) and [Async usage](async.md).

## User management

| Method | Signature |
|---|---|
| `register` | `register(name, email, password, ip_address=None, auto_verify=False) -> dict` |
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

`register()` returns a dict containing at least `id` and `email`. When
`email_verification_required` is enabled, the user starts unverified and you
must call `verify_email()` with the token from
`request_email_verification()` — or pass `auto_verify=True` to register.

`request_password_reset()` returns the reset token, or an empty string for an
unknown email (anti-enumeration). `change_password()` requires the current
password and enforces password history.

## Authentication & tokens

| Method | Signature |
|---|---|
| `login` | `login(email, password, ip_address=None, user_agent=None) -> dict` |
| `logout` | `logout(user_id, refresh_token=None, access_token_jti=None, ip_address=None)` |
| `logout_all` | `logout_all(user_id, exclude_refresh_token=None, ip_address=None) -> int` |
| `verify_access_token` | `verify_access_token(token) -> dict` |
| `refresh_access_token` | `refresh_access_token(refresh_token, ip_address=None, user_agent=None) -> dict` |
| `require_permission` | `require_permission(user_id, permission_code)` |

`login()` returns `access_token`, `refresh_token`, and `token_type` — or, when
MFA is enabled for the account, `mfa_required: True` and `user_id` instead.
`refresh_access_token()` rotates the refresh token by default and issues a new
pair. See [Tokens](tokens.md).

## Sessions

| Method | Signature |
|---|---|
| `list_sessions` | `list_sessions(user_id) -> list[dict]` |
| `revoke_session_by_id` | `revoke_session_by_id(user_id, session_token_id, ip_address=None) -> bool` |
| `revoke_all_sessions_for_user` | `revoke_all_sessions_for_user(user_id, exclude_token_id=None, ip_address=None) -> int` |

Sessions are the non-revoked, non-expired refresh tokens for a user. See
[Sessions](sessions.md).

## Multi-factor authentication

| Method | Signature |
|---|---|
| `setup_mfa` | `setup_mfa(user_id) -> dict` |
| `verify_and_enable_mfa` | `verify_and_enable_mfa(user_id, code, ip_address=None) -> dict` |
| `get_mfa_status` | `get_mfa_status(user_id) -> dict` |
| `disable_mfa` | `disable_mfa(user_id, password, ip_address=None) -> dict` |
| `verify_mfa_login` | `verify_mfa_login(user_id, code, ip_address=None) -> dict` |
| `verify_mfa_recovery_code` | `verify_mfa_recovery_code(user_id, recovery_code) -> bool` |
| `regenerate_recovery_codes` | `regenerate_recovery_codes(user_id, password, ip_address=None) -> dict` |

`setup_mfa()` returns `secret` and `provisioning_uri`. After
`verify_and_enable_mfa()`, the returned dict contains the one-time plaintext
`recovery_codes`. Disabling or regenerating codes requires the password.
See [MFA](mfa.md).

## WebAuthn / passkeys

| Method | Signature |
|---|---|
| `start_webauthn_registration` | `start_webauthn_registration(user_id, ip_address=None) -> dict` |
| `complete_webauthn_registration` | `complete_webauthn_registration(user_id, credential_data, ip_address=None) -> dict` |
| `start_webauthn_authentication` | `start_webauthn_authentication(user_id=None, ip_address=None) -> dict` |
| `complete_webauthn_authentication` | `complete_webauthn_authentication(credential_data, ip_address=None) -> dict` |
| `list_webauthn_credentials` | `list_webauthn_credentials(user_id) -> list[dict]` |
| `delete_webauthn_credential` | `delete_webauthn_credential(user_id, credential_id, ip_address=None) -> bool` |

See [WebAuthn](webauthn.md) for the full ceremony flow.

## RBAC

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
| `require_permission` | `require_permission(user_id, permission_code)` |

Permissions are assigned to roles, roles are assigned to users, and a user's
effective permissions are the union across all their roles. See [RBAC](rbac.md).

## API keys

| Method | Signature |
|---|---|
| `create_api_key` | `create_api_key(user_id, description=None, scopes=None, expires_in_days=None, ip_address=None) -> dict` |
| `verify_api_key` | `verify_api_key(api_key) -> dict` |
| `list_api_keys` | `list_api_keys(user_id) -> list[dict]` |
| `revoke_api_key` | `revoke_api_key(user_id, key_prefix, ip_address=None) -> bool` |

`create_api_key()` returns `key` (plaintext, shown once) and `prefix`. Only the
prefix is stored; verification hashes the presented key. See [API keys](api-keys.md).

## Audit logging

| Method | Signature |
|---|---|
| `get_audit_log` | `get_audit_log(user_id=None, action=None, limit=100, offset=0) -> list[dict]` |

See [Audit log](audit.md).
