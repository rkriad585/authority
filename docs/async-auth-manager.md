# AsyncAuthManager

`AsyncAuthManager` is the asynchronous twin of `AuthManager`. Every method is a
coroutine; everything else about the API is identical. It is backed by
`AsyncSQLiteStorage` and uses `aiosqlite` (the `async` extra).

```python
import asyncio

from authority import AuthConfig
from authority.async_core import AsyncAuthManager
from authority.storage.aiosqlite import AsyncSQLiteStorage

async def main():
    config = AuthConfig(jwt_secret_key="your-secret-key-min-32-chars")
    storage = AsyncSQLiteStorage("authority_data.db")
    await storage.connect()

    async with AsyncAuthManager(config, storage) as auth:
        user = await auth.register("Alice", "alice@example.com", "SecureP@ss1234!")

asyncio.run(main())
```

`AsyncAuthManager` is also a context manager — leaving the `async with` block
closes the storage connection.

The FastAPI integration binds an `AsyncAuthManager` globally with
`init_auth(manager)`; the framework dependencies then `await` its methods for
you. See [FastAPI](examples/fastapi.md) and [Integrations](integrations.md).

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

## Authentication & tokens

| Method | Signature |
|---|---|
| `login` | `login(email, password, ip_address=None, user_agent=None) -> dict` |
| `logout` | `logout(user_id, refresh_token=None, access_token_jti=None, ip_address=None)` |
| `logout_all` | `logout_all(user_id, exclude_refresh_token=None, ip_address=None) -> int` |
| `verify_access_token` | `verify_access_token(token) -> dict` |
| `refresh_access_token` | `refresh_access_token(refresh_token, ip_address=None, user_agent=None) -> dict` |
| `require_permission` | `require_permission(user_id, permission_code)` |

## Sessions

| Method | Signature |
|---|---|
| `list_sessions` | `list_sessions(user_id) -> list[dict]` |
| `revoke_session_by_id` | `revoke_session_by_id(user_id, session_token_id, ip_address=None) -> bool` |
| `revoke_all_sessions_for_user` | `revoke_all_sessions_for_user(user_id, exclude_token_id=None, ip_address=None) -> int` |

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

## WebAuthn / passkeys

| Method | Signature |
|---|---|
| `start_webauthn_registration` | `start_webauthn_registration(user_id, ip_address=None) -> dict` |
| `complete_webauthn_registration` | `complete_webauthn_registration(user_id, credential_data, ip_address=None) -> dict` |
| `start_webauthn_authentication` | `start_webauthn_authentication(user_id=None, ip_address=None) -> dict` |
| `complete_webauthn_authentication` | `complete_webauthn_authentication(credential_data, ip_address=None) -> dict` |
| `list_webauthn_credentials` | `list_webauthn_credentials(user_id) -> list[dict]` |
| `delete_webauthn_credential` | `delete_webauthn_credential(user_id, credential_id, ip_address=None) -> bool` |

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

## API keys

| Method | Signature |
|---|---|
| `create_api_key` | `create_api_key(user_id, description=None, scopes=None, expires_in_days=None, ip_address=None) -> dict` |
| `verify_api_key` | `verify_api_key(api_key) -> dict` |
| `list_api_keys` | `list_api_keys(user_id) -> list[dict]` |
| `revoke_api_key` | `revoke_api_key(user_id, key_prefix, ip_address=None) -> bool` |

## Audit logging

| Method | Signature |
|---|---|
| `get_audit_log` | `get_audit_log(user_id=None, action=None, limit=100, offset=0) -> list[dict]` |
