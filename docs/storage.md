# Storage

All persistence goes through a storage backend that implements a
`StorageInterface` (sync) or `AsyncStorageInterface` (async). The library
ships SQLite implementations for both.

```python
from authority.core import AuthManager
from authority.storage.sqlite import SQLiteStorage

# Sync
auth = AuthManager(config, SQLiteStorage("authority_data.db"))

# Async
from authority.async_core import AsyncAuthManager
from authority.storage.aiosqlite import AsyncSQLiteStorage

storage = AsyncSQLiteStorage("authority_data.db")
await storage.connect()
auth = AsyncAuthManager(config, storage)
```

## Implementations

| Class | Sync / Async | Extra | Notes |
|---|---|---|---|
| `SQLiteStorage(db_path)` | sync | none | Uses the stdlib `sqlite3`; connects lazily |
| `AsyncSQLiteStorage(db_path)` | async | `async` | Uses `aiosqlite`; call `await storage.connect()` before use |

## StorageInterface (sync)

Abstract contract — 58 methods. Implement it (or subclass `SQLiteStorage`) to
swap in your own database. The manager expects these operations, grouped by
domain:

**Users & profiles**

```
create_user, get_user_by_id, get_user_by_email,
find_user_by_verification_token, find_user_by_reset_token,
find_user_by_email_change_token, find_user_by_pending_email,
update_user, delete_user,
get_user_custom_profile, update_user_custom_profile
```

**Password history**

```
add_password_history, get_password_history
```

**Refresh tokens / sessions**

```
store_refresh_token, get_refresh_token_by_id, get_refresh_token_by_hash,
mark_refresh_token_used, rotate_refresh_token, revoke_refresh_token,
revoke_all_refresh_tokens_for_user, revoke_token_family,
prune_expired_refresh_tokens, list_refresh_tokens_for_user
```

**RBAC**

```
create_role, get_role_by_id, get_role_by_name, delete_role, list_roles,
create_permission, get_permission_by_id, get_permission_by_code,
delete_permission, list_permissions,
assign_permission_to_role, remove_permission_from_role, get_role_permissions,
assign_role_to_user, remove_role_from_user, get_user_roles, get_user_permissions
```

**MFA**

```
set_mfa_recovery_codes, use_mfa_recovery_code, get_active_mfa_recovery_codes_count
```

**WebAuthn**

```
add_webauthn_credential, get_webauthn_credential_by_id,
get_webauthn_credentials_for_user, update_webauthn_credential_sign_count,
update_webauthn_credential_last_used, delete_webauthn_credential
```

**API keys**

```
store_api_key, get_api_key_by_prefix_and_hash, list_api_keys_for_user,
delete_api_key_by_prefix, update_api_key_last_used
```

**Audit & schema**

```
log_audit_event, get_audit_log, initialize_schema, close
```

## AsyncStorageInterface (async)

The same 58-method surface, with every method as a coroutine.
`AsyncSQLiteStorage` implements it.

## Custom backends

To use another database:

1. Subclass `StorageInterface` (or `AsyncStorageInterface`) and implement every
   method. The method names above are the full contract.
2. Pass an instance to the manager constructor.

```python
from authority.storage.base import StorageInterface

class MyStorage(StorageInterface):
    ...  # implement all 58 methods
```

Only `initialize_schema` and `close` are lifecycle calls; everything else is
driven by the manager. `prune_tokens_on_startup` (config, default `True`)
triggers `prune_expired_refresh_tokens` when the manager is created.
