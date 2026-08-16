# API Reference

Every public name in `authority-auth` is importable from the top-level
`authority` package unless noted otherwise. The reference is split into
per-topic pages:

| Topic | Page |
|---|---|
| Configuration | [Configuration](configuration.md) |
| Sync manager | [AuthManager](auth-manager.md) |
| Async manager | [AsyncAuthManager](async-auth-manager.md) |
| Tokens | [Tokens](tokens.md) |
| Sessions | [Sessions](sessions.md) |
| Multi-factor authentication | [MFA](mfa.md) |
| WebAuthn / passkeys | [WebAuthn](webauthn.md) |
| Roles & permissions | [RBAC](rbac.md) |
| API keys | [API keys](api-keys.md) |
| Audit log | [Audit](audit.md) |
| Events | [Events](events.md) |
| Exceptions | [Exceptions](exceptions.md) |
| Storage | [Storage](storage.md) |
| Framework integrations | [Integrations](integrations.md) |
| Utilities | [Utilities](utils.md) |

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

## Syncing and async

Both managers expose the same 55-method surface; the async manager's methods
are coroutines and require the `async` extra.

- [AuthManager](auth-manager.md) — sync, backed by `SQLiteStorage`.
- [AsyncAuthManager](async-auth-manager.md) — async, backed by
  `AsyncSQLiteStorage` (`aiosqlite`).

Managers are context managers: `with AuthManager(...)` / `async with
AsyncAuthManager(...)` close the storage connection on exit. Otherwise call
`close()` / `await close()` explicitly. There is no `.open()` call —
SQLite storage connects lazily, and `AsyncSQLiteStorage` requires an explicit
`await storage.connect()`.

## Constructor arguments

### AuthConfig

`AuthConfig(**kwargs)` — dataclass. Values resolve as constructor kwargs >
environment variables (`AUTHORITY_*`) > defaults. An empty `jwt_secret_key`
raises `ConfigurationError`. See [Configuration](configuration.md) for all 36
fields.

### AuthManager / AsyncAuthManager

```python
AuthManager(config: AuthConfig, storage: StorageInterface, event_bus: EventBus | None = None)
AsyncAuthManager(config: AuthConfig, storage: AsyncStorageInterface, event_bus: EventBus | None = None)
```

`event_bus` is optional; pass one to receive lifecycle events. See
[Events](events.md).

## Exceptions

All errors inherit from `AuthError`. The full 24-class hierarchy is on the
[Exceptions](exceptions.md) page. Import from `authority`:

```python
from authority import AuthError, InvalidTokenError, InsufficientPermissionsError
```
