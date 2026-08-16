# Events

The `EventBus` broadcasts typed lifecycle events. Handlers are plain
functions; they may be synchronous or coroutines.

```python
from authority.events import Event, EventBus

bus = EventBus()

def on_register(payload):
    print("New user:", payload["email"])

async def on_login(payload):
    await notify_slack(f"user {payload['user_id']} logged in")

bus.on(Event.USER_REGISTERED, on_register)
bus.on(Event.USER_LOGIN_SUCCESS, on_login)

bus.emit(Event.USER_REGISTERED, {"user_id": 1, "email": "a@b.com"})
await bus.emit_async(Event.USER_LOGIN_SUCCESS, {"user_id": 1})
```

## EventBus

| Method | Signature | Purpose |
|---|---|---|
| `on` | `on(event, handler)` | Register a handler for an event |
| `off` | `off(event, handler)` | Remove a handler |
| `emit` | `emit(event, data=None)` | Fire handlers synchronously; async handlers are scheduled on the running loop (skipped with a log if none) |
| `emit_async` | `emit_async(event, data=None)` | Fire handlers, awaiting coroutine handlers |
| `clear` | `clear()` | Remove all handlers |

`event` may be an `Event` member or the raw string value (e.g. `"user.registered"`).
`data` is a `dict` passed to every handler. Handler exceptions are caught and
logged; one failing handler does not stop the others.

## Event enum

`Event(str, Enum)` — all 22 lifecycle events:

| Event | Value | Emitted when |
|---|---|---|
| `USER_REGISTERED` | `user.registered` | A user registers |
| `USER_LOGIN_SUCCESS` | `user.login_success` | Login succeeds |
| `USER_LOGIN_FAILED` | `user.login_failed` | Login fails |
| `USER_LOGOUT` | `user.logout` | A user logs out |
| `USER_PASSWORD_CHANGED` | `user.password_changed` | Password changed |
| `USER_PASSWORD_RESET` | `user.password_reset_requested` | Password reset requested |
| `USER_EMAIL_CHANGED` | `user.email_changed` | Email changed |
| `USER_DELETED` | `user.deleted` | A user is deleted |
| `MFA_SETUP_INITIATED` | `mfa.setup_initiated` | MFA setup started |
| `MFA_ENABLED` | `mfa.enabled` | MFA enabled |
| `MFA_DISABLED` | `mfa.disabled` | MFA disabled |
| `MFA_FAILED` | `mfa.failed` | MFA verification failed |
| `TOKEN_REFRESHED` | `token.refreshed` | Refresh token rotated |
| `TOKEN_REUSE_DETECTED` | `token.reuse_detected` | A rotated token was reused |
| `TOKEN_REVOKED` | `token.revoked` | A token was revoked |
| `WEBAUTHN_CREDENTIAL_ADDED` | `webauthn.credential_added` | Passkey registered |
| `WEBAUTHN_CREDENTIAL_REMOVED` | `webauthn.credential_removed` | Passkey removed |
| `RBAC_ROLE_ASSIGNED` | `rbac.role_assigned` | Role assigned to a user |
| `RBAC_ROLE_REVOKED` | `rbac.role_revoked` | Role removed from a user |
| `API_KEY_CREATED` | `api_key.created` | API key created |
| `API_KEY_REVOKED` | `api_key.revoked` | API key revoked |
| `AUDIT_EVENT_LOGGED` | `audit.event_logged` | An audit entry was written |

## Wiring the bus to a manager

Pass an `EventBus` to the manager constructor to receive its events:

```python
from authority import AuthConfig
from authority.core import AuthManager
from authority.events import Event, EventBus
from authority.storage.sqlite import SQLiteStorage

bus = EventBus()
bus.on(Event.TOKEN_REUSE_DETECTED, lambda p: security_alert(p))

auth = AuthManager(
    AuthConfig(jwt_secret_key="your-secret-key-min-32-chars"),
    SQLiteStorage("authority_data.db"),
    event_bus=bus,
)
```
