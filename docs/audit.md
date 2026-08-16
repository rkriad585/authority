# Audit Log

Every sensitive operation writes an **append-only** audit entry. Entries are
**chain-hashed** — each entry includes the hash of the previous entry — so
tampering with history is detectable. Disable globally with
`audit_log_enabled=False`.

## Reading the log

```python
events = auth.get_audit_log(
    user_id=user["id"],   # optional filter
    action="login",       # optional filter
    limit=100,            # default 100
    offset=0,
)
```

Each entry contains at minimum:

| Field | Description |
|---|---|
| `id` | Monotonic entry id |
| `user_id` | Acting user (may be `None`) |
| `action` | The audited action |
| `ip_address` | Client IP, when provided |
| `user_agent` | Client user-agent, when provided |
| `details` | JSON context |
| `timestamp` | When the entry was written |
| `prev_hash` | Hash chain link to the previous entry |

## What gets logged

Register, login success/failure, logout, password change/reset, email change,
user deletion, MFA setup/enable/disable/failure, token refresh/reuse/revoke,
WebAuthn add/remove, RBAC role assignment/revocation, and API key
create/revoke — plus any custom event you log through the
[EventBus](events.md).

## Manual audit entries

The manager writes audit entries automatically for built-in flows. For custom
actions, hook a handler on the EventBus and call the storage log method, or log
through your own middleware. `Event.AUDIT_EVENT_LOGGED` is emitted each time an
entry is persisted.

## Verification

To verify chain integrity, recompute the hashes across the returned window and
confirm each entry's `prev_hash` matches the previous entry's own hash. A
mismatch indicates the log was modified.

Method signature lives on the [AuthManager](auth-manager.md) /
[AsyncAuthManager](async-auth-manager.md) pages.
