# Sessions

A **session** is a non-revoked, non-expired refresh token for a user. Every
`login()` creates one; `refresh_access_token()` keeps it alive under a new
token while rotating the underlying credential.

## Listing sessions

```python
sessions = auth.list_sessions(user_id=user["id"])
```

Each entry includes the token id, the user-agent and IP address captured at
login (when provided), creation and expiry timestamps, and revocation state.

## Revoking sessions

```python
# Revoke one session by its refresh-token id
auth.revoke_session_by_id(user_id=user["id"], session_token_id=42)

# Revoke everything, optionally keeping the current session alive
count = auth.revoke_all_sessions_for_user(
    user_id=user["id"],
    exclude_token_id=current_session_id,
)
```

- `revoke_session_by_id()` returns `True` if a session was revoked.
- `revoke_all_sessions_for_user()` returns the number of revoked sessions.
  Pass `exclude_token_id` to keep the current session (typical for
  "log out other devices" flows).

## Session metadata

Sessions record context captured at login time:

```python
result = auth.login(
    email="alice@example.com",
    password="...",
    ip_address=request.client.host,
    user_agent=request.headers.get("user-agent"),
)
```

Later, `list_sessions()` exposes that context so you can render a
"your devices" screen and let users revoke unrecognized sessions individually.

## Relationship to tokens

Sessions and refresh tokens are the same records:

| Method | Effect |
|---|---|
| `logout(refresh_token=...)` | Revokes one session |
| `logout_all()` | Revokes all sessions (optionally excluding one) |
| `revoke_session_by_id()` | Revokes one session by id |
| `revoke_all_sessions_for_user()` | Revokes all sessions |

Method signatures live on the [AuthManager](auth-manager.md) /
[AsyncAuthManager](async-auth-manager.md) pages. See [Tokens](tokens.md) for
rotation and reuse detection.
