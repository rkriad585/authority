# Tokens

`authority-auth` issues a two-token pair on login: a short-lived **access
token** (JWT) and an opaque **refresh token**.

| Token | Type | Default lifetime | Revocable |
|---|---|---|---|
| Access token | JWT (`HS256` default) | 15 min (`jwt_access_token_expiry_minutes`) | no (stateless) |
| Refresh token | Opaque, URL-safe | 14 days (`jwt_refresh_token_expiry_days`) | yes |

## Access tokens

JWTs are signed with `jwt_secret_key` using `jwt_algorithm`. The payload
contains at minimum:

```
user_id, jti, iat, exp, iss, typ
```

Verify and decode an access token with `verify_access_token()` — it returns the
payload dict and raises `InvalidTokenError` / `TokenExpiredError` on failure:

```python
payload = auth.verify_access_token(result["access_token"])
user = auth.get_user(payload["user_id"])
```

Logout can pass the token's `jti` to revoke the session immediately:

```python
auth.logout(
    user_id=user["id"],
    refresh_token=result["refresh_token"],
    access_token_jti=payload["jti"],
)
```

## Refresh tokens

Refresh tokens are stored hashed (SHA-256) in the database — the raw token is
never persisted. They are used to obtain new pairs without re-entering
credentials:

```python
pair = auth.refresh_access_token(refresh_token)
new_access, new_refresh = pair["access_token"], pair["refresh_token"]
```

### Rotation and reuse detection

By default (`refresh_token_rotate=True`) every refresh rotates the token: the
old refresh token is marked used and a new pair is issued. A short
`refresh_token_reuse_grace_seconds` window (default 10 s) absorbs legitimate
race-condition retries from concurrent requests.

If a rotated token is presented **after** the grace window, the library
detects reuse, revokes the entire token family, and emits
`Event.TOKEN_REUSE_DETECTED`. Any access tokens already issued to that family
become ineffective once the session is gone — `require_permission()` /
`verify_access_token()` still validate the JWT, but downstream authorization
checks on the session fail.

### Absolute maximum lifetime

`jwt_refresh_token_absolute_max_days` caps how long a refresh token chain may
live regardless of rotation, so a session that is refreshed forever still
expires.

## Lifecycle

1. `login()` → `access_token` + `refresh_token` (or `mfa_required`).
2. Frontend stores the pair and sends the access token as
   `Authorization: Bearer <token>`.
3. When the access token expires (or slightly before), call
   `refresh_access_token()` for a new pair.
4. `logout()` revokes the refresh token; `logout_all()` revokes every session.
5. Unused refresh tokens are pruned on manager startup when
   `prune_tokens_on_startup` is enabled.

## Config reference

| Field | Default | Purpose |
|---|---|---|
| `jwt_secret_key` | — (required) | Signing key, ≥ 32 chars |
| `jwt_algorithm` | `"HS256"` | JWT signing algorithm |
| `jwt_access_token_expiry_minutes` | `15` | Access token lifetime |
| `jwt_refresh_token_expiry_days` | `14` | Per-token refresh lifetime |
| `jwt_refresh_token_absolute_max_days` | `30` | Maximum chain lifetime |
| `refresh_token_rotate` | `True` | Rotate refresh tokens on use |
| `refresh_token_reuse_grace_seconds` | `10` | Reuse-detection grace window |

See [Configuration](configuration.md) for the full table.
