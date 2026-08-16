# API Keys

Machine-to-machine access uses opaque API keys with **prefix-based lookup**.
Only the prefix and a hash of the full key are stored — the full key is never
persisted, so it cannot be recovered after creation.

## Creating keys

```python
result = auth.create_api_key(
    user_id=user["id"],
    description="Production API access",
    scopes=["read", "write"],
    expires_in_days=90,
)
key = result["key"]       # plaintext — shown once
prefix = result["prefix"] # e.g. "auth_3f8a2b"
```

Returned fields:

| Key | Description |
|---|---|
| `key` | The full secret; display it to the user exactly once |
| `prefix` | Stable identifier for listing and revocation |
| `id` | Database id |
| `scopes` | The scopes you passed |
| `expires_at` | Expiry timestamp, if `expires_in_days` was set |

## Verifying keys

```python
info = auth.verify_api_key(key)
print(info["user_id"], info["scopes"])
```

Verification hashes the presented key and looks it up by prefix + hash,
checking expiry and active status. On failure it raises `InvalidAPIKeyError`.

## Listing and revoking

```python
auth.list_api_keys(user_id=user["id"])

auth.revoke_api_key(user_id=user["id"], key_prefix=prefix)
```

`list_api_keys()` returns metadata (description, scopes, last used, expiry)
without the secret. `revoke_api_key()` returns `True` if a matching active key
was revoked.

## Key generation

`generate_secure_token()` powers key generation; `api_key_byte_length`
(default `32`) controls the entropy of the raw key.

## Events

`API_KEY_CREATED` and `API_KEY_REVOKED` are emitted for audit purposes. See
[Events](events.md).

Method signatures live on the [AuthManager](auth-manager.md) /
[AsyncAuthManager](async-auth-manager.md) pages.
