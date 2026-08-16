# Utilities

Standalone helpers in `authority.utils`, re-exported from the top-level
`authority` package.

## Token helpers

| Function | Signature | Purpose |
|---|---|---|
| `generate_secure_token` | `generate_secure_token(byte_length=32) -> str` | Cryptographically secure, URL-safe random token |
| `hash_token` | `hash_token(token) -> str` | SHA-256 hex digest for safe storage |

```python
from authority import generate_secure_token, hash_token

raw = generate_secure_token()
stored = hash_token(raw)  # never store the raw token
```

## Fernet encryption

| Function | Signature | Purpose |
|---|---|---|
| `encrypt_data` | `encrypt_data(data, fernet_key_override=None) -> str \| None` | Encrypt with Fernet; returns base64 ciphertext or `None` |
| `decrypt_data` | `decrypt_data(encrypted_data, fernet_key_override=None) -> str \| None` | Decrypt; returns plaintext or `None` on failure |
| `reset_fernet_cache` | `reset_fernet_cache() -> None` | Clear the cached Fernet instance (for key rotation / tests) |

Secrets are encrypted using the configured `fernet_key`. The library uses this
for TOTP MFA secrets at rest.

## Password helpers

| Function | Signature | Purpose |
|---|---|---|
| `check_password_pwned` | `check_password_pwned(password, api_key=None, timeout=5) -> int \| None` | HIBP Pwned Passwords k-anonymity check; returns breach count or `None` if unavailable |
| `estimate_password_strength` | `estimate_password_strength(password) -> dict` | Heuristic 0–4 strength estimate with reasons (no external deps) |

```python
from authority import check_password_pwned, estimate_password_strength

strength = estimate_password_strength("Tr0ub4dor&3")
if await check_password_pwned("Tr0ub4dor&3", api_key="...") :
    print("Password appears in known breaches")
```

## Email validation

| Function | Signature | Purpose |
|---|---|---|
| `validate_email_format` | `validate_email_format(email) -> bool` | Plausible email format check (simplified RFC 5322) |
