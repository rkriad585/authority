# Getting Started

This guide walks through the core concepts and the first end-to-end flow:
installing Authority, creating a manager, registering a user, logging in, and
verifying a token. It takes about five minutes.

## 1. Install

```bash
pip install authority-auth
```

For the async storage backend you also need the `async` extra:

```bash
pip install "authority-auth[async]"
```

See [Installation](installation.md) for all extras and a source install guide.

## 2. Create a configuration and storage

Every Authority setup needs an [`AuthConfig`](configuration.md) and a storage
backend. The SQLite backends create the database file on first use.

```python
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
)

storage = SQLiteStorage("auth.db")
auth = AuthManager(config, storage)
```

The two required values are the JWT signing secret and the Fernet key used to
encrypt MFA secrets. You can generate a Fernet key with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Both can also be provided through environment variables
(`AUTHORITY_JWT_SECRET_KEY`, `AUTHORITY_FERNET_KEY`) — see
[Configuration](configuration.md).

## 3. Register a user

```python
user = auth.register(
    name="Alice",
    email="alice@example.com",
    password="SecureP@ssw0rd!",
    auto_verify=True,
)
print(user["id"])
```

With `auto_verify=True` the email is considered verified immediately. In a real
app you would instead call `request_email_verification()` and have the user
click the emailed link, which is verified with `verify_email(token)`.

`register()` raises `UserExistsError` if the email is already taken, or
`ValidationError` if the password fails the configured policy.

## 4. Log in

```python
result = auth.login(email="alice@example.com", password="SecureP@ssw0rd!")

access_token = result["access_token"]
refresh_token = result["refresh_token"]
```

The result also includes `token_type: "Bearer"`. If MFA is enabled for the
account, `login()` returns `mfa_required: True` and `user_id` instead of tokens;
complete the login with [`verify_mfa_login`](usage.md#multi-factor-authentication).

## 5. Verify a token and read the user

```python
payload = auth.verify_access_token(access_token)
# {"user_id": 1, "jti": "...", "iat": ..., "exp": ..., "iss": "authority", "typ": "access"}

user = auth.get_user(payload["user_id"])
```

`verify_access_token()` raises `TokenExpiredError` if the token is expired and
`InvalidTokenError` if it is malformed or tampered with.

## 6. Refresh and log out

Access tokens expire quickly (15 minutes by default). Use the refresh token to
obtain a new pair; refresh tokens rotate by default and reused tokens are
detected and the whole family revoked.

```python
new_tokens = auth.refresh_access_token(refresh_token)

auth.logout(
    user_id=user["id"],
    refresh_token=refresh_token,
    access_token_jti=payload["jti"],
)
```

## 7. Clean up

```python
auth.close()
```

## What's next

- [Usage](usage.md) — full sync and async examples, MFA, RBAC, API keys, events
- [Framework Integrations](usage.md#framework-integrations) — FastAPI, Flask,
  Django, Starlette, and generic ASGI/WSGI middleware
- [API Reference](api.md) — every public method and class
- [Examples](examples/index.md) — runnable apps for each framework
