<div align="center">

# Authority

**Comprehensive, framework-agnostic Python authentication library**

[![PyPI version](https://img.shields.io/pypi/v/authority-auth?color=blue)](https://pypi.org/project/authority-auth/)
[![Python versions](https://img.shields.io/pypi/pyversions/authority-auth)](https://pypi.org/project/authority-auth/)
[![License: MIT](https://img.shields.io/pypi/l/authority-auth)](https://github.com/rkriad585/authority/blob/main/LICENSE)

A batteries-included authentication and authorization library for Python.
JWT access tokens with refresh rotation, TOTP MFA with recovery codes,
WebAuthn/passkey support, RBAC, API key management, password security with
HIBP breach checking, and pluggable storage -- all framework-agnostic.

</div>

---

## Features

- **JWT Authentication** -- Access tokens (HS256) with short-lived expiry and opaque refresh tokens with rotation, family tracking, and reuse detection
- **TOTP MFA** -- Time-based one-time passwords with Fernet-encrypted secrets and single-use recovery codes
- **WebAuthn / Passkeys** -- Registration and authentication via the WebAuthn standard
- **RBAC** -- Role-based access control with granular permissions
- **API Keys** -- Prefix-based lookup, scoped keys with optional expiry
- **Password Security** -- Configurable complexity rules, password history enforcement, and HIBP breach checking via k-anonymity
- **Pluggable Storage** -- Sync and async SQLite backends included; implement `StorageInterface` or `AsyncStorageInterface` for any database
- **Event Bus** -- Typed lifecycle events (login, MFA, token refresh, RBAC changes, etc.) with sync and async handler support
- **Audit Logging** -- Append-only audit trail with optional chain hashing for tamper evidence
- **Framework-Agnostic** -- First-party integrations for FastAPI, Flask, Django, and Starlette, plus generic ASGI/WSGI middleware for everything else
- **Full Async Support** -- `AsyncAuthManager` with `AsyncSQLiteStorage` for async-first applications

## Requirements

- Python 3.10+
- SQLite (included in Python standard library)

## Installation

```bash
pip install authority-auth
```

For async SQLite storage support:

```bash
pip install "authority-auth[async]"
```

For development:

```bash
pip install "authority-auth[dev]"
```

## Quick Start

```python
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

# Configure
config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",  # Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
)

# Initialize storage (creates/opens the database)
storage = SQLiteStorage("auth.db")

# Create the auth manager
auth = AuthManager(config, storage)

# Register a user
user = auth.register(
    name="Alice",
    email="alice@example.com",
    password="SecureP@ssw0rd!",
    auto_verify=True,
)
print(f"Registered user: {user['id']}")

# Login
result = auth.login(email="alice@example.com", password="SecureP@ssw0rd!")
print(f"Access token: {result['access_token'][:20]}...")
print(f"Refresh token: {result['refresh_token'][:20]}...")

# Verify an access token
payload = auth.verify_access_token(result["access_token"])
print(f"User ID from token: {payload['user_id']}")

# Refresh tokens
new_tokens = auth.refresh_access_token(result["refresh_token"])

# Logout
auth.logout(
    user_id=user["id"],
    refresh_token=result["refresh_token"],
    access_token_jti=payload["jti"],
)

# Clean up
auth.close()
```

## Async Usage

```python
import asyncio
from authority import AuthConfig, AsyncAuthManager
from authority.storage import AsyncSQLiteStorage

async def main():
    config = AuthConfig(
        jwt_secret_key="your-secret-key-min-32-chars",
        fernet_key="your-fernet-key",
    )

    storage = AsyncSQLiteStorage("auth.db")
    await storage.connect()

    auth = AsyncAuthManager(config, storage)

    # Register
    user = await auth.register(
        name="Bob",
        email="bob@example.com",
        password="SecureP@ssw0rd!",
        auto_verify=True,
    )

    # Login
    result = await auth.login(email="bob@example.com", password="SecureP@ssw0rd!")
    print(f"Access token: {result['access_token'][:20]}...")

    # Verify
    payload = await auth.verify_access_token(result["access_token"])
    print(f"User ID: {payload['user_id']}")

    # Refresh
    new_tokens = await auth.refresh_access_token(result["refresh_token"])

    # Logout all devices
    count = await auth.logout_all(user_id=user["id"])
    print(f"Revoked {count} tokens")

    await auth.close()

asyncio.run(main())
```

## FastAPI Integration

```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from authority import AuthConfig, AsyncAuthManager
from authority.storage import AsyncSQLiteStorage
from authority.exceptions import (
    InvalidCredentialsError,
    TokenExpiredError,
    InvalidTokenError,
    MFAFailedError,
    UserExistsError,
    ValidationError,
)

app = FastAPI()
security = HTTPBearer()

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
)
storage = AsyncSQLiteStorage("auth.db")
auth = AsyncAuthManager(config, storage)


@app.on_event("startup")
async def startup():
    await storage.connect()


@app.on_event("shutdown")
async def shutdown():
    await auth.close()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    try:
        payload = await auth.verify_access_token(credentials.credentials)
        user = await auth.get_user(payload["user_id"])
        return user
    except (InvalidTokenError, TokenExpiredError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


@app.post("/register")
async def register(name: str, email: str, password: str):
    try:
        user = await auth.register(name, email, password, auto_verify=True)
        return {"user_id": user["id"], "email": user["email"]}
    except UserExistsError:
        raise HTTPException(status_code=409, detail="Email already registered")
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=str(e))


@app.post("/login")
async def login(email: str, password: str):
    try:
        result = await auth.login(email=email, password=password)
        if result.get("mfa_required"):
            return {"mfa_required": True, "user_id": result["user_id"]}
        return {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    except InvalidCredentialsError:
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    return {"id": user["id"], "name": user["name"], "email": user["email"]}
```

## Framework Integrations

Each integration ships in its own module and requires the matching framework
extra. Fully working apps for every framework live in
[`examples/apps/`](examples/apps/).

```bash
pip install "authority-auth[flask]"    # Flask
pip install "authority-auth[django]"   # Django
pip install "authority-auth[starlette]"  # Starlette
pip install "authority-auth[fastapi]"  # FastAPI
```

### Flask

```python
from flask import Flask, jsonify
from authority import AuthConfig, AuthManager
from authority.storage.sqlite import SQLiteStorage
from authority.flask import FlaskAuth

app = Flask(__name__)
app.secret_key = "app-session-secret"

auth = FlaskAuth(
    app,
    AuthManager(
        AuthConfig(jwt_secret_key="your-secret-key-min-32-chars", fernet_key="your-fernet-key"),
        SQLiteStorage("auth.db"),
    ),
)

@app.route("/me")
@auth.login_required
def me():
    user = auth.current_user()  # full user dict, or None
    return jsonify({"id": user["id"], "email": user["email"]})

@app.route("/admin")
@auth.require_permission("admin.access")
def admin():
    return "Welcome, admin!"
```

Tokens are read from the `Authorization: Bearer <token>` header, or from
`session["access_token"]` for session-based flows. Module-level helpers
(`init_auth`, `login_required`, `require_permission`, `require_role`,
`current_user`) are also available.

### Django

```python
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.urls import path
from authority.django import get_current_user, init_auth, login_required, require_permission

init_auth(auth_manager)  # an authority.AuthManager

@login_required
def me(request):
    user = get_current_user(request)
    return JsonResponse({"email": user["email"]})

urlpatterns = [path("me", me)]
```

Add `authority.django.AuthorityBackend` to `AUTHENTICATION_BACKENDS` to
authenticate Django users with authority credentials, and use
`authority_user_to_django_user()` to mirror authority users into
`django.contrib.auth.models.User` (same primary key, unusable password).

### Starlette

```python
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from authority.starlette import StarletteAuth

auth = StarletteAuth(async_manager)  # an authority.AsyncAuthManager

@auth.require_role("admin")
async def admin(request):
    return JSONResponse({"message": "Welcome, admin!"})

app = Starlette(routes=[Route("/admin", admin)])
```

### Generic middleware

For frameworks without a dedicated helper (or for bare applications), use the
framework-agnostic middleware. Both attach the auth result to the request
(`scope["authority"]` / `environ["authority"]`) and provide `get_user_state`,
`is_authenticated`, `user_id_from_scope` / `user_id_from_environ`, and
`get_current_user` helpers.

```python
# ASGI (works with Starlette, FastAPI, Quart, bare ASGI apps)
from authority.asgi import AuthorityASGIMiddleware

app = AuthorityASGIMiddleware(inner_app, async_manager, auth_required=True)
```

```python
# WSGI (works with Flask, Django, bare WSGI apps)
from authority.wsgi import AuthorityWSGIMiddleware

app = AuthorityWSGIMiddleware(inner_app, manager, auth_required=True)
```

With `auth_required=True` unauthenticated requests are rejected with a 401 JSON
response before reaching the application.

## Configuration

`AuthConfig` accepts values via constructor arguments, environment variables (prefixed with `AUTHORITY_`), or defaults. Constructor kwargs take highest priority.

| Parameter | Env Var | Default | Description |
|---|---|---|---|
| `jwt_secret_key` | `AUTHORITY_JWT_SECRET_KEY` | `""` | **Required.** Secret key for signing JWTs |
| `fernet_key` | `AUTHORITY_FERNET_KEY` | `""` | **Required.** Fernet key for encrypting MFA secrets |
| `db_path` | `AUTHORITY_DB_PATH` | `"authority_data.db"` | Path to the SQLite database file |
| `jwt_algorithm` | -- | `"HS256"` | JWT signing algorithm |
| `jwt_access_token_expiry_minutes` | -- | `15` | Access token lifetime in minutes |
| `jwt_refresh_token_expiry_days` | -- | `7` | Refresh token lifetime in days |
| `jwt_refresh_token_absolute_max_days` | -- | `30` | Maximum refresh token age regardless of rotation |
| `password_min_length` | -- | `12` | Minimum password length |
| `password_history_depth` | -- | `5` | Number of previous passwords to remember |
| `password_require_complexity` | -- | `True` | Enforce complexity regex |
| `hibp_check_enabled` | -- | `False` | Check passwords against HIBP breach database |
| `hibp_api_key` | `AUTHORITY_HIBP_KEY` | `""` | Optional HIBP API key |
| `hibp_failure_mode` | -- | `"warn"` | `"reject"`, `"warn"`, or `"ignore"` |
| `failed_login_lockout_threshold` | -- | `5` | Failed attempts before lockout |
| `failed_login_lockout_minutes` | -- | `15` | Lockout duration in minutes |
| `email_verification_required` | -- | `True` | Require email verification on signup |
| `mfa_issuer_name` | -- | `"Authority Powered App"` | Issuer name shown in authenticator apps |
| `mfa_recovery_code_count` | -- | `10` | Number of recovery codes generated |
| `mfa_totp_valid_window` | -- | `1` | TOTP valid window (+-1 step = 30s each) |
| `refresh_token_rotate` | -- | `True` | Rotate refresh tokens on use |
| `refresh_token_reuse_grace_seconds` | -- | `10` | Grace period for legitimate refresh retries |
| `webauthn_rp_id` | `AUTHORITY_WEBAUTHN_RP_ID` | `""` | WebAuthn relying party ID |
| `webauthn_rp_name` | -- | `"My Application"` | WebAuthn relying party name |
| `webauthn_expected_origin` | `AUTHORITY_WEBAUTHN_ORIGIN` | `""` | Expected origin for WebAuthn |
| `audit_log_enabled` | -- | `True` | Enable audit logging |
| `default_user_role` | -- | `"user"` | Default role assigned to new users |
| `api_key_byte_length` | -- | `32` | Byte length of generated API keys |

## MFA Setup

TOTP-based multi-factor authentication with encrypted secret storage and recovery codes:

```python
# Initiate MFA setup -- returns secret and provisioning URI
setup = auth.setup_mfa(user_id=user["id"])
print(f"Secret: {setup['secret']}")
print(f"URI: {setup['provisioning_uri']}")
# Show this URI as a QR code in your frontend

# User scans QR code, enters 6-digit code to confirm
result = auth.verify_and_enable_mfa(user_id=user["id"], code="123456")
print(f"Recovery codes (store these!): {result['recovery_codes']}")

# During login, after password succeeds:
login_result = auth.login(email="alice@example.com", password="...")
if login_result.get("mfa_required"):
    # Ask user for TOTP code or recovery code
    tokens = auth.verify_mfa_login(
        user_id=login_result["user_id"],
        code="654321",  # TOTP code or recovery code
    )

# Check MFA status
status = auth.get_mfa_status(user_id=user["id"])
print(f"MFA enabled: {status['mfa_enabled']}")
print(f"Recovery codes remaining: {status['recovery_codes_remaining']}")

# Disable MFA (requires password re-authentication)
auth.disable_mfa(user_id=user["id"], password="...")
```

## RBAC

Role-based access control with permissions:

```python
# Create roles
admin_role = auth.create_role("admin", "Full system access")
editor_role = auth.create_role("editor", "Can edit content")

# Create permissions
read_perm = auth.create_permission("posts:read")
write_perm = auth.create_permission("posts:write")
delete_perm = auth.create_permission("posts:delete")

# Assign permissions to roles
auth.assign_permission_to_role(admin_role["id"], read_perm["id"])
auth.assign_permission_to_role(admin_role["id"], write_perm["id"])
auth.assign_permission_to_role(admin_role["id"], delete_perm["id"])
auth.assign_permission_to_role(editor_role["id"], read_perm["id"])
auth.assign_permission_to_role(editor_role["id"], write_perm["id"])

# Assign roles to users
auth.assign_role_to_user(user_id=1, role_id=admin_role["id"])

# Check permissions
if auth.has_permission(user_id=1, permission_code="posts:delete"):
    print("User can delete posts")

# Get all effective permissions
perms = auth.get_user_permissions(user_id=1)
# ["posts:read", "posts:write", "posts:delete"]
```

## API Keys

Scoped API keys with prefix-based lookup:

```python
# Create an API key
key_result = auth.create_api_key(
    user_id=user["id"],
    description="Production API access",
    scopes=["read", "write"],
    expires_in_days=90,
)
print(f"Key (save this, shown only once): {key_result['key']}")
print(f"Prefix: {key_result['prefix']}")

# Verify an API key (e.g., from a request header)
key_info = auth.verify_api_key(key_result["key"])
print(f"User: {key_info['user_id']}, Scopes: {key_info['scopes']}")

# List all API keys for a user
keys = auth.list_api_keys(user_id=user["id"])
for k in keys:
    print(f"{k['key_prefix']}... - {k['description']}")

# Revoke an API key
auth.revoke_api_key(user_id=user["id"], key_prefix=key_result["prefix"])
```

## Event System

Subscribe to lifecycle events for logging, notifications, analytics, or custom workflows:

```python
from authority import EventBus, Event

bus = EventBus()

# Sync handler
def on_login(data):
    print(f"Login: user {data['user_id']} from {data.get('ip_address')}")

# Async handler
async def on_register(data):
    await send_welcome_email(data["email"])

bus.on(Event.USER_LOGIN_SUCCESS, on_login)
bus.on(Event.USER_REGISTERED, on_register)

# Pass the event bus when creating the manager
auth = AuthManager(config, storage, event_bus=bus)

# Supported events:
#   USER_REGISTERED, USER_LOGIN_SUCCESS, USER_LOGIN_FAILED, USER_LOGOUT
#   USER_PASSWORD_CHANGED, USER_PASSWORD_RESET, USER_EMAIL_CHANGED, USER_DELETED
#   MFA_SETUP_INITIATED, MFA_ENABLED, MFA_DISABLED, MFA_FAILED
#   TOKEN_REFRESHED, TOKEN_REUSE_DETECTED
#   WEBAUTHN_CREDENTIAL_ADDED, WEBAUTHN_CREDENTIAL_REMOVED
#   RBAC_ROLE_ASSIGNED, RBAC_ROLE_REVOKED
#   API_KEY_CREATED, API_KEY_REVOKED
```

## Storage

Authority ships with SQLite backends. For other databases, implement `StorageInterface` (sync) or `AsyncStorageInterface` (async):

```python
from authority.storage.base import StorageInterface

class PostgresStorage(StorageInterface):
    def get_user_by_id(self, user_id: int) -> dict | None:
        # Your implementation here
        ...

    # Implement all abstract methods ...
```

## Security

See [SECURITY.md](SECURITY.md) for the full security policy, vulnerability reporting process, and security considerations.

Key security properties:

- Algorithm pinned in every `jwt.decode()` call to prevent algorithm confusion
- Refresh tokens stored as SHA-256 hashes, never plaintext
- Token rotation with family tracking and automatic revocation on reuse
- MFA secrets encrypted at rest with Fernet (AES-128-CBC)
- Passwords hashed with bcrypt (cost factor 12+)
- HIBP integration uses k-anonymity (only SHA-1 prefix sent)
- Audit log is append-only with chain hashing for tamper evidence

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

[MIT](LICENSE) -- authority-auth (c) 2026 rkriad585.
