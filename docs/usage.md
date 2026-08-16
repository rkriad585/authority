# Usage

This page covers the complete feature set of Authority, both sync
(`AuthManager`) and async (`AsyncAuthManager`). The two managers expose the
same 55-method surface; the async version's methods are coroutines.

## Core lifecycle

### Sync

```python
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
)
storage = SQLiteStorage("auth.db")
auth = AuthManager(config, storage)

user = auth.register(
    name="Alice",
    email="alice@example.com",
    password="SecureP@ssw0rd!",
    auto_verify=True,
)

result = auth.login(email="alice@example.com", password="SecureP@ssw0rd!")
payload = auth.verify_access_token(result["access_token"])
user = auth.get_user(payload["user_id"])

auth.logout(
    user_id=user["id"],
    refresh_token=result["refresh_token"],
    access_token_jti=payload["jti"],
)

auth.close()
```

### Async

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

    user = await auth.register(
        name="Bob",
        email="bob@example.com",
        password="SecureP@ssw0rd!",
        auto_verify=True,
    )

    result = await auth.login(email="bob@example.com", password="SecureP@ssw0rd!")
    payload = await auth.verify_access_token(result["access_token"])

    count = await auth.logout_all(user_id=user["id"])
    print(f"Revoked {count} tokens")

    await auth.close()


asyncio.run(main())
```

## Tokens

`login()` returns a dict with:

| Key | Description |
|---|---|
| `access_token` | Short-lived JWT (15 minutes by default) |
| `refresh_token` | Opaque token, hashed at rest, rotated on use |
| `token_type` | `"Bearer"` |

`verify_access_token(token)` returns the JWT payload (`user_id`, `jti`, `iat`,
`exp`, `iss`, `typ`).

Refresh tokens are rotated by default. The old token becomes unusable and a new
pair is issued; a `refresh_token_reuse_grace_seconds` window (default 10s)
absorbs legitimate race-condition retries. If a rotated token is reused after
the grace period, the entire token family is revoked.

```python
new_tokens = auth.refresh_access_token(refresh_token)
```

## User management

```python
user = auth.get_user(user_id)
profile = auth.get_profile(user_id)          # profile JSON blob
user = auth.update_user(user_id, {"name": "Alice Smith"})
profile = auth.update_profile(user_id, {"theme": "dark"})
auth.delete_user(user_id)
```

## Email verification

```python
token = auth.request_email_verification(user_id)
# email the token to the user...
user = auth.verify_email(token)
```

## Password reset

`request_password_reset()` always returns a token string, even for unknown
emails (an empty string when the user does not exist), to prevent email
enumeration.

```python
token = auth.request_password_reset("alice@example.com")
if token:
    user = auth.reset_password(token, "NewSecureP@ssw0rd!")
```

## Multi-factor authentication

TOTP-based, with secrets encrypted at rest using Fernet and single-use recovery
codes.

```python
# Step 1 — initiate setup; returns the shared secret and a provisioning URI
setup = auth.setup_mfa(user_id=user["id"])
print(setup["secret"])
print(setup["provisioning_uri"])   # render as a QR code in your frontend

# Step 2 — user scans the QR code and enters a 6-digit code
result = auth.verify_and_enable_mfa(user_id=user["id"], code="123456")
print(result["recovery_codes"])    # store these; shown only once

# Step 3 — during login, when MFA is enabled:
login_result = auth.login(email="alice@example.com", password="...")
if login_result.get("mfa_required"):
    tokens = auth.verify_mfa_login(
        user_id=login_result["user_id"],
        code="654321",             # a TOTP code or a recovery code
    )

# Status
status = auth.get_mfa_status(user_id=user["id"])
print(status["mfa_enabled"], status["recovery_codes_remaining"])

# Disable (requires the current password)
auth.disable_mfa(user_id=user["id"], password="...")

# Regenerate recovery codes (invalidates old ones, requires password)
auth.regenerate_recovery_codes(user_id=user["id"], password="...")
```

## WebAuthn / passkeys

The four WebAuthn methods map directly onto the browser API.

```python
# 1. Get registration options for navigator.credentials.create()
options = auth.start_webauthn_registration(user_id=user["id"])

# 2. Verify the browser response
cred = auth.complete_webauthn_registration(
    user_id=user["id"],
    credential_data=credential_data,   # dict from navigator.credentials.create()
)

# 3. Get authentication options for navigator.credentials.get()
options = auth.start_webauthn_authentication(user_id=user["id"])

# 4. Verify the assertion — returns tokens on success
result = auth.complete_webauthn_authentication(credential_data=assertion_data)

# List / remove credentials
auth.list_webauthn_credentials(user_id=user["id"])
auth.delete_webauthn_credential(user_id=user["id"], credential_id="...")
```

WebAuthn requires `webauthn_rp_id` and `webauthn_expected_origin` to be set in
the [configuration](configuration.md).

## RBAC

Roles and permissions are managed through the manager. Users gain permissions
through their roles.

```python
admin_role = auth.create_role("admin", "Full system access")
read_perm = auth.create_permission("posts:read")

auth.assign_permission_to_role(admin_role["id"], read_perm["id"])
auth.assign_role_to_user(user_id=user["id"], role_id=admin_role["id"])

if auth.has_permission(user_id=user["id"], permission_code="posts:read"):
    print("Can read posts")

auth.require_permission(user_id=user["id"], permission_code="posts:read")
# raises InsufficientPermissionsError if the user lacks the permission

print(auth.get_user_permissions(user_id=user["id"]))
print(auth.get_user_roles(user_id=user["id"]))
```

Other RBAC methods: `delete_role`, `list_roles`, `delete_permission`,
`list_permissions`, `remove_permission_from_role`, `get_role_permissions`,
`remove_role_from_user`.

New users are automatically assigned the role named by `default_user_role`
(`"user"` by default).

## API keys

Scoped keys with prefix-based lookup for machines.

```python
result = auth.create_api_key(
    user_id=user["id"],
    description="Production API access",
    scopes=["read", "write"],
    expires_in_days=90,
)
print(result["key"])      # plaintext, shown only once
print(result["prefix"])

info = auth.verify_api_key(result["key"])
print(info["user_id"], info["scopes"])

auth.list_api_keys(user_id=user["id"])
auth.revoke_api_key(user_id=user["id"], key_prefix=result["prefix"])
```

## Sessions

Refresh tokens are tracked as sessions and can be listed or revoked.

```python
auth.list_sessions(user_id=user["id"])
auth.revoke_session_by_id(user_id=user["id"], session_token_id=42)
count = auth.revoke_all_sessions_for_user(user_id=user["id"])
```

## Audit log

Every sensitive operation writes an append-only audit entry. Chain hashing
links entries so tampering is detectable.

```python
events = auth.get_audit_log(user_id=user["id"], limit=50)
```

## Events

Pass an `EventBus` to the manager to react to lifecycle events with sync or
async handlers.

```python
from authority import Event, EventBus

bus = EventBus()


def on_login(data):
    print(f"Login: user {data['user_id']} from {data.get('ip_address')}")


async def on_register(data):
    await send_welcome_email(data["email"])


bus.on(Event.USER_LOGIN_SUCCESS, on_login)
bus.on(Event.USER_REGISTERED, on_register)

auth = AuthManager(config, storage, event_bus=bus)
```

The 22 events: `USER_REGISTERED`, `USER_LOGIN_SUCCESS`, `USER_LOGIN_FAILED`,
`USER_LOGOUT`, `USER_PASSWORD_CHANGED`, `USER_PASSWORD_RESET`,
`USER_EMAIL_CHANGED`, `USER_DELETED`, `MFA_SETUP_INITIATED`, `MFA_ENABLED`,
`MFA_DISABLED`, `MFA_FAILED`, `TOKEN_REFRESHED`, `TOKEN_REUSE_DETECTED`,
`TOKEN_REVOKED`, `WEBAUTHN_CREDENTIAL_ADDED`, `WEBAUTHN_CREDENTIAL_REMOVED`,
`RBAC_ROLE_ASSIGNED`, `RBAC_ROLE_REVOKED`, `API_KEY_CREATED`,
`API_KEY_REVOKED`, `AUDIT_EVENT_LOGGED`.

## Storage

Authority ships `SQLiteStorage` (sync) and `AsyncSQLiteStorage` (async,
requires the `async` extra). To use another database, implement
`StorageInterface` or `AsyncStorageInterface` and pass it to the manager:

```python
from authority.storage.base import StorageInterface


class PostgresStorage(StorageInterface):
    def get_user_by_id(self, user_id: int) -> dict | None:
        ...

    # ... implement all abstract methods
```

## Framework integrations

### FastAPI

Requires the `fastapi` extra. Bind a global manager with `init_auth`, then use
the provided dependencies.

```python
from fastapi import FastAPI, Depends
from authority import AuthConfig, AsyncAuthManager
from authority.storage import AsyncSQLiteStorage
from authority.fastapi import get_current_user, init_auth, require_permission

app = FastAPI()

config = AuthConfig(jwt_secret_key="...", fernet_key="...")
storage = AsyncSQLiteStorage("auth.db")
auth = AsyncAuthManager(config, storage)
init_auth(auth)

require_admin = require_permission("admin.access")


@app.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


@app.get("/admin")
async def admin(user: dict = Depends(require_admin)):
    return {"message": "Welcome, admin!"}
```

Connect storage and close the manager in the FastAPI lifespan or startup /
shutdown events. `require_role(role_name)` is available too.

### Flask

Requires the `flask` extra. `FlaskAuth` provides instance decorators; module
helpers (`init_auth`, `current_user`, `login_required`, `require_permission`,
`require_role`) are also available.

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
        AuthConfig(jwt_secret_key="...", fernet_key="..."),
        SQLiteStorage("auth.db"),
    ),
)


@app.route("/me")
@auth.login_required
def me():
    user = auth.current_user()
    return jsonify({"id": user["id"], "email": user["email"]})


@app.route("/admin")
@auth.require_permission("admin.access")
def admin():
    return "Welcome, admin!"
```

Tokens are read from the `Authorization: Bearer <token>` header, or from
`session["access_token"]` for session-based flows.

### Django

Requires the `django` extra. `init_auth()` binds the manager; decorators and
helpers protect views; `AuthorityBackend` plugs into Django's session auth.

```python
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.urls import path
from authority.django import get_current_user, init_auth, login_required

init_auth(auth_manager)  # an authority.AuthManager


@login_required
def me(request):
    user = get_current_user(request)
    return JsonResponse({"email": user["email"]})


urlpatterns = [path("me", me)]
```

Add `authority.django.AuthorityBackend` to `AUTHENTICATION_BACKENDS` to
authenticate Django users with authority credentials. Use
`authority_user_to_django_user()` to mirror authority users into
`django.contrib.auth.models.User` (same primary key, unusable password).

### Starlette

Requires the `starlette` extra. `StarletteAuth` provides decorators and
`current_user()` for `async` endpoints.

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

For bare ASGI/WSGI apps or frameworks without a dedicated helper, wrap the app
in the middleware. Auth state is stored at `scope["authority"]` /
`environ["authority"]`.

```python
# ASGI
from authority.asgi import AuthorityASGIMiddleware

app = AuthorityASGIMiddleware(inner_app, async_manager, auth_required=True)
```

```python
# WSGI
from authority.wsgi import AuthorityWSGIMiddleware

app = AuthorityWSGIMiddleware(inner_app, manager, auth_required=True)
```

Helpers: `get_user_state()`, `is_authenticated()`,
`user_id_from_scope()` / `user_id_from_environ()`, `get_current_user()`.
With `auth_required=True` unauthenticated requests receive a `401` JSON
response before reaching the application.

See the [Examples](examples/index.md) for fully runnable applications for every
integration.
