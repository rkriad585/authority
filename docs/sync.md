# Sync usage

`AuthManager` is the synchronous entry point, built for WSGI apps, scripts, and
synchronous services.

## Setup

```python
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
)
auth = AuthManager(config, SQLiteStorage("authority_data.db"))
```

`SQLiteStorage` connects lazily: the first operation initializes the schema.
There is no mandatory `.open()` call.

## Lifecycle

Prefer the context manager — it calls `close()` for you:

```python
with AuthManager(config, SQLiteStorage("authority_data.db")) as auth:
    user = auth.register("Alice", "alice@example.com", "SecureP@ss1234!")
```

Or close explicitly when the app shuts down:

```python
auth = AuthManager(config, storage)
try:
    ...
finally:
    auth.close()
```

For a web app, create the manager at startup and close it on shutdown (Flask
`teardown_appcontext`, Django `AppConfig.ready` / atexit, WSGI middleware
teardown).

## Framework integrations

- [Flask](examples/flask.md) — `FlaskAuth` decorators and `current_user()`.
- [Django](examples/django.md) — `init_auth()`, view decorators, and
  `AuthorityBackend`.
- [WSGI](examples/wsgi.md) — `AuthorityWSGIMiddleware` wraps any WSGI app.

## Full feature tour

Register, login, tokens, MFA, WebAuthn, RBAC, API keys, sessions, and audit
are all covered with examples on the [Usage](usage.md) page. Method signatures
are on the [AuthManager](auth-manager.md) reference page.

## Threading

`AuthManager` operations are synchronous and share the SQLite connection from
`SQLiteStorage`. For concurrent request handling, either give each thread its
own manager/storage pair, or use the [async](async.md) manager with an
async framework instead.
