# Starlette Example App

A runnable Starlette web app demonstrating the `authority.starlette` integration.
It starts a real ASGI server (via `uvicorn`).

## What it demonstrates

- `authority.starlette.StarletteAuth` decorators (`login_required`,
  `require_permission`) and `current_user()`
- Async endpoint handlers backed by `AsyncAuthManager` and
  `AsyncSQLiteStorage`

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
pip install uvicorn
```

## Run

```bash
uvicorn examples.apps.starlette_app.app:app
```

The app seeds a demo admin account on startup and then serves on:

```
http://127.0.0.1:8000
```

## Demo account

```
email:    demo@example.com
password: SecureP@ss1234!
```

## Endpoints

| Endpoint  | Method | Description |
|-----------|--------|-------------|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login`    | POST | Log in and receive `access_token` / `refresh_token` |
| `/me`       | GET  | Current user, requires `Authorization: Bearer <token>` |
| `/admin`    | GET  | Requires the `admin.access` permission |

## Try it

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token>"
```

## How it works

`app.py` builds an `AsyncAuthManager` and wraps it in
`auth = StarletteAuth(manager)`. Routes are plain `async` functions decorated
with `@auth.login_required` and `@auth.require_permission("admin.access")`; the
decorators raise Starlette `HTTPException` (401/403) when the token is missing
or the permission is absent. The app's `lifespan` connects the async storage
and seeds the demo data on startup, closing the manager on shutdown.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
