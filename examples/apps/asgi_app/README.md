# ASGI Middleware Example App

A runnable plain-ASGI web app (no framework) wrapped in
`authority.asgi.AuthorityASGIMiddleware`. It starts a real ASGI server (via
`uvicorn`) with full lifespan support so you can exercise the middleware end to
end.

## What it demonstrates

- `authority.asgi.AuthorityASGIMiddleware` wrapping a bare ASGI application
- Authentication state read back with `get_user_state()`,
  `is_authenticated()`, `user_id_from_scope()`, and `get_current_user()`
- Manual lifespan handling (`startup` / `shutdown`) for the async storage
- JSON registration and login routes built directly on `AsyncAuthManager` and
  `AsyncSQLiteStorage`

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
pip install uvicorn
```

## Run

```bash
uvicorn examples.apps.asgi_app.app:wrapped_app
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
| any other path | GET | Echoes the middleware state (`authenticated`, `user_id`, path, authority) |

## Try it

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token>"

# Inspect the middleware state on a route without explicit auth handling
curl http://127.0.0.1:8000/anything
```

## How it works

`app.py` defines a bare `async def app(scope, receive, send)` ASGI application
that routes `/register`, `/login`, and `/me` by hand and handles the lifespan
protocol (connecting the async storage and seeding demo data on startup). The
app is wrapped in `AuthorityASGIMiddleware(app, manager)`, which reads the
`Authorization: Bearer` header, verifies the token, and stores the result at
`scope["authority"]` before the application runs. The application reads that
state back with the module-level helpers. With `auth_required=True` (not set
here) the middleware itself would return a `401` before reaching the app.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
