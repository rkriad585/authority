# WSGI Middleware Example App

A runnable plain-WSGI web app (no framework) wrapped in
`authority.wsgi.AuthorityWSGIMiddleware`. It starts a real server via Python's
built-in `wsgiref` so you can exercise the middleware end to end.

## What it demonstrates

- `authority.wsgi.AuthorityWSGIMiddleware` wrapping a bare WSGI application
- Authentication state read back with `get_user_state()`,
  `user_id_from_environ()`, and `get_current_user()`
- JSON registration and login routes built directly on `AuthManager` and
  `SQLiteStorage`

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
```

## Run

```bash
python -m examples.apps.wsgi_app.app
```

The app seeds a demo admin account on first startup and then serves on:

```
http://127.0.0.1:8080
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
| any other path | GET | Echoes the middleware state (`authenticated`, `user_id`, path) |

## Try it

```bash
curl -X POST http://127.0.0.1:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8080/me \
  -H "Authorization: Bearer <access_token>"

# Inspect the middleware state on a route without a decorator
curl http://127.0.0.1:8080/anything
```

## How it works

`app.py` defines a bare WSGI `application(environ, start_response)` that routes
`/register`, `/login`, and `/me` by hand. The app is wrapped in
`AuthorityWSGIMiddleware(application, manager)`, which reads
`HTTP_AUTHORIZATION`, verifies the Bearer token, and stores the result at
`environ["authority"]` before the application runs. The application reads that
state back with the module-level helpers. With `auth_required=True` (not set
here) the middleware itself would return a `401` before reaching the app.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
