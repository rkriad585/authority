# Example Applications

The repository ships six fully working example web applications under
[`examples/apps/`](https://github.com/rkriad585/authority/tree/main/examples/apps).
Each app is a real, runnable server that demonstrates one integration. The four
framework apps (FastAPI, Flask, Django, Starlette) share one template set in
[`examples/apps/_templates/`](https://github.com/rkriad585/authority/tree/main/examples/apps/_templates)
and serve the same HTML pages plus the JSON endpoints below.

| App | Folder | Stack | Run | URL |
|---|---|---|---|---|
| [Flask](flask.md) | [`flask_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/flask_app) | Flask + `SQLiteStorage` (sync) | `python -m examples.apps.flask_app.app` | http://127.0.0.1:5000 |
| [Django](django.md) | [`django_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/django_app) | Django + `SQLiteStorage` (sync) | `python -m examples.apps.django_app.app` | http://127.0.0.1:8000 |
| [WSGI middleware](wsgi.md) | [`wsgi_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/wsgi_app) | Bare WSGI + `AuthorityWSGIMiddleware` (sync) | `python -m examples.apps.wsgi_app.app` | http://127.0.0.1:8080 |
| [FastAPI](fastapi.md) | [`fastapi_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/fastapi_app) | FastAPI + `AsyncSQLiteStorage` (async) | `uvicorn examples.apps.fastapi_app.app:app` | http://127.0.0.1:8000 |
| [Starlette](starlette.md) | [`starlette_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/starlette_app) | Starlette + `AsyncSQLiteStorage` (async) | `uvicorn examples.apps.starlette_app.app:app` | http://127.0.0.1:8000 |
| [ASGI middleware](asgi.md) | [`asgi_app/`](https://github.com/rkriad585/authority/tree/main/examples/apps/asgi_app) | Bare ASGI + `AuthorityASGIMiddleware` (async) | `uvicorn examples.apps.asgi_app.app:wrapped_app` | http://127.0.0.1:8000 |

## Web pages (framework apps)

The FastAPI, Flask, Django, and Starlette apps serve these pages from the
shared [`examples/apps/_templates/`](https://github.com/rkriad585/authority/tree/main/examples/apps/_templates)
template set. The bare WSGI/ASGI middleware apps are JSON-only.

| Page | Description |
|---|---|
| `/` | Landing page linking to login/register and listing the API endpoints |
| `/login` | Login form; POSTs JSON to `/login`, then redirects to `/dashboard` |
| `/register` | Registration form; POSTs JSON to `/register` |
| `/dashboard` | Shows the signed-in user and permissions (requires the login cookie) |

## Common endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login` | POST | Login and receive `access_token` / `refresh_token` (also sets an `HttpOnly` cookie) |
| `/logout` | POST | Clears the `access_token` cookie and redirects to `/login` |
| `/me` | GET | Current user, requires a valid token (`Authorization: Bearer` header or `access_token` cookie) |
| `/admin` | GET | Requires the `admin.access` permission (header or cookie token) |

A demo admin account is seeded on first startup in every app:

```
email:    demo@example.com
password: SecureP@ss1234!
```

Log in to get a token, then use it like this:

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token>"
```

Web login sets an `HttpOnly` `access_token` cookie; the `/dashboard` page
verifies that cookie server-side and renders the user. The API routes accept a
token via the `Authorization: Bearer` header or the `access_token` cookie (the
example apps promote the cookie to the header when no header is sent). Log out
via `POST /logout`.

## Requirements

Install the library and the framework extras you want to try:

```bash
pip install -e ".[dev]"
```

The WSGI apps (Flask, Django, plain WSGI) run on Python's built-in `wsgiref`
server. The ASGI apps (FastAPI, Starlette, plain ASGI) run on `uvicorn`:

```bash
pip install uvicorn
```

## What each app demonstrates

- `flask_app/` — `authority.flask.FlaskAuth` decorators
  (`login_required`, `require_permission`) and `current_user()`.
- `django_app/` — `authority.django` helpers (`init_auth`, `login_required`,
  `require_permission`, `get_current_user`) plus the `AuthorityBackend` for
  Django's session auth.
- `wsgi_app/` — framework-agnostic `authority.wsgi.AuthorityWSGIMiddleware`
  wrapping a bare WSGI app; state read back via `get_user_state` /
  `get_current_user`.
- `fastapi_app/` — `authority.fastapi` dependencies (`get_current_user`,
  `require_permission`).
- `starlette_app/` — `authority.starlette.StarletteAuth` decorators and
  `current_user()`.
- `asgi_app/` — framework-agnostic `authority.asgi.AuthorityASGIMiddleware`
  wrapping a bare ASGI app with full lifespan support; state read back via
  `get_user_state` / `get_current_user`.

!!! note "Django app"

    The Django app creates its own SQLite database for Django's auth tables
    (`django_auth_db.sqlite3`) alongside the authority database, and mirrors
    authority users into `django.contrib.auth.models.User` through
    `authority.django.AuthorityBackend`. It also demonstrates a session-based
    login flow: `POST /session-login` then `GET /session-protected`.

Each app page below embeds the app's own README.
