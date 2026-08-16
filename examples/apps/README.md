# Example Apps

Fully working web applications demonstrating the authority-auth integration
helpers. Every app lives in its own folder with its own `README.md`, exposes
the same JSON endpoints, and starts a real web server so you can test
everything end to end.

| App | Folder | Run | URL |
|---|---|---|---|
| Flask | [`flask_app/`](flask_app/) | `python -m examples.apps.flask_app.app` | http://127.0.0.1:5000 |
| Django | [`django_app/`](django_app/) | `python -m examples.apps.django_app.app` | http://127.0.0.1:8000 |
| WSGI middleware | [`wsgi_app/`](wsgi_app/) | `python -m examples.apps.wsgi_app.app` | http://127.0.0.1:8080 |
| FastAPI | [`fastapi_app/`](fastapi_app/) | `uvicorn examples.apps.fastapi_app.app:app` | http://127.0.0.1:8000 |
| Starlette | [`starlette_app/`](starlette_app/) | `uvicorn examples.apps.starlette_app.app:app` | http://127.0.0.1:8000 |
| ASGI middleware | [`asgi_app/`](asgi_app/) | `uvicorn examples.apps.asgi_app.app:wrapped_app` | http://127.0.0.1:8000 |

## Common endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login` | POST | Login and receive `access_token` / `refresh_token` |
| `/me` | GET | Current user, requires `Authorization: Bearer <token>` |
| `/admin` | GET | Requires the `admin.access` permission |

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

- `flask_app/` -- `authority.flask.FlaskAuth` decorators
  (`login_required`, `require_permission`) and `current_user()`.
- `django_app/` -- `authority.django` helpers (`init_auth`, `login_required`,
  `require_permission`, `get_current_user`) plus the `AuthorityBackend` for
  Django's session auth.
- `wsgi_app/` -- framework-agnostic `authority.wsgi.AuthorityWSGIMiddleware`
  wrapping a bare WSGI app; state read back via `get_user_state` /
  `get_current_user`.
- `fastapi_app/` -- `authority.fastapi` dependencies (`get_current_user`,
  `require_permission`).
- `starlette_app/` -- `authority.starlette.StarletteAuth` decorators and
  `current_user()`.
- `asgi_app/` -- framework-agnostic `authority.asgi.AuthorityASGIMiddleware`
  wrapping a bare ASGI app with full lifespan support; state read back via
  `get_user_state` / `get_current_user`.

Note: the Django app creates its own SQLite database for Django's auth tables
(`django_auth_db.sqlite3`) alongside the authority database, and mirrors
authority users into `django.contrib.auth.models.User` through
`authority.django.AuthorityBackend`. It also demonstrates a session-based
login flow: `POST /session-login` then `GET /session-protected`.

Each app folder contains its own `README.md` with full run instructions.

Back to the [main README](https://github.com/rkriad585/authority/blob/main/README.md).
