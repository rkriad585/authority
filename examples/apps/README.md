# Example Apps

Fully working web applications demonstrating the authority-auth integration
helpers. Every app exposes the same JSON endpoints so you can compare the
frameworks side by side:

| Endpoint | Method | Description |
|---|---|---|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login` | POST | Login and receive `access_token` / `refresh_token` |
| `/me` | GET | Current user, requires `Authorization: Bearer <token>` |
| `/admin` | GET | Requires the `admin.access` permission |

A demo admin account is seeded on first startup:

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

## Run

Each app binds to `127.0.0.1` on its own port (all defaults shown here):

| App | Command | URL |
|---|---|---|
| Flask | `python examples/apps/flask_app.py` | http://127.0.0.1:5000 |
| Django | `python examples/apps/django_app.py` | http://127.0.0.1:8000 |
| WSGI middleware | `python examples/apps/wsgi_app.py` | http://127.0.0.1:8080 |
| FastAPI | `uvicorn examples.apps.fastapi_app:app` | http://127.0.0.1:8000 |
| Starlette | `uvicorn examples.apps.starlette_app:app` | http://127.0.0.1:8000 |
| ASGI middleware | `uvicorn examples.apps.asgi_app:wrapped_app` | http://127.0.0.1:8000 |

Note: the Django app creates its own SQLite database for Django's auth tables
(`django_auth_db.sqlite3`) alongside the authority database, and mirrors
authority users into `django.contrib.auth.models.User` through
`authority.django.AuthorityBackend`. It also demonstrates a session-based
login flow: `POST /session-login/` then `GET /session-protected/`.

## What each app demonstrates

- `flask_app.py` -- `authority.flask.FlaskAuth` decorators
  (`login_required`, `require_permission`) and `current_user()`.
- `django_app.py` -- `authority.django` helpers (`init_auth`, `login_required`,
  `require_permission`, `get_current_user`) plus the `AuthorityBackend` for
  Django's session auth.
- `wsgi_app.py` -- framework-agnostic `authority.wsgi.AuthorityWSGIMiddleware`
  wrapping a bare WSGI app; state read back via `get_user_state` /
  `get_current_user`.
- `fastapi_app.py` -- `authority.fastapi` dependencies (`get_current_user`,
  `require_permission`).
- `starlette_app.py` -- `authority.starlette.StarletteAuth` decorators and
  `current_user()`.
- `asgi_app.py` -- framework-agnostic `authority.asgi.AuthorityASGIMiddleware`
  wrapping a bare ASGI app with full lifespan support; state read back via
  `get_user_state` / `get_current_user`.
