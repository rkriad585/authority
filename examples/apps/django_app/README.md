# Django Example App

A runnable single-file Django web app demonstrating the `authority.django`
integration. It configures a minimal Django project at import time, runs
migrations, and starts a real server backed by Django's built-in `wsgiref`.

## What it demonstrates

- `authority.django` helpers: `init_auth()`, `login_required`,
  `require_permission`, `get_current_user`
- `authority.django.AuthorityBackend` as the Django authentication backend
- Session-based login (`/session-login`) that mirrors authority users into
  `django.contrib.auth.models.User` via `authority_user_to_django_user()`
- Bearer token routes protected by authority decorators

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
```

## Run

```bash
python -m examples.apps.django_app.app
```

The app creates its own SQLite database for Django's auth tables
(`django_auth_db.sqlite3`) alongside the authority database, seeds a demo admin
account, and serves on:

```
http://127.0.0.1:8000
```

## Demo account

```
email:    demo@example.com
password: SecureP@ss1234!
```

## Endpoints

| Endpoint            | Method | Description |
|---------------------|--------|-------------|
| `/register`         | POST   | Create an account (`name`, `email`, `password` JSON body) |
| `/login`            | POST   | Log in and receive `access_token` / `refresh_token` |
| `/session-login`    | POST   | Log in through Django sessions via the `AuthorityBackend` |
| `/me`               | GET    | Current user, requires `Authorization: Bearer <token>` |
| `/admin`            | GET    | Requires the `admin.access` permission |
| `/session-protected`| GET    | Protected by Django's own `django.contrib.auth.decorators.login_required` |

Note: Django URLs have no trailing slashes here so `POST` requests are not
redirected.

## Try it

```bash
# Bearer token flow
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token>"

# Session flow (then visit /session-protected with a session cookie)
curl -X POST http://127.0.0.1:8000/session-login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}' \
  -c cookies.txt
curl http://127.0.0.1:8000/session-protected -b cookies.txt
```

## How it works

`app.py` calls `settings.configure()` with a minimal Django setup, runs
`django.setup()`, points `AUTHENTICATION_BACKENDS` at
`authority.django.AuthorityBackend`, and registers the `wsgi_app` handler. The
`AuthorityBackend.authenticate()` checks credentials against the authority
`AuthManager`, then mirrors the authority user into Django's user table so the
standard Django session machinery works unchanged.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
