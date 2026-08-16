# Flask Example App

A runnable Flask web app demonstrating the `authority.flask` integration. It is
a real web app: server-rendered HTML pages (`/`, `/login`, `/register`,
`/dashboard`) plus a JSON API, served through a real web server you can
exercise with `curl` or a browser.

## What it demonstrates

- `authority.flask.FlaskAuth` instance decorators (`login_required`,
  `require_permission`)
- Module-level helpers `init_auth()` and `current_user()`
- Server-rendered HTML pages via Flask's `render_template`
- Cookie-based web login (`HttpOnly` `access_token` cookie) plus bearer-token
  JSON API routes
- Bearer token extraction from the `Authorization` header
- JSON registration and login routes backed by `authority.core.AuthManager`
  and `SQLiteStorage`

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
```

## Run

```bash
python -m examples.apps.flask_app.app
```

The app seeds a demo admin account on first startup and then serves on:

```
http://127.0.0.1:5000
```

## Demo account

```
email:    demo@example.com
password: SecureP@ss1234!
```

## Web pages

| Page        | Description |
|-------------|-------------|
| `/`         | Landing page linking to login/register and listing the API endpoints |
| `/login`    | Login form (POSTs JSON to `/login`, then redirects to `/dashboard`) |
| `/register` | Registration form (POSTs JSON to `/register`) |
| `/dashboard`| Shows the signed-in user and permissions (requires the login cookie) |

## API endpoints

| Endpoint  | Method | Description |
|-----------|--------|-------------|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login`    | POST | Log in and receive `access_token` / `refresh_token` (also sets an `HttpOnly` cookie) |
| `/logout`   | POST | Clears the `access_token` cookie and redirects to `/login` |
| `/me`       | GET  | Current user, requires a valid token (`Authorization: Bearer` header or `access_token` cookie) |
| `/admin`    | GET  | Requires the `admin.access` permission (header or cookie token) |

## Try it

Open `http://127.0.0.1:5000/` in a browser, or exercise the API with curl:

```bash
# Log in and capture the access token
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

# Call a protected endpoint with the returned token
curl http://127.0.0.1:5000/me \
  -H "Authorization: Bearer <access_token>"
```

## How it works

`app.py` builds an `AuthManager` with a local SQLite database, binds it to the
Flask app through `FlaskAuth`, and seeds the demo role, permission, and admin
user. Templates are rendered from the shared `examples/apps/_templates/`
directory via `render_template`. Web login sets an `HttpOnly` `access_token`
cookie; the `/dashboard` page verifies that cookie with
`manager.verify_access_token()` and renders the user server-side. A
`before_request` hook promotes the `access_token` cookie to the
`Authorization` header when no header is sent, so the header-based decorators
(`@auth.login_required`, `@auth.require_permission`) work for the browser flow
too. Protected routes return `401`/`403` JSON when the token is missing or the
permission is absent.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
