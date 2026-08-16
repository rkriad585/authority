# Starlette Example App

A runnable Starlette web app demonstrating the `authority.starlette` integration.
It is a real web app: server-rendered HTML pages (`/`, `/login`, `/register`,
`/dashboard`) plus a JSON API, served through a real ASGI server (via
`uvicorn`).

## What it demonstrates

- `authority.starlette.StarletteAuth` decorators (`login_required`,
  `require_permission`) and `current_user()`
- Server-rendered HTML pages via `starlette.templating.Jinja2Templates`
- Cookie-based web login (`HttpOnly` `access_token` cookie) plus bearer-token
  JSON API routes
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

Open `http://127.0.0.1:8000/` in a browser, or exercise the API with curl:

```bash
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

curl http://127.0.0.1:8000/me \
  -H "Authorization: Bearer <access_token>"
```

## How it works

`app.py` builds an `AsyncAuthManager` and wraps it in
`auth = StarletteAuth(manager)`. Routes are plain `async` functions; the HTML
pages are rendered with `Jinja2Templates` from the shared
`examples/apps/_templates/` directory. Web login sets an `HttpOnly`
`access_token` cookie; the `/dashboard` page verifies that cookie with
`manager.verify_access_token()` and renders the user server-side. A
`BaseHTTPMiddleware` promotes the `access_token` cookie to the `Authorization`
header when no header is sent, so the header-based decorators
(`@auth.login_required`, `@auth.require_permission`) work for the browser flow
too. Protected routes raise Starlette `HTTPException` (401/403) when the token
is missing or the permission is absent. The app's `lifespan` connects the async
storage and seeds the demo data on startup, closing the manager on shutdown.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
