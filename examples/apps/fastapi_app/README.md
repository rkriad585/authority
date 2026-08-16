# FastAPI Example App

A runnable FastAPI web app demonstrating the `authority.fastapi` integration.
It is a real web app: server-rendered HTML pages (`/`, `/login`, `/register`,
`/dashboard`) plus a JSON API, served through a real ASGI server (via
`uvicorn`) with interactive OpenAPI docs at `/docs`.

## What it demonstrates

- `authority.fastapi` dependencies: `get_current_user`, `require_permission`
- `init_auth()` to bind a global `AsyncAuthManager`
- Server-rendered HTML pages via `starlette.templating.Jinja2Templates`
- Cookie-based web login (`HttpOnly` `access_token` cookie) plus bearer-token
  JSON API routes
- Pydantic request bodies and `AsyncSQLiteStorage` on the event-loop lifespan

## Requirements

From the repository root:

```bash
pip install -e ".[dev]"
pip install uvicorn
```

## Run

```bash
uvicorn examples.apps.fastapi_app.app:app
```

The app seeds a demo admin account on startup and then serves on:

```
http://127.0.0.1:8000
```

Interactive API docs are available at `http://127.0.0.1:8000/docs`.

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

`app.py` builds an `AsyncAuthManager` with `AsyncSQLiteStorage`, calls
`init_auth(manager)`, and registers `Jinja2Templates` pointing at the shared
`examples/apps/_templates/` directory. Web login sets an `HttpOnly`
`access_token` cookie; the `/dashboard` page verifies that cookie with
`manager.verify_access_token()` and renders the user server-side. A small
`@app.middleware("http")` promotes the `access_token` cookie to the
`Authorization` header when no header is sent, so the header-based dependencies
(`get_current_user`, `require_permission`) work for the browser flow too. The
admin route is protected with the `require_permission("admin.access")`
dependency:

```python
@app.get("/admin")
async def admin(_: dict = Depends(require_permission("admin.access"))):
    return {"message": "Welcome, admin!"}
```

The `lifespan` context connects the async storage and seeds the demo data on
startup, and closes the manager on shutdown.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
