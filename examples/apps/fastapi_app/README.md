# FastAPI Example App

A runnable FastAPI web app demonstrating the `authority.fastapi` integration.
It starts a real ASGI server (via `uvicorn`) with interactive OpenAPI docs at
`/docs`.

## What it demonstrates

- `authority.fastapi` dependencies: `get_current_user`, `require_permission`
- `init_auth()` to bind a global `AsyncAuthManager`
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

`app.py` builds an `AsyncAuthManager` with `AsyncSQLiteStorage`, calls
`init_auth(manager)`, and creates the admin dependency once at import time:

```python
require_admin = asyncio.run(require_permission("admin.access"))
```

Routes use `Depends(get_current_user)` and `Depends(require_admin)`. The
`lifespan` context connects the async storage and seeds the demo data on
startup, and closes the manager on shutdown.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
