# Async usage

`AsyncAuthManager` is the asynchronous twin of `AuthManager`. Every method is a
coroutine and must be awaited. It requires the `async` extra
(`pip install authority-auth[async]`) and is backed by `AsyncSQLiteStorage`
(uses `aiosqlite`).

## Setup

```python
import asyncio

from authority import AuthConfig, AsyncAuthManager
from authority.storage import AsyncSQLiteStorage


async def main():
    config = AuthConfig(
        jwt_secret_key="your-secret-key-min-32-chars",
        fernet_key="your-fernet-key",
    )
    storage = AsyncSQLiteStorage("authority_data.db")
    await storage.connect()          # required for async storage

    async with AsyncAuthManager(config, storage) as auth:
        user = await auth.register(
            "Alice", "alice@example.com", "SecureP@ss1234!", auto_verify=True
        )
        result = await auth.login(email="alice@example.com", password="SecureP@ss1234!")
        payload = await auth.verify_access_token(result["access_token"])
        print(payload["user_id"])


asyncio.run(main())
```

## Lifecycle

- `await storage.connect()` opens the database connection before the manager
  is used.
- `AsyncAuthManager` is a context manager: leaving the `async with` block
  closes the storage connection. Otherwise call `await auth.close()` at
  shutdown.

## FastAPI

Bind the manager once, then use the dependencies. The dependencies `await` the
manager's methods for you, so `get_current_user` and `require_permission(...)`
work as plain `Depends(...)` arguments:

```python
from fastapi import Depends, FastAPI
from authority.fastapi import get_current_user, init_auth, require_permission

app = FastAPI()
init_auth(auth)

@app.get("/me")
async def me(payload: dict = Depends(get_current_user)):
    return {"id": payload["user_id"]}

@app.get("/admin")
async def admin(_: dict = Depends(require_permission("admin.access"))):
    return {"ok": True}
```

Connect storage and close the manager inside the FastAPI lifespan.

## Other async frameworks

- [Starlette](examples/starlette.md) — `StarletteAuth` decorators.
- [ASGI](examples/asgi.md) — `AuthorityASGIMiddleware`.

## Full feature tour

The feature set is identical to the sync manager — see the [Usage](usage.md)
page for examples (add `await` to each call). Method signatures are on the
[AsyncAuthManager](async-auth-manager.md) reference page.

## Event loop awareness

`AsyncAuthManager` must be created and used within the same event loop that
runs your app. If you share a manager across multiple loops (e.g. in tests or
threaded workers), construct one manager per loop. `EventBus` handlers that are
coroutines are scheduled with `asyncio.create_task()` and must run on the
manager's loop.
