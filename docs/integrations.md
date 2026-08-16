# Framework Integrations

`authority-auth` is framework-agnostic at its core, and ships first-party
adapters for the most common Python web frameworks. Each integration lives in
its own module; extras install the framework dependency.

| Extra | Module | Framework |
|---|---|---|
| `fastapi` | `authority.fastapi` | FastAPI |
| `flask` | `authority.flask` | Flask |
| `django` | `authority.django` | Django |
| `starlette` | `authority.starlette` | Starlette |
| — | `authority.asgi` | Any ASGI app (no extra) |
| — | `authority.wsgi` | Any WSGI app (no extra) |
| `quart` | — | (extra only, async) |

## FastAPI (`authority.fastapi`)

| Symbol | Purpose |
|---|---|
| `init_auth(manager)` | Bind the global `AsyncAuthManager` |
| `get_auth_manager()` | Retrieve it (raises `RuntimeError` if unset) |
| `get_current_user` | Dependency returning the verified token payload (`dict`) |
| `require_permission(permission_code)` | Dependency factory → 401/403 via `HTTPException` |
| `require_role(role_name)` | Dependency factory → 401/403 via `HTTPException` |

```python
from fastapi import Depends, FastAPI
from authority.fastapi import get_current_user, init_auth, require_permission

init_auth(manager)

@app.get("/me")
async def me(payload: dict = Depends(get_current_user)):
    ...

@app.get("/admin")
async def admin(payload: dict = Depends(require_permission("admin.access"))):
    ...
```

## Flask (`authority.flask`)

| Symbol | Purpose |
|---|---|
| `FlaskAuth(app, manager)` | Binds the manager to the app |
| `FlaskAuth.login_required` | Instance decorator (401 via `abort`) |
| `FlaskAuth.require_permission(code)` | Instance decorator (401/403) |
| `FlaskAuth.require_role(name)` | Instance decorator (401/403) |
| `FlaskAuth.current_user()` | Full user dict or `None` |
| `init_auth(manager)` | Module-level binding |
| `login_required` | Module-level decorator |
| `require_permission(code)` | Module-level decorator factory |
| `require_role(name)` | Module-level decorator factory |
| `current_user()` | Module-level user accessor |

Tokens are read from `Authorization: Bearer <token>` or `session["access_token"]`.

## Django (`authority.django`)

| Symbol | Purpose |
|---|---|
| `init_auth(manager)` | Bind the global `AuthManager` |
| `login_required` | View decorator (plain-text 401) |
| `require_permission(code)` | View decorator factory |
| `require_role(name)` | View decorator factory |
| `get_current_user(request)` | User dict from the request |
| `AuthorityBackend` | Django `BaseBackend` that authenticates against authority |
| `authority_user_to_django_user(user)` | Mirror an authority user into `django.contrib.auth.models.User` |

## Starlette (`authority.starlette`)

| Symbol | Purpose |
|---|---|
| `StarletteAuth(manager)` | Binds an `AsyncAuthManager` |
| `StarletteAuth.login_required` | Instance decorator (401 via `HTTPException`) |
| `StarletteAuth.require_permission(code)` | Instance decorator |
| `StarletteAuth.require_role(name)` | Instance decorator |
| `StarletteAuth.current_user()` | User dict or `None` |

## ASGI middleware (`authority.asgi`)

| Symbol | Purpose |
|---|---|
| `AuthorityASGIMiddleware(app, manager, auth_required=False)` | Wraps any ASGI app |
| `get_user_state(scope)` | State dict at `scope["authority"]` |
| `is_authenticated(scope)` | Boolean |
| `user_id_from_scope(scope)` | `int \| None` |
| `get_current_user(scope, manager)` | User dict or `None` |

## WSGI middleware (`authority.wsgi`)

| Symbol | Purpose |
|---|---|
| `AuthorityWSGIMiddleware(app, manager, auth_required=False)` | Wraps any WSGI app |
| `get_user_state(environ)` | State dict at `environ["authority"]` |
| `is_authenticated(environ)` | Boolean |
| `user_id_from_environ(environ)` | `int \| None` |
| `get_current_user(environ, manager)` | User dict or `None` |

See the [Examples](examples/index.md) for runnable apps using every adapter.
