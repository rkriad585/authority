# Flask Example App

A runnable Flask web app demonstrating the `authority.flask` integration. It
starts a real web server you can exercise with `curl` or a browser.

## What it demonstrates

- `authority.flask.FlaskAuth` instance decorators (`login_required`,
  `require_permission`)
- Module-level helpers `init_auth()` and `current_user()`
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

## Endpoints

| Endpoint  | Method | Description |
|-----------|--------|-------------|
| `/register` | POST | Create an account (`name`, `email`, `password` JSON body) |
| `/login`    | POST | Log in and receive `access_token` / `refresh_token` |
| `/me`       | GET  | Current user, requires `Authorization: Bearer <token>` |
| `/admin`    | GET  | Requires the `admin.access` permission |

## Try it

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
user. The `/me` and `/admin` routes are protected by `@auth.login_required` and
`@auth.require_permission("admin.access")` respectively; protected routes
return `401`/`403` JSON when the token is missing or the permission is absent.

Back to the [examples index](https://github.com/rkriad585/authority/blob/main/examples/apps/README.md).
