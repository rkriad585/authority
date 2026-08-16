# Deployment

Guidance for running Authority in production.

## Configuration hygiene

- Set `jwt_secret_key` and `fernet_key` via environment variables
  (`AUTHORITY_JWT_SECRET_KEY`, `AUTHORITY_FERNET_KEY`), never in code or
  committed files. Use a secret manager in production and rotate keys on a
  schedule or after personnel changes.
- Generate a fresh Fernet key per environment:
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- Set `webauthn_rp_id` and `webauthn_expected_origin` to the production origin
  for passkey flows.

## Database

- SQLite is the bundled backend. For a single-node deployment it is fine, but
  put the database file on durable storage with regular backups.
- For multi-process or high-concurrency deployments, implement
  `StorageInterface` / `AsyncStorageInterface` over a server database
  (PostgreSQL, MySQL, …). The manager API does not change.
- `prune_tokens_on_startup` (default `True`) clears expired tokens when the
  manager opens, keeping the token tables small.

## Token lifetimes

Tune the defaults to your threat model:

- `jwt_access_token_expiry_minutes` (default 15) — shorter is safer for
  bearer tokens in browsers and mobile apps.
- `jwt_refresh_token_expiry_days` (default 7) with
  `jwt_refresh_token_absolute_max_days` (default 30) bounds the refresh window
  even with rotation.

## Serving the framework integration

- FastAPI / Starlette / plain ASGI: run with a production ASGI server
  (`uvicorn --workers N`, `hypercorn`, `gunicorn` with a Uvicorn worker, …).
- Flask / Django / plain WSGI: run behind a production WSGI server
  (gunicorn, waitress, `mod_wsgi`, …). The example apps use Python's built-in
  `wsgiref` for development only.
- Terminate TLS at the reverse proxy and set the `Authorization` header, the
  `Host` header, and (for WebAuthn) the expected origin to the public scheme /
  host.

## Example: running the ASGI app with multiple workers

```bash
uvicorn examples.apps.fastapi_app.app:app --workers 4 --proxy-headers
```

## Observability

- Enable audit logging (`audit_log_enabled`, default `True`) and ship
  `get_audit_log()` entries to your log pipeline for compliance.
- Subscribe to the `EventBus` events (`TOKEN_REUSE_DETECTED`,
  `USER_LOGIN_FAILED`, `MFA_FAILED`, …) to alert on suspicious activity.
- Log at `INFO`/`WARNING` using Python's standard `logging`; the library's
  loggers are namespaced under `authority.*`.

## CI/CD

- Run the test suite and lint on every push — see
  [Development](development.md). The repository's CI exercises Python 3.10–3.13
  and builds the package with `python -m build`.
- The documentation site is deployed to GitHub Pages automatically from
  `.github/workflows/docs.yml`.
