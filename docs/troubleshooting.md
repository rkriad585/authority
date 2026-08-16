# Troubleshooting

Common issues and their fixes. If your problem is not listed here, please
[open an issue](https://github.com/rkriad585/authority/issues).

## `ConfigurationError: jwt_secret_key is required`

`AuthConfig` requires a signing secret. Set it via the constructor or the
`AUTHORITY_JWT_SECRET_KEY` environment variable:

```python
config = AuthConfig(jwt_secret_key="at-least-32-random-characters")
```

## `ConfigurationError: fernet_key is required for MFA encryption`

MFA secrets must be encryptable. Generate a key:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then pass it as `fernet_key` or set `AUTHORITY_FERNET_KEY`.

## `ModuleNotFoundError: No module named 'aiosqlite'`

The async storage backend lives behind the `async` extra:

```bash
pip install "authority-auth[async]"
```

## `ImportError` for `authority.fastapi` / `authority.flask` / etc.

Framework integrations require their extras:

```bash
pip install "authority-auth[fastapi]"
pip install "authority-auth[flask]"
pip install "authority-auth[django]"
pip install "authority-auth[starlette]"
```

## 401 on every protected route

- Make sure you send `Authorization: Bearer <token>`.
- Check that the token has not expired — access tokens default to 15 minutes.
- Ensure you are using the access token, not the refresh token, for requests.

## `TokenExpiredError` during `refresh_access_token`

- The refresh token was already rotated (each token is single-use). Use the
  newest token from the last `refresh_access_token()` / `login()` response.
- The token's absolute maximum age (`jwt_refresh_token_absolute_max_days`,
  default 30) has passed; the user must log in again.

## `InvalidTokenError` during refresh / whole family revoked

The library detects a rotated refresh token being replayed after the grace
window (`refresh_token_reuse_grace_seconds`, default 10s) and raises
`InvalidTokenError` while revoking the entire token family as a security
response. Ask the user to re-authenticate. If your client races between
concurrent refresh calls, they must share the single newest token.

## Password policy errors (`ValidationError`)

The default policy requires ≥12 characters with uppercase, lowercase, digit,
and special character. See `password_min_length`,
`password_require_complexity`, `password_complexity_regex`, and
`password_prevent_email_username_use` in [Configuration](configuration.md).

## `PasswordPwnedError` after enabling HIBP

The password appears in known breach data and was rejected. If HIBP is
unavailable and you prefer not to block, set `hibp_failure_mode = "warn"` or
`"ignore"`.

## Account locked / `AccountLockedError`

`failed_login_lockout_threshold` (default 5) failed attempts trigger a lockout
lasting `failed_login_lockout_minutes` (default 15).

## Login returns `mfa_required` but I want to test without MFA

Disable MFA for the test account with `disable_mfa(user_id, password)`, or
complete the flow with `verify_mfa_login(user_id, code)`.

## WebAuthn errors (`WebAuthnError`, `WebAuthnRegistrationError`)

- Set `webauthn_rp_id` and `webauthn_expected_origin` in `AuthConfig` to match
  your origin.
- WebAuthn requires a secure context (HTTPS or `localhost`).
- Ensure the `credential_data` you pass to `complete_webauthn_registration` /
  `complete_webauthn_authentication` is the raw object returned by
  `navigator.credentials.create()` / `.get()`.

## `RuntimeError: AuthManager not initialized. Call init_auth(manager) first.`

The FastAPI / Django helpers use a global manager. Call `init_auth(manager)`
once during application startup before routes run.

## Example apps won't start (ports in use)

The example apps bind fixed ports (Flask 5000, Django 8000, WSGI 8080, ASGI
apps 8000). Kill the previous instance or change the port in the app source.
The ASGI apps additionally require `uvicorn`:

```bash
pip install uvicorn
```

## Audit log looks empty

`audit_log_enabled` defaults to `True`, but the storage must be initialized
before events are recorded, and `get_audit_log()` reads from the same database
as the manager. Confirm you are querying with the same `db_path`.
