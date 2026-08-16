# FAQ

## What Python versions are supported?

Python 3.10, 3.11, 3.12, and 3.13. The test matrix runs all four in CI.

## Which frameworks does Authority support?

First-party integrations for FastAPI, Flask, Django, and Starlette, plus
generic ASGI and WSGI middleware that works with anything (including Quart).
See [Usage — Framework integrations](usage.md#framework-integrations).

## Do I need a database server?

No. The bundled `SQLiteStorage` / `AsyncSQLiteStorage` backends persist to a
file. For a server database, implement `StorageInterface` /
`AsyncStorageInterface`.

## How are refresh tokens protected?

They are stored as SHA-256 hashes (never plaintext), rotated on every use, and
tracked in families. Reusing a rotated token beyond a short grace window
revokes the whole family.

## Is MFA stored securely?

TOTP secrets are encrypted at rest with Fernet (AES-128-CBC) using the
`fernet_key` from `AuthConfig`. Recovery codes are single-use.

## What is the HIBP check?

When `hibp_check_enabled` is set, `register()` and password changes query the
"Have I Been Pwned" breach API using k-anonymity — only the first 5 characters
of the password's SHA-1 hash are sent, so the full password never leaves the
client. `PasswordPwnedError` is raised for breached passwords
(depending on `hibp_failure_mode`).

## How do I generate the required keys?

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Use this output as `fernet_key`. `jwt_secret_key` is any high-entropy string of
at least 32 characters.

## Why does login return `mfa_required`?

The account has MFA enabled. Call `verify_mfa_login(user_id, code)` with the
TOTP code or a recovery code to complete the login and receive tokens.

## Can I use the sync and async managers together?

They are independent implementations. Use one per application (sync stack vs.
asyncio stack) and pick the matching storage backend (`SQLiteStorage` vs.
`AsyncSQLiteStorage`).

## Where do the example applications run?

Each app in [`examples/apps/`](https://github.com/rkriad585/authority/tree/main/examples/apps)
starts a real server. Flask runs on port 5000, Django on 8000, the WSGI
middleware app on 8080, and the ASGI apps (FastAPI, Starlette, ASGI middleware)
on 8000. All seed a demo account `demo@example.com` / `SecureP@ss1234!`.

## Is this project production-ready?

The current release is version 0.2.5 and the package is classified
`Development Status :: 3 - Alpha`. The API is exercised by a large test suite,
but expect possible breaking changes before 1.0. See
[Security](https://github.com/rkriad585/authority/blob/main/SECURITY.md) for the
supported-versions policy.

## How do I report a security issue?

Privately, per [SECURITY.md](https://github.com/rkriad585/authority/blob/main/SECURITY.md).
Do not open a public issue for vulnerabilities.
