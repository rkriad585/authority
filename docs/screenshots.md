# Screenshots

The images below are generated with [`tools/screenshots_gen.py`](https://github.com/rkriad585/authority/blob/main/tools/screenshots_gen.py)
(Pillow) and illustrate the library, its integrations, and the example apps.
They live in the [`Screenshots/`](https://github.com/rkriad585/authority/tree/main/Screenshots)
folder at the repository root.

## Home

![Home](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/home.png)

Terminal-style banner introducing the library.

## Quick start (sync)

![Sync usage](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/quickstart.png)

Register, login, refresh, and logout with `AuthManager`.

## Async usage

![Async usage](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/async.png)

The same flow with `AsyncAuthManager`.

## TOTP MFA

![MFA](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/mfa.png)

MFA setup, login, and recovery codes.

## RBAC

![RBAC](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/rbac.png)

Roles, permissions, and permission checks.

## API keys

![API keys](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/apikeys.png)

Create, verify, and revoke scoped API keys.

## WebAuthn / passkeys

![WebAuthn](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/webauthn.png)

Registration and authentication ceremonies.

## Event bus

![Events](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/events.png)

Subscribing to lifecycle events.

## FastAPI integration

![FastAPI](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/fastapi.png)

`get_current_user` / `require_permission` dependencies.

## Flask integration

![Flask](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/flask.png)

`FlaskAuth` decorators.

## Django integration

![Django](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/django.png)

Decorators, helpers, and the `AuthorityBackend`.

## Starlette integration

![Starlette](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/starlette.png)

`StarletteAuth` decorators.

## ASGI & WSGI middleware

![Middleware](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/middleware.png)

Framework-agnostic middleware.

## Example app

![Terminal](https://raw.githubusercontent.com/rkriad585/authority/main/Screenshots/terminal.png)

Exercising the live example endpoints with `curl`.
