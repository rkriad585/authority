# Authority

![Authority logo](https://raw.githubusercontent.com/rkriad585/authority/main/logo/logo.svg){ align="left" width="120" }

**Comprehensive, framework-agnostic Python authentication library.**

Authority is a batteries-included authentication and authorization library for
Python. It provides JWT access tokens with refresh rotation, TOTP MFA with
recovery codes, WebAuthn / passkey support, RBAC, API key management, password
security with HIBP breach checking, an event bus, and pluggable storage — all
independent of any web framework.

Use Authority standalone, or plug it into **FastAPI**, **Flask**, **Django**,
or **Starlette** with first-party integration modules. Generic **ASGI** and
**WSGI** middleware cover everything else (including Quart).

[Get Started :material-rocket-launch:](getting-started.md){ .md-button }
[Read the API Reference :material-book-open-page-variant:](api.md){ .md-button }
[Try the examples :material-folder-open:](examples/index.md){ .md-button }

## Highlights

- **JWT authentication** with short-lived access tokens, opaque refresh tokens,
  rotation, family tracking, and reuse detection
- **TOTP MFA** with Fernet-encrypted secrets and single-use recovery codes
- **WebAuthn / passkeys** registration and authentication
- **RBAC** with granular permissions and role assignments
- **API keys** with prefix-based lookup, scopes, and expiry
- **Password security**: complexity rules, history enforcement, and HIBP breach
  checking via k-anonymity
- **Pluggable storage**: sync and async SQLite backends included, or implement
  `StorageInterface` / `AsyncStorageInterface`
- **Event bus** with 22 typed lifecycle events and sync/async handlers
- **Audit logging** with an append-only, chain-hashed trail
- **Full async support** through `AsyncAuthManager` + `AsyncSQLiteStorage`

## Quick links

| Topic | Page |
|---|---|
| First steps | [Getting Started](getting-started.md) |
| Install options | [Installation](installation.md) |
| Sync & async usage, MFA, RBAC, API keys | [Usage](usage.md) |
| Every option and environment variable | [Configuration](configuration.md) |
| Full public API reference | [API Reference](api.md) |
| Design and module map | [Architecture](architecture.md) |
| Screenshots of the example apps | [Screenshots](screenshots.md) |
| Contributing, testing, CI | [Development](development.md) |
| Production guidance | [Deployment](deployment.md) |
| Common questions | [FAQ](faq.md) |
| Problems and fixes | [Troubleshooting](troubleshooting.md) |
| Runnable web apps for each framework | [Examples](examples/index.md) |

## Project links

- **Source**: [github.com/rkriad585/authority](https://github.com/rkriad585/authority)
- **PyPI**: [authority-auth](https://pypi.org/project/authority-auth/)
- **License**: [MIT](https://github.com/rkriad585/authority/blob/main/LICENSE)
- **Changelog**: [CHANGELOG.md](https://github.com/rkriad585/authority/blob/main/CHANGELOG.md)

## Requirements

- Python 3.10+
- SQLite (included in the Python standard library)
