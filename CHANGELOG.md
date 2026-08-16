# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.5] - 2026-08-16

### Added

- Example apps (FastAPI, Flask, Django, Starlette) are now real web apps:
  server-rendered HTML pages at `/`, `/login`, `/register`, and `/dashboard`
  (rendered from the shared `examples/apps/_templates/` template set) alongside
  the existing JSON API, plus a `POST /logout` route. Web login sets an
  `HttpOnly` `access_token` cookie; `/dashboard` verifies it server-side.
- Django example app now renders its pages through Django's Jinja2 template
  backend and merges the GET page / POST JSON handlers per route.
- Protected routes (`/me`, `/admin`) in the example apps now accept a token via
  the `Authorization: Bearer` header or the `access_token` cookie: a small
  per-framework middleware promotes the cookie to the header when no header is
  sent, so the header-based decorators/dependencies work in the browser.

### Fixed

- `authority.fastapi.require_permission` / `require_role` were declared
  `async def`, which made `Depends(require_permission("..."))` receive a
  coroutine instead of a dependency. They are now regular factory functions, so
  the documented `Depends(...)` pattern works directly.
- Example apps (FastAPI, Flask, Django, Starlette) now serve app info, demo
  credentials, and their endpoint list at `/` instead of returning 404.
- Example apps no longer return HTTP 500 when a weak password is submitted to
  `POST /register`: password validation failures are caught and reported as
  `400` with the complexity message instead of an unhandled exception.

## [0.2.0] - 2026-08-16

### Added

- Flask integration helpers (`authority.flask`) with module-level and
  instance-based (`FlaskAuth`) decorators, Bearer/session token extraction,
  and `current_user`
- Django integration (`authority.django`) with the `AuthorityBackend` auth
  backend, Django-user mirroring, and `login_required` / `require_permission` /
  `require_role` decorators
- Starlette integration (`authority.starlette`) with the `StarletteAuth` helper
  and async decorators
- Framework-agnostic ASGI middleware (`authority.asgi`) that exposes
  authentication state on the ASGI scope
- Framework-agnostic WSGI middleware (`authority.wsgi`) that exposes
  authentication state on the WSGI environ
- Optional extras for `flask`, `django`, `starlette`, and `quart`
- Fully working example apps under `examples/apps/` for FastAPI, Flask, Django,
  Starlette, and the raw ASGI/WSGI middleware
- Per-app READMEs under `examples/apps/` and an examples index
- MkDocs documentation site (`docs/`) with per-topic pages (getting started,
  usage, configuration, API reference, architecture, deployment, FAQ,
  troubleshooting)
- Project logo (`logo/logo.svg`) and generated screenshots (`Screenshots/`)
- Documentation deployment workflow (`.github/workflows/docs.yml`) publishing
  to GitHub Pages
- `docs` extra (`mkdocs`, `mkdocs-material`, `pymdown-extensions`)
- PyPI project URLs for the documentation site and author website
- Standard project files: `CODE_OF_CONDUCT.md`, `CODEOWNERS`, `CONTRIBUTORS`,
  `ACCESSIBILITY.md`, `Dockerfile`, `.editorconfig`, `.gitattributes`,
  `.dockerignore`, and `.env.example`

## [0.1.0] - 2026-07-23

### Added

- JWT access tokens with configurable expiry
- Refresh token rotation with family tracking and reuse detection
- User registration with email verification flow
- Password authentication with account lockout
- Password strength validation (length, complexity, HIBP breach check)
- Password history enforcement
- Password reset flow with token-based verification
- Password change with current password verification
- Email change workflow with double opt-in
- TOTP-based MFA with Fernet-encrypted secrets
- MFA recovery codes with one-time use enforcement
- MFA recovery code verification (`verify_mfa_recovery_code`)
- WebAuthn/passkey registration and authentication
- Role-based access control (RBAC) with permissions
- `require_permission` guard for RBAC enforcement
- Session management: `list_sessions`, `revoke_session_by_id`, `revoke_all_sessions_for_user`
- Context manager support (`with AuthManager(...)` / `async with AsyncAuthManager(...)`)
- Password strength estimation (`estimate_password_strength`)
- API key management with prefix-based lookup
- Audit logging with append-only enforcement
- Custom user profile data (JSON)
- SQLite storage (sync and async)
- Event bus system with typed events (including `token.revoked`)
- Framework-agnostic architecture
- FastAPI integration helpers
- Comprehensive test suite with 700+ tests
- Property-based tests with Hypothesis
- Security-specific tests (algorithm confusion, timing attacks)
- PyPI packaging (dynamic version from `.version`, `async`/`fastapi`/`dev` extras)
- Contributing guidelines (`CONTRIBUTING.md`)
