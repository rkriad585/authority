# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
