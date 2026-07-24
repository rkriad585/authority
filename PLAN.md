# PLAN.md — Authority Authentication Library

> **Single source of truth for all development work.**
> This document is a living artifact — update it as work proceeds.

---

## Table of Contents

1. [Project Summary](#1-project-summary)
2. [Research Findings](#2-research-findings)
3. [Critical Dependency Changes](#3-critical-dependency-changes)
4. [Security Assessment](#4-security-assessment)
5. [Competitive Landscape](#5-competitive-landscape)
6. [Missing Features & Gaps](#6-missing-features--gaps)
7. [Design Decisions](#7-design-decisions)
8. [Development Roadmap](#8-development-roadmap)
9. [Prioritization Matrix](#9-prioritization-matrix)
10. [Implementation Checklist](#10-implementation-checklist)

---

## 1. Project Summary

**Authority** is a comprehensive, framework-agnostic Python authentication library designed to be the "batteries-included" solution for modern applications. It provides JWT-based auth with refresh token rotation, encrypted MFA, WebAuthn/passkeys, RBAC, API keys, and pluggable storage — all in a single `pip install`.

### Current State

The project currently exists **only as design specifications** in `Authority.md` and `README.md`. No actual Python source files have been implemented yet. The specs contain detailed code outlines for all planned modules.

### Planned Features

| Feature | Status |
|---------|--------|
| JWT Access Tokens + Refresh Tokens with Rotation | Spec complete |
| Encrypted MFA (TOTP + Recovery Codes) | Spec complete |
| WebAuthn (Passkeys) Framework | Spec complete |
| HIBP Password Breach Check | Spec complete |
| RBAC (Role-Based Access Control) | Spec complete |
| Password History Enforcement | Spec complete |
| API Keys Management | Spec complete |
| Email Change Workflow | Spec complete |
| Audit Log | Spec complete |
| Custom Profile Data (JSON) | Spec complete |
| Pluggable Storage (Sync + Async SQLite) | Spec complete |
| Event System | Spec complete |
| Environment Variable Configuration | Spec complete |

### Tech Stack (Planned → Recommended)

| Component | Spec | Recommended |
|-----------|------|-------------|
| Python | >=3.8 | **>=3.10** (3.8/3.9 are EOL) |
| Build System | setuptools | **hatchling** (PyPA recommended) |
| JWT | PyJWT>=2.0.0 | **PyJWT>=2.8.0** |
| Password Hashing | passlib[bcrypt]>=1.7.4 | **bcrypt>=4.1,<5** or **hashward[argon2]** |
| MFA (TOTP) | pyotp>=2.6.0 | **pyotp>=2.9.0** |
| Encryption | cryptography>=3.4.0 | **cryptography>=44.0** |
| WebAuthn | webauthn>=1.6.0 | **webauthn>=2.7.0,<4.0.0** |
| HTTP Client | requests>=2.25.0 | **httpx>=0.27.0** (async-native) |
| Async DB | aiosqlite>=0.17.0 | **aiosqlite>=0.20.0** |
| Linting | flake8 + black + isort | **ruff** (replaces all three) |
| Type Checking | mypy | **pyright** (stricter, faster) |
| Testing | pytest | **pytest + hypothesis + pytest-asyncio** |

### Planned Project Structure

```
authority/
├── src/
│   └── authority/
│       ├── __init__.py
│       ├── core.py              # AuthManager (sync)
│       ├── async_core.py        # AsyncAuthManager
│       ├── exceptions.py        # Exception hierarchy
│       ├── utils.py             # Encryption, HIBP, tokens
│       ├── config.py            # Config dataclass (NEW)
│       ├── events.py            # Event bus (NEW)
│       └── storage/
│           ├── __init__.py
│           ├── base.py          # StorageInterface ABCs
│           ├── sqlite.py        # SQLiteStorage (sync)
│           └── aiosqlite.py     # AsyncSQLiteStorage
├── tests/
│   ├── conftest.py
│   ├── test_core.py
│   ├── test_async_core.py
│   ├── test_utils.py
│   ├── test_storage_sqlite.py
│   └── test_storage_aiosqlite.py
├── pyproject.toml
├── LICENSE
├── README.md
├── CHANGELOG.md
├── .gitignore
└── .version
```

---

## 2. Research Findings

### 2.1 Architecture Assessment (Source: Architecture Agent)

**src layout** — Correct. Modern standard recommended by pytest and PyPA. No changes needed.

**ABC-based storage** — Good pattern, but:
- Sync and async interfaces are fully duplicated (~600 lines). Consider `typing.Protocol` or a code-generation approach to reduce drift.
- ABC methods inconsistently use `pass` vs `raise NotImplementedError` — standardize on `raise NotImplementedError`.
- Return types use `Dict[str, Any]` everywhere — recommend dataclasses/TypedDicts for type safety.

**Separate sync/async managers** — Idiomatic for Python 3.8+. The optional `aiosqlite` dependency is correctly handled.

**Suggested additions to structure:**
- `config.py` — typed configuration dataclass instead of raw dicts
- `events.py` — dedicated event bus module
- `models.py` — typed dataclasses for User, Token, Credential, etc.

### 2.2 Dependency Status (Source: Architecture + Implementation Agents)

| Dependency | Status | Action Required |
|-----------|--------|----------------|
| `passlib` | **DEAD** — broken on Python 3.13+, incompatible with bcrypt>=5.0, last release 2020 | **Replace immediately** |
| `webauthn` | v3.0.0 available, spec pins >=1.6.0 (July 2022) | **Pin >=2.7.0** for modern API |
| `PyJWT` | v2.13.0 current with 5 security fixes | Pin >=2.8.0 |
| `cryptography` | v49.0.0 current | Pin >=44.0 for MultiFernet support |
| `pyotp` | v2.10.0 current | Pin >=2.9.0 |
| `requests` | v2.32+ current | Consider **httpx** for async support |

### 2.3 Event System Assessment

The current "trigger" pattern in the spec is insufficient. Recommendation:

- Implement a proper **event bus** with typed event names (constants/enum, not magic strings)
- Support both **sync and async** handlers
- Fire-and-forget by default with optional await-all
- Include event metadata (user_id, timestamp, ip_address, action)
- Allow unsubscribe to prevent listener leaks

**Events to support:**
```
user.registered, user.login_success, user.login_failed,
user.password_changed, user.email_changed, user.mfa_enabled,
user.mfa_disabled, token.refreshed, token.reuse_detected,
webauthn.credential_added, webauthn.credential_removed,
rbac.role_assigned, rbac.role_revoked, audit.event_logged
```

### 2.4 JWT + Refresh Token Design Gaps (Source: Security Agent)

**What the spec gets right:**
- Refresh tokens stored as SHA-256 hashes
- `revoked` boolean field
- `revoke_all_refresh_tokens_for_user`
- Short-lived access tokens, long-lived refresh tokens

**Critical missing columns in `refresh_tokens` table:**

```sql
-- ADD THESE:
family_id TEXT NOT NULL,            -- Groups rotation chain
used BOOLEAN NOT NULL DEFAULT FALSE, -- Has this token been consumed?
used_at TIMESTAMP                    -- When was it consumed?
```

**Without these, refresh token rotation is incomplete:**
1. No reuse detection (stolen token can be replayed after rotation)
2. No family revocation (can't revoke entire chain on detection)
3. Race conditions on concurrent refresh requests

**Complete rotation pattern (per OWASP, RFC 9700):**
```
1. Login → create token family, store token with used=FALSE
2. Refresh → check used=FALSE → mark used=TRUE → issue new token in SAME family
3. If used=TRUE presented → REUSE DETECTED → revoke entire family → force re-login
4. Grace period (5-10s) for legitimate retries (same family_id + within N seconds)
```

---

## 3. Critical Dependency Changes

### 3.1 passlib Replacement (P0)

**passlib is dead.** Broken on Python 3.13+ (PEP 594 removed `crypt` module), incompatible with bcrypt>=5.0 (removed `__about__` attribute), last release October 2020. A PyPI takeover request was filed February 2026.

**Replacement options (ranked):**

| Option | Python | Pros | Cons |
|--------|--------|------|------|
| `hashward[argon2]` | >=3.10 | Drop-in CryptContext API, Argon2id default, passlib hash migration | Python 3.10+ only |
| `pwdlib[argon2]` | >=3.10 | Used by FastAPI official tutorial, Argon2 + bcrypt | Python 3.10+ only |
| `bcrypt` directly | >=3.7 | Simple, no wrapper | No auto-upgrade, no multi-scheme |
| `argon2-cffi` directly | >=3.7 | Memory-hard, IETF RFC 9106 | Lower-level API |

**Decision:** Use `bcrypt>=4.1,<5` for Python 3.9+ compatibility. Note: Python 3.8/3.9 must be dropped (both EOL). For maximum security, recommend `hashward[argon2]` for Python 3.10+ as the primary scheme.

### 3.2 Minimum Python Version (P0)

**Drop Python 3.8 and 3.9.** Both are EOL:
- Python 3.8: EOL October 2024
- Python 3.9: EOL October 2025

Set `requires-python = ">=3.10"` to align with:
- `hashward` / `pwdlib` requirement (3.10+)
- `cryptography` v44+ (dropped 3.8)
- Modern Python features (match statements, `|` type unions, `tomllib`)

---

## 4. Security Assessment

### 4.1 JWT Security

| Vulnerability | Mitigation |
|--------------|-----------|
| Algorithm confusion (RS256→HS256 swap) | **Pin algorithm** in every `jwt.decode()` call — never read `alg` from token |
| `alg: none` bypass | Reject unconditionally; add explicit test |
| `kid` injection | Validate against server-side allowlist; never use as file path or DB query |
| `jku`/`x5u` poisoning | Ignore entirely; resolve keys from config only |
| Cross-service replay | Validate `iss`, `aud`, `exp`, `nbf`, `typ` on every verification |
| Token persistence after logout | Add JTI blacklist check in `verify_access_token` |

**Recommendation:** Consider ES256 over HS256 — shorter keys, faster, no RSA key size pitfalls. For asymmetric use cases, support RS256/ES256 via configurable algorithm.

### 4.2 MFA Security

| Area | Recommendation |
|------|---------------|
| TOTP secret encryption | Fernet (AES-128-CBC) is acceptable for v1. Document `FERNET_KEY` requirements. Plan AES-256-GCM upgrade for v2. |
| TOTP verification | ±1 step (30s) max window. Never wider. |
| Recovery codes | Generate 10-16 codes, 10+ chars each. Hash with same scheme as passwords. Display only once. |
| Rate limiting | Max 5 MFA attempts per 15 minutes per account |

### 4.3 Password Security

| Area | Recommendation |
|------|---------------|
| Hashing | Argon2id (IETF RFC 9106, OWASP recommended). Params: m=19456, t=2, p=1 |
| Minimum length | 12 characters (OWASP 2025 guideline) |
| Complexity | Require uppercase, lowercase, number, special character |
| HIBP check | Use k-anonymity API. Add `Add-Padding: true` header. Cache locally. |
| Hash migration | Support auto-rehashing on login when scheme is deprecated |

### 4.4 Rate Limiting

Implement at multiple levels:

| Level | Key | Window | Limit |
|-------|-----|--------|-------|
| Login attempts | Per username | 15 min | 5 attempts |
| Login attempts | Per IP | 15 min | 20 attempts |
| MFA verification | Per user | 5 min | 5 attempts |
| Password reset | Per email | 1 hour | 3 requests |
| API key creation | Per user | 1 hour | 10 keys |

Use sliding window or token bucket algorithm. The current `RateLimitExceededError` hint exception must be replaced with actual logic.

### 4.5 Account Lockout

- Use **exponential backoff**: 1s → 2s → 4s → 8s → 16s → 30s → permanent
- Associate counters with the account, not IP
- Allow password reset even during lockout
- Never reveal whether an account exists ("Invalid credentials" for both cases)

### 4.6 OWASP Authentication Cheat Sheet Compliance

| Requirement | Current Status | Action |
|------------|---------------|--------|
| Rate limiting on login | Not implemented | Add per-username + per-IP |
| Account lockout | Schema exists, logic needed | Implement exponential backoff |
| Password complexity | Configurable regex | Enforce min 12 chars + breach DB |
| Error message leakage | Partial | Always use "Invalid credentials" |
| Secure session management | Partial | Validate all JWT claims |
| TLS enforcement | Document only | Document HTTPS requirement |

---

## 5. Competitive Landscape

### 5.1 Feature Comparison

| Feature | **authority** | FastAPI-Users | Tenxyte | fastapi-fullauth | django-allauth | Keycloak |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| JWT + Refresh Rotation | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Encrypted MFA (TOTP) | ✅ (Fernet) | ❌ | ✅ | ❌ | ✅ | ✅ |
| MFA Recovery Codes | ✅ | ❌ | ✅ | ❌ | ❌ | ✅ |
| WebAuthn / Passkeys | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| RBAC | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| API Keys | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| HIBP Check | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Password History | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Email Change Flow | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Audit Log | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| Pluggable Storage | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Async Support | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Framework-Agnostic | ✅ | ❌ (FastAPI) | Partial | ❌ (FastAPI) | ❌ (Django) | ✅ |
| OAuth2 Social Login | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rate Limiting | ❌ (hint) | ❌ | ✅ | ✅ | ❌ | ✅ |

### 5.2 Market Positioning

```
Low complexity ◄─────────────────────────────────────► High complexity

PyJWT          authority        FastAPI-Users       Keycloak/Authentik
(auth only)    (auth library)   (user management)   (identity server)

Framework-specific ◄────────────────────────────────► Framework-agnostic

django-allauth    FastAPI-Users    authority    PyAuth    Tenxyte
```

**Authority occupies the "framework-agnostic, batteries-included auth library" niche** — positioned between low-level primitives (PyJWT) and full identity platforms (Keycloak).

### 5.3 Competitive Advantages

Authority offers features **no other framework-agnostic Python auth library has:**
- **Password History** — built-in reuse prevention
- **Encrypted MFA Secrets** — Fernet encryption at rest (competitors store plaintext)
- **Email Change Flow** — complete double-opt-in workflow
- **HIBP Integration** — k-anonymity privacy-respecting breach check
- **API Keys** — scoped, prefix-based key management

### 5.4 Threats

1. **FastAPI-Users' successor** — if the maintainer launches a new toolkit, it will have massive mindshare
2. **Tenxyte** — has Organizations + AI features; could attract B2B customers
3. **fastapi-fullauth** — very similar feature set but FastAPI-only

---

## 6. Missing Features & Gaps

### 6.1 Critical Missing Features (Must-Have for Production)

| Feature | Why It Matters | Priority |
|---------|---------------|----------|
| **OAuth2/OIDC (Social Login)** | 23.8% of logins use social login (2025). Without it, users must create yet another password. | **P0** |
| **Token Revocation / Blacklist** | JWTs are stateless — without a blacklist, "logged out" tokens remain valid until expiry. JTI check against storage needed. | **P0** |
| **Rate Limiting (Built-in)** | `RateLimitExceededError` is just a hint exception. Production needs actual per-user/IP limiting. | **P0** |
| **Passwordless Login (Magic Links)** | 41.2% of auths use magic links (2025). +15-25% signup completion. | **P1** |
| **CSRF Protection** | Required for cookie-based sessions. Any cookie-based deployment is vulnerable without it. | **P1** |
| **GDPR Account Deletion** | EU mandates right to erasure. Need confirmation tokens, grace periods, data export. | **P1** |

### 6.2 High Priority Missing Features

| Feature | Notes |
|---------|-------|
| Framework Integrations (FastAPI, Flask, Django) | Every competitor ships adapters. Users must wire everything manually. |
| CLI Tools | `authority migrate`, `authority doctor`, `authority create-admin` |
| Device Management | Refresh tokens track IP/UA but no device list or trust workflow |
| Session Management (Beyond JWT) | DB-backed opaque sessions as alternative to JWT |
| PostgreSQL Storage Adapter | SQLite won't survive production auth workloads |
| Multi-Tenant Support | Enterprise adoption requires `tenant_id` in schema |

### 6.3 Scalability Concerns

**SQLite concurrent write limitations:**
- Only one writer at a time (WAL mode helps reads, not writes)
- At 100+ concurrent writers: `database is locked` errors
- Missing pragmas: `busy_timeout=5000`, `synchronous=NORMAL`, `cache_size=-64000`

**Required storage extensions:**
- PostgreSQL adapter (asyncpg for async, psycopg2 for sync)
- Connection pooling configuration
- `health_check()` / `ping()` method
- Batch operation methods
- Alembic-style versioned migrations

### 6.4 Modern Auth Trends (2025-2026)

| Trend | Status | Action |
|-------|--------|--------|
| **Passkeys / FIDO2** | 5B+ active passkeys, 93% login success rate | Make passkeys primary auth, not secondary MFA |
| **Passwordless-First** | 84% global adoption predicted 2026 | Pivot architecture: Passkeys > Password > Magic Links |
| **SMS OTP Dying** | Regulatory bans in UAE, India, Philippines (2026) | Do not invest in SMS OTP |
| **Post-Quantum Crypto** | ML-DSA (CRYSTALS-Dilithium) in 2026 roadmap | Plan for algorithm migration, support ES256 minimum |

---

## 7. Design Decisions

### Decision Blockers (Resolve Before Coding)

| # | Decision | Options | Recommendation | Status |
|---|----------|---------|---------------|--------|
| D1 | Minimum Python version | 3.9 / 3.10 | **3.10** (hashward/pwdlib require it, 3.8/3.9 EOL) | Pending |
| D2 | Password hashing library | bcrypt / hashward / pwdlib | **bcrypt>=4.1,<5** (broadest compat) | Pending |
| D3 | Build system | setuptools / hatchling / pdm | **hatchling** (PyPA recommended, src-layout auto-detect) | Pending |
| D4 | HTTP client | requests / httpx | **httpx** (async-native, modern) | Pending |
| D5 | Type system for models | Dict[str,Any] / dataclasses / Pydantic | **dataclasses** (no extra dep, stdlib) | Pending |
| D6 | Event system pattern | callbacks / signals / event bus | **Event bus** (typed events, sync+async, fire-and-forget) | Pending |

---

## 8. Development Roadmap

### Phase 1: Foundation (Weeks 1-2)

**Objective:** Build the core infrastructure — exceptions, utilities, storage abstractions, and SQLite implementation.

**Deliverables:**
- [ ] `pyproject.toml` with hatchling, correct dependencies
- [ ] `src/authority/__init__.py` with public API exports
- [ ] `src/authority/exceptions.py` — complete exception hierarchy
- [ ] `src/authority/utils.py` — email validation, token generation/hashing, Fernet encryption, HIBP check
- [ ] `src/authority/config.py` — typed AuthConfig dataclass
- [ ] `src/authority/events.py` — event bus implementation
- [ ] `src/authority/storage/base.py` — StorageInterface + AsyncStorageInterface ABCs
- [ ] `src/authority/storage/sqlite.py` — SQLiteStorage with all CRUD methods
- [ ] Tests: `test_exceptions.py`, `test_utils.py`, `test_storage_sqlite.py`
- [ ] `.gitignore`, `LICENSE`, `.version`

**Dependencies:** None (this is the foundation)

**Risks:**
- Storage interface must be frozen before core.py implementation
- Event bus API must be stable before async_core.py

**Estimated effort:** 2-3 days

---

### Phase 2: Core Authentication (Weeks 3-4)

**Objective:** Implement the synchronous `AuthManager` with registration, login, JWT tokens, and refresh token rotation.

**Deliverables:**
- [ ] `src/authority/core.py` — AuthManager class with:
  - [ ] Configuration validation (env vars + constructor params)
  - [ ] `register()` — user registration with email verification
  - [ ] `login()` — password authentication with account lockout
  - [ ] `verify_access_token()` — JWT verification with algorithm pinning
  - [ ] `refresh_access_token()` — token rotation with family tracking
  - [ ] `verify_email()` — email verification flow
  - [ ] `request_password_reset()` + `reset_password()` — reset flow
  - [ ] `change_password()` — with history check
  - [ ] `request_email_change()` + `confirm_email_change()` — double opt-in
  - [ ] Password validation (complexity, HIBP, history)
  - [ ] Event triggering for all auth actions
  - [ ] Audit logging for all events
- [ ] Tests: `test_core.py` — full integration tests
- [ ] Refresh token family tracking + reuse detection

**Dependencies:** Phase 1 complete

**Risks:**
- Refresh token rotation race conditions need careful handling
- JWT algorithm pinning must be tested against known attack vectors

**Estimated effort:** 3-4 days

---

### Phase 3: MFA (Weeks 5-6)

**Objective:** Implement TOTP-based MFA with encrypted secrets, recovery codes, and the complete MFA lifecycle.

**Deliverables:**
- [ ] `setup_mfa()` — generate TOTP secret, encrypt with Fernet, return provisioning URI
- [ ] `verify_and_enable_mfa()` — verify TOTP code, enable MFA, generate recovery codes
- [ ] `verify_mfa_login()` — TOTP or recovery code verification during login
- [ ] `disable_mfa()` — MFA removal with re-authentication
- [ ] `regenerate_recovery_codes()` — new recovery code generation
- [ ] Recovery codes: hashed storage, one-time use, count tracking
- [ ] Tests: `test_mfa.py` — TOTP verification, recovery codes, encryption roundtrip
- [ ] Integration with login flow (MFA challenge/requirement)

**Dependencies:** Phase 2 complete

**Risks:**
- Fernet key loss = all MFA secrets unrecoverable (document this clearly)
- Recovery code generation must be cryptographically secure

**Estimated effort:** 2-3 days

---

### Phase 4: Advanced Features (Weeks 7-9)

**Objective:** Implement WebAuthn, RBAC, API keys, and audit logging.

**Deliverables:**
- [ ] **WebAuthn:**
  - [ ] `start_webauthn_registration()` — generate registration options
  - [ ] `complete_webauthn_registration()` — verify registration response
  - [ ] `start_webauthn_authentication()` — generate authentication options
  - [ ] `complete_webauthn_authentication()` — verify assertion, issue tokens
  - [ ] `list_webauthn_credentials()` + `delete_webauthn_credential()`
  - [ ] Credential management (description, last used tracking)
- [ ] **RBAC:**
  - [ ] `create_role()` + `delete_role()` + `list_roles()`
  - [ ] `create_permission()` + `delete_permission()` + `list_permissions()`
  - [ ] `assign_permission_to_role()` + `remove_permission_from_role()`
  - [ ] `assign_role_to_user()` + `remove_role_from_user()`
  - [ ] `get_user_roles()` + `get_user_permissions()` (effective)
  - [ ] Role hierarchy (optional: role inheritance)
- [ ] **API Keys:**
  - [ ] `create_api_key()` — generate, store hash, return prefix+secret once
  - [ ] `verify_api_key()` — prefix+hash lookup, scope check, expiry check
  - [ ] `list_api_keys()` + `revoke_api_key()` — user-facing management
- [ ] **Audit Log:**
  - [ ] Query methods: `get_audit_log()` with filtering (user, action, date range)
  - [ ] Log all auth events automatically
  - [ ] Append-only enforcement
- [ ] **Custom Profile:**
  - [ ] `update_profile()` + `get_profile()` — JSON blob storage
- [ ] Tests: `test_webauthn.py`, `test_rbac.py`, `test_api_keys.py`, `test_audit.py`

**Dependencies:** Phase 2 complete (Phase 3 optional but recommended)

**Risks:**
- WebAuthn requires careful browser interaction (client-side JS is out of scope but server-side must be correct)
- RBAC permission resolution must handle circular role assignments

**Estimated effort:** 4-5 days

---

### Phase 5: Async Implementation (Weeks 10-11)

**Objective:** Create the async counterpart — `AsyncAuthManager` and `AsyncSQLiteStorage`.

**Deliverables:**
- [ ] `src/authority/storage/aiosqlite.py` — full AsyncStorageInterface implementation
- [ ] `src/authority/async_core.py` — AsyncAuthManager mirroring sync AuthManager
- [ ] Tests: `test_async_core.py`, `test_storage_aiosqlite.py`
- [ ] Async event bus support

**Dependencies:** Phases 2-4 complete (can reuse sync test patterns)

**Risks:**
- aiosqlite connection management differs from sync sqlite3
- Transaction handling must use `async with conn:` context managers
- Test isolation with async fixtures

**Estimated effort:** 2-3 days

---

### Phase 6: Polish & Release (Weeks 12-14)

**Objective:** Production-ready quality — tests, documentation, packaging, CI/CD.

**Deliverables:**
- [ ] **Testing:**
  - [ ] 90%+ code coverage (enforce via pytest-cov)
  - [ ] Property-based tests with hypothesis for password validation
  - [ ] Security-specific tests (timing attacks, algorithm confusion)
  - [ ] Mock HIBP API responses for deterministic tests
  - [ ] Mock WebAuthn browser responses
- [ ] **Code Quality:**
  - [ ] Ruff linting (replace flake8+black+isort)
  - [ ] Pyright type checking (strict mode)
  - [ ] Pre-commit hooks
- [ ] **Documentation:**
  - [ ] README.md with quickstart, API reference, configuration guide
  - [ ] Docstrings for all public methods (Google style)
  - [ ] CHANGELOG.md
  - [ ] Security policy (SECURITY.md)
- [ ] **Packaging:**
  - [ ] `pyproject.toml` with hatchling
  - [ ] `__version__` from `.version` file
  - [ ] PyPI-ready build (`python -m build`)
  - [ ] `.version` file for version-tracker skill
- [ ] **CI/CD:**
  - [ ] GitHub Actions: test, lint, type-check, build
  - [ ] Codecov integration
  - [ ] Dependabot for dependency updates
- [ ] **Framework Integration (Minimum):**
  - [ ] `authority.contrib.fastapi` — dependency injection helpers
  - [ ] Example FastAPI application

**Dependencies:** All previous phases complete

**Risks:**
- Documentation quality directly impacts adoption
- CI/CD must catch regressions before release

**Estimated effort:** 3-4 days

---

## 9. Prioritization Matrix

| Feature | User Value | Complexity | Dependencies | Priority Score |
|---------|-----------|------------|--------------|----------------|
| JWT + Refresh Rotation | High | Medium | Phase 1 | **P0** — Core |
| Registration + Login | High | Low | Phase 1 | **P0** — Core |
| Password Validation | High | Low | Phase 1 | **P0** — Core |
| TOTP MFA | High | Medium | Phase 2 | **P0** — Security |
| Recovery Codes | High | Low | MFA | **P0** — Security |
| Password History | Medium | Low | Phase 2 | **P1** |
| Email Verification | High | Low | Phase 2 | **P1** |
| Password Reset | High | Low | Phase 2 | **P1** |
| Email Change | Medium | Medium | Phase 2 | **P1** |
| Audit Logging | High | Medium | Phase 2 | **P1** |
| WebAuthn / Passkeys | High | High | Phase 2 | **P1** — Differentiator |
| RBAC | High | Medium | Phase 2 | **P1** |
| API Keys | High | Medium | Phase 2 | **P1** — Differentiator |
| Custom Profile | Low | Low | Phase 2 | **P2** |
| OAuth2 Social Login | High | High | Phase 6 | **P2** — Post-v1 |
| Rate Limiting | High | Medium | Phase 6 | **P2** — Post-v1 |
| Magic Links | Medium | Medium | Phase 6 | **P2** — Post-v1 |
| Framework Integrations | High | Medium | Phase 6 | **P2** — Post-v1 |
| PostgreSQL Adapter | High | High | Phase 6 | **P2** — Post-v1 |

---

## 10. Implementation Checklist

### Pre-Implementation (Before Phase 1)

- [ ] Resolve all 6 design decisions (D1-D6)
- [ ] Initialize git repository: `https://github.com/rkriad585/authority.git`
- [ ] Set up `.version` file (version-tracker skill)
- [ ] Create `pyproject.toml` with hatchling
- [ ] Create `LICENSE` (MIT)
- [ ] Create `.gitignore`
- [ ] Create `src/authority/` package structure

### Phase 1: Foundation — [ ] Pending

- [ ] `exceptions.py` — all exception classes
- [ ] `config.py` — AuthConfig dataclass
- [ ] `events.py` — event bus (sync)
- [ ] `utils.py` — email validation, token gen/hashing, Fernet encrypt/decrypt, HIBP
- [ ] `storage/base.py` — StorageInterface + AsyncStorageInterface ABCs
- [ ] `storage/sqlite.py` — full SQLiteStorage implementation
- [ ] `storage/__init__.py` — package exports
- [ ] `__init__.py` — public API re-exports
- [ ] Tests for all Phase 1 modules

### Phase 2: Core Auth — [ ] Pending

- [ ] `core.py` — AuthManager.__init__, config validation
- [ ] `core.py` — register()
- [ ] `core.py` — login() with lockout
- [ ] `core.py` — verify_access_token()
- [ ] `core.py` — refresh_access_token() with rotation + family tracking
- [ ] `core.py` — verify_email()
- [ ] `core.py` — request_password_reset() + reset_password()
- [ ] `core.py` — change_password()
- [ ] `core.py` — request_email_change() + confirm_email_change()
- [ ] `core.py` — logout() + logout_all()
- [ ] `core.py` — get_user() + update_user() + delete_user()
- [ ] `core.py` — event system integration
- [ ] `core.py` — audit logging integration
- [ ] `core.py` — JTI blacklist for access tokens
- [ ] Tests for all Phase 2 methods

### Phase 3: MFA — [ ] Pending

- [ ] `core.py` — setup_mfa()
- [ ] `core.py` — verify_and_enable_mfa()
- [ ] `core.py` — verify_mfa_login() (TOTP + recovery codes)
- [ ] `core.py` — disable_mfa()
- [ ] `core.py` — regenerate_recovery_codes()
- [ ] Recovery code hashing + one-time use enforcement
- [ ] Tests for all MFA methods

### Phase 4: Advanced Features — [x] Complete

- [x] `core.py` — WebAuthn registration/auth flows
- [x] `core.py` — RBAC CRUD + permission resolution
- [x] `core.py` — API key CRUD + verification
- [x] `core.py` — Audit log queries
- [x] `core.py` — Profile CRUD
- [x] Tests for all Phase 4 features

### Phase 5: Async — [x] Complete

- [x] `storage/aiosqlite.py` — full AsyncStorageInterface implementation
- [x] `async_core.py` — AsyncAuthManager (mirror of sync)
- [x] Async event bus support
- [x] Tests for all async modules

### Phase 6: Polish — [ ] Pending

- [ ] 90%+ test coverage
- [ ] Ruff linting configured
- [ ] Pyright type checking configured
- [ ] Pre-commit hooks
- [ ] README.md
- [ ] Docstrings for all public methods
- [ ] CHANGELOG.md
- [ ] SECURITY.md
- [ ] `.version` file
- [ ] PyPI build test
- [ ] GitHub Actions CI
- [ ] `authority.contrib.fastapi` — basic integration

---

## Appendix A: Refresh Token Table Schema (Updated)

```sql
CREATE TABLE refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    family_id TEXT NOT NULL,           -- NEW: groups rotation chain
    used BOOLEAN NOT NULL DEFAULT FALSE, -- NEW: for reuse detection
    used_at TIMESTAMP,                  -- NEW: when consumed
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_refresh_token_user_id ON refresh_tokens(user_id, revoked);
CREATE INDEX idx_refresh_token_family ON refresh_tokens(family_id);
CREATE INDEX idx_refresh_token_expires ON refresh_tokens(expires_at);
```

## Appendix B: Rate Limiting Schema (Optional)

```sql
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,          -- e.g., "login:username:user@example.com"
    window_start TIMESTAMP NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    UNIQUE(key, window_start)
);

CREATE INDEX idx_rate_limit_key ON rate_limits(key, window_start);
```

## Appendix C: Audit Log Schema (Updated)

```sql
CREATE TABLE auth_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    user_id INTEGER,
    email TEXT,
    action TEXT NOT NULL,
    ip_address TEXT,
    success BOOLEAN,
    details_json TEXT,
    chain_hash TEXT,             -- NEW: SHA-256 of prev hash + entry (tamper evidence)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX idx_audit_log_timestamp ON auth_audit_log(timestamp DESC);
CREATE INDEX idx_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_audit_log_action ON auth_audit_log(action);
```

---

> **Last updated:** 2026-07-23
> **Next review:** After Phase 1 completion
