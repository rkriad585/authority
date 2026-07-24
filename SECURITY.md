# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability within Authority, please send an email to rkriad585@gmail.com. All security vulnerabilities will be promptly addressed.

**Please do not report security vulnerabilities through public GitHub issues.**

### What to include

When reporting a vulnerability, please include:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix or mitigation**: Within 2 weeks for critical issues

## Security Considerations

### JWT Tokens

- Access tokens are signed with HS256 by default
- Algorithm is pinned in every `jwt.decode()` call to prevent algorithm confusion attacks
- Refresh tokens are stored as SHA-256 hashes, never plaintext
- Token rotation with family tracking prevents replay attacks

### Password Storage

- Passwords are hashed with bcrypt (cost factor 12+)
- HIBP integration checks passwords against known breaches
- Password history prevents reuse

### MFA

- TOTP secrets are encrypted at rest with Fernet (AES-128-CBC)
- Recovery codes are hashed before storage
- MFA requires re-authentication to disable

### Storage

- Refresh tokens include `family_id` for rotation chain tracking
- `used` flag enables reuse detection
- Audit log is append-only with chain hashing for tamper evidence

## Best Practices

1. **Use environment variables** for all secrets (JWT key, Fernet key, database URL)
2. **Enable HTTPS** in production — tokens in transit must be encrypted
3. **Set short-lived access tokens** (15-30 minutes recommended)
4. **Enable MFA** for all user accounts
5. **Monitor audit logs** for suspicious activity
6. **Rotate secrets** periodically
7. **Use a proper database** (PostgreSQL) in production — SQLite is for development only
