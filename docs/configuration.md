# Configuration

`AuthConfig` is a dataclass controlling every knob in the library. Values are
resolved in this order:

1. **Constructor keyword arguments** — highest priority
2. **Environment variables** — prefixed with `AUTHORITY_`
3. **Defaults**

Secrets (`jwt_secret_key`, `fernet_key`) should come from the environment in
production.

```python
from authority import AuthConfig

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
    password_min_length=14,
)
```

The same via environment variables:

```bash
export AUTHORITY_JWT_SECRET_KEY="your-secret-key-min-32-chars"
export AUTHORITY_FERNET_KEY="your-fernet-key"
export AUTHORITY_DB_PATH="/var/lib/app/auth.db"
```

## Reference

| Parameter | Env Var | Default | Description |
|---|---|---|---|
| `db_path` | `AUTHORITY_DB_PATH` | `"authority_data.db"` | Path to the SQLite database file |
| `prune_tokens_on_startup` | -- | `True` | Prune expired tokens when the manager opens |
| `jwt_secret_key` | `AUTHORITY_JWT_SECRET_KEY` | `""` | **Required.** Secret key for signing JWTs |
| `fernet_key` | `AUTHORITY_FERNET_KEY` | `""` | **Required.** Fernet key for encrypting MFA secrets |
| `jwt_algorithm` | -- | `"HS256"` | JWT signing algorithm |
| `jwt_access_token_expiry_minutes` | -- | `15` | Access token lifetime in minutes |
| `jwt_refresh_token_expiry_days` | -- | `7` | Refresh token lifetime in days |
| `jwt_refresh_token_absolute_max_days` | -- | `30` | Maximum refresh token age regardless of rotation |
| `password_min_length` | -- | `12` | Minimum password length |
| `password_history_depth` | -- | `5` | Number of previous passwords to remember |
| `password_require_complexity` | -- | `True` | Enforce the complexity regex |
| `password_complexity_regex` | -- | see below | Regex used for complexity checks |
| `password_complexity_desc` | -- | see below | Human-readable description of the complexity policy |
| `password_prevent_email_username_use` | -- | `True` | Reject passwords containing the email or username |
| `hibp_check_enabled` | -- | `False` | Check passwords against the HIBP breach database |
| `hibp_api_key` | `AUTHORITY_HIBP_KEY` | `""` | Optional HIBP API key |
| `hibp_failure_mode` | -- | `"warn"` | `"reject"`, `"warn"`, or `"ignore"` |
| `failed_login_lockout_threshold` | -- | `5` | Failed attempts before lockout |
| `failed_login_lockout_minutes` | -- | `15` | Lockout duration in minutes |
| `email_verification_required` | -- | `True` | Require email verification on signup |
| `verification_token_expiry_minutes` | -- | `1440` | Email verification token lifetime |
| `password_reset_token_expiry_minutes` | -- | `30` | Password reset token lifetime |
| `email_change_token_expiry_minutes` | -- | `60` | Email change token lifetime |
| `mfa_issuer_name` | -- | `"Authority Powered App"` | Issuer name shown in authenticator apps |
| `mfa_recovery_code_count` | -- | `10` | Number of recovery codes generated |
| `mfa_totp_valid_window` | -- | `1` | TOTP valid window (±1 step = 30s each) |
| `refresh_token_rotate` | -- | `True` | Rotate refresh tokens on use |
| `refresh_token_reuse_grace_seconds` | -- | `10` | Grace period for legitimate refresh retries |
| `webauthn_rp_id` | `AUTHORITY_WEBAUTHN_RP_ID` | `""` | WebAuthn relying party ID |
| `webauthn_rp_name` | -- | `"My Application"` | WebAuthn relying party name |
| `webauthn_expected_origin` | `AUTHORITY_WEBAUTHN_ORIGIN` | `""` | Expected origin for WebAuthn |
| `webauthn_timeout_ms` | -- | `60000` | WebAuthn ceremony timeout |
| `audit_log_enabled` | -- | `True` | Enable audit logging |
| `default_user_role` | -- | `"user"` | Default role assigned to new users |
| `api_key_byte_length` | -- | `32` | Byte length of generated API keys |

The default complexity regex is
`^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$` — at least 12 characters
containing a lowercase letter, an uppercase letter, a digit, and a special
character.

## Notes

- `jwt_secret_key` is required: `AuthConfig` raises `ConfigurationError` if it
  is empty. Set it via the constructor or `AUTHORITY_JWT_SECRET_KEY`.
- `fernet_key` is required for MFA: it encrypts TOTP secrets and recovery codes
  at rest. Generate one with
  `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
- `webauthn_rp_id` and `webauthn_expected_origin` are required for WebAuthn
  flows.
- `hibp_failure_mode` controls behavior when the HIBP API is unavailable:
  `"reject"` blocks the password, `"warn"` logs and continues, `"ignore"`
  skips silently.
