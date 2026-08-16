# Multi-Factor Authentication (MFA)

MFA uses **TOTP** (RFC 6238, 30-second codes from an authenticator app). The
shared secret is encrypted at rest with Fernet (`fernet_key`); recovery codes
are single-use and stored hashed.

## Enabling MFA

```python
# 1. Initiate setup — returns the shared secret + provisioning URI
setup = auth.setup_mfa(user_id=user["id"])
print(setup["secret"])
print(setup["provisioning_uri"])   # render as QR code

# 2. User scans the QR and enters a 6-digit code
result = auth.verify_and_enable_mfa(user_id=user["id"], code="123456")
print(result["recovery_codes"])    # plaintext, shown once — store these
```

`setup_mfa()` returns:

| Key | Description |
|---|---|
| `secret` | The TOTP shared secret |
| `provisioning_uri` | `otpauth://` URI for QR generation |

`verify_and_enable_mfa()` only accepts a correct code; it then activates MFA and
returns the `recovery_codes` list. `mfa_recovery_code_count` controls how many
are generated.

## Logging in with MFA

```python
result = auth.login(email="alice@example.com", password="...")
if result.get("mfa_required"):
    tokens = auth.verify_mfa_login(
        user_id=result["user_id"],
        code="654321",      # a TOTP code OR a recovery code
    )
```

When MFA is enabled, `login()` does **not** issue tokens — it returns
`mfa_required: True` and `user_id` instead. `verify_mfa_login()` accepts either
a TOTP code or a recovery code and returns the normal token pair.

## Recovery codes

Recovery codes are single-use. `verify_mfa_recovery_code()` consumes one when
used; `get_mfa_status()` reports how many remain via
`recovery_codes_remaining`.

```python
# Check status
status = auth.get_mfa_status(user_id=user["id"])
print(status["mfa_enabled"], status["recovery_codes_remaining"])

# Regenerate (invalidates old codes, requires password)
auth.regenerate_recovery_codes(user_id=user["id"], password="...")
```

## Disabling MFA

```python
auth.disable_mfa(user_id=user["id"], password="...")
```

Requires the current password to prevent trivial takeover of accounts that were
already compromised.

## MFA-related errors

| Exception | When |
|---|---|
| `MFARequiredError` | Login requires the MFA step |
| `MFAFailedError` | The supplied code is invalid |
| `InvalidRecoveryCodeError` | A recovery code was invalid |
| `MFANotEnabledError` | MFA operation on a user without MFA |

## Config reference

| Field | Default | Purpose |
|---|---|---|
| `mfa_issuer_name` | `"Authority"` | Issuer shown in the authenticator app |
| `mfa_recovery_code_count` | `10` | Number of recovery codes |
| `mfa_totp_valid_window` | `1` | ±TOTP windows accepted for clock drift |

Method signatures live on the [AuthManager](auth-manager.md) page.
