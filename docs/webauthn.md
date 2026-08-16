# WebAuthn / Passkeys

`authority-auth` implements the WebAuthn ceremony for passwordless
registration and authentication. Requires `webauthn_rp_id` and
`webauthn_expected_origin` to be set in the [configuration](configuration.md).

## Configuration

| Field | Purpose |
|---|---|
| `webauthn_rp_id` | Relying Party ID — the effective domain (e.g. `example.com`) |
| `webauthn_rp_name` | Display name shown by the platform authenticator |
| `webauthn_expected_origin` | Allowed origin(s), e.g. `https://example.com` |
| `webauthn_timeout_ms` | Challenge timeout in milliseconds |

## Registration ceremony

Maps onto `navigator.credentials.create()`:

```python
# 1. Server: generate registration options
options = auth.start_webauthn_registration(user_id=user["id"])
#    -> {challenge, rp, user, pubKeyCredParams, timeout, attestation, ...}

# 2. Browser: pass options to navigator.credentials.create(options)
#    and send the resulting credential JSON back.

# 3. Server: verify and store the credential
cred = auth.complete_webauthn_registration(
    user_id=user["id"],
    credential_data=credential_data,   # dict from navigator.credentials.create()
)
```

`complete_webauthn_registration()` verifies the attestation, signature, origin
and RP id, then stores the public key.

## Authentication ceremony

Maps onto `navigator.credentials.get()`:

```python
# 1. Server: generate authentication options (discoverable credential flow)
options = auth.start_webauthn_authentication(user_id=user["id"])
#    -> {challenge, rpId, allowCredentials, timeout, userVerification, ...}

# 2. Browser: pass options to navigator.credentials.get(options)
#    and send the assertion JSON back.

# 3. Server: verify the assertion; returns the token pair on success
result = auth.complete_webauthn_authentication(
    credential_data=assertion_data,
)
tokens = result["access_token"], result["refresh_token"]
```

`start_webauthn_authentication(user_id=None)` omits `allowCredentials` when no
user is specified, enabling the discoverable / passkey-first flow where the
authenticator picks the credential.

## Managing credentials

```python
auth.list_webauthn_credentials(user_id=user["id"])
auth.delete_webauthn_credential(user_id=user["id"], credential_id="...")
```

`list_webauthn_credentials()` returns each credential's id, transports, and
last-used time (no private key material).

## Errors

| Exception | When |
|---|---|
| `WebAuthnError` | Base for all WebAuthn failures |
| `WebAuthnRegistrationError` | Registration ceremony failed |
| `WebAuthnVerificationError` | Authentication assertion invalid |

Method signatures live on the [AuthManager](auth-manager.md) page.
