"""Utility functions: validation, encryption, token handling, HIBP checks."""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import secrets

import httpx
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken as FernetInvalidToken

logger = logging.getLogger("authority.utils")

# ── Email Validation ─────────────────────────────────────────

_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def validate_email_format(email: str) -> bool:
    """Check whether *email* has a plausible format (RFC 5322 simplified)."""
    if not email or not isinstance(email, str):
        return False
    return _EMAIL_RE.match(email) is not None


# ── Password Strength ───────────────────────────────────────


def estimate_password_strength(password: str) -> dict[str, int | list[str]]:
    """Estimate the strength of *password* on a 0-4 scale (no external deps).

    Scores 0-1 (weak), 2 (fair), 3 (good), 4 (strong) based on length,
    character-class diversity, and common-substring heuristics.

    Args:
        password: The password to evaluate.

    Returns:
        Dict with ``score`` (0-4) and ``feedback`` (list of suggestions).
    """
    if not password:
        return {"score": 0, "feedback": ["Password cannot be empty."]}

    score = 0
    feedback: list[str] = []
    length = len(password)

    if length < 8:
        feedback.append("Use at least 8 characters.")
    elif length < 12:
        score += 1
        feedback.append("Aim for at least 12 characters.")
    else:
        score += 2

    classes = 0
    if any(c.islower() for c in password):
        classes += 1
    if any(c.isupper() for c in password):
        classes += 1
    if any(c.isdigit() for c in password):
        classes += 1
    if any(not c.isalnum() for c in password):
        classes += 1

    score += max(0, classes - 2)
    if classes < 3:
        feedback.append("Mix uppercase, lowercase, numbers, and special characters.")

    lower = password.lower()
    common = (
        "password",
        "123456",
        "qwerty",
        "letmein",
        "admin",
        "welcome",
        "iloveyou",
        "monkey",
        "abc123",
    )
    if any(pat in lower for pat in common):
        score = min(score, 2)
        feedback.append("Avoid common words and sequences.")

    if len(password) >= 12 and classes == 4:
        score = 4

    return {"score": max(0, min(score, 4)), "feedback": feedback}


# ── Token Generation / Hashing ───────────────────────────────


def generate_secure_token(byte_length: int = 32) -> str:
    """Return a cryptographically secure, URL-safe random token."""
    return secrets.token_urlsafe(byte_length)


def hash_token(token: str) -> str:
    """SHA-256 hash of *token* for safe storage."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ── Fernet Encryption ────────────────────────────────────────

_fernet_instance: Fernet | None = None


def _get_fernet(key_override: str | None = None) -> Fernet:
    """Return a cached :class:`Fernet` instance, initialising from env or *key_override*."""
    global _fernet_instance
    if _fernet_instance is not None and key_override is None:
        return _fernet_instance

    key_str = key_override or os.environ.get("AUTHORITY_FERNET_KEY", "")
    if not key_str:
        raise ValueError(
            "Fernet key not provided. Set AUTHORITY_FERNET_KEY env var "
            "or pass fernet_key to AuthConfig."
        )

    key_bytes = key_str.encode("utf-8")
    decoded = base64.urlsafe_b64decode(key_bytes)
    if len(decoded) != 32:
        raise ValueError("Fernet key must decode to exactly 32 bytes.")

    instance = Fernet(key_bytes)
    if key_override is None:
        _fernet_instance = instance
    return instance


def encrypt_data(data: str, fernet_key_override: str | None = None) -> str | None:
    """Encrypt *data* with Fernet. Returns base64-encoded ciphertext or ``None``."""
    if not data:
        return None
    try:
        fernet = _get_fernet(fernet_key_override)
        return fernet.encrypt(data.encode("utf-8")).decode("utf-8")
    except Exception:
        logger.exception("Encryption failed")
        return None


def decrypt_data(
    encrypted_data: str, fernet_key_override: str | None = None
) -> str | None:
    """Decrypt Fernet ciphertext. Returns plaintext or ``None`` on failure."""
    if not encrypted_data:
        return None
    try:
        fernet = _get_fernet(fernet_key_override)
        return fernet.decrypt(encrypted_data.encode("utf-8")).decode("utf-8")
    except FernetInvalidToken:
        logger.warning("Decryption failed: invalid token (wrong key or corrupted data)")
        return None
    except Exception:
        logger.exception("Decryption failed")
        return None


def reset_fernet_cache() -> None:
    """Clear cached Fernet instance (useful in tests with key rotation)."""
    global _fernet_instance
    _fernet_instance = None


# ── HIBP Password Breach Check ───────────────────────────────

HIBP_API_URL = "https://api.pwnedpasswords.com/range/"


def check_password_pwned(
    password: str,
    api_key: str | None = None,
    timeout: int = 5,
) -> int | None:
    """Check *password* against the HIBP Pwned Passwords API (k-anonymity).

    Returns the breach count (>=0) if found, ``0`` if not found,
    or ``None`` on network/API error.
    """
    if not password:
        return 0

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"{HIBP_API_URL}{prefix}"

    headers: dict[str, str] = {
        "User-Agent": "authority-auth/0.1 (Python; +https://github.com/rkriad585/authority)",
        "Add-Padding": "true",
    }
    hibp_key = api_key or os.environ.get("AUTHORITY_HIBP_KEY", "")
    if hibp_key:
        headers["Hibp-Api-Key"] = hibp_key

    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(url, headers=headers)

        if response.status_code == 404:
            return 0

        response.raise_for_status()

        for line in response.text.splitlines():
            try:
                h_suffix, count_str = line.strip().split(":", 1)
                if h_suffix == suffix:
                    return int(count_str)
            except ValueError:
                continue

        return 0
    except httpx.TimeoutException:
        logger.error("HIBP API request timed out after %ds", timeout)
        return None
    except httpx.HTTPStatusError as exc:
        logger.error("HIBP API returned HTTP %s", exc.response.status_code)
        return None
    except Exception:
        logger.exception("Unexpected error during HIBP check")
        return None
