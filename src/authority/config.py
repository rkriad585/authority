"""Typed configuration for the authority library."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class AuthConfig:
    """Central configuration for AuthManager.

    Values are resolved in order: constructor kwargs > environment variables > defaults.
    Environment variables are prefixed with ``AUTHORITY_`` (e.g. ``AUTHORITY_JWT_SECRET_KEY``).
    """

    # ── Storage ──────────────────────────────────────────────
    db_path: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_DB_PATH", "authority_data.db")
    )
    prune_tokens_on_startup: bool = True

    # ── Secrets (must come from env or be passed explicitly) ─
    jwt_secret_key: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_JWT_SECRET_KEY", "")
    )
    fernet_key: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_FERNET_KEY", "")
    )

    # ── JWT ──────────────────────────────────────────────────
    jwt_algorithm: str = "HS256"
    jwt_access_token_expiry_minutes: int = 15
    jwt_refresh_token_expiry_days: int = 7
    jwt_refresh_token_absolute_max_days: int = 30

    # ── Password Policy ──────────────────────────────────────
    password_min_length: int = 12
    password_history_depth: int = 5
    password_require_complexity: bool = True
    password_complexity_regex: str = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$"
    )
    password_complexity_desc: str = (
        "Password must be at least 12 characters and contain "
        "uppercase, lowercase, number, and special character."
    )
    password_prevent_email_username_use: bool = True

    # ── HIBP ─────────────────────────────────────────────────
    hibp_check_enabled: bool = False
    hibp_api_key: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_HIBP_KEY", "")
    )
    hibp_failure_mode: str = "warn"  # "reject" | "warn" | "ignore"

    # ── Account Lockout ──────────────────────────────────────
    failed_login_lockout_threshold: int = 5
    failed_login_lockout_minutes: int = 15

    # ── Email / Verification ─────────────────────────────────
    email_verification_required: bool = True
    verification_token_expiry_minutes: int = 1440  # 24 hours
    password_reset_token_expiry_minutes: int = 30
    email_change_token_expiry_minutes: int = 60

    # ── MFA ──────────────────────────────────────────────────
    mfa_issuer_name: str = "Authority Powered App"
    mfa_recovery_code_count: int = 10
    mfa_totp_valid_window: int = 1  # ±1 step (30s each)

    # ── Refresh Tokens ───────────────────────────────────────
    refresh_token_rotate: bool = True
    refresh_token_reuse_grace_seconds: int = 10

    # ── WebAuthn ─────────────────────────────────────────────
    webauthn_rp_id: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_WEBAUTHN_RP_ID", "")
    )
    webauthn_rp_name: str = "My Application"
    webauthn_expected_origin: str = field(
        default_factory=lambda: os.environ.get("AUTHORITY_WEBAUTHN_ORIGIN", "")
    )
    webauthn_timeout_ms: int = 60_000

    # ── Audit ────────────────────────────────────────────────
    audit_log_enabled: bool = True

    # ── RBAC ─────────────────────────────────────────────────
    default_user_role: str = "user"

    # ── API Keys ─────────────────────────────────────────────
    api_key_byte_length: int = 32

    def validate(self) -> None:
        """Validate critical configuration. Raises ConfigurationError on failure."""
        from .exceptions import ConfigurationError

        if not self.jwt_secret_key:
            raise ConfigurationError(
                "jwt_secret_key is required. Set AUTHORITY_JWT_SECRET_KEY env var "
                "or pass jwt_secret_key to AuthConfig."
            )
        if not self.fernet_key:
            raise ConfigurationError(
                "fernet_key is required for MFA encryption. Set AUTHORITY_FERNET_KEY env var "
                "or pass fernet_key to AuthConfig."
            )
        if self.jwt_access_token_expiry_minutes <= 0:
            raise ConfigurationError(
                "jwt_access_token_expiry_minutes must be positive."
            )
        if self.jwt_refresh_token_expiry_days <= 0:
            raise ConfigurationError("jwt_refresh_token_expiry_days must be positive.")
        if self.password_min_length < 8:
            raise ConfigurationError("password_min_length must be at least 8.")
        if self.hibp_failure_mode not in ("reject", "warn", "ignore"):
            raise ConfigurationError(
                "hibp_failure_mode must be 'reject', 'warn', or 'ignore'."
            )
        if self.failed_login_lockout_threshold < 0:
            raise ConfigurationError(
                "failed_login_lockout_threshold must be non-negative."
            )
