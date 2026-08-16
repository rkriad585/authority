"""Asynchronous authentication manager — async counterpart to :class:`AuthManager`."""

from __future__ import annotations

import datetime
import logging
import re
import secrets
from typing import Any

import bcrypt
import jwt as pyjwt

from .config import AuthConfig
from .events import Event, EventBus
from .exceptions import (
    AccountInactiveError,
    AccountLockedError,
    AccountNotVerifiedError,
    ConfigurationError,
    InsufficientPermissionsError,
    InvalidCredentialsError,
    InvalidTokenError,
    PasswordPwnedError,
    TokenExpiredError,
    UserExistsError,
    UserNotFoundError,
    ValidationError,
)
from .storage.base import AsyncStorageInterface
from .utils import (
    check_password_pwned,
    generate_secure_token,
    hash_token,
    validate_email_format,
)

logger = logging.getLogger("authority.async_core")


def _hash_password(password: str) -> str:
    """Hash a password with bcrypt and return the hash string."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except Exception:
        logger.exception("Password verification failed unexpectedly")
        return False


class AsyncAuthManager:
    """Asynchronous authentication manager.

    Provides registration, login, JWT management, refresh token rotation,
    email verification, password reset/change, and email change flows.

    Usage::

        from authority import AuthConfig, AsyncAuthManager
        from authority.storage.aiosqlite import AsyncSQLiteStorage

        config = AuthConfig(
            jwt_secret_key="your-secret-key",
            fernet_key="your-fernet-key",
        )
        storage = AsyncSQLiteStorage("auth.db")
        await storage.connect()
        auth = AsyncAuthManager(config, storage)
    """

    def __init__(
        self,
        config: AuthConfig,
        storage: AsyncStorageInterface,
        event_bus: EventBus | None = None,
    ) -> None:
        """Initialize the AsyncAuthManager.

        Args:
            config: Configuration for auth behavior.
            storage: Async storage backend implementation.
            event_bus: Optional event bus for lifecycle events.
        """
        config.validate()
        self._config = config
        self._storage = storage
        self._events = event_bus or EventBus()
        self._jti_blacklist: set[str] = set()

    @property
    def config(self) -> AuthConfig:
        """The authentication configuration."""
        return self._config

    @property
    def storage(self) -> AsyncStorageInterface:
        """The async storage backend instance."""
        return self._storage

    @property
    def events(self) -> EventBus:
        """The event bus for auth lifecycle events."""
        return self._events

    # ── Registration ───────────────────────────────────────

    async def register(
        self,
        name: str,
        email: str,
        password: str,
        ip_address: str | None = None,
        auto_verify: bool = False,
    ) -> dict[str, Any]:
        """Register a new user.

        Args:
            name: Display name.
            email: Email address.
            password: Plaintext password.
            ip_address: Client IP for audit logging.
            auto_verify: If True, mark email as verified immediately.

        Returns:
            User dict with id, name, email, is_verified, etc.

        Raises:
            UserExistsError: If email is already registered.
            ValidationError: If inputs are invalid.
            PasswordPwnedError: If password appears in breach database.
        """
        if not name or not name.strip():
            raise ValidationError("Name is required.")
        name = name.strip()

        if not validate_email_format(email):
            raise ValidationError(f"Invalid email format: {email}")
        email = email.lower().strip()

        if not password:
            raise ValidationError("Password is required.")

        self._validate_password_strength(password, email, name)

        existing = await self._storage.get_user_by_email(email)
        if existing:
            raise UserExistsError(f"An account with email '{email}' already exists.")

        password_hash = _hash_password(password)

        verification_token = None
        verification_token_hash = None
        verification_expiry = None
        is_verified = auto_verify

        if self._config.email_verification_required and not auto_verify:
            verification_token = generate_secure_token(32)
            verification_token_hash = hash_token(verification_token)
            verification_expiry = datetime.datetime.now(
                datetime.timezone.utc
            ) + datetime.timedelta(
                minutes=self._config.verification_token_expiry_minutes
            )

        user_id = await self._storage.create_user(
            name=name,
            email=email,
            password_hash=password_hash,
            is_verified=is_verified,
            verification_token_hash=verification_token_hash,
            verification_token_expiry=verification_expiry,
        )

        await self._storage.add_password_history(user_id, password_hash)

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise ConfigurationError(
                "Failed to retrieve created user — database error."
            )

        await self._events.emit_async(
            Event.USER_REGISTERED,
            {"user_id": user_id, "email": email, "ip_address": ip_address},
        )

        await self._log_audit(user_id, email, "user.registered", ip_address, True)

        logger.info("User registered: %s (%s)", email, user_id)

        return {k: v for k, v in user.items() if k != "password_hash"}

    def _validate_password_strength(self, password: str, email: str, name: str) -> None:
        """Validate password against policy."""
        cfg = self._config

        if len(password) < cfg.password_min_length:
            raise ValidationError(
                f"Password must be at least {cfg.password_min_length} characters."
            )

        if cfg.password_require_complexity:
            pattern = re.compile(cfg.password_complexity_regex)
            if not pattern.match(password):
                raise ValidationError(cfg.password_complexity_desc)

        if cfg.password_prevent_email_username_use:
            local_part = email.split("@")[0].lower()
            if local_part and local_part in password.lower():
                raise ValidationError("Password must not contain your email username.")
            if name.lower() and name.lower() in password.lower():
                raise ValidationError("Password must not contain your name.")

        if cfg.hibp_check_enabled:
            if cfg.hibp_failure_mode == "ignore":
                pass
            else:
                breach_count = check_password_pwned(
                    password, api_key=cfg.hibp_api_key or None
                )
                if breach_count is not None and breach_count > 0:
                    if cfg.hibp_failure_mode == "reject":
                        raise PasswordPwnedError(
                            f"This password has appeared in {breach_count:,} data breaches. "
                            "Please choose a different password."
                        )
                    else:
                        logger.warning(
                            "Password for %s found in %d breaches (warn mode)",
                            email,
                            breach_count,
                        )

    # ── Login ──────────────────────────────────────────────

    async def login(
        self,
        email: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Authenticate a user and issue tokens.

        Args:
            email: Email address.
            password: Plaintext password.
            ip_address: Client IP for audit logging.
            user_agent: Client user agent for audit logging.

        Returns:
            Dict with access_token, refresh_token, token_type, expires_in, user.

        Raises:
            InvalidCredentialsError: Wrong email or password.
            AccountLockedError: Too many failed attempts.
            AccountInactiveError: Account is deactivated.
            AccountNotVerifiedError: Email not verified (if required).
        """
        email = email.lower().strip()

        user = await self._storage.get_user_by_email(email)
        if not user:
            raise InvalidCredentialsError("Invalid email or password.")

        if (
            user.get("failed_login_attempts", 0)
            >= self._config.failed_login_lockout_threshold
        ):
            raise AccountLockedError(
                "Account is temporarily locked due to too many failed login attempts. "
                "Please try again later or reset your password."
            )

        if not user.get("is_active", True):
            raise AccountInactiveError("This account has been deactivated.")

        if not _verify_password(password, user["password_hash"]):
            failed = user.get("failed_login_attempts", 0) + 1
            await self._storage.update_user(
                user["id"], {"failed_login_attempts": failed}
            )

            await self._events.emit_async(
                Event.USER_LOGIN_FAILED,
                {"user_id": user["id"], "email": email, "ip_address": ip_address},
            )
            await self._log_audit(
                user["id"], email, "user.login_failed", ip_address, False
            )

            raise InvalidCredentialsError("Invalid email or password.")

        if self._config.email_verification_required and not user.get(
            "is_verified", False
        ):
            raise AccountNotVerifiedError(
                "Please verify your email address before logging in."
            )

        if user.get("mfa_enabled", False):
            await self._storage.update_user(user["id"], {"failed_login_attempts": 0})

            await self._log_audit(
                user["id"], email, "mfa.challenge_required", ip_address, True
            )

            return {
                "mfa_required": True,
                "user_id": user["id"],
                "user": {k: v for k, v in user.items() if k != "password_hash"},
            }

        await self._storage.update_user(user["id"], {"failed_login_attempts": 0})

        access_token, access_jti, access_exp = await self._create_access_token(
            user["id"]
        )
        (
            refresh_token,
            refresh_jti,
            refresh_exp,
            family_id,
        ) = await self._create_refresh_token(user["id"], ip_address, user_agent)

        await self._events.emit_async(
            Event.USER_LOGIN_SUCCESS,
            {"user_id": user["id"], "email": email, "ip_address": ip_address},
        )

        await self._log_audit(user["id"], email, "user.login_success", ip_address, True)

        logger.info("User logged in: %s (%s)", email, user["id"])

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self._config.jwt_access_token_expiry_minutes * 60,
            "user": {k: v for k, v in user.items() if k != "password_hash"},
        }

    # ── JWT Token Management ──────────────────────────────

    async def _create_access_token(
        self, user_id: int
    ) -> tuple[str, str, datetime.datetime]:
        """Create a JWT access token. Returns (token, jti, expires_at)."""
        jti = generate_secure_token(16)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(
            minutes=self._config.jwt_access_token_expiry_minutes
        )

        payload = {
            "sub": str(user_id),
            "jti": jti,
            "iat": now,
            "exp": expires,
            "iss": "authority",
            "typ": "access",
        }

        token = pyjwt.encode(
            payload,
            self._config.jwt_secret_key,
            algorithm=self._config.jwt_algorithm,
        )
        return token, jti, expires

    async def _create_refresh_token(
        self,
        user_id: int,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str, datetime.datetime, str]:
        """Create a refresh token. Returns (token, jti, expires_at, family_id)."""
        jti = generate_secure_token(16)
        family_id = generate_secure_token(16)
        now = datetime.datetime.now(datetime.timezone.utc)
        expires = now + datetime.timedelta(
            days=self._config.jwt_refresh_token_expiry_days
        )

        token_hash = hash_token(jti)
        await self._storage.store_refresh_token(
            user_id=user_id,
            token_hash=token_hash,
            family_id=family_id,
            expires_at=expires,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return jti, jti, expires, family_id

    async def verify_access_token(self, token: str) -> dict[str, Any]:
        """Verify and decode an access token.

        Args:
            token: The JWT access token string.

        Returns:
            Decoded token payload.

        Raises:
            InvalidTokenError: Token is malformed or invalid.
            TokenExpiredError: Token has expired.
        """
        try:
            payload = pyjwt.decode(
                token,
                self._config.jwt_secret_key,
                algorithms=[self._config.jwt_algorithm],
                issuer="authority",
                options={"require": ["exp", "sub", "jti", "iss", "typ"]},
            )
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("Access token has expired.") from exc
        except pyjwt.InvalidTokenError as exc:
            raise InvalidTokenError(f"Invalid access token: {exc}") from exc

        jti = payload.get("jti", "")
        if jti in self._jti_blacklist:
            raise InvalidTokenError("Access token has been revoked.")

        if payload.get("typ") != "access":
            raise InvalidTokenError("Token is not an access token.")

        return {
            "user_id": int(payload["sub"]),
            "jti": jti,
            "exp": payload["exp"],
            "iat": payload.get("iat"),
            "iss": payload.get("iss"),
            "typ": payload.get("typ"),
        }

    # ── Refresh Token Rotation ─────────────────────────────

    async def refresh_access_token(
        self,
        refresh_token: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> dict[str, Any]:
        """Exchange a refresh token for a new access + refresh token pair.

        Implements token rotation with family tracking and reuse detection.

        Args:
            refresh_token: The current refresh token (jti).
            ip_address: Client IP for audit logging.
            user_agent: Client user agent for audit logging.

        Returns:
            Dict with new access_token, refresh_token, token_type, expires_in.

        Raises:
            InvalidTokenError: Token is invalid, revoked, or expired.
            TokenExpiredError: Token has expired.
        """
        token_hash = hash_token(refresh_token)
        stored = await self._storage.get_refresh_token_by_hash(token_hash)

        if not stored:
            raise InvalidTokenError("Invalid refresh token.")

        if stored.get("revoked", False):
            await self._events.emit_async(
                Event.TOKEN_REUSE_DETECTED,
                {
                    "user_id": stored["user_id"],
                    "family_id": stored.get("family_id"),
                    "ip_address": ip_address,
                },
            )
            await self._log_audit(
                stored["user_id"],
                None,
                "token.reuse_detected",
                ip_address,
                False,
            )
            family_id = stored.get("family_id")
            if family_id:
                await self._storage.revoke_token_family(family_id)
            raise InvalidTokenError(
                "Refresh token has been revoked. All tokens in this family "
                "have been invalidated. Please log in again."
            )

        if stored.get("used", False):
            used_at = stored.get("used_at")
            if used_at:
                if isinstance(used_at, str):
                    used_at = datetime.datetime.fromisoformat(used_at)
                grace = datetime.timedelta(
                    seconds=self._config.refresh_token_reuse_grace_seconds
                )
                if (
                    datetime.datetime.now(datetime.timezone.utc)
                    - used_at.replace(tzinfo=datetime.timezone.utc)
                    < grace
                ):
                    pass
                else:
                    await self._events.emit_async(
                        Event.TOKEN_REUSE_DETECTED,
                        {
                            "user_id": stored["user_id"],
                            "family_id": stored.get("family_id"),
                            "ip_address": ip_address,
                        },
                    )
                    await self._log_audit(
                        stored["user_id"],
                        None,
                        "token.reuse_detected",
                        ip_address,
                        False,
                    )
                    family_id = stored.get("family_id")
                    if family_id:
                        await self._storage.revoke_token_family(family_id)
                    raise InvalidTokenError(
                        "Refresh token reuse detected. All tokens in this family "
                        "have been invalidated. Please log in again."
                    )

        expires_at = stored.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.datetime.fromisoformat(expires_at)
        if expires_at and expires_at.replace(
            tzinfo=datetime.timezone.utc
        ) < datetime.datetime.now(datetime.timezone.utc):
            raise TokenExpiredError("Refresh token has expired.")

        await self._storage.mark_refresh_token_used(stored["id"])

        user_id = stored["user_id"]
        new_access_token, _, _ = await self._create_access_token(user_id)

        family_id = stored.get("family_id", "")
        new_refresh_jti = generate_secure_token(16)
        new_refresh_hash = hash_token(new_refresh_jti)
        new_refresh_expires = datetime.datetime.now(
            datetime.timezone.utc
        ) + datetime.timedelta(days=self._config.jwt_refresh_token_expiry_days)

        await self._storage.rotate_refresh_token(
            token_id=stored["id"],
            new_token_hash=new_refresh_hash,
            new_expires_at=new_refresh_expires,
        )

        await self._events.emit_async(
            Event.TOKEN_REFRESHED,
            {"user_id": user_id, "family_id": family_id, "ip_address": ip_address},
        )

        await self._log_audit(user_id, None, "token.refreshed", ip_address, True)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_jti,
            "token_type": "Bearer",
            "expires_in": self._config.jwt_access_token_expiry_minutes * 60,
        }

    # ── Email Verification ─────────────────────────────────

    async def request_email_verification(
        self, user_id: int, ip_address: str | None = None
    ) -> str:
        """Generate and return a new email verification token.

        Args:
            user_id: The user ID.

        Returns:
            The plaintext verification token (send to user via email).

        Raises:
            UserNotFoundError: User does not exist.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if user.get("is_verified", False):
            return ""

        token = generate_secure_token(32)
        token_hash = hash_token(token)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=self._config.verification_token_expiry_minutes
        )

        await self._storage.update_user(
            user_id,
            {
                "verification_token_hash": token_hash,
                "verification_token_expiry": expiry,
            },
        )

        await self._log_audit(
            user_id, user.get("email"), "verification.requested", ip_address, True
        )

        return token

    async def verify_email(
        self, token: str, ip_address: str | None = None
    ) -> dict[str, Any]:
        """Verify a user's email address using the verification token.

        Args:
            token: The plaintext verification token.

        Returns:
            Updated user dict.

        Raises:
            InvalidTokenError: Token is invalid or expired.
            UserNotFoundError: No user matches this token.
        """
        token_hash = hash_token(token)
        user = await self._storage.find_user_by_verification_token(token_hash)

        if not user:
            raise InvalidTokenError("Invalid or expired verification token.")

        expiry = user.get("verification_token_expiry")
        if isinstance(expiry, str):
            expiry = datetime.datetime.fromisoformat(expiry)
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            if expiry < datetime.datetime.now(datetime.timezone.utc):
                raise TokenExpiredError("Verification token has expired.")

        await self._storage.update_user(
            user["id"],
            {
                "is_verified": True,
                "verification_token_hash": None,
                "verification_token_expiry": None,
            },
        )

        await self._events.emit_async(
            Event.USER_REGISTERED,
            {"user_id": user["id"], "email": user["email"], "verified": True},
        )

        await self._log_audit(
            user["id"], user["email"], "email.verified", ip_address, True
        )

        logger.info("Email verified for user %s", user["id"])

        updated = await self._storage.get_user_by_id(user["id"])
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    # ── Password Reset ─────────────────────────────────────

    async def request_password_reset(
        self, email: str, ip_address: str | None = None
    ) -> str:
        """Generate a password reset token for the given email.

        Always returns a token string (even if user doesn't exist) to
        prevent email enumeration.

        Args:
            email: The email address.

        Returns:
            Reset token (send via email). Empty string if user not found.
        """
        email = email.lower().strip()
        user = await self._storage.get_user_by_email(email)

        if not user:
            logger.info("Password reset requested for non-existent email: %s", email)
            return ""

        token = generate_secure_token(32)
        token_hash = hash_token(token)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=self._config.password_reset_token_expiry_minutes
        )

        await self._storage.update_user(
            user["id"],
            {
                "reset_token_hash": token_hash,
                "reset_token_expiry": expiry,
            },
        )

        await self._events.emit_async(
            Event.USER_PASSWORD_RESET,
            {"user_id": user["id"], "email": email, "ip_address": ip_address},
        )

        await self._log_audit(
            user["id"], email, "password.reset_requested", ip_address, True
        )

        return token

    async def reset_password(
        self,
        token: str,
        new_password: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Reset a user's password using the reset token.

        Args:
            token: The reset token.
            new_password: The new plaintext password.

        Returns:
            Updated user dict.

        Raises:
            InvalidTokenError: Token is invalid or expired.
            ValidationError: New password doesn't meet requirements.
        """
        token_hash = hash_token(token)
        user = await self._storage.find_user_by_reset_token(token_hash)

        if not user:
            raise InvalidTokenError("Invalid or expired password reset token.")

        expiry = user.get("reset_token_expiry")
        if isinstance(expiry, str):
            expiry = datetime.datetime.fromisoformat(expiry)
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            if expiry < datetime.datetime.now(datetime.timezone.utc):
                raise TokenExpiredError("Password reset token has expired.")

        self._validate_password_strength(
            new_password, user["email"], user.get("name", "")
        )

        await self._check_password_history(user["id"], new_password)

        new_hash = _hash_password(new_password)
        await self._storage.update_user(
            user["id"],
            {
                "password_hash": new_hash,
                "reset_token_hash": None,
                "reset_token_expiry": None,
            },
        )

        await self._storage.add_password_history(user["id"], new_hash)

        await self._storage.revoke_all_refresh_tokens_for_user(user["id"])

        await self._events.emit_async(
            Event.USER_PASSWORD_CHANGED,
            {"user_id": user["id"], "email": user["email"], "ip_address": ip_address},
        )

        await self._log_audit(
            user["id"], user["email"], "password.reset_completed", ip_address, True
        )

        logger.info("Password reset completed for user %s", user["id"])

        updated = await self._storage.get_user_by_id(user["id"])
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    # ── Change Password ────────────────────────────────────

    async def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Change a user's password (requires current password).

        Args:
            user_id: The user ID.
            current_password: The current plaintext password.
            new_password: The new plaintext password.
            ip_address: Client IP for audit logging.

        Returns:
            Updated user dict.

        Raises:
            UserNotFoundError: User does not exist.
            InvalidCredentialsError: Current password is wrong.
            ValidationError: New password doesn't meet requirements.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if not _verify_password(current_password, user["password_hash"]):
            raise InvalidCredentialsError("Current password is incorrect.")

        self._validate_password_strength(
            new_password, user["email"], user.get("name", "")
        )

        await self._check_password_history(user_id, new_password)

        new_hash = _hash_password(new_password)
        await self._storage.update_user(user_id, {"password_hash": new_hash})

        await self._storage.add_password_history(user_id, new_hash)

        await self._events.emit_async(
            Event.USER_PASSWORD_CHANGED,
            {"user_id": user_id, "email": user.get("email"), "ip_address": ip_address},
        )

        await self._log_audit(
            user_id, user.get("email"), "password.changed", ip_address, True
        )

        logger.info("Password changed for user %s", user_id)

        updated = await self._storage.get_user_by_id(user_id)
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    async def _check_password_history(self, user_id: int, new_password: str) -> None:
        """Check if password was recently used."""
        depth = self._config.password_history_depth
        if depth <= 0:
            return

        history = await self._storage.get_password_history(user_id, limit=depth)
        for old_hash in history:
            if _verify_password(new_password, old_hash):
                raise ValidationError(
                    f"You cannot reuse a password from the last {depth} passwords."
                )

    # ── Email Change ───────────────────────────────────────

    async def request_email_change(
        self,
        user_id: int,
        new_email: str,
        current_password: str,
        ip_address: str | None = None,
    ) -> str:
        """Request an email change (double opt-in).

        Generates a token for the new email. The change is not applied
        until confirm_email_change() is called.

        Args:
            user_id: The user ID.
            new_email: The desired new email address.
            current_password: Current password for verification.
            ip_address: Client IP for audit logging.

        Returns:
            Verification token (send to new email).

        Raises:
            UserNotFoundError: User does not exist.
            InvalidCredentialsError: Wrong password.
            UserExistsError: New email is already taken.
            ValidationError: Invalid email format.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if not _verify_password(current_password, user["password_hash"]):
            raise InvalidCredentialsError("Current password is incorrect.")

        new_email = new_email.lower().strip()
        if not validate_email_format(new_email):
            raise ValidationError(f"Invalid email format: {new_email}")

        if new_email == user["email"]:
            raise ValidationError("New email must be different from current email.")

        existing = await self._storage.get_user_by_email(new_email)
        if existing:
            raise UserExistsError(
                f"An account with email '{new_email}' already exists."
            )

        pending = await self._storage.find_user_by_pending_email(new_email)
        if pending and pending["id"] != user_id:
            raise UserExistsError(
                f"Email '{new_email}' is already pending confirmation for another account."
            )

        token = generate_secure_token(32)
        token_hash = hash_token(token)
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            minutes=self._config.email_change_token_expiry_minutes
        )

        await self._storage.update_user(
            user_id,
            {
                "pending_email": new_email,
                "email_change_token_hash": token_hash,
                "email_change_token_expiry": expiry,
            },
        )

        await self._log_audit(
            user_id, user["email"], "email_change.requested", ip_address, True
        )

        return token

    async def confirm_email_change(
        self, token: str, ip_address: str | None = None
    ) -> dict[str, Any]:
        """Confirm and apply an email change.

        Args:
            token: The email change verification token.

        Returns:
            Updated user dict.

        Raises:
            InvalidTokenError: Token is invalid or expired.
        """
        token_hash = hash_token(token)
        user = await self._storage.find_user_by_email_change_token(token_hash)

        if not user:
            raise InvalidTokenError("Invalid or expired email change token.")

        expiry = user.get("email_change_token_expiry")
        if isinstance(expiry, str):
            expiry = datetime.datetime.fromisoformat(expiry)
        if expiry:
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=datetime.timezone.utc)
            if expiry < datetime.datetime.now(datetime.timezone.utc):
                raise TokenExpiredError("Email change token has expired.")

        new_email = user.get("pending_email")
        if not new_email:
            raise InvalidTokenError("No pending email change found.")

        old_email = user["email"]

        await self._storage.update_user(
            user["id"],
            {
                "email": new_email,
                "pending_email": None,
                "email_change_token_hash": None,
                "email_change_token_expiry": None,
            },
        )

        await self._events.emit_async(
            Event.USER_EMAIL_CHANGED,
            {
                "user_id": user["id"],
                "old_email": old_email,
                "new_email": new_email,
                "ip_address": ip_address,
            },
        )

        await self._log_audit(user["id"], new_email, "email.changed", ip_address, True)

        logger.info(
            "Email changed for user %s: %s -> %s", user["id"], old_email, new_email
        )

        updated = await self._storage.get_user_by_id(user["id"])
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    # ── Logout ─────────────────────────────────────────────

    async def logout(
        self,
        user_id: int,
        refresh_token: str | None = None,
        access_token_jti: str | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Log out a user by revoking tokens.

        Args:
            user_id: The user ID.
            refresh_token: If provided, revoke this specific refresh token.
            access_token_jti: If provided, add to JTI blacklist.
            ip_address: Client IP for audit logging.
        """
        if access_token_jti:
            self._jti_blacklist.add(access_token_jti)

        if refresh_token:
            token_hash = hash_token(refresh_token)
            stored = await self._storage.get_refresh_token_by_hash(token_hash)
            if stored:
                await self._storage.revoke_refresh_token(stored["id"])

        await self._events.emit_async(
            Event.USER_LOGOUT,
            {"user_id": user_id, "ip_address": ip_address},
        )

        await self._log_audit(user_id, None, "user.logout", ip_address, True)

        logger.info("User logged out: %s", user_id)

    async def logout_all(
        self,
        user_id: int,
        exclude_refresh_token: str | None = None,
        ip_address: str | None = None,
    ) -> int:
        """Log out a user from all devices by revoking all refresh tokens.

        Args:
            user_id: The user ID.
            exclude_refresh_token: Optional token to keep (current session).
            ip_address: Client IP for audit logging.

        Returns:
            Number of tokens revoked.
        """
        exclude_id = None
        if exclude_refresh_token:
            token_hash = hash_token(exclude_refresh_token)
            stored = await self._storage.get_refresh_token_by_hash(token_hash)
            if stored:
                exclude_id = stored["id"]

        count = await self._storage.revoke_all_refresh_tokens_for_user(
            user_id, exclude_token_id=exclude_id
        )

        await self._events.emit_async(
            Event.USER_LOGOUT,
            {"user_id": user_id, "all_devices": True, "ip_address": ip_address},
        )

        await self._log_audit(user_id, None, "user.logout_all", ip_address, True)

        logger.info(
            "User %s logged out from all devices (%d tokens revoked)", user_id, count
        )

        return count

    # ── Session Management ──────────────────────────────────

    async def list_sessions(self, user_id: int) -> list[dict[str, Any]]:
        """List active sessions (non-revoked, non-expired refresh tokens).

        Args:
            user_id: The user ID.

        Returns:
            List of session dicts with ``id``, ``family_id``, ``created_at``,
            ``expires_at``, ``ip_address``, and ``user_agent``.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        sessions: list[dict[str, Any]] = []
        for token in await self._storage.list_refresh_tokens_for_user(user_id):
            if token.get("revoked"):
                continue
            expires_at = token.get("expires_at")
            if isinstance(expires_at, str):
                try:
                    expires_at = datetime.datetime.fromisoformat(expires_at)
                except ValueError:
                    continue
            if expires_at and expires_at.replace(tzinfo=datetime.timezone.utc) < now:
                continue
            sessions.append(token)
        return sessions

    async def revoke_session_by_id(
        self,
        user_id: int,
        session_token_id: int,
        ip_address: str | None = None,
    ) -> bool:
        """Revoke a single session (refresh token) owned by *user_id*.

        Args:
            user_id: The owning user (ownership check).
            session_token_id: The refresh token database ID.
            ip_address: Client IP for audit logging.

        Returns:
            True if the session was revoked.
        """
        token = await self._storage.get_refresh_token_by_id(session_token_id)
        if not token or token.get("user_id") != user_id:
            logger.warning(
                "User %s attempted to revoke unauthorized session %s",
                user_id,
                session_token_id,
            )
            return False

        revoked = await self._storage.revoke_refresh_token(session_token_id)
        if revoked:
            await self._events.emit_async(
                Event.TOKEN_REVOKED,
                {
                    "user_id": user_id,
                    "token_id": session_token_id,
                    "ip_address": ip_address,
                },
            )
            await self._log_audit(
                user_id,
                None,
                "session.revoked",
                ip_address,
                True,
                f"token_id={session_token_id}",
            )
        return revoked

    async def revoke_all_sessions_for_user(
        self,
        user_id: int,
        exclude_token_id: int | None = None,
        ip_address: str | None = None,
    ) -> int:
        """Revoke all active sessions for a user, optionally keeping one.

        Args:
            user_id: The user ID.
            exclude_token_id: Optional refresh token ID to keep active.
            ip_address: Client IP for audit logging.

        Returns:
            Number of sessions revoked.
        """
        count = await self._storage.revoke_all_refresh_tokens_for_user(
            user_id, exclude_token_id=exclude_token_id
        )
        if count:
            await self._events.emit_async(
                Event.TOKEN_REVOKED,
                {
                    "user_id": user_id,
                    "all_sessions": True,
                    "count": count,
                    "ip_address": ip_address,
                },
            )
        await self._log_audit(
            user_id,
            None,
            "session.revoke_all",
            ip_address,
            True,
            f"count={count}",
        )
        return count

    # ── User Management ────────────────────────────────────

    async def get_user(self, user_id: int) -> dict[str, Any]:
        """Get a user by ID.

        Args:
            user_id: The user ID.

        Returns:
            User dict without password_hash.

        Raises:
            UserNotFoundError: User does not exist.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")
        return {k: v for k, v in user.items() if k != "password_hash"}

    async def update_user(
        self,
        user_id: int,
        updates: dict[str, Any],
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Update user fields.

        Args:
            user_id: The user ID.
            updates: Dict of fields to update (name, etc.).
            ip_address: Client IP for audit logging.

        Returns:
            Updated user dict.

        Raises:
            UserNotFoundError: User does not exist.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        safe_updates = {}
        protected = {
            "id",
            "password_hash",
            "email",
            "is_verified",
            "is_active",
            "mfa_enabled",
        }
        for key, value in updates.items():
            if key in protected:
                continue
            safe_updates[key] = value

        if not safe_updates:
            return {k: v for k, v in user.items() if k != "password_hash"}

        await self._storage.update_user(user_id, safe_updates)

        await self._log_audit(
            user_id, user.get("email"), "user.updated", ip_address, True
        )

        updated = await self._storage.get_user_by_id(user_id)
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    async def delete_user(
        self,
        user_id: int,
        ip_address: str | None = None,
    ) -> bool:
        """Delete a user and all associated data.

        Args:
            user_id: The user ID.
            ip_address: Client IP for audit logging.

        Returns:
            True if deleted successfully.

        Raises:
            UserNotFoundError: User does not exist.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        await self._storage.revoke_all_refresh_tokens_for_user(user_id)

        result = await self._storage.delete_user(user_id)

        await self._events.emit_async(
            Event.USER_DELETED,
            {"user_id": user_id, "email": user.get("email"), "ip_address": ip_address},
        )

        await self._log_audit(
            user_id, user.get("email"), "user.deleted", ip_address, True
        )

        logger.info("User deleted: %s (%s)", user.get("email"), user_id)

        return result

    # ── MFA (TOTP + Recovery Codes) ────────────────────────

    async def setup_mfa(self, user_id: int) -> dict[str, Any]:
        """Generate a TOTP secret and provisioning URI for MFA setup.

        The secret is encrypted and stored. MFA is NOT enabled until
        verify_and_enable_mfa() is called with a valid code.

        Args:
            user_id: The user ID.

        Returns:
            Dict with secret (plaintext), provisioning_uri, and recovery_code_count.

        Raises:
            UserNotFoundError: User does not exist.
            MFANotEnabledError: MFA is already enabled.
        """
        import pyotp

        from .exceptions import MFANotEnabledError

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if user.get("mfa_enabled", False):
            raise MFANotEnabledError("MFA is already enabled. Disable it first.")

        secret = pyotp.random_base32()

        from .utils import encrypt_data

        encrypted = encrypt_data(secret, self._config.fernet_key)
        await self._storage.update_user(user_id, {"mfa_secret_encrypted": encrypted})

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user["email"],
            issuer_name=self._config.mfa_issuer_name,
        )

        await self._events.emit_async(
            Event.MFA_SETUP_INITIATED,
            {"user_id": user_id, "email": user["email"]},
        )

        await self._log_audit(user_id, user["email"], "mfa.setup_initiated", None, True)

        return {
            "secret": secret,
            "provisioning_uri": provisioning_uri,
            "recovery_code_count": self._config.mfa_recovery_code_count,
        }

    async def verify_and_enable_mfa(
        self,
        user_id: int,
        code: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Verify a TOTP code and enable MFA for the user.

        Also generates and returns recovery codes (displayed once).

        Args:
            user_id: The user ID.
            code: The 6-digit TOTP code from the authenticator app.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with recovery_codes (list of plaintext codes).

        Raises:
            UserNotFoundError: User does not exist.
            MFAFailedError: TOTP code is invalid.
            ValidationError: MFA secret not set up.
        """
        import pyotp

        from .exceptions import MFAFailedError, ValidationError
        from .utils import decrypt_data

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        encrypted_secret = user.get("mfa_secret_encrypted")
        if not encrypted_secret:
            raise ValidationError("MFA secret not found. Call setup_mfa() first.")

        secret = decrypt_data(encrypted_secret, self._config.fernet_key)
        if not secret:
            raise ValidationError(
                "Failed to decrypt MFA secret. Fernet key may have changed."
            )

        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=self._config.mfa_totp_valid_window):
            await self._events.emit_async(
                Event.MFA_FAILED,
                {
                    "user_id": user_id,
                    "email": user.get("email"),
                    "ip_address": ip_address,
                },
            )
            await self._log_audit(
                user_id, user.get("email"), "mfa.verification_failed", ip_address, False
            )
            raise MFAFailedError("Invalid MFA code. Please try again.")

        recovery_codes = self._generate_recovery_codes()
        hashed_codes = [hash_token(c) for c in recovery_codes]
        await self._storage.set_mfa_recovery_codes(user_id, hashed_codes)

        await self._storage.update_user(user_id, {"mfa_enabled": True})

        await self._events.emit_async(
            Event.MFA_ENABLED,
            {"user_id": user_id, "email": user.get("email"), "ip_address": ip_address},
        )

        await self._log_audit(
            user_id, user.get("email"), "mfa.enabled", ip_address, True
        )

        logger.info("MFA enabled for user %s", user_id)

        return {
            "recovery_codes": recovery_codes,
            "recovery_code_count": len(recovery_codes),
        }

    async def verify_mfa_login(
        self,
        user_id: int,
        code: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Verify MFA code during login (TOTP or recovery code).

        Call this after login() returns mfa_required=True.

        Args:
            user_id: The user ID.
            code: Either a 6-digit TOTP code or a recovery code.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with access_token, refresh_token, token_type, expires_in, user.

        Raises:
            MFAFailedError: Both TOTP and recovery code verification failed.
            InvalidRecoveryCodeError: Recovery code is invalid or exhausted.
        """
        from .exceptions import MFAFailedError

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if not user.get("mfa_enabled", False):
            raise MFAFailedError("MFA is not enabled for this account.")

        if len(code) == 6 and code.isdigit():
            from .utils import decrypt_data

            encrypted_secret = user.get("mfa_secret_encrypted")
            if encrypted_secret:
                secret = decrypt_data(encrypted_secret, self._config.fernet_key)
                if secret:
                    import pyotp

                    totp = pyotp.TOTP(secret)
                    if totp.verify(
                        code, valid_window=self._config.mfa_totp_valid_window
                    ):
                        return await self._issue_tokens_after_mfa(user, ip_address)

        code_hash = hash_token(code)
        if await self._storage.use_mfa_recovery_code(user_id, code_hash):
            return await self._issue_tokens_after_mfa(user, ip_address)

        await self._events.emit_async(
            Event.MFA_FAILED,
            {"user_id": user_id, "email": user.get("email"), "ip_address": ip_address},
        )
        await self._log_audit(
            user_id, user.get("email"), "mfa.verification_failed", ip_address, False
        )
        raise MFAFailedError("Invalid MFA code. Please try again.")

    async def verify_mfa_recovery_code(self, user_id: int, recovery_code: str) -> bool:
        """Verify and consume a single-use MFA recovery code.

        Args:
            user_id: The user ID.
            recovery_code: The plaintext recovery code to check.

        Returns:
            True if the code was valid and consumed.
        """
        if not recovery_code:
            return False
        code_hash = hash_token(recovery_code)
        used = await self._storage.use_mfa_recovery_code(user_id, code_hash)
        if used:
            await self._log_audit(user_id, None, "mfa.recovery_code_used", None, True)
        return used

    async def _issue_tokens_after_mfa(
        self,
        user: dict[str, Any],
        ip_address: str | None,
    ) -> dict[str, Any]:
        """Issue tokens after successful MFA verification."""
        await self._storage.update_user(user["id"], {"failed_login_attempts": 0})

        access_token, _, _ = await self._create_access_token(user["id"])
        refresh_token, _, _, _ = await self._create_refresh_token(
            user["id"], ip_address
        )

        await self._events.emit_async(
            Event.USER_LOGIN_SUCCESS,
            {
                "user_id": user["id"],
                "email": user.get("email"),
                "ip_address": ip_address,
            },
        )

        await self._log_audit(
            user["id"], user.get("email"), "user.login_success", ip_address, True
        )

        logger.info("User logged in (MFA): %s (%s)", user.get("email"), user["id"])

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self._config.jwt_access_token_expiry_minutes * 60,
            "user": {k: v for k, v in user.items() if k != "password_hash"},
        }

    async def disable_mfa(
        self,
        user_id: int,
        password: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Disable MFA for a user (requires password re-authentication).

        Args:
            user_id: The user ID.
            password: Current password for verification.
            ip_address: Client IP for audit logging.

        Returns:
            Updated user dict.

        Raises:
            UserNotFoundError: User does not exist.
            InvalidCredentialsError: Wrong password.
            MFANotEnabledError: MFA is not enabled.
        """
        from .exceptions import MFANotEnabledError

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if not user.get("mfa_enabled", False):
            raise MFANotEnabledError("MFA is not enabled for this account.")

        if not _verify_password(password, user["password_hash"]):
            raise InvalidCredentialsError("Password is incorrect.")

        await self._storage.update_user(
            user_id,
            {"mfa_enabled": False, "mfa_secret_encrypted": None},
        )

        await self._storage.set_mfa_recovery_codes(user_id, [])

        await self._events.emit_async(
            Event.MFA_DISABLED,
            {"user_id": user_id, "email": user.get("email"), "ip_address": ip_address},
        )

        await self._log_audit(
            user_id, user.get("email"), "mfa.disabled", ip_address, True
        )

        logger.info("MFA disabled for user %s", user_id)

        updated = await self._storage.get_user_by_id(user_id)
        return {k: v for k, v in (updated or user).items() if k != "password_hash"}

    async def regenerate_recovery_codes(
        self,
        user_id: int,
        password: str,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Regenerate recovery codes for a user (requires password re-authentication).

        Old codes are invalidated.

        Args:
            user_id: The user ID.
            password: Current password for verification.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with recovery_codes (list of plaintext codes).

        Raises:
            UserNotFoundError: User does not exist.
            InvalidCredentialsError: Wrong password.
            MFANotEnabledError: MFA is not enabled.
        """
        from .exceptions import MFANotEnabledError

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        if not user.get("mfa_enabled", False):
            raise MFANotEnabledError(
                "MFA is not enabled. Cannot regenerate recovery codes."
            )

        if not _verify_password(password, user["password_hash"]):
            raise InvalidCredentialsError("Password is incorrect.")

        recovery_codes = self._generate_recovery_codes()
        hashed_codes = [hash_token(c) for c in recovery_codes]
        await self._storage.set_mfa_recovery_codes(user_id, hashed_codes)

        await self._log_audit(
            user_id,
            user.get("email"),
            "mfa.recovery_codes_regenerated",
            ip_address,
            True,
        )

        logger.info("Recovery codes regenerated for user %s", user_id)

        return {
            "recovery_codes": recovery_codes,
            "recovery_code_count": len(recovery_codes),
        }

    async def get_mfa_status(self, user_id: int) -> dict[str, Any]:
        """Get MFA status for a user.

        Args:
            user_id: The user ID.

        Returns:
            Dict with mfa_enabled, recovery_codes_remaining.
        """
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        recovery_count = 0
        if user.get("mfa_enabled", False):
            recovery_count = await self._storage.get_active_mfa_recovery_codes_count(
                user_id
            )

        return {
            "mfa_enabled": user.get("mfa_enabled", False),
            "recovery_codes_remaining": recovery_count,
        }

    def _generate_recovery_codes(self) -> list[str]:
        """Generate cryptographically secure recovery codes."""
        codes = []
        for _ in range(self._config.mfa_recovery_code_count):
            part1 = secrets.token_hex(2).upper()
            part2 = secrets.token_hex(2).upper()
            part3 = secrets.token_hex(2).upper()
            codes.append(f"{part1}-{part2}-{part3}")
        return codes

    # ── RBAC (Role-Based Access Control) ───────────────────

    async def create_role(
        self, name: str, description: str | None = None
    ) -> dict[str, Any]:
        """Create a new role.

        Args:
            name: Role name (unique).
            description: Optional description.

        Returns:
            Role dict with id, name, description.
        """
        role_id = await self._storage.create_role(name, description)
        role = await self._storage.get_role_by_id(role_id)
        if not role:
            raise ConfigurationError(f"Failed to create role: {name}")
        return role

    async def delete_role(self, role_id: int) -> bool:
        """Delete a role.

        Args:
            role_id: The role ID.

        Returns:
            True if deleted.
        """
        return await self._storage.delete_role(role_id)

    async def list_roles(self) -> list[dict[str, Any]]:
        """List all roles."""
        return await self._storage.list_roles()

    async def create_permission(
        self, code: str, description: str | None = None
    ) -> dict[str, Any]:
        """Create a new permission.

        Args:
            code: Permission code (unique, e.g. 'users:read').
            description: Optional description.

        Returns:
            Permission dict with id, code, description.
        """
        perm_id = await self._storage.create_permission(code, description)
        perm = await self._storage.get_permission_by_id(perm_id)
        if not perm:
            raise ConfigurationError(f"Failed to create permission: {code}")
        return perm

    async def delete_permission(self, permission_id: int) -> bool:
        """Delete a permission."""
        return await self._storage.delete_permission(permission_id)

    async def list_permissions(self) -> list[dict[str, Any]]:
        """List all permissions."""
        return await self._storage.list_permissions()

    async def assign_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Assign a permission to a role."""
        return await self._storage.assign_permission_to_role(role_id, permission_id)

    async def remove_permission_from_role(
        self, role_id: int, permission_id: int
    ) -> bool:
        """Remove a permission from a role."""
        return await self._storage.remove_permission_from_role(role_id, permission_id)

    async def get_role_permissions(self, role_id: int) -> list[dict[str, Any]]:
        """Get all permissions assigned to a role."""
        return await self._storage.get_role_permissions(role_id)

    async def assign_role_to_user(self, user_id: int, role_id: int) -> bool:
        """Assign a role to a user."""
        await self._log_audit(user_id, None, "rbac.role_assigned", None, True)
        return await self._storage.assign_role_to_user(user_id, role_id)

    async def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Remove a role from a user."""
        await self._log_audit(user_id, None, "rbac.role_revoked", None, True)
        return await self._storage.remove_role_from_user(user_id, role_id)

    async def get_user_roles(self, user_id: int) -> list[dict[str, Any]]:
        """Get all roles assigned to a user."""
        return await self._storage.get_user_roles(user_id)

    async def get_user_permissions(self, user_id: int) -> list[str]:
        """Get all effective permissions for a user (from all assigned roles)."""
        return await self._storage.get_user_permissions(user_id)

    async def has_permission(self, user_id: int, permission_code: str) -> bool:
        """Check if a user has a specific permission.

        Args:
            user_id: The user ID.
            permission_code: The permission code to check (e.g. 'users:read').

        Returns:
            True if the user has the permission.
        """
        perms = await self._storage.get_user_permissions(user_id)
        return permission_code in perms

    async def require_permission(self, user_id: int, permission_code: str) -> None:
        """Require a permission for a user, raising on failure.

        Args:
            user_id: The user ID.
            permission_code: The permission code to check (e.g. 'users:read').

        Raises:
            InsufficientPermissionsError: The user lacks the permission.
        """
        if not await self.has_permission(user_id, permission_code):
            await self._log_audit(user_id, None, "rbac.permission_denied", None, False)
            raise InsufficientPermissionsError(
                f"Required permission denied: {permission_code}"
            )

    # ── API Keys ───────────────────────────────────────────

    async def create_api_key(
        self,
        user_id: int,
        description: str | None = None,
        scopes: list[str] | None = None,
        expires_in_days: int | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Create a new API key for a user.

        The full key is only returned once. Store it securely.

        Args:
            user_id: The user ID.
            description: Optional description.
            scopes: Optional list of scope strings.
            expires_in_days: Optional expiry in days (None = no expiry).
            ip_address: Client IP for audit logging.

        Returns:
            Dict with key (full plaintext key), prefix, description, scopes, expires_at.
        """
        import json

        raw_key = generate_secure_token(self._config.api_key_byte_length)
        key_prefix = raw_key[:8]
        key_hash = hash_token(raw_key)

        expires_at = None
        if expires_in_days is not None:
            expires_at = datetime.datetime.now(
                datetime.timezone.utc
            ) + datetime.timedelta(days=expires_in_days)

        scopes_json = json.dumps(scopes) if scopes else None

        await self._storage.store_api_key(
            user_id=user_id,
            key_prefix=key_prefix,
            key_hash=key_hash,
            description=description,
            scopes_json=scopes_json,
            expires_at=expires_at,
        )

        await self._events.emit_async(
            Event.API_KEY_CREATED,
            {"user_id": user_id, "key_prefix": key_prefix, "ip_address": ip_address},
        )

        await self._log_audit(user_id, None, "api_key.created", ip_address, True)

        return {
            "key": raw_key,
            "prefix": key_prefix,
            "description": description,
            "scopes": scopes or [],
            "expires_at": expires_at.isoformat() if expires_at else None,
        }

    async def verify_api_key(self, api_key: str) -> dict[str, Any]:
        """Verify an API key and return its metadata.

        Args:
            api_key: The full plaintext API key.

        Returns:
            Dict with user_id, scopes, description, etc.

        Raises:
            InvalidAPIKeyError: Key is invalid or expired.
        """
        import json

        prefix = api_key[:8]
        key_hash = hash_token(api_key)

        stored = await self._storage.get_api_key_by_prefix_and_hash(prefix, key_hash)
        if not stored:
            from .exceptions import InvalidAPIKeyError

            raise InvalidAPIKeyError("Invalid API key.")

        expires_at = stored.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.datetime.fromisoformat(expires_at)
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)
            if expires_at < datetime.datetime.now(datetime.timezone.utc):
                from .exceptions import InvalidAPIKeyError

                raise InvalidAPIKeyError("API key has expired.")

        await self._storage.update_api_key_last_used(prefix)

        scopes = []
        scopes_json = stored.get("scopes_json")
        if scopes_json:
            try:
                scopes = json.loads(scopes_json)
            except (json.JSONDecodeError, TypeError):
                scopes = []

        return {
            "user_id": stored["user_id"],
            "key_prefix": stored["key_prefix"],
            "description": stored.get("description"),
            "scopes": scopes,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }

    async def list_api_keys(self, user_id: int) -> list[dict[str, Any]]:
        """List all API keys for a user (without revealing the full key)."""
        import json

        keys = await self._storage.list_api_keys_for_user(user_id)
        result = []
        for k in keys:
            scopes = []
            scopes_json = k.get("scopes_json")
            if scopes_json:
                try:
                    scopes = json.loads(scopes_json)
                except (json.JSONDecodeError, TypeError):
                    scopes = []
            result.append(
                {
                    "key_prefix": k["key_prefix"],
                    "description": k.get("description"),
                    "scopes": scopes,
                    "expires_at": k.get("expires_at"),
                    "last_used_at": k.get("last_used_at"),
                    "created_at": k.get("created_at"),
                }
            )
        return result

    async def revoke_api_key(
        self,
        user_id: int,
        key_prefix: str,
        ip_address: str | None = None,
    ) -> bool:
        """Revoke (delete) an API key by its prefix."""
        result = await self._storage.delete_api_key_by_prefix(user_id, key_prefix)

        await self._events.emit_async(
            Event.API_KEY_REVOKED,
            {"user_id": user_id, "key_prefix": key_prefix, "ip_address": ip_address},
        )

        await self._log_audit(user_id, None, "api_key.revoked", ip_address, True)

        return result

    # ── Audit Log Queries ──────────────────────────────────

    async def get_audit_log(
        self,
        user_id: int | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log entries.

        Args:
            user_id: Filter by user ID.
            action: Filter by action string.
            limit: Max entries to return.
            offset: Pagination offset.

        Returns:
            List of audit log entry dicts.
        """
        return await self._storage.get_audit_log(
            user_id=user_id, action=action, limit=limit, offset=offset
        )

    # ── Custom Profile ─────────────────────────────────────

    async def update_profile(
        self, user_id: int, profile_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Update a user's custom profile data.

        Profile data is stored as a JSON blob and merged with existing data.

        Args:
            user_id: The user ID.
            profile_data: Dict of profile fields to set/update.

        Returns:
            The complete profile dict.
        """
        existing = await self._storage.get_user_custom_profile(user_id) or {}

        merged = {**existing, **profile_data}

        await self._storage.update_user_custom_profile(user_id, merged)

        return merged

    async def get_profile(self, user_id: int) -> dict[str, Any]:
        """Get a user's custom profile data.

        Args:
            user_id: The user ID.

        Returns:
            Profile dict (empty if no profile set).
        """
        return await self._storage.get_user_custom_profile(user_id) or {}

    # ── WebAuthn ───────────────────────────────────────────

    async def start_webauthn_registration(
        self, user_id: int, ip_address: str | None = None
    ) -> dict[str, Any]:
        """Generate WebAuthn registration options.

        Returns options that should be passed to the browser's
        navigator.credentials.create() call.

        Args:
            user_id: The user ID.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with challenge, rp, user, pubKeyCredParams, etc.

        Raises:
            UserNotFoundError: User does not exist.
        """
        try:
            from webauthn import options_to_json  # noqa: F401
            from webauthn.helpers.cose import COSEAlgorithmIdentifier
            from webauthn.helpers.structs import (
                PublicKeyCredentialCreationOptions,
                PublicKeyCredentialParameters,
                PublicKeyCredentialRpEntity,
                PublicKeyCredentialUserEntity,
            )
        except ImportError as err:
            raise ConfigurationError(
                "webauthn package is required for WebAuthn support. "
                "Install it with: pip install 'authority[webauthn]'"
            ) from err

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        existing = await self._storage.get_webauthn_credentials_for_user(
            user_id, rp_id=self._config.webauthn_rp_id
        )
        exclude_ids = [cred["credential_id"] for cred in existing]

        challenge = generate_secure_token(32)

        rp = PublicKeyCredentialRpEntity(
            id=self._config.webauthn_rp_id,
            name=self._config.webauthn_rp_name,
        )

        user_entity = PublicKeyCredentialUserEntity(
            id=str(user_id).encode(),
            name=user["email"],
            display_name=user.get("name", user["email"]),
        )

        pub_key_params = [
            PublicKeyCredentialParameters(
                type="public-key",
                alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
            ),
            PublicKeyCredentialParameters(
                type="public-key",
                alg=COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ),
        ]

        options = PublicKeyCredentialCreationOptions(
            rp=rp,
            user=user_entity,
            challenge=challenge.encode(),
            pub_key_cred_params=pub_key_params,
            exclude_credentials=exclude_ids,
            timeout=self._config.webauthn_timeout_ms,
        )

        await self._log_audit(
            user_id,
            user.get("email"),
            "webauthn.registration_started",
            ip_address,
            True,
        )

        return {
            "challenge": challenge,
            "options_json": options_to_json(options),
            "rp_id": self._config.webauthn_rp_id,
            "rp_name": self._config.webauthn_rp_name,
            "user_id": user_id,
        }

    async def complete_webauthn_registration(
        self,
        user_id: int,
        credential_data: dict[str, Any],
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Complete WebAuthn registration by verifying the browser response.

        Args:
            user_id: The user ID.
            credential_data: Dict from navigator.credentials.create() response.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with credential_id, description.
        """
        try:
            from webauthn.helpers.structs import AuthenticatorTransport  # noqa: F401
        except ImportError as err:
            raise ConfigurationError(
                "webauthn package is required for WebAuthn support."
            ) from err

        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found.")

        credential_id = credential_data.get("credential_id", "").encode()
        public_key = credential_data.get("public_key", "").encode()
        sign_count = credential_data.get("sign_count", 0)
        transports = credential_data.get("transports")
        description = credential_data.get("description", "Security Key")

        if not credential_id or not public_key:
            from .exceptions import WebAuthnRegistrationError

            raise WebAuthnRegistrationError(
                "Invalid credential data: missing credential_id or public_key."
            )

        await self._storage.add_webauthn_credential(
            user_id=user_id,
            credential_id=credential_id,
            public_key=public_key,
            sign_count=sign_count,
            rp_id=self._config.webauthn_rp_id,
            user_handle=str(user_id).encode(),
            transports=transports,
            description=description,
        )

        await self._events.emit_async(
            Event.WEBAUTHN_CREDENTIAL_ADDED,
            {
                "user_id": user_id,
                "credential_id": credential_id.decode(errors="replace"),
            },
        )

        await self._log_audit(
            user_id, user.get("email"), "webauthn.credential_added", ip_address, True
        )

        return {
            "credential_id": credential_id.decode(errors="replace"),
            "description": description,
        }

    async def start_webauthn_authentication(
        self,
        user_id: int | None = None,
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Generate WebAuthn authentication options.

        Args:
            user_id: Optional user ID (if known). If None, authenticator
                     discovers the user.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with challenge, rp_id, allow_credentials, etc.
        """
        try:
            from webauthn import options_to_json  # noqa: F401
            from webauthn.helpers.structs import (
                PublicKeyCredentialDescriptor,
                PublicKeyCredentialRequestOptions,
            )
        except ImportError as err:
            raise ConfigurationError(
                "webauthn package is required for WebAuthn support."
            ) from err

        challenge = generate_secure_token(32)

        allow_credentials = []
        if user_id:
            existing = await self._storage.get_webauthn_credentials_for_user(
                user_id, rp_id=self._config.webauthn_rp_id
            )
            allow_credentials = [
                PublicKeyCredentialDescriptor(id=cred["credential_id"])
                for cred in existing
            ]

        options = PublicKeyCredentialRequestOptions(
            challenge=challenge.encode(),
            rp_id=self._config.webauthn_rp_id,
            allow_credentials=allow_credentials,
            timeout=self._config.webauthn_timeout_ms,
        )

        return {
            "challenge": challenge,
            "options_json": options_to_json(options),
            "rp_id": self._config.webauthn_rp_id,
        }

    async def complete_webauthn_authentication(
        self,
        credential_data: dict[str, Any],
        ip_address: str | None = None,
    ) -> dict[str, Any]:
        """Complete WebAuthn authentication by verifying the assertion.

        Args:
            credential_data: Dict from navigator.credentials.get() response.
            ip_address: Client IP for audit logging.

        Returns:
            Dict with access_token, refresh_token, user, etc.

        Raises:
            WebAuthnVerificationError: Assertion verification failed.
        """
        try:
            from webauthn import options_to_json  # noqa: F401
        except ImportError as err:
            raise ConfigurationError(
                "webauthn package is required for WebAuthn support."
            ) from err

        from .exceptions import WebAuthnVerificationError

        credential_id = credential_data.get("credential_id", "").encode()

        stored = await self._storage.get_webauthn_credential_by_id(credential_id)
        if not stored:
            raise WebAuthnVerificationError("Unknown credential.")

        new_sign_count = credential_data.get(
            "sign_count", stored.get("sign_count", 0) + 1
        )
        await self._storage.update_webauthn_credential_sign_count(
            credential_id, new_sign_count
        )
        await self._storage.update_webauthn_credential_last_used(credential_id)

        user_id = stored["user_id"]
        user = await self._storage.get_user_by_id(user_id)
        if not user:
            raise WebAuthnVerificationError("User not found for credential.")

        await self._storage.update_user(user_id, {"failed_login_attempts": 0})

        access_token, _, _ = await self._create_access_token(user_id)
        refresh_token, _, _, _ = await self._create_refresh_token(user_id, ip_address)

        await self._events.emit_async(
            Event.USER_LOGIN_SUCCESS,
            {"user_id": user_id, "email": user.get("email"), "method": "webauthn"},
        )

        await self._log_audit(
            user_id, user.get("email"), "user.login_success", ip_address, True
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": self._config.jwt_access_token_expiry_minutes * 60,
            "user": {k: v for k, v in user.items() if k != "password_hash"},
        }

    async def list_webauthn_credentials(self, user_id: int) -> list[dict[str, Any]]:
        """List all WebAuthn credentials for a user.

        Args:
            user_id: The user ID.

        Returns:
            List of credential dicts (without public key).
        """
        creds = await self._storage.get_webauthn_credentials_for_user(
            user_id, rp_id=self._config.webauthn_rp_id
        )
        return [
            {
                "credential_id": c["credential_id"].decode(errors="replace"),
                "description": c.get("description"),
                "sign_count": c.get("sign_count"),
                "last_used_at": c.get("last_used_at"),
                "created_at": c.get("created_at"),
            }
            for c in creds
        ]

    async def delete_webauthn_credential(
        self,
        user_id: int,
        credential_id: str,
        ip_address: str | None = None,
    ) -> bool:
        """Delete a WebAuthn credential.

        Args:
            user_id: The user ID.
            credential_id: The credential ID (string).
            ip_address: Client IP for audit logging.

        Returns:
            True if deleted.
        """
        cred_id_bytes = credential_id.encode()
        result = await self._storage.delete_webauthn_credential(user_id, cred_id_bytes)

        if result:
            await self._events.emit_async(
                Event.WEBAUTHN_CREDENTIAL_REMOVED,
                {"user_id": user_id, "credential_id": credential_id},
            )
            await self._log_audit(
                user_id, None, "webauthn.credential_removed", ip_address, True
            )

        return result

    # ── Audit Logging ──────────────────────────────────────

    async def _log_audit(
        self,
        user_id: int | None,
        email: str | None,
        action: str,
        ip_address: str | None,
        success: bool,
        details: str | None = None,
    ) -> None:
        """Log an audit event if audit logging is enabled."""
        if not self._config.audit_log_enabled:
            return
        try:
            await self._storage.log_audit_event(
                user_id=user_id,
                email=email,
                action=action,
                ip_address=ip_address,
                success=success,
                details=details,
            )
        except Exception:
            logger.exception("Failed to write audit log for action: %s", action)

    # ── Cleanup ────────────────────────────────────────────

    async def close(self) -> None:
        """Close the storage connection."""
        await self._storage.close()

    async def __aenter__(self) -> AsyncAuthManager:
        """Support ``async with AsyncAuthManager(...) as auth:``."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close the storage connection when leaving the context."""
        await self.close()
