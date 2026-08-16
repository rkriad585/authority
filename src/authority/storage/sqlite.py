"""Synchronous SQLite implementation of :class:`StorageInterface`."""

from __future__ import annotations

import datetime
import json
import logging
import re
import sqlite3
from typing import Any

from ..exceptions import DatabaseError
from .base import StorageInterface

logger = logging.getLogger("authority.storage.sqlite")


_BOOLEAN_FIELDS = frozenset(
    {
        "is_active",
        "is_verified",
        "mfa_enabled",
        "revoked",
        "used",
        "success",
    }
)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for key in _BOOLEAN_FIELDS:
        if key in d and isinstance(d[key], int):
            d[key] = bool(d[key])
    return d


def _dt_to_iso(dt: datetime.datetime | None) -> str | None:
    return dt.isoformat() if dt else None


class SQLiteStorage(StorageInterface):
    """SQLite implementation of the storage interface.

    Enables WAL mode and foreign keys on connect. Auto-creates the schema
    on first use.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None
        self._cursor: sqlite3.Cursor | None = None
        try:
            self._conn = sqlite3.connect(
                self.db_path,
                detect_types=0,
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA foreign_keys=ON;")
            self._conn.execute("PRAGMA busy_timeout=5000;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._cursor = self._conn.cursor()
            logger.info("SQLite connection established to %s", db_path)
            self.initialize_schema()
        except sqlite3.Error as exc:
            logger.exception("Failed to connect to SQLite at %s", db_path)
            raise DatabaseError(f"SQLite connection failed: {exc}") from exc

    def close(self) -> None:
        """Close the connection to the storage backend."""
        if self._conn:
            try:
                self._conn.commit()
                self._conn.close()
                logger.info("SQLite connection closed for %s", self.db_path)
            except sqlite3.Error as exc:
                logger.error("Error closing SQLite: %s", exc)
            finally:
                self._conn = None
                self._cursor = None

    # ── Internal helpers ──────────────────────────────────

    def _execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        if not self._conn or not self._cursor:
            raise DatabaseError("Database connection is not available.")
        try:
            return self._cursor.execute(query, params)
        except sqlite3.Error as exc:
            logger.error("SQLite error: %s | params: %s", query, params)
            raise DatabaseError(f"SQLite query failed: {exc}") from exc

    def _commit(self) -> None:
        if not self._conn:
            raise DatabaseError("Database connection is not available.")
        try:
            self._conn.commit()
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite commit failed: {exc}") from exc

    def _rollback(self) -> None:
        if self._conn:
            try:
                self._conn.rollback()
            except sqlite3.Error:
                logger.warning("SQLite rollback failed", exc_info=True)

    # ── Schema ────────────────────────────────────────────

    def initialize_schema(self) -> None:
        """Ensure the SQLite database schema exists and is up-to-date."""
        try:
            c = self._execute

            c("""CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                is_verified BOOLEAN NOT NULL DEFAULT FALSE,
                verification_token_hash TEXT UNIQUE,
                verification_token_expiry TIMESTAMP,
                reset_token_hash TEXT UNIQUE,
                reset_token_expiry TIMESTAMP,
                failed_login_attempts INTEGER NOT NULL DEFAULT 0,
                last_failed_login TIMESTAMP,
                locked_until TIMESTAMP,
                mfa_secret_encrypted TEXT,
                mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
                pending_email TEXT UNIQUE COLLATE NOCASE,
                email_change_token_hash TEXT UNIQUE,
                email_change_token_expiry TIMESTAMP,
                custom_profile TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )""")

            c("""CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
                AFTER UPDATE ON users
                FOR EACH ROW WHEN NEW.updated_at <= OLD.updated_at
                BEGIN
                    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
                END
            """)

            c("""CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""")
            c(
                "CREATE INDEX IF NOT EXISTS idx_pwd_hist_user_time ON password_history(user_id, created_at DESC)"
            )

            c("""CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                family_id TEXT NOT NULL,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                used_at TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""")
            c(
                "CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id, revoked)"
            )
            c(
                "CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens(family_id)"
            )
            c(
                "CREATE INDEX IF NOT EXISTS idx_refresh_expires ON refresh_tokens(expires_at)"
            )

            c("""CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                hashed_code TEXT NOT NULL UNIQUE,
                used BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""")
            c(
                "CREATE INDEX IF NOT EXISTS idx_mfa_recovery_user ON mfa_recovery_codes(user_id, used)"
            )

            c("""CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                user_handle BLOB NOT NULL,
                credential_id BLOB NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                rp_id TEXT NOT NULL,
                transports TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                last_used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""")
            c(
                "CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)"
            )

            c("""CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )""")

            c("""CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code TEXT NOT NULL UNIQUE COLLATE NOCASE,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
            )""")

            c("""CREATE TABLE IF NOT EXISTS role_permissions (
                role_id INTEGER NOT NULL,
                permission_id INTEGER NOT NULL,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                PRIMARY KEY (role_id, permission_id),
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
            )""")

            c("""CREATE TABLE IF NOT EXISTS user_roles (
                user_id INTEGER NOT NULL,
                role_id INTEGER NOT NULL,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                PRIMARY KEY (user_id, role_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
            )""")

            c("""CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                key_prefix TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL UNIQUE,
                description TEXT,
                scopes_json TEXT,
                expires_at TIMESTAMP,
                last_used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )""")
            c("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")

            c("""CREATE TABLE IF NOT EXISTS auth_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
                user_id INTEGER,
                email TEXT,
                action TEXT NOT NULL,
                ip_address TEXT,
                success BOOLEAN,
                details_json TEXT,
                chain_hash TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )""")
            c(
                "CREATE INDEX IF NOT EXISTS idx_audit_ts ON auth_audit_log(timestamp DESC)"
            )
            c("CREATE INDEX IF NOT EXISTS idx_audit_user ON auth_audit_log(user_id)")
            c("CREATE INDEX IF NOT EXISTS idx_audit_action ON auth_audit_log(action)")

            self._commit()
            logger.debug("SQLite schema initialised")
        except sqlite3.Error as exc:
            self._rollback()
            logger.exception("Schema init failed")
            raise DatabaseError(f"SQLite schema setup failed: {exc}") from exc

    # ── User Management ───────────────────────────────────

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Retrieve a user by their ID.

        Args:
            user_id: The user's integer ID.

        Returns:
            User dict or None if not found."""
        cur = self._execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return _row_to_dict(cur.fetchone())

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Retrieve a user by their email address (case-insensitive).

        Args:
            email: The user's email address.

        Returns:
            User dict or None if not found."""
        cur = self._execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
        return _row_to_dict(cur.fetchone())

    def create_user(
        self,
        name: str,
        email: str,
        password_hash: str,
        is_verified: bool,
        verification_token_hash: str | None,
        verification_token_expiry: datetime.datetime | None,
    ) -> int:
        """Create a new user record.

        Args:
            name: Display name.
            email: Email address.
            password_hash: Bcrypt-hashed password.
            is_verified: Whether the user is verified.
            verification_token: Token for email verification.

        Returns:
            The newly created user dict."""
        try:
            cur = self._execute(
                """INSERT INTO users
                   (name, email, password_hash, is_verified,
                    verification_token_hash, verification_token_expiry, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    name.strip(),
                    email.lower(),
                    password_hash,
                    is_verified,
                    verification_token_hash,
                    _dt_to_iso(verification_token_expiry),
                    True,
                ),
            )
            user_id = cur.lastrowid
            self._commit()
            if user_id is None:
                raise DatabaseError("Failed to get user ID after insertion.")
            return user_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error creating user: {exc}") from exc

    def update_user(self, user_id: int, updates: dict[str, Any]) -> bool:
        """Update fields on an existing user.

        Args:
            user_id: The user's integer ID.
            **fields: Fields to update.

        Returns:
            True if the user was updated."""
        if not updates:
            return True
        fields: list[str] = []
        params: list[Any] = []
        for key, value in updates.items():
            if key in ("id", "created_at", "updated_at"):
                continue
            if not re.match(r"^[a-zA-Z0-9_]+$", key):
                raise ValueError(f"Invalid field name: {key}")
            if key in ("email", "pending_email") and isinstance(value, str):
                value = value.lower()
            fields.append(f"{key} = ?")
            params.append(value)
        if not fields:
            return True
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
        try:
            cur = self._execute(query, tuple(params))
            self._commit()
            return cur.rowcount > 0
        except sqlite3.IntegrityError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error updating user {user_id}: {exc}") from exc

    def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID.

        Args:
            user_id: The user's integer ID.

        Returns:
            True if the user was deleted."""
        try:
            cur = self._execute("DELETE FROM users WHERE id = ?", (user_id,))
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error deleting user {user_id}: {exc}") from exc

    def find_user_by_verification_token(self, token_hash: str) -> dict[str, Any] | None:
        """Find a user by their email verification token.

        Args:
            token: The verification token.

        Returns:
            User dict or None."""
        cur = self._execute(
            "SELECT * FROM users WHERE verification_token_hash = ?", (token_hash,)
        )
        return _row_to_dict(cur.fetchone())

    def find_user_by_reset_token(self, token_hash: str) -> dict[str, Any] | None:
        """Find a user by their password reset token.

        Args:
            token: The reset token.

        Returns:
            User dict or None."""
        cur = self._execute(
            "SELECT * FROM users WHERE reset_token_hash = ?", (token_hash,)
        )
        return _row_to_dict(cur.fetchone())

    def find_user_by_email_change_token(self, token_hash: str) -> dict[str, Any] | None:
        """Find a user by their email change confirmation token.

        Args:
            token: The email change token.

        Returns:
            User dict or None."""
        cur = self._execute(
            "SELECT * FROM users WHERE email_change_token_hash = ?", (token_hash,)
        )
        return _row_to_dict(cur.fetchone())

    def find_user_by_pending_email(self, pending_email: str) -> dict[str, Any] | None:
        """Find a user by their pending (unconfirmed) new email.

        Args:
            email: The pending email address.

        Returns:
            User dict or None."""
        cur = self._execute(
            "SELECT * FROM users WHERE pending_email = ?", (pending_email.lower(),)
        )
        return _row_to_dict(cur.fetchone())

    # ── Password History ──────────────────────────────────

    def add_password_history(self, user_id: int, password_hash: str) -> None:
        """Record a password hash in the user's password history.

        Args:
            user_id: The user's integer ID.
            password_hash: The bcrypt-hashed password.
            max_history: Maximum number of historical entries to retain."""
        try:
            self._execute(
                "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)",
                (user_id, password_hash),
            )
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("Failed to add password history for user %d: %s", user_id, exc)

    def get_password_history(self, user_id: int, limit: int) -> list[str]:
        """Retrieve password hashes for a user.

        Args:
            user_id: The user's integer ID.
            limit: Maximum number of entries to return.

        Returns:
            List of password history dicts."""
        if limit <= 0:
            return []
        try:
            cur = self._execute(
                "SELECT password_hash FROM password_history WHERE user_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (user_id, limit),
            )
            return [row["password_hash"] for row in cur.fetchall()]
        except sqlite3.Error as exc:
            logger.error("Failed to get password history for user %d: %s", user_id, exc)
            return []

    # ── Refresh Tokens ────────────────────────────────────

    def store_refresh_token(
        self,
        user_id: int,
        token_hash: str,
        family_id: str,
        expires_at: datetime.datetime,
        ip_address: str | None,
        user_agent: str | None,
    ) -> int:
        """Persist a refresh token hash.

        Args:
            user_id: The user's integer ID.
            token_hash: SHA-256 hash of the token.
            device_id: Optional device identifier.
            user_agent: Optional user-agent string.
            ip_address: Optional IP address.
            expires_at: Token expiration datetime.
            family: Token family identifier for reuse detection."""
        try:
            cur = self._execute(
                """INSERT INTO refresh_tokens
                   (user_id, token_hash, family_id, expires_at, ip_address, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    token_hash,
                    family_id,
                    _dt_to_iso(expires_at),
                    ip_address,
                    user_agent,
                ),
            )
            token_id = cur.lastrowid
            self._commit()
            if token_id is None:
                raise DatabaseError("Failed to get refresh token ID after insertion.")
            return token_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error storing refresh token: {exc}") from exc

    def get_refresh_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Look up a refresh token by its hash.

        Args:
            token_hash: SHA-256 hash of the token.

        Returns:
            Token dict or None."""
        cur = self._execute(
            "SELECT * FROM refresh_tokens WHERE token_hash = ?", (token_hash,)
        )
        return _row_to_dict(cur.fetchone())

    def get_refresh_token_by_id(self, token_id: int) -> dict[str, Any] | None:
        """Look up a refresh token by its database ID.

        Args:
            token_id: The token's database ID.

        Returns:
            Token dict or None."""
        cur = self._execute("SELECT * FROM refresh_tokens WHERE id = ?", (token_id,))
        return _row_to_dict(cur.fetchone())

    def mark_refresh_token_used(self, token_id: int) -> bool:
        """Mark a refresh token as used and record the timestamp.

        Args:
            token_hash: SHA-256 hash of the token."""
        try:
            cur = self._execute(
                "UPDATE refresh_tokens SET used = TRUE, used_at = CURRENT_TIMESTAMP WHERE id = ? AND used = FALSE",
                (token_id,),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error marking token used: {exc}") from exc

    def rotate_refresh_token(
        self,
        token_id: int,
        new_token_hash: str,
        new_expires_at: datetime.datetime,
    ) -> bool:
        """Rotate a refresh token: revoke the old one, store the new one.

        Args:
            old_token_hash: Hash of the token being replaced.
            new_token_hash: Hash of the new token.
            new_expires_at: Expiration datetime for the new token.
            user_agent: Optional user-agent string.
            ip_address: Optional IP address."""
        try:
            # Get the current token to preserve user_id and family_id
            cur = self._execute(
                "SELECT user_id, family_id, ip_address, user_agent FROM refresh_tokens WHERE id = ?",
                (token_id,),
            )
            row = cur.fetchone()
            if not row:
                return False

            # Mark old token as used
            self._execute(
                """UPDATE refresh_tokens
                   SET used = TRUE, used_at = CURRENT_TIMESTAMP
                   WHERE id = ?""",
                (token_id,),
            )

            # Insert new token in the same family
            self._execute(
                """INSERT INTO refresh_tokens
                   (user_id, token_hash, family_id, expires_at, ip_address, user_agent)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    row["user_id"],
                    new_token_hash,
                    row["family_id"],
                    _dt_to_iso(new_expires_at),
                    row["ip_address"],
                    row["user_agent"],
                ),
            )
            self._commit()
            return True
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error rotating token: {exc}") from exc

    def revoke_refresh_token(self, token_id: int) -> bool:
        """Revoke a single refresh token.

        Args:
            token_hash: SHA-256 hash of the token."""
        try:
            cur = self._execute(
                "UPDATE refresh_tokens SET revoked = TRUE WHERE id = ?", (token_id,)
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error revoking token: {exc}") from exc

    def revoke_all_refresh_tokens_for_user(
        self, user_id: int, exclude_token_id: int | None = None
    ) -> int:
        """Revoke all refresh tokens for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            Number of tokens revoked."""
        try:
            query = "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ? AND revoked = FALSE"
            params: list[Any] = [user_id]
            if exclude_token_id is not None:
                query += " AND id != ?"
                params.append(exclude_token_id)
            cur = self._execute(query, tuple(params))
            count = cur.rowcount
            self._commit()
            return count
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(
                f"SQLite error revoking all tokens for user {user_id}: {exc}"
            ) from exc

    def revoke_token_family(self, family_id: str) -> int:
        """Revoke all tokens in a family (for reuse detection).

        Args:
            family: The token family identifier."""
        try:
            cur = self._execute(
                "UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = ? AND revoked = FALSE",
                (family_id,),
            )
            count = cur.rowcount
            self._commit()
            return count
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(
                f"SQLite error revoking family {family_id}: {exc}"
            ) from exc

    def list_refresh_tokens_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """List all refresh tokens for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            List of token dicts."""
        try:
            cur = self._execute(
                "SELECT id, family_id, expires_at, created_at, revoked, ip_address, user_agent "
                "FROM refresh_tokens WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error listing tokens: {exc}") from exc

    def prune_expired_refresh_tokens(self) -> int:
        """Delete expired refresh tokens from the database.

        Returns:
            Number of tokens pruned."""
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            cur = self._execute(
                "DELETE FROM refresh_tokens WHERE expires_at < ? OR revoked = TRUE",
                (now,),
            )
            count = cur.rowcount
            self._commit()
            if count:
                logger.info("Pruned %d expired/revoked refresh tokens", count)
            return count
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("Token pruning failed: %s", exc)
            return 0

    # ── MFA Recovery Codes ────────────────────────────────

    def set_mfa_recovery_codes(self, user_id: int, hashed_codes: list[str]) -> None:
        """Store hashed MFA recovery codes for a user.

        Args:
            user_id: The user's integer ID.
            codes: List of plaintext recovery codes to hash and store."""
        try:
            self._execute(
                "DELETE FROM mfa_recovery_codes WHERE user_id = ? AND used = FALSE",
                (user_id,),
            )
            if hashed_codes:
                params = [(user_id, h) for h in hashed_codes]
                self._cursor.executemany(  # type: ignore[union-attr]
                    "INSERT INTO mfa_recovery_codes (user_id, hashed_code) VALUES (?, ?)",
                    params,
                )
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error setting recovery codes: {exc}") from exc

    def use_mfa_recovery_code(self, user_id: int, hashed_code: str) -> bool:
        """Consume a recovery code (mark it as used).

        Args:
            user_id: The user's integer ID.
            code: The plaintext recovery code.

        Returns:
            True if the code was valid and consumed."""
        try:
            cur = self._execute(
                """UPDATE mfa_recovery_codes
                   SET used = TRUE, used_at = CURRENT_TIMESTAMP
                   WHERE user_id = ? AND hashed_code = ? AND used = FALSE""",
                (user_id, hashed_code),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error using recovery code: {exc}") from exc

    def get_active_mfa_recovery_codes_count(self, user_id: int) -> int:
        """Count unused recovery codes for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            Number of active recovery codes."""
        try:
            cur = self._execute(
                "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used = FALSE",
                (user_id,),
            )
            result = cur.fetchone()
            return result[0] if result else 0
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error counting recovery codes: {exc}") from exc

    # ── WebAuthn Credentials ──────────────────────────────

    def add_webauthn_credential(
        self,
        user_id: int,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        rp_id: str,
        user_handle: bytes,
        transports: list[str] | None = None,
        description: str | None = None,
    ) -> int:
        """Register a new WebAuthn credential.

        Args:
            user_id: The user's integer ID.
            credential_id: WebAuthn credential identifier.
            public_key: The credential's public key.
            sign_count: Initial signature counter.
            transports: List of supported transports.
            nickname: Optional human-readable label.

        Returns:
            The stored credential dict."""
        transports_json = json.dumps(transports) if transports else None
        try:
            cur = self._execute(
                """INSERT INTO webauthn_credentials
                   (user_id, user_handle, credential_id, public_key, sign_count,
                    rp_id, transports, description)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    user_handle,
                    credential_id,
                    public_key,
                    sign_count,
                    rp_id,
                    transports_json,
                    description,
                ),
            )
            cred_id = cur.lastrowid
            self._commit()
            if cred_id is None:
                raise DatabaseError("Failed to get WebAuthn credential ID.")
            return cred_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(
                f"SQLite error adding WebAuthn credential: {exc}"
            ) from exc

    def get_webauthn_credentials_for_user(
        self, user_id: int, rp_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List all WebAuthn credentials for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            List of credential dicts."""
        try:
            query = "SELECT * FROM webauthn_credentials WHERE user_id = ?"
            params: list[Any] = [user_id]
            if rp_id:
                query += " AND rp_id = ?"
                params.append(rp_id)
            cur = self._execute(query, tuple(params))
            creds: list[dict[str, Any]] = []
            for row in cur.fetchall():
                d = dict(row)
                if d.get("transports"):
                    try:
                        d["transports"] = json.loads(d["transports"])
                    except json.JSONDecodeError:
                        d["transports"] = []
                creds.append(d)
            return creds
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error listing WebAuthn creds: {exc}") from exc

    def get_webauthn_credential_by_id(
        self, credential_id: bytes
    ) -> dict[str, Any] | None:
        """Retrieve a WebAuthn credential by its ID.

        Args:
            credential_id: The WebAuthn credential identifier.

        Returns:
            Credential dict or None."""
        try:
            cur = self._execute(
                "SELECT * FROM webauthn_credentials WHERE credential_id = ?",
                (credential_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("transports"):
                try:
                    d["transports"] = json.loads(d["transports"])
                except json.JSONDecodeError:
                    d["transports"] = []
            return d
        except sqlite3.Error as exc:
            raise DatabaseError(
                f"SQLite error getting WebAuthn credential: {exc}"
            ) from exc

    def update_webauthn_credential_sign_count(
        self, credential_id: bytes, new_sign_count: int
    ) -> bool:
        """Update the signature counter on a credential.

        Args:
            credential_id: The WebAuthn credential identifier.
            new_count: The new signature counter value."""
        try:
            cur = self._execute(
                "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
                (new_sign_count, credential_id),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error updating sign count: {exc}") from exc

    def update_webauthn_credential_last_used(self, credential_id: bytes) -> None:
        """Update the last-used timestamp on a credential.

        Args:
            credential_id: The WebAuthn credential identifier."""
        try:
            self._execute(
                "UPDATE webauthn_credentials SET last_used_at = CURRENT_TIMESTAMP WHERE credential_id = ?",
                (credential_id,),
            )
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("Failed to update WebAuthn last_used: %s", exc)

    def delete_webauthn_credential(self, user_id: int, credential_id: bytes) -> bool:
        """Delete a WebAuthn credential.

        Args:
            credential_id: The WebAuthn credential identifier."""
        try:
            cur = self._execute(
                "DELETE FROM webauthn_credentials WHERE user_id = ? AND credential_id = ?",
                (user_id, credential_id),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error deleting WebAuthn cred: {exc}") from exc

    # ── RBAC ──────────────────────────────────────────────

    def create_role(self, name: str, description: str | None = None) -> int:
        """Create a new role.

        Args:
            name: Unique role name.
            description: Optional description.

        Returns:
            The integer ID of the new role."""
        try:
            cur = self._execute(
                "INSERT INTO roles (name, description) VALUES (?, ?)",
                (name, description),
            )
            role_id = cur.lastrowid
            self._commit()
            if role_id is None:
                raise DatabaseError("Failed to get role ID.")
            return role_id
        except sqlite3.IntegrityError:
            self._rollback()
            existing = self.get_role_by_name(name)
            if existing:
                return existing["id"]
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error creating role: {exc}") from exc

    def get_role_by_name(self, name: str) -> dict[str, Any] | None:
        """Look up a role by name.

        Args:
            name: The role name.

        Returns:
            Role dict or None."""
        cur = self._execute("SELECT * FROM roles WHERE name = ?", (name,))
        return _row_to_dict(cur.fetchone())

    def get_role_by_id(self, role_id: int) -> dict[str, Any] | None:
        """Look up a role by ID.

        Args:
            role_id: The role's integer ID.

        Returns:
            Role dict or None."""
        cur = self._execute("SELECT * FROM roles WHERE id = ?", (role_id,))
        return _row_to_dict(cur.fetchone())

    def delete_role(self, role_id: int) -> bool:
        """Delete a role by ID.

        Args:
            role_id: The role's integer ID.

        Returns:
            True if the role was deleted."""
        try:
            cur = self._execute("DELETE FROM roles WHERE id = ?", (role_id,))
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error deleting role: {exc}") from exc

    def list_roles(self) -> list[dict[str, Any]]:
        """List all roles.

        Returns:
            List of role dicts."""
        try:
            cur = self._execute("SELECT * FROM roles ORDER BY name")
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error listing roles: {exc}") from exc

    def create_permission(self, code: str, description: str | None = None) -> int:
        """Create a new permission.

        Args:
            code: Unique permission code (e.g., "items.delete").
            description: Optional description.

        Returns:
            The integer ID of the new permission."""
        try:
            cur = self._execute(
                "INSERT INTO permissions (code, description) VALUES (?, ?)",
                (code, description),
            )
            perm_id = cur.lastrowid
            self._commit()
            if perm_id is None:
                raise DatabaseError("Failed to get permission ID.")
            return perm_id
        except sqlite3.IntegrityError:
            self._rollback()
            existing = self.get_permission_by_code(code)
            if existing:
                return existing["id"]
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error creating permission: {exc}") from exc

    def get_permission_by_code(self, code: str) -> dict[str, Any] | None:
        """Look up a permission by code.

        Args:
            code: The permission code.

        Returns:
            Permission dict or None."""
        cur = self._execute("SELECT * FROM permissions WHERE code = ?", (code,))
        return _row_to_dict(cur.fetchone())

    def get_permission_by_id(self, permission_id: int) -> dict[str, Any] | None:
        """Look up a permission by ID.

        Args:
            permission_id: The permission's integer ID.

        Returns:
            Permission dict or None."""
        cur = self._execute("SELECT * FROM permissions WHERE id = ?", (permission_id,))
        return _row_to_dict(cur.fetchone())

    def delete_permission(self, permission_id: int) -> bool:
        """Delete a permission by ID.

        Args:
            permission_id: The permission's integer ID.

        Returns:
            True if the permission was deleted."""
        try:
            cur = self._execute(
                "DELETE FROM permissions WHERE id = ?", (permission_id,)
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error deleting permission: {exc}") from exc

    def list_permissions(self) -> list[dict[str, Any]]:
        """List all permissions.

        Returns:
            List of permission dicts."""
        try:
            cur = self._execute("SELECT * FROM permissions ORDER BY code")
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error listing permissions: {exc}") from exc

    def assign_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Assign a permission to a role.

        Args:
            role_id: The role's integer ID.
            permission_id: The permission's integer ID.

        Returns:
            True if assigned."""
        try:
            self._execute(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                (role_id, permission_id),
            )
            self._commit()
            return True
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error assigning permission: {exc}") from exc

    def remove_permission_from_role(self, role_id: int, permission_id: int) -> bool:
        """Remove a permission from a role.

        Args:
            role_id: The role's integer ID.
            permission_id: The permission's integer ID.

        Returns:
            True if removed."""
        try:
            cur = self._execute(
                "DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?",
                (role_id, permission_id),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error removing permission: {exc}") from exc

    def get_role_permissions(self, role_id: int) -> list[dict[str, Any]]:
        """Get all permissions assigned to a role.

        Args:
            role_id: The role's integer ID.

        Returns:
            List of permission dicts."""
        try:
            cur = self._execute(
                "SELECT p.* FROM permissions p "
                "JOIN role_permissions rp ON p.id = rp.permission_id "
                "WHERE rp.role_id = ? ORDER BY p.code",
                (role_id,),
            )
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(
                f"SQLite error getting role permissions: {exc}"
            ) from exc

    def assign_role_to_user(self, user_id: int, role_id: int) -> bool:
        """Assign a role to a user.

        Args:
            user_id: The user's integer ID.
            role_id: The role's integer ID.

        Returns:
            True if assigned."""
        try:
            self._execute(
                "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
                (user_id, role_id),
            )
            self._commit()
            return True
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error assigning role: {exc}") from exc

    def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Remove a role from a user.

        Args:
            user_id: The user's integer ID.
            role_id: The role's integer ID.

        Returns:
            True if removed."""
        try:
            cur = self._execute(
                "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
                (user_id, role_id),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error removing role: {exc}") from exc

    def get_user_roles(self, user_id: int) -> list[dict[str, Any]]:
        """Get all roles assigned to a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            List of role dicts."""
        try:
            cur = self._execute(
                "SELECT r.* FROM roles r "
                "JOIN user_roles ur ON r.id = ur.role_id "
                "WHERE ur.user_id = ? ORDER BY r.name",
                (user_id,),
            )
            return [dict(row) for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error getting user roles: {exc}") from exc

    def get_user_permissions(self, user_id: int) -> list[str]:
        """Get all effective permission codes for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            List of permission code strings."""
        try:
            cur = self._execute(
                "SELECT DISTINCT p.code FROM permissions p "
                "JOIN role_permissions rp ON p.id = rp.permission_id "
                "JOIN user_roles ur ON rp.role_id = ur.role_id "
                "WHERE ur.user_id = ?",
                (user_id,),
            )
            return [row["code"] for row in cur.fetchall()]
        except sqlite3.Error as exc:
            raise DatabaseError(
                f"SQLite error getting user permissions: {exc}"
            ) from exc

    # ── API Keys ──────────────────────────────────────────

    def store_api_key(
        self,
        user_id: int,
        key_prefix: str,
        key_hash: str,
        description: str | None,
        scopes_json: str | None,
        expires_at: datetime.datetime | None,
    ) -> int:
        """Persist a hashed API key.

        Args:
            user_id: The user's integer ID.
            key_prefix: First few chars of the key for identification.
            key_hash: SHA-256 hash of the full key.
            description: Optional description.
            scopes: Optional list of scope strings.
            expires_at: Optional expiration datetime.
            ip_address: Optional IP address restriction.

        Returns:
            The stored API key dict."""
        try:
            cur = self._execute(
                """INSERT INTO api_keys
                   (user_id, key_prefix, key_hash, description, scopes_json, expires_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    user_id,
                    key_prefix,
                    key_hash,
                    description,
                    scopes_json,
                    _dt_to_iso(expires_at),
                ),
            )
            key_id = cur.lastrowid
            self._commit()
            if key_id is None:
                raise DatabaseError("Failed to get API key ID.")
            return key_id
        except sqlite3.IntegrityError:
            self._rollback()
            raise
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error storing API key: {exc}") from exc

    def get_api_key_by_prefix_and_hash(
        self, key_prefix: str, key_hash: str
    ) -> dict[str, Any] | None:
        """Look up an API key by prefix and hash.

        Args:
            prefix: The key prefix.
            key_hash: SHA-256 hash of the full key.

        Returns:
            API key dict or None."""
        try:
            cur = self._execute(
                """SELECT k.*, u.email as user_email, u.is_active as user_is_active
                   FROM api_keys k JOIN users u ON k.user_id = u.id
                   WHERE k.key_prefix = ? AND k.key_hash = ?""",
                (key_prefix, key_hash),
            )
            return _row_to_dict(cur.fetchone())
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error getting API key: {exc}") from exc

    def update_api_key_last_used(self, key_prefix: str) -> None:
        """Update the last-used timestamp on an API key.

        Args:
            key_prefix: The key prefix."""
        try:
            self._execute(
                "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_prefix = ?",
                (key_prefix,),
            )
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("Failed to update API key last_used: %s", exc)

    def list_api_keys_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """List all API keys for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            List of API key dicts."""
        try:
            cur = self._execute(
                "SELECT id, key_prefix, description, scopes_json, expires_at, last_used_at, created_at "
                "FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            keys: list[dict[str, Any]] = []
            for row in cur.fetchall():
                d = dict(row)
                try:
                    d["scopes"] = (
                        json.loads(d.pop("scopes_json")) if d.get("scopes_json") else []
                    )
                except json.JSONDecodeError:
                    d["scopes"] = []
                    d.pop("scopes_json", None)
                keys.append(d)
            return keys
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error listing API keys: {exc}") from exc

    def delete_api_key_by_prefix(self, user_id: int, key_prefix: str) -> bool:
        """Delete an API key by its prefix.

        Args:
            prefix: The key prefix.

        Returns:
            True if deleted."""
        try:
            cur = self._execute(
                "DELETE FROM api_keys WHERE user_id = ? AND key_prefix = ?",
                (user_id, key_prefix),
            )
            self._commit()
            return cur.rowcount > 0
        except sqlite3.Error as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error deleting API key: {exc}") from exc

    # ── Custom Profile ────────────────────────────────────

    def update_user_custom_profile(
        self, user_id: int, profile_data: dict[str, Any]
    ) -> bool:
        """Update custom profile data for a user.

        Args:
            user_id: The user's integer ID.
            data: Dictionary of custom profile fields.

        Returns:
            True if updated."""
        try:
            profile_json = json.dumps(profile_data)
            cur = self._execute(
                "UPDATE users SET custom_profile = ? WHERE id = ?",
                (profile_json, user_id),
            )
            self._commit()
            return cur.rowcount > 0
        except (sqlite3.Error, TypeError) as exc:
            self._rollback()
            raise DatabaseError(f"SQLite error updating profile: {exc}") from exc

    def get_user_custom_profile(self, user_id: int) -> dict[str, Any] | None:
        """Retrieve custom profile data for a user.

        Args:
            user_id: The user's integer ID.

        Returns:
            Custom profile dict or empty dict."""
        try:
            cur = self._execute(
                "SELECT custom_profile FROM users WHERE id = ?", (user_id,)
            )
            row = cur.fetchone()
            if row and row["custom_profile"]:
                return json.loads(row["custom_profile"])
            return None
        except (sqlite3.Error, json.JSONDecodeError) as exc:
            logger.error("Error getting profile for user %d: %s", user_id, exc)
            return None

    # ── Audit Log ─────────────────────────────────────────

    def log_audit_event(
        self,
        user_id: int | None,
        email: str | None,
        action: str,
        ip_address: str | None,
        success: bool | None,
        details: str | None,
    ) -> None:
        """Record an audit log entry.

        Args:
            user_id: The user's integer ID.
            actor_id: ID of the user performing the action.
            action: Action code (e.g., "auth.login").
            resource: Optional resource identifier.
            success: Whether the action succeeded.
            details: Optional JSON-serializable detail dict."""
        try:
            self._execute(
                """INSERT INTO auth_audit_log
                   (user_id, email, action, ip_address, success, details_json)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (user_id, email, action, ip_address, success, details),
            )
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            logger.error("Failed to write audit log: %s", exc)

    def get_audit_log(
        self,
        user_id: int | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log entries.

        Args:
            user_id: Filter by user ID.
            action: Filter by action code.
            limit: Maximum number of entries to return.
            offset: Pagination offset.

        Returns:
            List of audit log dicts."""
        try:
            conditions = []
            params: list[Any] = []

            if user_id is not None:
                conditions.append("user_id = ?")
                params.append(user_id)
            if action is not None:
                conditions.append("action = ?")
                params.append(action)

            where = ""
            if conditions:
                where = "WHERE " + " AND ".join(conditions)

            query = f"""
                SELECT id, timestamp, user_id, email, action, ip_address,
                       success, details_json
                FROM auth_audit_log
                {where}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            params.extend([limit, offset])

            cur = self._execute(query, tuple(params))
            rows = cur.fetchall()
            return [d for r in rows if (d := _row_to_dict(r)) is not None]
        except sqlite3.Error as exc:
            raise DatabaseError(f"SQLite error querying audit log: {exc}") from exc
