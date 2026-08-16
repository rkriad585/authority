"""Abstract base classes for synchronous and asynchronous storage backends."""

from __future__ import annotations

import datetime
from abc import ABC, abstractmethod
from typing import Any

# ── Synchronous Interface ─────────────────────────────────────


class StorageInterface(ABC):
    """Contract that all synchronous storage backends must implement."""

    @abstractmethod
    def close(self) -> None:
        """Close the connection to the storage backend."""

    # ── Schema ────────────────────────────────────────────

    @abstractmethod
    def initialize_schema(self) -> None:
        """Ensure database schema exists and is up-to-date."""

    # ── User Management ───────────────────────────────────

    @abstractmethod
    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Return a user dict by primary key, or None if not found."""

    @abstractmethod
    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Return a user dict by email address, or None if not found."""

    @abstractmethod
    def create_user(
        self,
        name: str,
        email: str,
        password_hash: str,
        is_verified: bool,
        verification_token_hash: str | None,
        verification_token_expiry: datetime.datetime | None,
    ) -> int:
        """Insert a new user and return the generated user ID.

        Args:
            name: Display name.
            email: Email address.
            password_hash: Bcrypt-hashed password.
            is_verified: Whether the email is already verified.
            verification_token_hash: Hashed verification token, if any.
            verification_token_expiry: Expiry for the verification token.

        Returns:
            The newly created user's integer ID.
        """

    @abstractmethod
    def update_user(self, user_id: int, updates: dict[str, Any]) -> bool:
        """Apply a partial update to a user row.

        Args:
            user_id: The user to update.
            updates: Column-name to value mapping of fields to set.

        Returns:
            True if the user existed and was updated.
        """

    @abstractmethod
    def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID.

        Returns:
            True if a row was deleted.
        """

    @abstractmethod
    def find_user_by_verification_token(self, token_hash: str) -> dict[str, Any] | None:
        """Look up a user by their hashed email-verification token."""

    @abstractmethod
    def find_user_by_reset_token(self, token_hash: str) -> dict[str, Any] | None:
        """Look up a user by their hashed password-reset token."""

    @abstractmethod
    def find_user_by_email_change_token(self, token_hash: str) -> dict[str, Any] | None:
        """Look up a user by their hashed email-change token."""

    @abstractmethod
    def find_user_by_pending_email(self, pending_email: str) -> dict[str, Any] | None:
        """Return the user who has ``pending_email`` awaiting confirmation."""

    # ── Password History ──────────────────────────────────

    @abstractmethod
    def add_password_history(self, user_id: int, password_hash: str) -> None:
        """Record a password hash in the user's history for reuse checks."""

    @abstractmethod
    def get_password_history(self, user_id: int, limit: int) -> list[str]:
        """Return the most recent password hashes for a user.

        Args:
            user_id: The user whose history to retrieve.
            limit: Maximum number of hashes to return.
        """

    # ── Refresh Tokens ────────────────────────────────────

    @abstractmethod
    def store_refresh_token(
        self,
        user_id: int,
        token_hash: str,
        family_id: str,
        expires_at: datetime.datetime,
        ip_address: str | None,
        user_agent: str | None,
    ) -> int:
        """Persist a new refresh token and return its row ID.

        Args:
            user_id: Owner of the token.
            token_hash: Hashed opaque token value.
            family_id: Token family identifier for rotation tracking.
            expires_at: When the token expires (UTC).
            ip_address: Client IP at time of creation.
            user_agent: Client user-agent at time of creation.
        """

    @abstractmethod
    def get_refresh_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Return a refresh token record by its hash, or None."""

    @abstractmethod
    def get_refresh_token_by_id(self, token_id: int) -> dict[str, Any] | None:
        """Return a refresh token record by its ID, or None."""

    @abstractmethod
    def mark_refresh_token_used(self, token_id: int) -> bool:
        """Mark a refresh token as used for reuse detection.

        Returns:
            True if the token existed and was updated.
        """

    @abstractmethod
    def rotate_refresh_token(
        self,
        token_id: int,
        new_token_hash: str,
        new_expires_at: datetime.datetime,
    ) -> bool:
        """Rotate a refresh token in place with a new hash and expiry.

        Args:
            token_id: ID of the token to rotate.
            new_token_hash: Hashed replacement token.
            new_expires_at: Expiry of the replacement token (UTC).

        Returns:
            True if the token was successfully rotated.
        """

    @abstractmethod
    def revoke_refresh_token(self, token_id: int) -> bool:
        """Revoke a single refresh token.

        Returns:
            True if the token was revoked.
        """

    @abstractmethod
    def revoke_all_refresh_tokens_for_user(
        self, user_id: int, exclude_token_id: int | None = None
    ) -> int:
        """Revoke every refresh token belonging to a user.

        Args:
            user_id: The user whose tokens to revoke.
            exclude_token_id: Optional token ID to keep active.

        Returns:
            Number of tokens revoked.
        """

    @abstractmethod
    def revoke_token_family(self, family_id: str) -> int:
        """Revoke all tokens sharing the same rotation family.

        Returns:
            Number of tokens revoked.
        """

    @abstractmethod
    def list_refresh_tokens_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """Return all refresh token records for a user."""

    @abstractmethod
    def prune_expired_refresh_tokens(self) -> int:
        """Delete all expired refresh tokens across all users.

        Returns:
            Number of tokens removed.
        """

    # ── MFA Recovery Codes ────────────────────────────────

    @abstractmethod
    def set_mfa_recovery_codes(self, user_id: int, hashed_codes: list[str]) -> None:
        """Replace a user's MFA recovery codes with the given hashed set.

        Pass an empty list to clear all recovery codes.
        """

    @abstractmethod
    def use_mfa_recovery_code(self, user_id: int, hashed_code: str) -> bool:
        """Consume a single recovery code (one-time use).

        Returns:
            True if the code matched and was removed.
        """

    @abstractmethod
    def get_active_mfa_recovery_codes_count(self, user_id: int) -> int:
        """Return how many unused recovery codes remain for a user."""

    # ── WebAuthn Credentials ──────────────────────────────

    @abstractmethod
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
        """Register a new WebAuthn credential and return its row ID.

        Args:
            user_id: Owner of the credential.
            credential_id: WebAuthn credential identifier.
            public_key: Public key bytes.
            sign_count: Initial signature counter.
            rp_id: Relying party identifier.
            user_handle: User handle bytes.
            transports: Supported transport hints (e.g. ``["internal"]``).
            description: Optional human-readable label.
        """

    @abstractmethod
    def get_webauthn_credentials_for_user(
        self, user_id: int, rp_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return WebAuthn credentials for a user, optionally filtered by RP."""

    @abstractmethod
    def get_webauthn_credential_by_id(
        self, credential_id: bytes
    ) -> dict[str, Any] | None:
        """Return a single WebAuthn credential by its identifier."""

    @abstractmethod
    def update_webauthn_credential_sign_count(
        self, credential_id: bytes, new_sign_count: int
    ) -> bool:
        """Update the signature counter after a successful assertion.

        Returns:
            True if the credential was found and updated.
        """

    @abstractmethod
    def update_webauthn_credential_last_used(self, credential_id: bytes) -> None:
        """Record the current time as the credential's last-use timestamp."""

    @abstractmethod
    def delete_webauthn_credential(self, user_id: int, credential_id: bytes) -> bool:
        """Delete a WebAuthn credential.

        Args:
            user_id: Owner of the credential (ownership check).
            credential_id: The credential to delete.

        Returns:
            True if a credential was deleted.
        """

    # ── RBAC ──────────────────────────────────────────────

    @abstractmethod
    def create_role(self, name: str, description: str | None = None) -> int:
        """Create a new role and return its ID.

        Args:
            name: Unique role name.
            description: Optional human-readable description.
        """

    @abstractmethod
    def get_role_by_name(self, name: str) -> dict[str, Any] | None:
        """Return a role dict by name, or None."""

    @abstractmethod
    def get_role_by_id(self, role_id: int) -> dict[str, Any] | None:
        """Return a role dict by ID, or None."""

    @abstractmethod
    def delete_role(self, role_id: int) -> bool:
        """Delete a role by ID.

        Returns:
            True if a role was deleted.
        """

    @abstractmethod
    def list_roles(self) -> list[dict[str, Any]]:
        """Return all defined roles."""

    @abstractmethod
    def create_permission(self, code: str, description: str | None = None) -> int:
        """Create a new permission and return its ID.

        Args:
            code: Unique permission code (e.g. ``"users.read"``).
            description: Optional human-readable description.
        """

    @abstractmethod
    def get_permission_by_code(self, code: str) -> dict[str, Any] | None:
        """Return a permission dict by code, or None."""

    @abstractmethod
    def get_permission_by_id(self, permission_id: int) -> dict[str, Any] | None:
        """Return a permission dict by ID, or None."""

    @abstractmethod
    def delete_permission(self, permission_id: int) -> bool:
        """Delete a permission by ID.

        Returns:
            True if a permission was deleted.
        """

    @abstractmethod
    def list_permissions(self) -> list[dict[str, Any]]:
        """Return all defined permissions."""

    @abstractmethod
    def assign_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Grant a permission to a role.

        Returns:
            True if the assignment was created.
        """

    @abstractmethod
    def remove_permission_from_role(self, role_id: int, permission_id: int) -> bool:
        """Revoke a permission from a role.

        Returns:
            True if the assignment was removed.
        """

    @abstractmethod
    def get_role_permissions(self, role_id: int) -> list[dict[str, Any]]:
        """Return all permissions assigned to a role."""

    @abstractmethod
    def assign_role_to_user(self, user_id: int, role_id: int) -> bool:
        """Assign a role to a user.

        Returns:
            True if the assignment was created.
        """

    @abstractmethod
    def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Remove a role from a user.

        Returns:
            True if the assignment was removed.
        """

    @abstractmethod
    def get_user_roles(self, user_id: int) -> list[dict[str, Any]]:
        """Return all roles assigned to a user."""

    @abstractmethod
    def get_user_permissions(self, user_id: int) -> list[str]:
        """Return the de-duplicated permission codes for a user.

        Walks all assigned roles and collects their permissions.
        """

    # ── API Keys ──────────────────────────────────────────

    @abstractmethod
    def store_api_key(
        self,
        user_id: int,
        key_prefix: str,
        key_hash: str,
        description: str | None,
        scopes_json: str | None,
        expires_at: datetime.datetime | None,
    ) -> int:
        """Persist a new API key and return its row ID.

        Args:
            user_id: Owner of the key.
            key_prefix: Public prefix of the key for identification.
            key_hash: Hashed full key value.
            description: Optional label for the key.
            scopes_json: JSON-encoded scope list, or None.
            expires_at: Key expiry (UTC), or None for non-expiring keys.
        """

    @abstractmethod
    def get_api_key_by_prefix_and_hash(
        self, key_prefix: str, key_hash: str
    ) -> dict[str, Any] | None:
        """Look up an API key by its prefix and full hash.

        Returns:
            The key record, or None if not found or revoked.
        """

    @abstractmethod
    def update_api_key_last_used(self, key_prefix: str) -> None:
        """Update the last-used timestamp for an API key by its prefix."""

    @abstractmethod
    def list_api_keys_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """Return all API keys belonging to a user."""

    @abstractmethod
    def delete_api_key_by_prefix(self, user_id: int, key_prefix: str) -> bool:
        """Delete an API key by its prefix.

        Args:
            user_id: Owner of the key (ownership check).
            key_prefix: The prefix of the key to delete.

        Returns:
            True if a key was deleted.
        """

    # ── Custom Profile ────────────────────────────────────

    @abstractmethod
    def update_user_custom_profile(
        self, user_id: int, profile_data: dict[str, Any]
    ) -> bool:
        """Merge ``profile_data`` into the user's custom profile.

        Returns:
            True if the profile was updated.
        """

    @abstractmethod
    def get_user_custom_profile(self, user_id: int) -> dict[str, Any] | None:
        """Return the user's custom profile dict, or None if empty."""

    # ── Audit Log ─────────────────────────────────────────

    @abstractmethod
    def log_audit_event(
        self,
        user_id: int | None,
        email: str | None,
        action: str,
        ip_address: str | None,
        success: bool | None,
        details: str | None,
    ) -> None:
        """Write an audit log entry.

        Args:
            user_id: The acting user, or None for system events.
            email: Email of the acting user, or None.
            action: Dot-notation action code (e.g. ``"user.login_success"``).
            ip_address: Client IP, or None if unavailable.
            success: Whether the action succeeded, or None if inconclusive.
            details: Optional free-form JSON string with extra context.
        """

    @abstractmethod
    def get_audit_log(
        self,
        user_id: int | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with optional filters and pagination.

        Args:
            user_id: Filter to a specific user.
            action: Filter to a specific action prefix.
            limit: Maximum entries to return (default 100).
            offset: Number of entries to skip (default 0).
        """


# ── Asynchronous Interface ────────────────────────────────────


class AsyncStorageInterface(ABC):
    """Contract that all asynchronous storage backends must implement."""

    @abstractmethod
    async def close(self) -> None:
        """Close the connection to the storage backend."""

    @abstractmethod
    async def initialize_schema(self) -> None:
        """Ensure database schema exists and is up-to-date."""

    @abstractmethod
    async def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Return a user dict by primary key, or None if not found."""

    @abstractmethod
    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Return a user dict by email address, or None if not found."""

    @abstractmethod
    async def create_user(
        self,
        name: str,
        email: str,
        password_hash: str,
        is_verified: bool,
        verification_token_hash: str | None,
        verification_token_expiry: datetime.datetime | None,
    ) -> int:
        """Insert a new user and return the generated user ID.

        Args:
            name: Display name.
            email: Email address.
            password_hash: Bcrypt-hashed password.
            is_verified: Whether the email is already verified.
            verification_token_hash: Hashed verification token, if any.
            verification_token_expiry: Expiry for the verification token.

        Returns:
            The newly created user's integer ID.
        """

    @abstractmethod
    async def update_user(self, user_id: int, updates: dict[str, Any]) -> bool:
        """Apply a partial update to a user row.

        Args:
            user_id: The user to update.
            updates: Column-name to value mapping of fields to set.

        Returns:
            True if the user existed and was updated.
        """

    @abstractmethod
    async def delete_user(self, user_id: int) -> bool:
        """Delete a user by ID.

        Returns:
            True if a row was deleted.
        """

    @abstractmethod
    async def find_user_by_verification_token(
        self, token_hash: str
    ) -> dict[str, Any] | None:
        """Look up a user by their hashed email-verification token."""

    @abstractmethod
    async def find_user_by_reset_token(self, token_hash: str) -> dict[str, Any] | None:
        """Look up a user by their hashed password-reset token."""

    @abstractmethod
    async def find_user_by_email_change_token(
        self, token_hash: str
    ) -> dict[str, Any] | None:
        """Look up a user by their hashed email-change token."""

    @abstractmethod
    async def find_user_by_pending_email(
        self, pending_email: str
    ) -> dict[str, Any] | None:
        """Return the user who has ``pending_email`` awaiting confirmation."""

    @abstractmethod
    async def add_password_history(self, user_id: int, password_hash: str) -> None:
        """Record a password hash in the user's history for reuse checks."""

    @abstractmethod
    async def get_password_history(self, user_id: int, limit: int) -> list[str]:
        """Return the most recent password hashes for a user.

        Args:
            user_id: The user whose history to retrieve.
            limit: Maximum number of hashes to return.
        """

    @abstractmethod
    async def store_refresh_token(
        self,
        user_id: int,
        token_hash: str,
        family_id: str,
        expires_at: datetime.datetime,
        ip_address: str | None,
        user_agent: str | None,
    ) -> int:
        """Persist a new refresh token and return its row ID.

        Args:
            user_id: Owner of the token.
            token_hash: Hashed opaque token value.
            family_id: Token family identifier for rotation tracking.
            expires_at: When the token expires (UTC).
            ip_address: Client IP at time of creation.
            user_agent: Client user-agent at time of creation.
        """

    @abstractmethod
    async def get_refresh_token_by_hash(self, token_hash: str) -> dict[str, Any] | None:
        """Return a refresh token record by its hash, or None."""

    @abstractmethod
    async def get_refresh_token_by_id(self, token_id: int) -> dict[str, Any] | None:
        """Return a refresh token record by its ID, or None."""

    @abstractmethod
    async def mark_refresh_token_used(self, token_id: int) -> bool:
        """Mark a refresh token as used for reuse detection.

        Returns:
            True if the token existed and was updated.
        """

    @abstractmethod
    async def rotate_refresh_token(
        self,
        token_id: int,
        new_token_hash: str,
        new_expires_at: datetime.datetime,
    ) -> bool:
        """Rotate a refresh token in place with a new hash and expiry.

        Args:
            token_id: ID of the token to rotate.
            new_token_hash: Hashed replacement token.
            new_expires_at: Expiry of the replacement token (UTC).

        Returns:
            True if the token was successfully rotated.
        """

    @abstractmethod
    async def revoke_refresh_token(self, token_id: int) -> bool:
        """Revoke a single refresh token.

        Returns:
            True if the token was revoked.
        """

    @abstractmethod
    async def revoke_all_refresh_tokens_for_user(
        self, user_id: int, exclude_token_id: int | None = None
    ) -> int:
        """Revoke every refresh token belonging to a user.

        Args:
            user_id: The user whose tokens to revoke.
            exclude_token_id: Optional token ID to keep active.

        Returns:
            Number of tokens revoked.
        """

    @abstractmethod
    async def revoke_token_family(self, family_id: str) -> int:
        """Revoke all tokens sharing the same rotation family.

        Returns:
            Number of tokens revoked.
        """

    @abstractmethod
    async def list_refresh_tokens_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """Return all refresh token records for a user."""

    @abstractmethod
    async def prune_expired_refresh_tokens(self) -> int:
        """Delete all expired refresh tokens across all users.

        Returns:
            Number of tokens removed.
        """

    @abstractmethod
    async def set_mfa_recovery_codes(
        self, user_id: int, hashed_codes: list[str]
    ) -> None:
        """Replace a user's MFA recovery codes with the given hashed set.

        Pass an empty list to clear all recovery codes.
        """

    @abstractmethod
    async def use_mfa_recovery_code(self, user_id: int, hashed_code: str) -> bool:
        """Consume a single recovery code (one-time use).

        Returns:
            True if the code matched and was removed.
        """

    @abstractmethod
    async def get_active_mfa_recovery_codes_count(self, user_id: int) -> int:
        """Return how many unused recovery codes remain for a user."""

    @abstractmethod
    async def add_webauthn_credential(
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
        """Register a new WebAuthn credential and return its row ID.

        Args:
            user_id: Owner of the credential.
            credential_id: WebAuthn credential identifier.
            public_key: Public key bytes.
            sign_count: Initial signature counter.
            rp_id: Relying party identifier.
            user_handle: User handle bytes.
            transports: Supported transport hints (e.g. ``["internal"]``).
            description: Optional human-readable label.
        """

    @abstractmethod
    async def get_webauthn_credentials_for_user(
        self, user_id: int, rp_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return WebAuthn credentials for a user, optionally filtered by RP."""

    @abstractmethod
    async def get_webauthn_credential_by_id(
        self, credential_id: bytes
    ) -> dict[str, Any] | None:
        """Return a single WebAuthn credential by its identifier."""

    @abstractmethod
    async def update_webauthn_credential_sign_count(
        self, credential_id: bytes, new_sign_count: int
    ) -> bool:
        """Update the signature counter after a successful assertion.

        Returns:
            True if the credential was found and updated.
        """

    @abstractmethod
    async def update_webauthn_credential_last_used(self, credential_id: bytes) -> None:
        """Record the current time as the credential's last-use timestamp."""

    @abstractmethod
    async def delete_webauthn_credential(
        self, user_id: int, credential_id: bytes
    ) -> bool:
        """Delete a WebAuthn credential.

        Args:
            user_id: Owner of the credential (ownership check).
            credential_id: The credential to delete.

        Returns:
            True if a credential was deleted.
        """

    @abstractmethod
    async def create_role(self, name: str, description: str | None = None) -> int:
        """Create a new role and return its ID.

        Args:
            name: Unique role name.
            description: Optional human-readable description.
        """

    @abstractmethod
    async def get_role_by_name(self, name: str) -> dict[str, Any] | None:
        """Return a role dict by name, or None."""

    @abstractmethod
    async def get_role_by_id(self, role_id: int) -> dict[str, Any] | None:
        """Return a role dict by ID, or None."""

    @abstractmethod
    async def delete_role(self, role_id: int) -> bool:
        """Delete a role by ID.

        Returns:
            True if a role was deleted.
        """

    @abstractmethod
    async def list_roles(self) -> list[dict[str, Any]]:
        """Return all defined roles."""

    @abstractmethod
    async def create_permission(self, code: str, description: str | None = None) -> int:
        """Create a new permission and return its ID.

        Args:
            code: Unique permission code (e.g. ``"users.read"``).
            description: Optional human-readable description.
        """

    @abstractmethod
    async def get_permission_by_code(self, code: str) -> dict[str, Any] | None:
        """Return a permission dict by code, or None."""

    @abstractmethod
    async def get_permission_by_id(self, permission_id: int) -> dict[str, Any] | None:
        """Return a permission dict by ID, or None."""

    @abstractmethod
    async def delete_permission(self, permission_id: int) -> bool:
        """Delete a permission by ID.

        Returns:
            True if a permission was deleted.
        """

    @abstractmethod
    async def list_permissions(self) -> list[dict[str, Any]]:
        """Return all defined permissions."""

    @abstractmethod
    async def assign_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Grant a permission to a role.

        Returns:
            True if the assignment was created.
        """

    @abstractmethod
    async def remove_permission_from_role(
        self, role_id: int, permission_id: int
    ) -> bool:
        """Revoke a permission from a role.

        Returns:
            True if the assignment was removed.
        """

    @abstractmethod
    async def get_role_permissions(self, role_id: int) -> list[dict[str, Any]]:
        """Return all permissions assigned to a role."""

    @abstractmethod
    async def assign_role_to_user(self, user_id: int, role_id: int) -> bool:
        """Assign a role to a user.

        Returns:
            True if the assignment was created.
        """

    @abstractmethod
    async def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Remove a role from a user.

        Returns:
            True if the assignment was removed.
        """

    @abstractmethod
    async def get_user_roles(self, user_id: int) -> list[dict[str, Any]]:
        """Return all roles assigned to a user."""

    @abstractmethod
    async def get_user_permissions(self, user_id: int) -> list[str]:
        """Return the de-duplicated permission codes for a user.

        Walks all assigned roles and collects their permissions.
        """

    @abstractmethod
    async def store_api_key(
        self,
        user_id: int,
        key_prefix: str,
        key_hash: str,
        description: str | None,
        scopes_json: str | None,
        expires_at: datetime.datetime | None,
    ) -> int:
        """Persist a new API key and return its row ID.

        Args:
            user_id: Owner of the key.
            key_prefix: Public prefix of the key for identification.
            key_hash: Hashed full key value.
            description: Optional label for the key.
            scopes_json: JSON-encoded scope list, or None.
            expires_at: Key expiry (UTC), or None for non-expiring keys.
        """

    @abstractmethod
    async def get_api_key_by_prefix_and_hash(
        self, key_prefix: str, key_hash: str
    ) -> dict[str, Any] | None:
        """Look up an API key by its prefix and full hash.

        Returns:
            The key record, or None if not found or revoked.
        """

    @abstractmethod
    async def update_api_key_last_used(self, key_prefix: str) -> None:
        """Update the last-used timestamp for an API key by its prefix."""

    @abstractmethod
    async def list_api_keys_for_user(self, user_id: int) -> list[dict[str, Any]]:
        """Return all API keys belonging to a user."""

    @abstractmethod
    async def delete_api_key_by_prefix(self, user_id: int, key_prefix: str) -> bool:
        """Delete an API key by its prefix.

        Args:
            user_id: Owner of the key (ownership check).
            key_prefix: The prefix of the key to delete.

        Returns:
            True if a key was deleted.
        """

    @abstractmethod
    async def update_user_custom_profile(
        self, user_id: int, profile_data: dict[str, Any]
    ) -> bool:
        """Merge ``profile_data`` into the user's custom profile.

        Returns:
            True if the profile was updated.
        """

    @abstractmethod
    async def get_user_custom_profile(self, user_id: int) -> dict[str, Any] | None:
        """Return the user's custom profile dict, or None if empty."""

    @abstractmethod
    async def log_audit_event(
        self,
        user_id: int | None,
        email: str | None,
        action: str,
        ip_address: str | None,
        success: bool | None,
        details: str | None,
    ) -> None:
        """Write an audit log entry.

        Args:
            user_id: The acting user, or None for system events.
            email: Email of the acting user, or None.
            action: Dot-notation action code (e.g. ``"user.login_success"``).
            ip_address: Client IP, or None if unavailable.
            success: Whether the action succeeded, or None if inconclusive.
            details: Optional free-form JSON string with extra context.
        """

    @abstractmethod
    async def get_audit_log(
        self,
        user_id: int | None = None,
        action: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query audit log entries with optional filters and pagination.

        Args:
            user_id: Filter to a specific user.
            action: Filter to a specific action prefix.
            limit: Maximum entries to return (default 100).
            offset: Number of entries to skip (default 0).
        """
