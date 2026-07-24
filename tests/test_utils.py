"""Tests for authority.utils."""

from __future__ import annotations

import pytest

from authority.utils import (
    _get_fernet,
    check_password_pwned,
    decrypt_data,
    encrypt_data,
    generate_secure_token,
    hash_token,
    reset_fernet_cache,
    validate_email_format,
)


class TestEmailValidation:
    @pytest.mark.parametrize(
        "email,expected",
        [
            ("user@example.com", True),
            ("test.user+tag@domain.co", True),
            ("a@b.cc", True),
            ("", False),
            ("not-an-email", False),
            ("@domain.com", False),
            ("user@", False),
            ("user @example.com", False),
            (None, False),  # type: ignore[arg-type]
        ],
    )
    def test_validate_email_format(self, email, expected):
        assert validate_email_format(email) == expected


class TestTokenGeneration:
    def test_generate_secure_token_default(self):
        token = generate_secure_token()
        assert isinstance(token, str)
        assert len(token) > 20

    def test_generate_secure_token_custom_length(self):
        token = generate_secure_token(byte_length=64)
        assert isinstance(token, str)

    def test_tokens_are_unique(self):
        tokens = {generate_secure_token() for _ in range(100)}
        assert len(tokens) == 100


class TestTokenHashing:
    def test_hash_token_returns_hex(self):
        result = hash_token("my-token")
        assert len(result) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_token_deterministic(self):
        assert hash_token("test") == hash_token("test")

    def test_hash_token_different_inputs(self):
        assert hash_token("a") != hash_token("b")


class TestFernetEncryption:
    def test_encrypt_decrypt_roundtrip(self, fernet_key):
        plaintext = "super-secret-mfa-secret"
        encrypted = encrypt_data(plaintext, fernet_key)
        assert encrypted is not None
        assert encrypted != plaintext
        decrypted = decrypt_data(encrypted, fernet_key)
        assert decrypted == plaintext

    def test_encrypt_empty_returns_none(self, fernet_key):
        assert encrypt_data("", fernet_key) is None

    def test_decrypt_empty_returns_none(self, fernet_key):
        assert decrypt_data("", fernet_key) is None

    def test_decrypt_garbage_returns_none(self, fernet_key):
        assert decrypt_data("not-valid-ciphertext", fernet_key) is None

    def test_decrypt_wrong_key_returns_none(self, fernet_key):
        from cryptography.fernet import Fernet

        other_key = Fernet.generate_key().decode()
        encrypted = encrypt_data("data", fernet_key)
        assert encrypted is not None
        reset_fernet_cache()
        result = decrypt_data(encrypted, other_key)
        assert result is None
        reset_fernet_cache()

    def test_invalid_key_returns_none(self):
        reset_fernet_cache()
        result = encrypt_data("data", "not-a-valid-base64-key")
        assert result is None

    def test_empty_fernet_key_raises(self):
        reset_fernet_cache()
        with pytest.raises(ValueError, match="Fernet key not provided"):
            _get_fernet("")


class TestHIBP:
    def test_empty_password_returns_zero(self):
        assert check_password_pwned("") == 0

    @pytest.mark.network
    def test_known_pwned_password(self):
        """This uses the real HIBP API — 'password' is definitely pwned."""
        result = check_password_pwned("password")
        assert result is not None
        assert result > 0

    @pytest.mark.network
    def test_unique_password_returns_zero(self):
        """A very unlikely-to-be-pwned password."""
        result = check_password_pwned("xK9!mZ2@qW7#bN4$vL1^")
        assert result == 0
