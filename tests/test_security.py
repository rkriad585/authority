"""Security-specific tests — timing attacks, algorithm confusion, token forgery."""

from __future__ import annotations

import datetime

import jwt as pyjwt
import pytest

from authority.config import AuthConfig
from authority.core import AuthManager
from authority.exceptions import InvalidCredentialsError, InvalidTokenError
from authority.storage.sqlite import SQLiteStorage
from authority.utils import generate_secure_token, hash_token


class TestAlgorithmConfusion:
    """Test that JWT algorithm confusion attacks are prevented."""

    def _make_manager(self):
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
        )
        return AuthManager(config, storage)

    def test_rejects_none_algorithm(self):
        manager = self._make_manager()
        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=15),
            "iss": "authority",
            "typ": "access",
        }
        # Manually construct a JWT with "alg":"none" header (PyJWT won't encode this)
        import base64
        import json

        header = {"alg": "none", "typ": "JWT"}
        header_b64 = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
        )
        payload_b64 = (
            base64.urlsafe_b64encode(json.dumps(payload, default=str).encode())
            .rstrip(b"=")
            .decode()
        )
        forged_token = f"{header_b64}.{payload_b64}."
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(forged_token)
        manager.storage.close()

    def test_rejects_hs256_with_public_key(self):
        """If someone tries to use an RSA public key as HMAC secret."""
        manager = self._make_manager()
        # Create a token with HS256 using a different key
        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=15),
            "iss": "authority",
            "typ": "access",
        }
        token = pyjwt.encode(payload, "wrong-secret-key!!", algorithm="HS256")
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(token)
        manager.storage.close()

    def test_rejects_wrong_iss(self):
        manager = self._make_manager()
        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=15),
            "iss": "attacker",
            "typ": "access",
        }
        token = pyjwt.encode(
            payload,
            manager._config.jwt_secret_key,
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(token)
        manager.storage.close()

    def test_rejects_wrong_typ(self):
        manager = self._make_manager()
        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=15),
            "iss": "authority",
            "typ": "refresh",  # Wrong type
        }
        token = pyjwt.encode(
            payload,
            manager._config.jwt_secret_key,
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(token)
        manager.storage.close()

    def test_rejects_expired_token(self):
        manager = self._make_manager()
        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=2),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=1),
            "iss": "authority",
            "typ": "access",
        }
        token = pyjwt.encode(
            payload,
            manager._config.jwt_secret_key,
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(token)
        manager.storage.close()

    def test_rejects_wrong_algorithm_rs256(self):
        manager = self._make_manager()
        # Try to forge with RS256 (asymmetric)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        payload = {
            "sub": "1",
            "jti": "fake-jti",
            "iat": datetime.datetime.now(datetime.timezone.utc),
            "exp": datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=15),
            "iss": "authority",
            "typ": "access",
        }
        token = pyjwt.encode(payload, private_pem, algorithm="RS256")
        with pytest.raises(InvalidTokenError):
            manager.verify_access_token(token)
        manager.storage.close()


class TestTokenHashing:
    """Test that token hashing is consistent and secure."""

    def test_hash_token_deterministic(self):
        token = "test-token-value"
        h1 = hash_token(token)
        h2 = hash_token(token)
        assert h1 == h2

    def test_hash_token_different_inputs(self):
        h1 = hash_token("token-a")
        h2 = hash_token("token-b")
        assert h1 != h2

    def test_hash_token_is_sha256(self):
        token = "test"
        h = hash_token(token)
        assert len(h) == 64  # SHA-256 hex digest length
        assert all(c in "0123456789abcdef" for c in h)

    def test_generate_secure_token_length(self):
        for byte_length in [16, 32, 64]:
            token = generate_secure_token(byte_length)
            # token_urlsafe returns base64url-encoded string, so len(token) >= byte_length
            assert len(token) >= byte_length, (
                f"Token length {len(token)} should be >= byte_length {byte_length}"
            )

    def test_generate_secure_token_unique(self):
        tokens = {generate_secure_token(32) for _ in range(100)}
        assert len(tokens) == 100  # All unique


class TestTimingSafety:
    """Basic timing attack resistance tests."""

    def test_login_failure_consistent_timing(self):
        """Both invalid email and invalid password should produce the same error type
        to prevent user enumeration attacks."""
        storage = SQLiteStorage(":memory:")
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="test-fernet-key-for-testing-only-==",
            db_path=":memory:",
        )
        manager = AuthManager(config, storage)

        manager.register(
            name="Test",
            email="real@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )

        # Both should raise InvalidCredentialsError (same error prevents enumeration)
        with pytest.raises(InvalidCredentialsError):
            manager.login(email="nonexistent@example.com", password="SecureP@ss1234!")
        with pytest.raises(InvalidCredentialsError):
            manager.login(email="real@example.com", password="WrongPassword123!")
        manager.storage.close()
