"""Tests for authority.config."""

from __future__ import annotations

import pytest

from authority.config import AuthConfig
from authority.exceptions import ConfigurationError


class TestAuthConfig:
    def test_defaults(self):
        config = AuthConfig()
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_access_token_expiry_minutes == 15
        assert config.password_min_length == 12
        assert config.hibp_failure_mode == "warn"

    def test_validation_missing_jwt_key(self):
        config = AuthConfig(jwt_secret_key="", fernet_key="valid-key")
        with pytest.raises(ConfigurationError, match="jwt_secret_key"):
            config.validate()

    def test_validation_missing_fernet_key(self):
        config = AuthConfig(jwt_secret_key="valid-key", fernet_key="")
        with pytest.raises(ConfigurationError, match="fernet_key"):
            config.validate()

    def test_validation_negative_expiry(self):
        config = AuthConfig(
            jwt_secret_key="key",
            fernet_key="key",
            jwt_access_token_expiry_minutes=-1,
        )
        with pytest.raises(ConfigurationError, match="jwt_access_token_expiry_minutes"):
            config.validate()

    def test_validation_invalid_hibp_mode(self):
        config = AuthConfig(
            jwt_secret_key="key",
            fernet_key="key",
            hibp_failure_mode="invalid",
        )
        with pytest.raises(ConfigurationError, match="hibp_failure_mode"):
            config.validate()

    def test_validation_short_password_min(self):
        config = AuthConfig(
            jwt_secret_key="key",
            fernet_key="key",
            password_min_length=4,
        )
        with pytest.raises(ConfigurationError, match="password_min_length"):
            config.validate()

    def test_validation_passes(self):
        config = AuthConfig(
            jwt_secret_key="test-secret-key-for-testing-only-32chars!",
            fernet_key="dGVzdC1rZXktMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY=",
        )
        config.validate()  # Should not raise

    def test_env_var_loading(self, monkeypatch):
        monkeypatch.setenv("AUTHORITY_JWT_SECRET_KEY", "from-env")
        monkeypatch.setenv(
            "AUTHORITY_FERNET_KEY", "dGVzdC1rZXktMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY="
        )
        config = AuthConfig()
        assert config.jwt_secret_key == "from-env"

    def test_constructor_overrides_env(self, monkeypatch):
        monkeypatch.setenv("AUTHORITY_JWT_SECRET_KEY", "from-env")
        config = AuthConfig(jwt_secret_key="from-constructor")
        assert config.jwt_secret_key == "from-constructor"
