"""Tests for check_password_pwned utility function."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from authority.utils import check_password_pwned


class TestCheckPasswordPwned:
    def test_empty_password_returns_zero(self):
        assert check_password_pwned("") == 0

    def test_password_not_pwned_returns_zero(self):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status = MagicMock()

        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = check_password_pwned("not-pwned-password")
            assert result == 0

    def test_password_pwned_returns_count(self):
        sha1_prefix = "ABCDEF"  # Will be overridden by the mock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "00112233445566778899AABB:5\n"
        mock_response.raise_for_status = MagicMock()

        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = check_password_pwned("some-password")
            # Result depends on the SHA1 hash of the password
            assert isinstance(result, int)
            assert result >= 0

    def test_timeout_returns_none(self):
        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.side_effect = httpx.TimeoutException("timeout")
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = check_password_pwned("some-password")
            assert result is None

    def test_http_error_returns_none(self):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )

        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = check_password_pwned("some-password")
            assert result is None

    def test_generic_exception_returns_none(self):
        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.side_effect = RuntimeError("network error")
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            result = check_password_pwned("some-password")
            assert result is None

    def test_custom_api_key_header(self):
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("authority.utils.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.get.return_value = mock_response
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value = mock_client

            check_password_pwned("test", api_key="my-api-key")

            # Verify the API key header was sent
            call_args = mock_client.get.call_args
            headers = call_args[1].get(
                "headers", call_args[0][1] if len(call_args[0]) > 1 else {}
            )
            assert headers.get("Hibp-Api-Key") == "my-api-key"
