"""Tests for authority.wsgi — framework-agnostic WSGI authentication middleware."""

from __future__ import annotations

import io
import json

import pytest

from authority.core import AuthManager
from authority.wsgi import (
    AuthorityWSGIMiddleware,
    get_current_user,
    get_user_state,
    is_authenticated,
    user_id_from_environ,
)

# ── Helpers ─────────────────────────────────────────────────


def _build_environ(headers: dict[str, str] | None = None) -> dict:
    """Build a minimal WSGI environ."""
    env: dict = {
        "REQUEST_METHOD": "GET",
        "PATH_INFO": "/",
        "SCRIPT_NAME": "",
        "QUERY_STRING": "",
        "SERVER_NAME": "localhost",
        "SERVER_PORT": "80",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    if headers:
        env.update(headers)
    return env


def _call(app, environ: dict) -> tuple[str, str]:
    """Invoke a WSGI app and return (status, body)."""
    captured: dict = {}

    def start_response(status: str, response_headers: list, exc_info=None) -> None:
        captured["status"] = status
        captured["headers"] = response_headers

    body = b"".join(app(environ, start_response))
    return captured["status"], body.decode()


def _state_app(environ: dict, start_response) -> list[bytes]:
    """Echo the authority state from the environ as JSON."""
    state = get_user_state(environ)
    body = json.dumps(state).encode()
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


def _sample_app(environ: dict, start_response) -> list[bytes]:
    """Return the authenticated user's email as a plain response."""
    state = get_user_state(environ)
    user_id = user_id_from_environ(environ)
    text = f"authenticated={state.get('authenticated', False)};user_id={user_id}"
    body = text.encode()
    start_response(
        "200 OK",
        [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture()
def registered_user(auth_manager: AuthManager) -> dict:
    """Register and return a user."""
    return auth_manager.register(
        name="WSGI User",
        email="wsgi@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
def access_token(auth_manager: AuthManager, registered_user: dict) -> str:
    """Return a real access token for the registered user."""
    result = auth_manager.login("wsgi@example.com", "SecureP@ss1234!")
    return result["access_token"]


# ── Middleware behaviour ─────────────────────────────────────


class TestMiddleware:
    def test_authenticated_request(self, auth_manager: AuthManager, access_token: str):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        status, body = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": f"Bearer {access_token}"})
        )
        state = json.loads(body)
        assert status.startswith("200")
        assert state["authenticated"] is True
        assert state["user_id"] == 1
        assert state["token"] == access_token
        assert state["payload"]["user_id"] == 1

    def test_lowercase_scheme(self, auth_manager: AuthManager, access_token: str):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _, body = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": f"bearer {access_token}"})
        )
        assert json.loads(body)["authenticated"] is True

    def test_unauthenticated_request(self, auth_manager: AuthManager):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        status, body = _call(app, _build_environ())
        assert status.startswith("200")
        assert json.loads(body)["authenticated"] is False

    def test_invalid_token(self, auth_manager: AuthManager):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _, body = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": "Bearer garbage.token"})
        )
        assert json.loads(body)["authenticated"] is False

    def test_expired_token(self, auth_manager: AuthManager):
        import datetime

        import jwt as pyjwt

        from authority.utils import generate_secure_token

        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "sub": "1",
            "jti": generate_secure_token(16),
            "iat": now,
            "exp": now - datetime.timedelta(minutes=10),
            "iss": "authority",
            "typ": "access",
        }
        token = pyjwt.encode(
            payload, auth_manager.config.jwt_secret_key, algorithm="HS256"
        )
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _, body = _call(app, _build_environ({"HTTP_AUTHORIZATION": f"Bearer {token}"}))
        assert json.loads(body)["authenticated"] is False

    def test_auth_required_without_token(self, auth_manager: AuthManager):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager, auth_required=True)
        status, body = _call(app, _build_environ())
        assert status.startswith("401")
        assert json.loads(body) == {"detail": "Authentication required."}

    def test_auth_required_invalid_token(self, auth_manager: AuthManager):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager, auth_required=True)
        status, _ = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": "Bearer bad.token"})
        )
        assert status.startswith("401")

    def test_auth_required_valid_token(
        self, auth_manager: AuthManager, access_token: str
    ):
        app = AuthorityWSGIMiddleware(_state_app, auth_manager, auth_required=True)
        status, body = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": f"Bearer {access_token}"})
        )
        assert status.startswith("200")
        assert json.loads(body)["authenticated"] is True

    def test_app_sees_state(self, auth_manager: AuthManager, access_token: str):
        app = AuthorityWSGIMiddleware(_sample_app, auth_manager)
        _, body = _call(
            app, _build_environ({"HTTP_AUTHORIZATION": f"Bearer {access_token}"})
        )
        assert body == "authenticated=True;user_id=1"


# ── Helpers ─────────────────────────────────────────────────


class TestHelpers:
    def test_get_user_state_default(self):
        assert get_user_state({}) == {"authenticated": False}

    def test_is_authenticated(self, auth_manager: AuthManager, access_token: str):
        environ = _build_environ({"HTTP_AUTHORIZATION": f"Bearer {access_token}"})
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _call(app, environ)
        assert is_authenticated(environ) is True
        assert user_id_from_environ(environ) == 1

    def test_get_current_user(
        self, auth_manager: AuthManager, access_token: str, registered_user: dict
    ):
        environ = _build_environ({"HTTP_AUTHORIZATION": f"Bearer {access_token}"})
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _call(app, environ)
        user = get_current_user(environ, auth_manager)
        assert user is not None
        assert user["email"] == "wsgi@example.com"

    def test_get_current_user_unauthenticated(self, auth_manager: AuthManager):
        environ = _build_environ()
        app = AuthorityWSGIMiddleware(_state_app, auth_manager)
        _call(app, environ)
        assert get_current_user(environ, auth_manager) is None
