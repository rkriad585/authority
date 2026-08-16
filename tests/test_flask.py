"""Tests for authority.flask — Flask integration helpers."""

from __future__ import annotations

import datetime
from collections.abc import Generator

import jwt as pyjwt
import pytest
from flask import Flask, g

import authority.flask as flask_mod
from authority.core import AuthManager
from authority.flask import (
    FlaskAuth,
    current_user,
    extract_bearer_token,
    get_auth_manager,
    init_auth,
    login_required,
    require_permission,
    require_role,
)
from authority.utils import generate_secure_token

# ── Helpers ─────────────────────────────────────────────────


def _make_token(
    secret: str,
    sub: str = "1",
    exp_minutes: int = 15,
) -> str:
    """Create a valid access token for testing."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": sub,
        "jti": generate_secure_token(16),
        "iat": now,
        "exp": now + datetime.timedelta(minutes=exp_minutes),
        "iss": "authority",
        "typ": "access",
    }
    return pyjwt.encode(payload, secret, algorithm="HS256")


def _make_expired_token(secret: str, sub: str = "1") -> str:
    """Create an expired access token for testing."""
    return _make_token(secret, sub=sub, exp_minutes=-10)


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture()
def init_done(auth_manager: AuthManager) -> Generator[AuthManager, None, None]:
    """Initialize the module-level auth manager and reset after the test."""
    init_auth(auth_manager)
    yield auth_manager
    flask_mod._global_auth_manager = None


@pytest.fixture()
def app() -> Flask:
    """Create a Flask app with protected routes."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.secret_key = "test-secret-key"

    @app.route("/private")
    @login_required
    def private() -> str:
        return f"Hello {g.authority_user_id}"

    @app.route("/perm")
    @require_permission("app.read")
    def perm() -> str:
        return "ok"

    @app.route("/role")
    @require_role("admin")
    def role() -> str:
        return "ok"

    return app


@pytest.fixture()
def registered(auth_manager: AuthManager) -> dict:
    """Register and return a user."""
    return auth_manager.register(
        name="Test User",
        email="test@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
def access_token(auth_manager: AuthManager, registered: dict) -> str:
    """Return a real access token for the registered user."""
    result = auth_manager.login("test@example.com", "SecureP@ss1234!")
    return result["access_token"]


# ── init_auth / get_auth_manager ─────────────────────────────


class TestInitAuth:
    def test_init_and_get(self, auth_manager: AuthManager):
        init_auth(auth_manager)
        assert get_auth_manager() is auth_manager
        flask_mod._global_auth_manager = None

    def test_get_before_init_raises(self):
        flask_mod._global_auth_manager = None
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_manager()


# ── extract_bearer_token ─────────────────────────────────────


class TestExtractBearerToken:
    def test_from_header(self, app: Flask, init_done: AuthManager):
        with app.test_request_context(headers={"Authorization": "Bearer abc.def.ghi"}):
            assert extract_bearer_token() == "abc.def.ghi"

    def test_lowercase_scheme(self, app: Flask, init_done: AuthManager):
        with app.test_request_context(headers={"Authorization": "bearer tok"}):
            assert extract_bearer_token() == "tok"

    def test_missing_returns_none(self, app: Flask, init_done: AuthManager):
        with app.test_request_context():
            assert extract_bearer_token() is None

    def test_from_session(self, app: Flask, init_done: AuthManager):
        with app.test_request_context() as ctx:
            ctx.session["access_token"] = "session-token"
            assert extract_bearer_token() == "session-token"


# ── login_required ───────────────────────────────────────────


class TestLoginRequired:
    def test_valid_token(self, app: Flask, init_done: AuthManager, access_token: str):
        resp = app.test_client().get(
            "/private", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        assert resp.data.decode() == "Hello 1"

    def test_token_from_session(
        self, app: Flask, init_done: AuthManager, access_token: str
    ):
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["access_token"] = access_token
        resp = client.get("/private")
        assert resp.status_code == 200

    def test_missing_token(self, app: Flask, init_done: AuthManager):
        resp = app.test_client().get("/private")
        assert resp.status_code == 401

    def test_invalid_token(self, app: Flask, init_done: AuthManager):
        resp = app.test_client().get(
            "/private", headers={"Authorization": "Bearer garbage.token"}
        )
        assert resp.status_code == 401

    def test_expired_token(
        self, app: Flask, auth_manager: AuthManager, init_done: AuthManager
    ):
        token = _make_expired_token(auth_manager.config.jwt_secret_key)
        resp = app.test_client().get(
            "/private", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401


# ── require_permission ───────────────────────────────────────


class TestRequirePermission:
    def test_has_permission(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        perm = auth_manager.create_permission(code="app.read", description="Read")
        role = auth_manager.create_role(name="reader", description="Reader")
        auth_manager.assign_permission_to_role(role["id"], perm["id"])
        auth_manager.assign_role_to_user(registered["id"], role["id"])
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        resp = app.test_client().get(
            "/perm", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200

    def test_lacks_permission(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        auth_manager.create_permission(code="app.read", description="Read")
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        resp = app.test_client().get(
            "/perm", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    def test_unauthenticated(self, app: Flask, init_done: AuthManager):
        resp = app.test_client().get("/perm")
        assert resp.status_code == 401


# ── require_role ─────────────────────────────────────────────


class TestRequireRole:
    def test_has_role(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        role = auth_manager.create_role(name="admin", description="Admin")
        auth_manager.assign_role_to_user(registered["id"], role["id"])
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        resp = app.test_client().get(
            "/role", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 200

    def test_lacks_role(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        auth_manager.create_role(name="admin", description="Admin")
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        resp = app.test_client().get(
            "/role", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    def test_unauthenticated(self, app: Flask, init_done: AuthManager):
        resp = app.test_client().get("/role")
        assert resp.status_code == 401


# ── current_user ─────────────────────────────────────────────


class TestCurrentUser:
    def test_returns_user(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        with app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
            user = current_user()
            assert user is not None
            assert user["email"] == "test@example.com"

    def test_none_without_token(self, app: Flask, init_done: AuthManager):
        with app.test_request_context():
            assert current_user() is None

    def test_none_with_invalid_token(self, app: Flask, init_done: AuthManager):
        with app.test_request_context(headers={"Authorization": "Bearer bad"}):
            assert current_user() is None


# ── FlaskAuth instance ───────────────────────────────────────


class TestFlaskAuth:
    def test_init_app(self, app: Flask, auth_manager: AuthManager):
        fa = FlaskAuth()
        fa.init_app(app, auth_manager)
        assert fa.manager is auth_manager
        assert app.extensions["authority_auth"] is fa

    def test_constructor_binds(self, app: Flask, auth_manager: AuthManager):
        fa = FlaskAuth(app, auth_manager)
        assert fa.manager is auth_manager

    def test_manager_missing_raises(self):
        fa = FlaskAuth()
        with pytest.raises(RuntimeError, match="not initialized"):
            _ = fa.manager

    def test_login_required_decorator(
        self, auth_manager: AuthManager, init_done: AuthManager, access_token: str
    ):
        app = Flask(__name__)
        app.config["TESTING"] = True
        fa = FlaskAuth(app, auth_manager)

        @app.route("/me")
        @fa.login_required
        def me() -> str:
            return "ok"

        resp = app.test_client().get(
            "/me", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200

    def test_current_user_instance(
        self,
        app: Flask,
        auth_manager: AuthManager,
        init_done: AuthManager,
        registered: dict,
    ):
        fa = FlaskAuth(app, auth_manager)
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        with app.test_request_context(headers={"Authorization": f"Bearer {token}"}):
            user = fa.current_user()
            assert user is not None
            assert user["email"] == "test@example.com"
