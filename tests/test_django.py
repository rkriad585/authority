"""Tests for authority.django — Django integration helpers.

Django requires settings to be configured before any model is touched, so this
module configures a minimal in-memory setup at import time.
"""

from __future__ import annotations

import datetime
from collections.abc import Generator
from typing import Any, cast

import pytest

# Configure Django before importing anything that touches models.
from django.conf import settings

settings.configure(
    SECRET_KEY="test-secret-key-for-django-tests-0123456789abcdef",
    DEBUG=True,
    ALLOWED_HOSTS=["*"],
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "django.contrib.sessions",
        "django.contrib.messages",
    ],
    MIDDLEWARE=[
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    },
    ROOT_URLCONF=__name__,
    AUTHENTICATION_BACKENDS=["authority.django.AuthorityBackend"],
    LOGIN_URL="/login/",
    USE_TZ=True,
)

import django  # noqa: E402

django.setup()

from django.contrib.auth import authenticate  # noqa: E402
from django.contrib.auth.decorators import (  # noqa: E402
    login_required as django_login_required,  # noqa: E402
)
from django.contrib.auth.models import User  # noqa: E402
from django.http import HttpResponse  # noqa: E402
from django.test import Client, RequestFactory  # noqa: E402
from django.urls import path  # noqa: E402

import authority.django as django_mod  # noqa: E402
from authority.core import AuthManager  # noqa: E402
from authority.django import (  # noqa: E402
    AuthorityBackend,
    authority_user_to_django_user,
    extract_bearer_token,
    get_auth_manager,
    get_current_user,
    init_auth,
    login_required,
    require_permission,
    require_role,
)
from authority.utils import generate_secure_token  # noqa: E402

# ── Test views / URLs ───────────────────────────────────────


def login_view(request: Any) -> HttpResponse:
    """Session login view used by the Client-based integration test."""
    user = authenticate(
        request,
        email=request.POST.get("email", ""),
        password=request.POST.get("password", ""),
    )
    if user is not None:
        from django.contrib.auth import login

        login(request, user)
        return HttpResponse(b"logged-in")
    return HttpResponse(b"failed", status=401)


def private_view(request: Any) -> HttpResponse:
    """View protected by Django's session-based login_required."""
    return HttpResponse(b"session-secret")


def api_view(request: Any) -> HttpResponse:
    """View protected by authority's JWT login_required."""
    return HttpResponse(b"jwt-secret")


def perm_view(request: Any) -> HttpResponse:
    """View protected by authority's require_permission."""
    return HttpResponse(b"perm-ok")


def role_view(request: Any) -> HttpResponse:
    """View protected by authority's require_role."""
    return HttpResponse(b"role-ok")


urlpatterns = [
    path("login/", login_view),
    path("private-session/", django_login_required(private_view)),
    path("private-api/", login_required(api_view)),
    path("perm/", require_permission("app.read")(perm_view)),
    path("role/", require_role("admin")(role_view)),
]

# ── Helpers ─────────────────────────────────────────────────


def _make_token(
    secret: str,
    sub: str = "1",
    exp_minutes: int = 15,
) -> str:
    """Create a valid access token for testing."""
    import jwt as pyjwt

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


# ── Fixtures ────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def django_db() -> None:
    """Create the in-memory Django schema once per test session."""
    from django.core.management import call_command

    call_command("migrate", verbosity=0, interactive=False, run_syncdb=True)


@pytest.fixture(autouse=True)
def clean_django_users(django_db) -> Generator[None, None, None]:
    """Flush mirrored Django users between tests."""
    yield
    User.objects.all().delete()


@pytest.fixture()
def init_done(auth_manager: AuthManager):
    """Initialize the module-level auth manager and reset after the test."""
    init_auth(auth_manager)
    yield auth_manager
    django_mod._global_auth_manager = None


@pytest.fixture()
def registered(auth_manager: AuthManager) -> dict:
    """Register and return a user."""
    return auth_manager.register(
        name="Django User",
        email="django@example.com",
        password="SecureP@ss1234!",
        auto_verify=True,
    )


@pytest.fixture()
def access_token(auth_manager: AuthManager, registered: dict) -> str:
    """Return a real access token for the registered user."""
    result = auth_manager.login("django@example.com", "SecureP@ss1234!")
    return result["access_token"]


# ── init_auth / get_auth_manager ─────────────────────────────


class TestInitAuth:
    def test_init_and_get(self, auth_manager: AuthManager):
        init_auth(auth_manager)
        assert get_auth_manager() is auth_manager
        django_mod._global_auth_manager = None

    def test_get_before_init_raises(self):
        django_mod._global_auth_manager = None
        with pytest.raises(RuntimeError, match="not initialized"):
            get_auth_manager()


# ── authority_user_to_django_user ────────────────────────────


class TestMirrorUser:
    def test_creates_mirror(self, registered: dict):
        user = authority_user_to_django_user(registered)
        assert user.pk == registered["id"]
        assert user.username == "django@example.com"
        assert user.email == "django@example.com"
        assert not user.has_usable_password()

    def test_idempotent(self, registered: dict):
        first = authority_user_to_django_user(registered)
        second = authority_user_to_django_user(registered)
        assert first.pk == second.pk


# ── AuthorityBackend ─────────────────────────────────────────


class TestAuthorityBackend:
    def test_authenticate_email_password(self, auth_manager: AuthManager, init_done):
        auth_manager.register(
            name="Backend User",
            email="backend@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        user = authenticate(
            request=None, email="backend@example.com", password="SecureP@ss1234!"
        )
        assert user is not None
        assert user.username == "backend@example.com"

    def test_authenticate_wrong_password(self, auth_manager: AuthManager, init_done):
        auth_manager.register(
            name="Backend User",
            email="backend@example.com",
            password="SecureP@ss1234!",
            auto_verify=True,
        )
        user = authenticate(
            request=None, email="backend@example.com", password="WrongP@ss12345!"
        )
        assert user is None

    def test_authenticate_unknown_user(self, init_done):
        user = authenticate(
            request=None, email="nobody@example.com", password="SecureP@ss1234!"
        )
        assert user is None

    def test_authenticate_access_token(
        self, auth_manager: AuthManager, init_done, access_token: str
    ):
        user = authenticate(request=None, access_token=access_token)
        assert user is not None
        assert user.username == "django@example.com"

    def test_authenticate_mfa_required_returns_none(
        self, auth_manager: AuthManager, init_done, registered: dict
    ):
        import pyotp

        setup = auth_manager.setup_mfa(registered["id"])
        totp = pyotp.TOTP(setup["secret"])
        auth_manager.verify_and_enable_mfa(registered["id"], totp.now())
        user = authenticate(
            request=None,
            email="django@example.com",
            password="SecureP@ss1234!",
        )
        assert user is None

    def test_authenticate_no_credentials(self, init_done):
        assert authenticate(request=None) is None

    def test_get_user(self, registered: dict):
        user = authority_user_to_django_user(registered)
        assert AuthorityBackend().get_user(user.pk) == user

    def test_get_user_missing(self):
        assert AuthorityBackend().get_user(999_999) is None


# ── extract_bearer_token ─────────────────────────────────────


class TestExtractBearerToken:
    def test_parses_header(self):
        request = RequestFactory().get("/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer abc.def.ghi"
        assert extract_bearer_token(request) == "abc.def.ghi"

    def test_lowercase_scheme(self):
        request = RequestFactory().get("/")
        request.META["HTTP_AUTHORIZATION"] = "bearer tok"
        assert extract_bearer_token(request) == "tok"

    def test_missing(self):
        assert extract_bearer_token(RequestFactory().get("/")) is None


# ── get_current_user ─────────────────────────────────────────


class TestGetCurrentUser:
    def test_valid_token(self, auth_manager: AuthManager, init_done, access_token: str):
        request = RequestFactory().get("/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
        user = get_current_user(request)
        assert user is not None
        assert user["email"] == "django@example.com"

    def test_missing_token(self, auth_manager: AuthManager, init_done):
        assert get_current_user(RequestFactory().get("/")) is None

    def test_invalid_token(self, auth_manager: AuthManager, init_done):
        request = RequestFactory().get("/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer garbage"
        assert get_current_user(request) is None


# ── Decorators ───────────────────────────────────────────────


class TestDecorators:
    def test_login_required_allows(self, init_done, access_token: str):
        request = RequestFactory().get("/private-api/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {access_token}"
        response = login_required(api_view)(request)
        assert response.status_code == 200
        assert response.content == b"jwt-secret"

    def test_login_required_blocks_missing(self, init_done):
        response = login_required(api_view)(RequestFactory().get("/private-api/"))
        assert response.status_code == 401

    def test_login_required_blocks_invalid(self, init_done):
        request = RequestFactory().get("/private-api/")
        request.META["HTTP_AUTHORIZATION"] = "Bearer garbage"
        response = login_required(api_view)(request)
        assert response.status_code == 401

    def test_require_permission_allowed(
        self,
        auth_manager: AuthManager,
        init_done,
        registered: dict,
    ):
        perm = auth_manager.create_permission(code="app.read", description="Read")
        role = auth_manager.create_role(name="reader", description="Reader")
        auth_manager.assign_permission_to_role(role["id"], perm["id"])
        auth_manager.assign_role_to_user(registered["id"], role["id"])
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        request = RequestFactory().get("/perm/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        response = require_permission("app.read")(perm_view)(request)
        assert response.status_code == 200

    def test_require_permission_denied(
        self,
        auth_manager: AuthManager,
        init_done,
        registered: dict,
    ):
        auth_manager.create_permission(code="app.read", description="Read")
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        request = RequestFactory().get("/perm/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        response = require_permission("app.read")(perm_view)(request)
        assert response.status_code == 403

    def test_require_permission_unauthenticated(self, init_done):
        response = require_permission("app.read")(perm_view)(
            RequestFactory().get("/perm/")
        )
        assert response.status_code == 401

    def test_require_role_allowed(
        self,
        auth_manager: AuthManager,
        init_done,
        registered: dict,
    ):
        role = auth_manager.create_role(name="admin", description="Admin")
        auth_manager.assign_role_to_user(registered["id"], role["id"])
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        request = RequestFactory().get("/role/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        response = require_role("admin")(role_view)(request)
        assert response.status_code == 200

    def test_require_role_denied(
        self,
        auth_manager: AuthManager,
        init_done,
        registered: dict,
    ):
        auth_manager.create_role(name="admin", description="Admin")
        token = _make_token(
            auth_manager.config.jwt_secret_key, sub=str(registered["id"])
        )
        request = RequestFactory().get("/role/")
        request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        response = require_role("admin")(role_view)(request)
        assert response.status_code == 403

    def test_require_role_unauthenticated(self, init_done):
        response = require_role("admin")(role_view)(RequestFactory().get("/role/"))
        assert response.status_code == 401


# ── Full session login flow ──────────────────────────────────


class TestSessionFlow:
    def test_login_protected_session(
        self, auth_manager: AuthManager, init_done, registered: dict
    ):
        client = Client()
        response: HttpResponse = cast(
            "HttpResponse",
            client.post(
                "/login/",
                {"email": "django@example.com", "password": "SecureP@ss1234!"},
            ),
        )
        assert response.status_code == 200
        response = cast("HttpResponse", client.get("/private-session/"))
        assert response.status_code == 200
        assert response.content == b"session-secret"

    def test_login_failure(
        self, auth_manager: AuthManager, init_done, registered: dict
    ):
        client = Client()
        response: HttpResponse = cast(
            "HttpResponse",
            client.post(
                "/login/",
                {"email": "django@example.com", "password": "WrongP@ss12345!"},
            ),
        )
        assert response.status_code == 401
