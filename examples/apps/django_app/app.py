"""Runnable single-file Django example app using the authority library.

Django needs settings configured before any model is touched, so this module
configures a minimal setup at import time (no separate project/application
structure required).

A real web app: server-rendered HTML pages (``/``, ``/login``, ``/register``,
``/dashboard``) plus a JSON API (``/register``, ``/login``, ``/session-login``,
``/me``, ``/admin``). Logging in through the web UI sets an ``HttpOnly``
``access_token`` cookie; the dashboard is rendered server-side from the verified
token. A second, Django-session-based login flow is demonstrated at
``/session-login`` using :class:`authority.django.AuthorityBackend`.

Run from the repository root with:

    python -m examples.apps.django_app.app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

import json
from pathlib import Path

from django.conf import settings

_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "_templates"

settings.configure(
    SECRET_KEY="django-example-secret-key-change-me",
    DEBUG=True,
    ALLOWED_HOSTS=["*"],
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "django.contrib.sessions",
        "django.contrib.messages",
    ],
    MIDDLEWARE=[
        f"{__name__}.CookieToBearerMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "django.contrib.messages.middleware.MessageMiddleware",
    ],
    DATABASES={
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": "django_auth_db.sqlite3",
        }
    },
    TEMPLATES=[
        {
            "BACKEND": "django.template.backends.jinja2.Jinja2",
            "DIRS": [_TEMPLATES_DIR],
            "APP_DIRS": False,
        }
    ],
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
from django.core.handlers.wsgi import WSGIHandler  # noqa: E402
from django.http import HttpRequest, HttpResponse, JsonResponse  # noqa: E402
from django.shortcuts import redirect, render  # noqa: E402
from django.urls import path  # noqa: E402
from django.views.decorators.csrf import csrf_exempt  # noqa: E402

from authority.core import AuthManager  # noqa: E402
from authority.django import (  # noqa: E402
    get_current_user,
    init_auth,
    login_required,
    require_permission,
)
from authority.exceptions import (  # noqa: E402
    AuthError,
    InvalidCredentialsError,
    UserExistsError,
)
from authority.storage.sqlite import SQLiteStorage  # noqa: E402

from .._common import app_info, default_config, seed_demo_sync  # noqa: E402

DB_PATH = "django_auth.db"
APP_NAME = "Authority Django Example"

manager = AuthManager(default_config(DB_PATH), SQLiteStorage(DB_PATH))
init_auth(manager)
seed_demo_sync(manager)


class CookieToBearerMiddleware:
    """Treat the access_token cookie as a Bearer token when no header is sent.

    This lets the browser (which only has the cookie) use the header-based
    ``login_required`` / ``require_permission`` decorators unchanged.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if "HTTP_AUTHORIZATION" not in request.META:
            token = request.COOKIES.get("access_token")
            if token:
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return self.get_response(request)


def index(request):
    return render(
        request,
        "index.html",
        {
            "app_name": APP_NAME,
            "endpoints": [
                "/register",
                "/login",
                "/session-login",
                "/me",
                "/admin",
                "/session-protected",
                "/dashboard",
            ],
        },
    )


def _current_user_from_cookie(request: HttpRequest) -> dict | None:
    token = request.COOKIES.get("access_token")
    if not token:
        return None
    try:
        payload = manager.verify_access_token(token)
        return manager.get_user(payload["user_id"])
    except AuthError:
        return None


def dashboard(request):
    user = _current_user_from_cookie(request)
    if user is None:
        return redirect("/login")
    permissions = manager.get_user_permissions(user["id"])
    return render(
        request,
        "dashboard.html",
        {"app_name": APP_NAME, "user": user, "permissions": permissions},
    )


def logout(request):
    response = redirect("/login")
    response.delete_cookie("access_token")
    return response


def _parse_json(request) -> dict:
    if not request.body:
        return {}
    return json.loads(request.body)


@csrf_exempt
def register(request):
    if request.method != "POST":
        return render(request, "register.html", {"app_name": APP_NAME})
    data = _parse_json(request)
    try:
        user = manager.register(
            data["name"], data["email"], data["password"], auto_verify=True
        )
    except UserExistsError:
        return JsonResponse({"error": "Email already registered"}, status=409)
    return JsonResponse({"user_id": user["id"], "email": user["email"]})


@csrf_exempt
def login(request):
    if request.method != "POST":
        return render(request, "login.html", {"app_name": APP_NAME})
    data = _parse_json(request)
    try:
        result = manager.login(data["email"], data["password"])
    except InvalidCredentialsError:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
    response = JsonResponse(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )
    response.set_cookie(
        "access_token",
        result["access_token"],
        httponly=True,
        samesite="lax",
        max_age=manager.config.jwt_access_token_expiry_minutes * 60,
    )
    return response


@csrf_exempt
def session_login(request):
    """Login via Django sessions using the AuthorityBackend."""
    data = _parse_json(request)
    user = authenticate(
        request,
        email=data.get("email", ""),
        password=data.get("password", ""),
    )
    if user is None:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
    from django.contrib.auth import login

    login(request, user)
    return JsonResponse({"authenticated": True})


@login_required
def me(request):
    user = get_current_user(request)
    if user is None:
        return JsonResponse({"error": "Not authenticated"}, status=401)
    return JsonResponse(
        {"id": user["id"], "name": user["name"], "email": user["email"]}
    )


@require_permission("admin.access")
def admin(request):
    return JsonResponse(
        app_info(
            APP_NAME,
            [
                "/register",
                "/login",
                "/session-login",
                "/me",
                "/admin",
                "/session-protected",
                "/dashboard",
            ],
        )
    )


def session_protected(request):
    """Protected by Django's own session-based login_required."""
    return HttpResponse(b"session-protected")


urlpatterns = [
    path("", index),
    path("register", register),
    path("login", login),
    path("dashboard", dashboard),
    path("logout", logout),
    path("session-login", session_login),
    path("me", me),
    path("admin", admin),
    path("session-protected", django_login_required(session_protected)),
]

wsgi_app = WSGIHandler()

if __name__ == "__main__":
    from wsgiref.simple_server import make_server

    from django.core.management import call_command  # noqa: PLC0415

    call_command("migrate", verbosity=0, interactive=False)
    server = make_server("127.0.0.1", 8000, wsgi_app)  # type: ignore[arg-type]
    print("Serving Django app on http://127.0.0.1:8000")
    server.serve_forever()
