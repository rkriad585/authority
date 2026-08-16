"""Runnable single-file Django example app using the authority library.

Django needs settings configured before any model is touched, so this module
configures a minimal setup at import time (no separate project/application
structure required).

Run from the repository root with:

    python -m examples.apps.django_app.app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

import json

from django.conf import settings

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
from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.urls import path  # noqa: E402
from django.views.decorators.csrf import csrf_exempt  # noqa: E402

from authority.core import AuthManager  # noqa: E402
from authority.django import (  # noqa: E402
    get_current_user,
    init_auth,
    login_required,
    require_permission,
)
from authority.exceptions import InvalidCredentialsError, UserExistsError  # noqa: E402
from authority.storage.sqlite import SQLiteStorage  # noqa: E402

from .._common import default_config, seed_demo_sync  # noqa: E402

DB_PATH = "django_auth.db"

manager = AuthManager(default_config(DB_PATH), SQLiteStorage(DB_PATH))
init_auth(manager)
seed_demo_sync(manager)


def _parse_json(request) -> dict:
    if not request.body:
        return {}
    return json.loads(request.body)


@csrf_exempt
def register(request):
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
    data = _parse_json(request)
    try:
        result = manager.login(data["email"], data["password"])
    except InvalidCredentialsError:
        return JsonResponse({"error": "Invalid credentials"}, status=401)
    return JsonResponse(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )


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
    return JsonResponse({"message": "Welcome, admin!"})


def session_protected(request):
    """Protected by Django's own session-based login_required."""
    return HttpResponse(b"session-protected")


urlpatterns = [
    path("register", register),
    path("login", login),
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
