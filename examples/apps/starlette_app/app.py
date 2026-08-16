"""Runnable Starlette example app using the authority library.

A real web app: server-rendered HTML pages (``/``, ``/login``, ``/register``,
``/dashboard``) plus a JSON API (``/login``, ``/register``, ``/me``,
``/admin``). Logging in through the web UI sets an ``HttpOnly`` ``access_token``
cookie; the dashboard is rendered server-side from the verified token.

Run from the repository root with:

    pip install uvicorn
    uvicorn examples.apps.starlette_app.app:app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from authority.async_core import AsyncAuthManager
from authority.exceptions import (
    AuthError,
    InvalidCredentialsError,
    UserExistsError,
    ValidationError,
)
from authority.starlette import StarletteAuth
from authority.storage.aiosqlite import AsyncSQLiteStorage

from .._common import app_info, default_config, seed_demo_async

if TYPE_CHECKING:
    from starlette.requests import Request

DB_PATH = "starlette_auth.db"
APP_NAME = "Authority Starlette Example"
_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "_templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

storage = AsyncSQLiteStorage(DB_PATH)
manager = AsyncAuthManager(default_config(DB_PATH), storage)
auth = StarletteAuth(manager)


def _login_response(result: dict) -> JSONResponse:
    response = JSONResponse(
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


async def _current_user_from_cookie(request: Request) -> dict | None:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = await manager.verify_access_token(token)
        return await manager.get_user(payload["user_id"])
    except AuthError:
        return None


async def index(request: Request) -> Response:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": APP_NAME,
            "endpoints": ["/register", "/login", "/me", "/admin", "/dashboard"],
        },
    )


async def login_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "login.html", {"app_name": APP_NAME})


async def register_page(request: Request) -> Response:
    return templates.TemplateResponse(request, "register.html", {"app_name": APP_NAME})


async def dashboard(request: Request) -> Response:
    user = await _current_user_from_cookie(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    permissions = await manager.get_user_permissions(user["id"])
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"app_name": APP_NAME, "user": user, "permissions": permissions},
    )


async def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    return response


async def register(request: Request) -> JSONResponse:
    data = await request.json()
    try:
        user = await manager.register(
            data["name"], data["email"], data["password"], auto_verify=True
        )
    except UserExistsError:
        return JSONResponse({"error": "Email already registered"}, status_code=409)
    except ValidationError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"user_id": user["id"], "email": user["email"]})


async def login(request: Request) -> JSONResponse:
    data = await request.json()
    try:
        result = await manager.login(data["email"], data["password"])
    except InvalidCredentialsError:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    return _login_response(result)


@auth.login_required
async def me(request: Request) -> JSONResponse:
    user = await auth.current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return JSONResponse(
        {"id": user["id"], "name": user["name"], "email": user["email"]}
    )


@auth.require_permission("admin.access")
async def admin(request: Request) -> JSONResponse:
    return JSONResponse(
        app_info(
            APP_NAME,
            ["/register", "/login", "/me", "/admin", "/dashboard"],
        )
    )


class CookieAuthMiddleware(BaseHTTPMiddleware):
    """Treat the access_token cookie as a Bearer token when no header is sent.

    This lets the browser (which only has the cookie) use the header-based
    ``@auth.login_required`` / ``@auth.require_permission`` decorators unchanged.
    """

    async def dispatch(self, request: Request, call_next):
        if "authorization" not in request.headers:
            token = request.cookies.get("access_token")
            if token:
                headers = list(request.scope["headers"])
                headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
                request.scope["headers"] = headers
        return await call_next(request)


@asynccontextmanager
async def lifespan(app: Starlette):
    await storage.connect()
    await seed_demo_async(manager)
    yield
    await manager.close()


app = Starlette(
    routes=[
        Route("/", index),
        Route("/login", login_page, methods=["GET"]),
        Route("/login", login, methods=["POST"]),
        Route("/register", register_page, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/dashboard", dashboard),
        Route("/logout", logout, methods=["POST"]),
        Route("/me", me),
        Route("/admin", admin),
    ],
    middleware=[Middleware(CookieAuthMiddleware)],
    lifespan=lifespan,
)
