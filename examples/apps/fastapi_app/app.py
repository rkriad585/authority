"""Runnable FastAPI example app using the authority library.

A real web app: server-rendered HTML pages (``/``, ``/login``, ``/register``,
``/dashboard``) plus a JSON API (``/login``, ``/register``, ``/me``,
``/admin``). Logging in through the web UI sets an ``HttpOnly`` ``access_token``
cookie; the dashboard is rendered server-side from the verified token.

Run from the repository root with:

    pip install uvicorn
    uvicorn examples.apps.fastapi_app.app:app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.templating import Jinja2Templates

from authority.async_core import AsyncAuthManager
from authority.exceptions import (
    AuthError,
    InvalidCredentialsError,
    UserExistsError,
    ValidationError,
)
from authority.fastapi import get_current_user, init_auth, require_permission
from authority.storage.aiosqlite import AsyncSQLiteStorage

from .._common import app_info, default_config, seed_demo_async

DB_PATH = "fastapi_auth.db"
APP_NAME = "Authority FastAPI Example"
_TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "_templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


class RegisterBody(BaseModel):
    name: str
    email: str
    password: str


class LoginBody(BaseModel):
    email: str
    password: str


storage = AsyncSQLiteStorage(DB_PATH)
manager = AsyncAuthManager(default_config(DB_PATH), storage)
init_auth(manager)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await storage.connect()
    await seed_demo_async(manager)
    yield
    await manager.close()


app = FastAPI(title=APP_NAME, lifespan=lifespan)


@app.middleware("http")
async def _cookie_to_bearer(request: Request, call_next):
    """Treat the access_token cookie as a Bearer token when no header is sent.

    This lets the browser (which only has the cookie) use the header-based
    ``get_current_user`` / ``require_permission`` dependencies unchanged.
    """
    if "authorization" not in request.headers:
        token = request.cookies.get("access_token")
        if token:
            headers = list(request.scope["headers"])
            headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
            request.scope["headers"] = headers
    return await call_next(request)


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


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "app_name": APP_NAME,
            "endpoints": ["/register", "/login", "/me", "/admin", "/dashboard"],
            "docs_url": "/docs",
        },
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "login.html", {"app_name": APP_NAME})


@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "register.html", {"app_name": APP_NAME})


@app.get("/dashboard", response_model=None)
async def dashboard(request: Request) -> HTMLResponse | RedirectResponse:
    user = await _current_user_from_cookie(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    permissions = await manager.get_user_permissions(user["id"])
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"app_name": APP_NAME, "user": user, "permissions": permissions},
    )


@app.post("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    return response


@app.post("/register")
async def register(body: RegisterBody) -> JSONResponse:
    try:
        user = await manager.register(
            body.name, body.email, body.password, auto_verify=True
        )
    except UserExistsError:
        return JSONResponse({"error": "Email already registered"}, status_code=409)
    except ValidationError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse({"user_id": user["id"], "email": user["email"]})


@app.post("/login")
async def login(body: LoginBody) -> JSONResponse:
    try:
        result = await manager.login(body.email, body.password)
    except InvalidCredentialsError:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    return _login_response(result)


@app.get("/me")
async def me(payload: dict = Depends(get_current_user)):  # noqa: B008
    user = await manager.get_user(payload["user_id"])
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


@app.get("/admin")
async def admin(_: dict = Depends(require_permission("admin.access"))):  # noqa: B008
    return app_info(APP_NAME, ["/register", "/login", "/me", "/admin", "/dashboard"])
