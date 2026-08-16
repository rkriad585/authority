"""Runnable Starlette example app using the authority library.

Run from the repository root with:

    pip install uvicorn
    uvicorn examples.apps.starlette_app.app:app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from authority.async_core import AsyncAuthManager
from authority.exceptions import InvalidCredentialsError, UserExistsError
from authority.starlette import StarletteAuth
from authority.storage.aiosqlite import AsyncSQLiteStorage

from .._common import default_config, seed_demo_async

if TYPE_CHECKING:
    from starlette.requests import Request

DB_PATH = "starlette_auth.db"

storage = AsyncSQLiteStorage(DB_PATH)
manager = AsyncAuthManager(default_config(DB_PATH), storage)
auth = StarletteAuth(manager)


async def register(request: Request) -> JSONResponse:
    data = await request.json()
    try:
        user = await manager.register(
            data["name"], data["email"], data["password"], auto_verify=True
        )
    except UserExistsError:
        return JSONResponse({"error": "Email already registered"}, status_code=409)
    return JSONResponse({"user_id": user["id"], "email": user["email"]})


async def login(request: Request) -> JSONResponse:
    data = await request.json()
    try:
        result = await manager.login(data["email"], data["password"])
    except InvalidCredentialsError:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    return JSONResponse(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )


@auth.login_required
async def me(request: Request) -> JSONResponse:
    user = await auth.current_user(request)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(
        {"id": user["id"], "name": user["name"], "email": user["email"]}
    )


@auth.require_permission("admin.access")
async def admin(request: Request) -> JSONResponse:
    return JSONResponse({"message": "Welcome, admin!"})


@asynccontextmanager
async def lifespan(app: Starlette):
    await storage.connect()
    await seed_demo_async(manager)
    yield
    await manager.close()


app = Starlette(
    routes=[
        Route("/register", register, methods=["POST"]),
        Route("/login", login, methods=["POST"]),
        Route("/me", me),
        Route("/admin", admin),
    ],
    lifespan=lifespan,
)
