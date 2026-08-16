"""Runnable FastAPI example app using the authority library.

Run from the repository root with:

    pip install uvicorn
    uvicorn examples.apps.fastapi_app.app:app

The demo admin account is seeded on startup:

    email:    demo@example.com
    password: SecureP@ss1234!
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from authority.async_core import AsyncAuthManager
from authority.exceptions import InvalidCredentialsError, UserExistsError
from authority.fastapi import get_current_user, init_auth, require_permission
from authority.storage.aiosqlite import AsyncSQLiteStorage

from .._common import default_config, seed_demo_async

DB_PATH = "fastapi_auth.db"


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

require_admin = asyncio.run(require_permission("admin.access"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await storage.connect()
    await seed_demo_async(manager)
    yield
    await manager.close()


app = FastAPI(title="Authority FastAPI Example", lifespan=lifespan)


@app.post("/register")
async def register(body: RegisterBody) -> JSONResponse:
    try:
        user = await manager.register(
            body.name, body.email, body.password, auto_verify=True
        )
    except UserExistsError:
        return JSONResponse({"error": "Email already registered"}, status_code=409)
    return JSONResponse({"user_id": user["id"], "email": user["email"]})


@app.post("/login")
async def login(body: LoginBody) -> JSONResponse:
    try:
        result = await manager.login(body.email, body.password)
    except InvalidCredentialsError:
        return JSONResponse({"error": "Invalid credentials"}, status_code=401)
    return JSONResponse(
        {
            "access_token": result["access_token"],
            "refresh_token": result["refresh_token"],
            "token_type": "Bearer",
        }
    )


@app.get("/me")
async def me(payload: dict = Depends(get_current_user)):  # noqa: B008
    user = await manager.get_user(payload["user_id"])
    return {"id": user["id"], "name": user["name"], "email": user["email"]}


@app.get("/admin")
async def admin(_: dict = Depends(require_admin)):  # noqa: B008
    return {"message": "Welcome, admin!"}
