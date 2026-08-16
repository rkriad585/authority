"""Generate product screenshots for the authority-auth project.

Creates terminal-style PNG images of real authority-auth code examples using
PIL (Pillow). Run from the repository root:

    python tools/screenshots_gen.py

Output is written to ``Screenshots/``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import cast

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "Screenshots"

# ── Palette ────────────────────────────────────────────────────────────────
WINDOW_BG = (30, 41, 59)
TITLE_BAR = (23, 33, 48)
BORDER = (51, 65, 85)
CODE_FG = (226, 232, 240)
LINE_NUM = (100, 116, 139)
DOT_RED = (248, 113, 113)
DOT_YELLOW = (251, 191, 36)
DOT_GREEN = (74, 222, 128)
TITLE_FG = (148, 163, 184)

KIND_COLORS = {
    "plain": (226, 232, 240),
    "keyword": (196, 132, 252),
    "string": (134, 239, 172),
    "comment": (100, 116, 139),
    "number": (251, 191, 36),
    "decorator": (34, 211, 238),
    "name": (226, 232, 240),
    "call": (96, 165, 250),
    "op": (148, 163, 184),
}

KEYWORDS = {
    "and",
    "as",
    "assert",
    "async",
    "await",
    "break",
    "class",
    "continue",
    "def",
    "del",
    "elif",
    "else",
    "except",
    "False",
    "finally",
    "for",
    "from",
    "global",
    "if",
    "import",
    "in",
    "is",
    "lambda",
    "None",
    "not",
    "or",
    "pass",
    "raise",
    "return",
    "True",
    "try",
    "while",
    "with",
    "yield",
}

_TOKEN_RE = re.compile(
    r"""
      (?P<comment>\#[^\n]*)
    | (?P<string>(?:[rRbBuUfF]{1,2})?(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"))
    | (?P<decorator>@\w+(?:\([^)]*\))?)
    | (?P<number>\b\d+(?:\.\d+)?\b)
    | (?P<name>\w+)
    | (?P<op>\S)
    """,
    re.VERBOSE,
)

# ── Fonts ──────────────────────────────────────────────────────────────────
FONT_CANDIDATES = {
    "regular": [
        "C:/Windows/Fonts/consola.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ],
    "bold": [
        "C:/Windows/Fonts/consolab.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
        "/System/Library/Fonts/Menlo.ttc",
    ],
}


def _load_font(path: str, size: int) -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES[path]:
        try:
            return ImageFont.truetype(candidate, size)
        except OSError:
            continue
    return cast(ImageFont.FreeTypeFont, ImageFont.load_default(size))


def _rgb(color: tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % color


def _tokenize(line: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    for match in _TOKEN_RE.finditer(line):
        if match.start() > pos:
            tokens.append((line[pos : match.start()], "plain"))
        text, kind = match.group(), match.lastgroup or "op"
        if kind == "name" and text not in KEYWORDS and _is_call(line, match.end()):
            kind = "call"
        tokens.append((text, kind))
        pos = match.end()
    if pos < len(line):
        tokens.append((line[pos:], "plain"))
    return tokens


def _is_call(line: str, after: int) -> bool:
    while after < len(line) and line[after] in " \t":
        after += 1
    return after < len(line) and line[after] == "("


def _wrap(
    indent: str,
    tokens: list[tuple[str, str]],
    font: ImageFont.FreeTypeFont,
    max_width: int,
) -> list[tuple[str, list[tuple[str, str]]]]:
    lines: list[tuple[str, list[tuple[str, str]]]] = []
    current: list[tuple[str, str]] = []
    width = 0
    for text, kind in tokens:
        text_width = font.getlength(text)
        if current and width + text_width > max_width:
            lines.append((indent, current))
            current = []
            width = 0
            indent = "        "
        current.append((text, kind))
        width += text_width
    if current:
        lines.append((indent, current))
    return lines


def _draw_tokens(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    tokens: list[tuple[str, str]],
    font: ImageFont.FreeTypeFont,
) -> int:
    for text, kind in tokens:
        color = KIND_COLORS.get(kind, KIND_COLORS["plain"])
        draw.text((x, y), text, font=font, fill=_rgb(color))
        x += int(font.getlength(text))
    return x


def render_snippet(
    title: str,
    source: str,
    *,
    filename: str,
    show_line_numbers: bool = True,
    shell: bool = False,
    font_size: int = 22,
    padding: int = 44,
) -> Path:
    """Render one code snippet into a terminal-style PNG and return its path."""
    font = _load_font("regular", font_size)
    metrics = font.getmetrics()
    line_height = metrics[0] + metrics[1] + 10

    title_bar_height = 46
    title_font = _load_font("bold", 18)

    source_lines = source.splitlines()
    wrapped: list[tuple[int, tuple[str, list[tuple[str, str]]]]] = []
    if shell:
        max_text_width = 1500
    else:
        max_text_width = 0
        for line in source_lines:
            tokens = _tokenize(line)
            width = sum(font.getlength(t) for t, _ in tokens)
            max_text_width = max(max_text_width, int(width))
        max_text_width = min(max(max_text_width, 720), 1500)

    for idx, line in enumerate(source_lines):
        tokens = _tokenize(line)
        for indent, part in _wrap("", tokens, font, max_text_width):
            wrapped.append((idx, (indent, part)))

    num_width = int(font.getlength("000")) + 24 if show_line_numbers else 0
    text_width = 0
    for _, (_, parts) in wrapped:
        text_width = max(text_width, int(sum(font.getlength(t) for t, _ in parts)))

    window_width = max(text_width, 720) + num_width + padding * 2
    window_height = title_bar_height + len(wrapped) * line_height + padding

    image = Image.new("RGB", (window_width, window_height), TITLE_BAR)
    draw = ImageDraw.Draw(image)

    draw.rounded_rectangle(
        [0, 0, window_width - 1, window_height - 1],
        radius=16,
        fill=WINDOW_BG,
        outline=BORDER,
    )
    draw.rectangle([0, 0, window_width - 1, title_bar_height], fill=TITLE_BAR)

    dot_y = title_bar_height // 2
    for i, color in enumerate((DOT_RED, DOT_YELLOW, DOT_GREEN)):
        cx = 26 + i * 22
        draw.ellipse([cx - 6, dot_y - 6, cx + 6, dot_y + 6], fill=_rgb(color))

    title_text = title_font.getlength(title)
    draw.text(
        ((window_width - title_text) / 2, (title_bar_height - 26) / 2),
        title,
        font=title_font,
        fill=_rgb(TITLE_FG),
    )
    draw.line([0, title_bar_height, window_width, title_bar_height], fill=BORDER)

    y = title_bar_height + padding // 2
    for source_idx, (indent, parts) in wrapped:
        x = padding
        if show_line_numbers and not shell:
            draw.text((x, y), str(source_idx + 1), font=font, fill=_rgb(LINE_NUM))
            x += num_width
        if shell:
            if indent:
                draw.text((x, y), ">", font=font, fill=_rgb(LINE_NUM))
            else:
                draw.text((x, y), "$", font=font, fill=_rgb((74, 222, 128)))
            x += int(font.getlength("$ ")) + 8
        _draw_tokens(draw, x + int(font.getlength(indent)), y, parts, font)
        y += line_height

    output = OUTPUT_DIR / filename
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output)
    return output


SNIPPETS: list[dict[str, object]] = [
    {
        "filename": "home.png",
        "title": "authority — quick start",
        "source": """\
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

config = AuthConfig(
    jwt_secret_key="your-secret-key-min-32-chars",
    fernet_key="your-fernet-key",
)
auth = AuthManager(config, SQLiteStorage("auth.db"))

# Register and verify a new user
user = auth.register(
    "Alice", "alice@example.com", "SecureP@ssw0rd!", auto_verify=True
)
print(f"Registered user: {user['id']}")

# Login and receive a token pair
result = auth.login(email="alice@example.com", password="SecureP@ssw0rd!")
print(f"Access token: {result['access_token'][:20]}...")

# Verify the access token
payload = auth.verify_access_token(result["access_token"])
print(f"User ID from token: {payload['user_id']}")

auth.close()""",
    },
    {
        "filename": "quickstart.png",
        "title": "sync usage — register · login · refresh · logout",
        "source": """\
from authority import AuthConfig, AuthManager
from authority.storage import SQLiteStorage

auth = AuthManager(
    AuthConfig(
        jwt_secret_key="your-secret-key-min-32-chars",
        fernet_key="your-fernet-key",
    ),
    SQLiteStorage("auth.db"),
)

with auth:
    user = auth.register(
        "Alice", "alice@example.com", "SecureP@ssw0rd!", auto_verify=True
    )
    result = auth.login("alice@example.com", "SecureP@ssw0rd!")

    # Refresh token rotation with reuse detection
    new_tokens = auth.refresh_access_token(result["refresh_token"])

    # Log out this session
    auth.logout(
        user_id=user["id"],
        refresh_token=result["refresh_token"],
        access_token_jti=result["access_token"],
    )""",
    },
    {
        "filename": "async.png",
        "title": "async usage — AsyncAuthManager",
        "source": """\
import asyncio
from authority import AsyncAuthManager, AuthConfig
from authority.storage import AsyncSQLiteStorage

async def main():
    storage = AsyncSQLiteStorage("auth.db")
    await storage.connect()

    auth = AsyncAuthManager(
        AuthConfig(
            jwt_secret_key="your-secret-key-min-32-chars",
            fernet_key="your-fernet-key",
        ),
        storage,
    )

    user = await auth.register(
        "Bob", "bob@example.com", "SecureP@ssw0rd!", auto_verify=True
    )
    result = await auth.login("bob@example.com", "SecureP@ssw0rd!")
    payload = await auth.verify_access_token(result["access_token"])
    print(f"User ID: {payload['user_id']}")
    await auth.close()

asyncio.run(main())""",
    },
    {
        "filename": "mfa.png",
        "title": "TOTP MFA — setup · login · recovery codes",
        "source": """\
# 1. Initiate setup — returns a secret and provisioning URI
setup = auth.setup_mfa(user_id=user["id"])
print(setup["provisioning_uri"])  # render this as a QR code

# 2. User scans the QR code and enters a 6-digit code
result = auth.verify_and_enable_mfa(user_id=user["id"], code="123456")
print(result["recovery_codes"])  # store these once

# 3. During login, when MFA is required:
login_result = auth.login(email="alice@example.com", password="...")
if login_result.get("mfa_required"):
    tokens = auth.verify_mfa_login(
        user_id=login_result["user_id"], code="654321"
    )

# 4. Check status and disable when no longer needed
status = auth.get_mfa_status(user_id=user["id"])
print(f"MFA enabled: {status['mfa_enabled']}")
auth.disable_mfa(user_id=user["id"], password="...")""",
    },
    {
        "filename": "rbac.png",
        "title": "RBAC — roles · permissions · checks",
        "source": """\
admin_role = auth.create_role("admin", "Full system access")
editor_role = auth.create_role("editor", "Can edit content")

read = auth.create_permission("posts:read")
write = auth.create_permission("posts:write")
delete = auth.create_permission("posts:delete")

auth.assign_permission_to_role(admin_role["id"], read["id"])
auth.assign_permission_to_role(admin_role["id"], write["id"])
auth.assign_permission_to_role(admin_role["id"], delete["id"])
auth.assign_role_to_user(user_id=1, role_id=admin_role["id"])

if auth.has_permission(user_id=1, permission_code="posts:delete"):
    print("User can delete posts")

perms = auth.get_user_permissions(user_id=1)
print(perms)  # ["posts:read", "posts:write", "posts:delete"]""",
    },
    {
        "filename": "apikeys.png",
        "title": "API keys — create · verify · revoke",
        "source": """\
key_result = auth.create_api_key(
    user_id=user["id"],
    description="Production API access",
    scopes=["read", "write"],
    expires_in_days=90,
)
print(f"Key (shown only once): {key_result['key']}")
print(f"Prefix: {key_result['prefix']}")

# Verify a key sent by a client
key_info = auth.verify_api_key(key_result["key"])
print(f"User: {key_info['user_id']}, Scopes: {key_info['scopes']}")

# List and revoke when no longer needed
keys = auth.list_api_keys(user_id=user["id"])
auth.revoke_api_key(user_id=user["id"], key_prefix=key_result["prefix"])""",
    },
    {
        "filename": "webauthn.png",
        "title": "WebAuthn / passkeys",
        "source": """\
# Browser requests options for navigator.credentials.create()
options = auth.start_webauthn_registration(user_id=user["id"])

# Verify the credential response returned by the browser
auth.complete_webauthn_registration(
    user_id=user["id"], credential_data=browser_credential
)

# Sign in with a passkey
auth_options = auth.start_webauthn_authentication(user_id=user["id"])
auth.complete_webauthn_authentication(credential_data=browser_assertion)

# Manage registered credentials
credentials = auth.list_webauthn_credentials(user_id=user["id"])
auth.delete_webauthn_credential(
    user_id=user["id"], credential_id=credentials[0]["credential_id"]
)""",
    },
    {
        "filename": "events.png",
        "title": "event bus — subscribe to lifecycle events",
        "source": """\
from authority import AuthManager, Event, EventBus

bus = EventBus()

def on_login(data):
    print(f"Login: user {data['user_id']} from {data.get('ip_address')}")

async def on_register(data):
    await send_welcome_email(data["email"])

bus.on(Event.USER_LOGIN_SUCCESS, on_login)
bus.on(Event.USER_REGISTERED, on_register)

auth = AuthManager(config, storage, event_bus=bus)""",
    },
    {
        "filename": "fastapi.png",
        "title": "FastAPI integration",
        "source": """\
import asyncio
from fastapi import Depends, FastAPI
from authority import AsyncAuthManager, AuthConfig
from authority.fastapi import get_current_user, init_auth, require_permission
from authority.storage import AsyncSQLiteStorage

app = FastAPI()
manager = AsyncAuthManager(
    AuthConfig(jwt_secret_key="...", fernet_key="..."),
    AsyncSQLiteStorage("auth.db"),
)
init_auth(manager)

require_admin = asyncio.run(require_permission("admin.access"))

@app.get("/me")
async def me(payload: dict = Depends(get_current_user)):
    return {"user_id": payload["user_id"]}

@app.get("/admin")
async def admin(_: dict = Depends(require_admin)):
    return {"message": "Welcome, admin!"}""",
    },
    {
        "filename": "flask.png",
        "title": "Flask integration",
        "source": """\
from flask import Flask, jsonify
from authority import AuthConfig, AuthManager
from authority.flask import FlaskAuth, current_user, init_auth
from authority.storage import SQLiteStorage

app = Flask(__name__)
app.secret_key = "app-session-secret"

manager = AuthManager(
    AuthConfig(jwt_secret_key="...", fernet_key="..."),
    SQLiteStorage("auth.db"),
)
init_auth(manager)
auth = FlaskAuth(app, manager)

@app.get("/me")
@auth.login_required
def me():
    user = current_user()
    return jsonify({"id": user["id"], "email": user["email"]})

@app.get("/admin")
@auth.require_permission("admin.access")
def admin():
    return jsonify({"message": "Welcome, admin!"})""",
    },
    {
        "filename": "django.png",
        "title": "Django integration",
        "source": """\
from django.http import JsonResponse
from django.urls import path
from authority.django import (
    get_current_user,
    init_auth,
    login_required,
    require_permission,
)

init_auth(auth_manager)

@login_required
def me(request):
    user = get_current_user(request)
    return JsonResponse({"email": user["email"]})

@require_permission("admin.access")
def admin(request):
    return JsonResponse({"message": "Welcome, admin!"})

urlpatterns = [
    path("me", me),
    path("admin", admin),
]""",
    },
    {
        "filename": "starlette.png",
        "title": "Starlette integration",
        "source": """\
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from authority.starlette import StarletteAuth

auth = StarletteAuth(async_manager)

@auth.login_required
async def me(request):
    user = await auth.current_user(request)
    return JSONResponse({"id": user["id"]})

@auth.require_permission("admin.access")
async def admin(request):
    return JSONResponse({"message": "Welcome, admin!"})

app = Starlette(routes=[Route("/me", me), Route("/admin", admin)])""",
    },
    {
        "filename": "middleware.png",
        "title": "framework-agnostic ASGI & WSGI middleware",
        "source": """\
# ASGI — works with Starlette, FastAPI, Quart, or bare ASGI apps
from authority.asgi import AuthorityASGIMiddleware

app = AuthorityASGIMiddleware(inner_app, async_manager, auth_required=True)

# WSGI — works with Flask, Django, or bare WSGI apps
from authority.wsgi import AuthorityWSGIMiddleware

app = AuthorityWSGIMiddleware(inner_app, manager, auth_required=True)

# Read the authentication state back inside your application
state = get_user_state(scope)          # scope["authority"]
if is_authenticated(scope):
    user = get_current_user(scope, async_manager)
    print(user["email"])""",
    },
    {
        "filename": "terminal.png",
        "title": "example app — try the live endpoints",
        "source": """\
# Register a new account
curl -X POST http://127.0.0.1:8000/register \\
  -H "Content-Type: application/json" \\
  -d '{"name": "Alice", "email": "alice@example.com", "password": "SecureP@ssw0rd!"}'

# Log in with the demo admin account
curl -X POST http://127.0.0.1:8000/login \\
  -H "Content-Type: application/json" \\
  -d '{"email": "demo@example.com", "password": "SecureP@ss1234!"}'

# Call a protected endpoint with the returned token
curl http://127.0.0.1:8000/me \\
  -H "Authorization: Bearer <access_token>"
""",
        "shell": True,
    },
]


def main() -> int:
    generated: list[Path] = []
    for snippet in SNIPPETS:
        path = render_snippet(
            str(snippet["title"]),
            str(snippet["source"]),
            filename=str(snippet["filename"]),
            shell=bool(snippet.get("shell", False)),
        )
        generated.append(path)
        print(f"Generated {path.relative_to(ROOT)}")
    print(f"\n{len(generated)} screenshots written to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
