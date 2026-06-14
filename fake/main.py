# fake_easy_entra_id.py
"""
Fake Easy Entra ID pro lokální debug/development.

Účel:
    - chová se jako jednoduchá reverzní proxy před docker stackem
    - místo Microsoft Entra ID loginu zobrazí statickou stránku s výběrem uživatele
    - zvoleného uživatele uloží do cookie
    - při proxyování požadavku dovnitř stacku doplní hlavičky:
        x-ms-client-principal
        x-ms-client-principal-id
        x-ms-client-principal-name

Tím lze lokálně testovat stejný frontend bridge, který v produkci běží za easy_entra_id.

Použití:
    uvicorn fake_easy_entra_id:app --host 0.0.0.0 --port 8000

Typické env:
    TARGET_SERVER=http://frontend:8000
    FAKE_USERS_JSON=/app/fake_users.json
    FAKE_LOGIN_HTML_PATH=/app/fake_login.html
    FAKE_AUTH_COOKIE=fake_easy_entra_user
    FAKE_ALLOW_HEADER_IMPERSONATION=false

Bezpečnost:
    Toto je pouze debug/development nástroj.
    Nikdy nepoužívat jako produkční autentizační vrstvu.
"""

from __future__ import annotations

import base64
import functools
import html
import json
import os
import secrets
from pathlib import Path

from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

BASE_DIR = Path(__file__).resolve().parent

APP_TITLE = os.getenv("APP_TITLE", "Fake Easy Entra ID")
TARGET_SERVER = os.getenv("TARGET_SERVER", "http://frontend:8000")

FAKE_AUTH_COOKIE = os.getenv("FAKE_AUTH_COOKIE", "fake_easy_entra_user")
FAKE_USERS_JSON = os.getenv("FAKE_USERS_JSON", "fake_users.json")
FAKE_LOGIN_HTML_PATH = BASE_DIR / "index.html"
FAKE_LOGIN_HTML_PATH = os.getenv("FAKE_LOGIN_HTML_PATH", FAKE_LOGIN_HTML_PATH)
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))

# Pro vývoj může být užitečné impersonovat uživatele hlavičkou.
# Produkčně nikdy.
FAKE_ALLOW_HEADER_IMPERSONATION = (
    os.getenv("FAKE_ALLOW_HEADER_IMPERSONATION", "false").lower() == "true"
)

PASS_THROUGH_PREFIXES = tuple(
    p.strip()
    for p in os.getenv(
        "FAKE_PASS_THROUGH_PREFIXES",
        "/login,/fake-select-user,/fake-logout,/fake-users,/fake-health",
    ).split(",")
    if p.strip()
)

DEFAULT_USERS = [
    {
        "id": "97c80a87-8206-4845-98df-2af25ed33916",
        "oid": "97c80a87-8206-4845-98df-2af25ed33916",
        "email": "john.newbie@world.com",
        "name": "John Newbie",
        "roles": ["student", "user"],
    },
    {
        "id": "b06d811c-6945-4c74-bbc7-0222537d2e13",
        "oid": "b06d811c-6945-4c74-bbc7-0222537d2e13",
        "email": "planner.admin@world.com",
        "name": "Planner Admin",
        "roles": ["plánovací administrátor", "user"],
    },
    {
        "id": "7c03699a-f3c2-48b5-854f-8302c47145c9",
        "oid": "7c03699a-f3c2-48b5-854f-8302c47145c9",
        "email": "auditor@world.com",
        "name": "Auditor",
        "roles": ["auditor", "user"],
    },
]


app = FastAPI(title=APP_TITLE)


# ---------------------------------------------------------------------
# Fake users
# ---------------------------------------------------------------------

@functools.lru_cache(maxsize=1)
def load_fake_users() -> list[dict[str, Any]]:
    """
    Načte seznam fake uživatelů.

    Podporovaný soubor fake_users.json:

    [
      {
        "id": "lokalni-user-id",
        "oid": "entra-object-id",
        "email": "user@example.com",
        "name": "User Name",
        "roles": ["student"]
      }
    ]
    """
    try:
        with open(FAKE_USERS_JSON, "r", encoding="utf-8") as f:
            users = json.load(f)

        if isinstance(users, list):
            return [
                normalize_user(user)
                for user in users
                if isinstance(user, dict)
            ]
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Cannot load {FAKE_USERS_JSON}: {e}", flush=True)

    return [normalize_user(user) for user in DEFAULT_USERS]


def normalize_user(user: dict[str, Any]) -> dict[str, Any]:
    email = str(user.get("email") or user.get("preferred_username") or user.get("name") or "unknown@example.com")
    oid = str(user.get("oid") or user.get("id") or email)
    user_id = str(user.get("id") or oid)
    name = str(user.get("name") or email)
    roles = user.get("roles") or []

    if isinstance(roles, str):
        roles = [r.strip() for r in roles.split(",") if r.strip()]

    return {
        "id": user_id,
        "oid": oid,
        "email": email,
        "preferred_username": str(user.get("preferred_username") or email),
        "unique_name": str(user.get("unique_name") or email),
        "name": name,
        "roles": list(roles),
        "tenant_id": str(user.get("tenant_id") or "fake-tenant"),
        "raw": user,
    }


def find_user(identifier: str | None) -> dict[str, Any] | None:
    if not identifier:
        return None

    users = load_fake_users()

    for user in users:
        if identifier in {
            user["id"],
            user["oid"],
            user["email"],
            user["preferred_username"],
            user["unique_name"],
        }:
            return user

    return None

# In-memory session store pro fake login.
# Cookie obsahuje pouze náhodný opaque token, ne e-mail ani jiné claimy.
# Po restartu procesu se session ztratí, což je pro lokální debug v pořádku.
SESSION_BY_TOKEN: dict[str, str] = {}
TOKEN_BY_USER_ID: dict[str, str] = {}


def user_to_cookie_value(user: dict[str, Any]) -> str:
    user_id = user["id"]

    existing_token = TOKEN_BY_USER_ID.get(user_id)
    if existing_token and SESSION_BY_TOKEN.get(existing_token) == user_id:
        return existing_token

    cookie_value = secrets.token_urlsafe(32)
    SESSION_BY_TOKEN[cookie_value] = user_id
    TOKEN_BY_USER_ID[user_id] = cookie_value
    return cookie_value


def user_from_cookie_value(cookie_value: str | None) -> dict[str, Any] | None:
    if not cookie_value:
        return None

    user_id = SESSION_BY_TOKEN.get(cookie_value)
    if not user_id:
        return None

    return find_user(user_id)


def forget_cookie_value(cookie_value: str | None) -> None:
    if not cookie_value:
        return

    user_id = SESSION_BY_TOKEN.pop(cookie_value, None)
    if user_id and TOKEN_BY_USER_ID.get(user_id) == cookie_value:
        TOKEN_BY_USER_ID.pop(user_id, None)


def current_user_from_request(request: Request) -> dict[str, Any] | None:
    if FAKE_ALLOW_HEADER_IMPERSONATION:
        header_user = request.headers.get("x-fake-user")
        if header_user:
            user = find_user(header_user)
            if user:
                return user

    cookie_user = request.cookies.get(FAKE_AUTH_COOKIE)
    return user_from_cookie_value(cookie_user)


# ---------------------------------------------------------------------
# EasyAuth-compatible principal
# ---------------------------------------------------------------------

def build_claims(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "aud": "fake-easy-entra-id",
        "iss": "https://fake.easy-entra-id.local/v2.0",
        "tid": user["tenant_id"],
        "oid": user["oid"],
        "sub": user["oid"],
        "name": user["name"],
        "preferred_username": user["preferred_username"],
        "unique_name": user["unique_name"],
        "email": user["email"],
        "roles": user["roles"],
        "auth_time": "0",
        "idp": "fake",
    }


def build_x_ms_client_principal(user: dict[str, Any]) -> str:
    claims = build_claims(user)

    principal = {
        "auth_typ": "aad",
        "name_typ": "name",
        "role_typ": "roles",
        "claims": [
            {
                "typ": key,
                "val": ",".join(map(str, value)) if isinstance(value, list) else str(value),
            }
            for key, value in claims.items()
        ],
    }

    raw = json.dumps(principal, ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def add_fake_entra_headers(headers: dict[str, str], user: dict[str, Any]) -> dict[str, str]:
    result = dict(headers)

    # Odstraníme případné podstrčené hodnoty z klienta.
    for key in list(result.keys()):
        if key.lower().startswith("x-ms-client-principal"):
            result.pop(key, None)

    result["x-ms-client-principal"] = build_x_ms_client_principal(user)
    result["x-ms-client-principal-id"] = user["oid"]
    result["x-ms-client-principal-name"] = user["email"]
    result["x-fake-easy-entra-id"] = "true"

    return result


# ---------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------

def read_login_template(request: Request, error: str | None = None) -> str:
    users = load_fake_users()
    current_user = current_user_from_request(request)

    debug_data = {
        "appTitle": APP_TITLE,
        "targetServer": TARGET_SERVER,
        "cookieName": FAKE_AUTH_COOKIE,
        "currentUser": current_user,
        "users": users,
        "error": error,
        "next": request.query_params.get("next") or "/",
        "loginPath": "/login",
        "logoutPath": "/fake-logout",
        "notes": [
            "Toto je pouze debug/development náhrada easy_entra_id.",
            "Po výběru uživatele se do requestů propagují x-ms-client-principal hlavičky.",
            "Produkční easy_entra_id zůstává beze změny.",
        ],
    }

    try:
        template = open(FAKE_LOGIN_HTML_PATH, "r", encoding="utf-8").read()
    except FileNotFoundError:
        template = ("""<!doctype html><html lang="cs"><body><h1>Fake Easy Entra ID</h1><p>Missing template: {}</p></body></html>"""
            .format(html.escape(str(FAKE_LOGIN_HTML_PATH)))
        )
        

    safe_json = (
        json.dumps(debug_data, ensure_ascii=False, indent=2)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )

    result = template
    for placeholder in ['"__FAKE_EASY_ENTRA_DATA__"', "__FAKE_EASY_ENTRA_DATA__"]:
        if placeholder in result:
            result = result.replace(placeholder, safe_json)
            break

    return result


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------

@app.get("/fake-health")
async def fake_health():
    return {
        "ok": True,
        "service": "fake_easy_entra_id",
        "target_server": TARGET_SERVER,
        "users_count": len(load_fake_users()),
    }


@app.get("/fake-users")
async def fake_users():
    return {
        "users": load_fake_users(),
    }


@app.get("/login")
async def fake_login(request: Request):
    return HTMLResponse(read_login_template(request))


@app.post("/login")
@app.post("/fake-select-user")
async def fake_select_user(
    request: Request,
    user: str = Form(...),
    next: str = Form(default="/"),
):
    selected_user = find_user(user)

    if not selected_user:
        return HTMLResponse(
            read_login_template(request, error=f"Unknown fake user: {user}"),
            status_code=400,
        )

    response = RedirectResponse(next or "/", status_code=303)
    response.set_cookie(
        key=FAKE_AUTH_COOKIE,
        value=user_to_cookie_value(selected_user),
        httponly=True,
        secure=request.url.scheme == "https",
        samesite="lax",
        max_age=24 * 60 * 60,
    )
    return response


@app.get("/fake-logout")
async def fake_logout(request: Request, next: str = "/login"):
    forget_cookie_value(request.cookies.get(FAKE_AUTH_COOKIE))
    response = RedirectResponse(next or "/login", status_code=303)
    response.delete_cookie(FAKE_AUTH_COOKIE)
    return response


def is_pass_through(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PASS_THROUGH_PREFIXES)


async def proxy_to_target(request: Request, path: str, user: dict[str, Any]) -> Response:
    target_path = path.lstrip("/")
    url = f"{TARGET_SERVER.rstrip('/')}/{target_path}"

    if request.url.query:
        url += f"?{request.url.query}"

    body = await request.body()

    headers = dict(request.headers)
    headers.pop("host", None)

    # Cookie fake identity je jen pro tento kontejner, dovnitř stacku ji neposíláme.
    cookie = headers.get("cookie")
    if cookie:
        parts = [
            part.strip()
            for part in cookie.split(";")
            if not part.strip().startswith(f"{FAKE_AUTH_COOKIE}=")
        ]
        if parts:
            headers["cookie"] = "; ".join(parts)
        else:
            headers.pop("cookie", None)

    headers = add_fake_entra_headers(headers, user)

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=False) as client:
            upstream = await client.request(
                method=request.method,
                url=url,
                headers=headers,
                content=body,
            )
    except httpx.RequestError as e:
        return JSONResponse(
            status_code=502,
            content={
                "detail": "Target server request failed",
                "target_server": TARGET_SERVER,
                "reason": str(e),
            },
        )

    excluded_headers = {
        "connection",
        "content-encoding",
        "transfer-encoding",
    }

    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in excluded_headers
    }

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    request_path = request.url.path

    if is_pass_through(request_path):
        # explicitní routy výše by to většinou zachytily,
        # toto je jen bezpečnostní fallback.
        return HTMLResponse(read_login_template(request))

    user = current_user_from_request(request)

    if not user:
        if request.method in {"GET", "HEAD"}:
            next_url = quote(str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))
            return RedirectResponse(f"/login?next={next_url}", status_code=302)

        return JSONResponse(
            status_code=401,
            content={
                "detail": "Unauthenticated",
                "reason": "No fake user selected",
                "login": "/login",
            },
            headers={"WWW-Authenticate": "Fake"},
        )

    return await proxy_to_target(request, path, user)
