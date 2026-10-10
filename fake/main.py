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
import time
import uuid
import logging
from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager
from pathlib import Path

from typing import Any
from urllib.parse import quote

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

BASE_DIR = Path(__file__).resolve().parent

APP_TITLE = os.getenv("APP_TITLE", "Fake Easy Entra ID")
TARGET_SERVER = os.getenv("TARGET_SERVER", "http://localhost:8080")

FAKE_AUTH_COOKIE = os.getenv("FAKE_AUTH_COOKIE", "fake_easy_entra_user")
# Výchozí JSON hledáme vedle tohoto modulu, nezávisle na pracovním adresáři.
FAKE_USERS_JSON = os.getenv("FAKE_USERS_JSON") or str(BASE_DIR / "fake_users.json")
FAKE_LOGIN_HTML_PATH = BASE_DIR / "index.html"
FAKE_LOGIN_HTML_PATH = os.getenv("FAKE_LOGIN_HTML_PATH", FAKE_LOGIN_HTML_PATH)
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))

# Logicka identita issueru nemusi odpovidat lokalni Docker DNS adrese.
JWT_ISSUER = os.getenv("JWT_ISSUER", "https://auth.dev.company.cz").rstrip("/")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "internal-api")
JWT_DISCOVERY_BASE_URL = os.getenv(
    "JWT_DISCOVERY_BASE_URL", "http://easy-entra-fake:8000"
).rstrip("/")
JWT_PRIVATE_KEY_FILE = Path(os.getenv(
    "JWT_PRIVATE_KEY_FILE", "/tmp/easy-entra-id-fake/jwt-private.pem"
))
JWT_KEY_ID = os.getenv("JWT_KEY_ID", "fake-shield-dev-1")
JWT_TOKEN_LIFETIME_SECONDS = int(os.getenv("JWT_TOKEN_LIFETIME_SECONDS", "900"))
JWT_PROXY_BEARER = os.getenv("JWT_PROXY_BEARER", "false").lower() == "true"
JWT_PROXY_IDENTITY_HEADER = os.getenv("JWT_PROXY_IDENTITY_HEADER", "false").lower() == "true"
if JWT_TOKEN_LIFETIME_SECONDS < 1 or JWT_TOKEN_LIFETIME_SECONDS > 86400:
    raise ValueError("JWT_TOKEN_LIFETIME_SECONDS must be between 1 and 86400")
if not JWT_ISSUER.startswith("https://") and not JWT_ISSUER.startswith("http://"):
    raise ValueError("JWT_ISSUER must be an absolute HTTP(S) URL")
if not JWT_DISCOVERY_BASE_URL.startswith(("https://", "http://")):
    raise ValueError("JWT_DISCOVERY_BASE_URL must be an absolute HTTP(S) URL")


def load_signing_key():
    """Generate a local development key once, or reuse a persisted RSA private key."""
    key_file = JWT_PRIVATE_KEY_FILE
    key_file.parent.mkdir(parents=True, exist_ok=True)
    if not key_file.exists():
        # Exclusive creation avoids silently replacing a concurrent container's key.
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            fd = os.open(str(key_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            logging.warning("Generated development JWT signing key at %s", key_file)
        except FileExistsError:
            pass
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("JWT_PRIVATE_KEY_FILE must contain an RSA private key")
    return key


def encode_rsa_number(value: int) -> str:
    return base64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode("ascii")


def create_identity_token(user: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": JWT_ISSUER, "aud": JWT_AUDIENCE,
        "sub": user["oid"], "oid": user["oid"], "tid": user["tenant_id"],
        "name": user["name"], "email": user["email"],
        "preferred_username": user["preferred_username"],
        "roles": user["roles"], "idp": "fake",
        "iat": now, "nbf": now,
        "exp": now + timedelta(seconds=JWT_TOKEN_LIFETIME_SECONDS),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, app.state.signing_key, algorithm="RS256",
                      headers={"kid": JWT_KEY_ID, "typ": "JWT"})


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Jeden sdílený klient pro celou aplikaci: zachová connection pool/keep-alive
    # a neměří opakované vytváření klienta jako součást upstream času.
    app.state.signing_key = load_signing_key()
    app.state.http = httpx.AsyncClient(
        timeout=HTTP_TIMEOUT_SECONDS,
        follow_redirects=False,
    )
    try:
        yield
    finally:
        await app.state.http.aclose()


app = FastAPI(title=APP_TITLE, lifespan=lifespan)


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
        "scp": user.get("scopes", []),
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
@app.get("/.well-known/openid-configuration")
async def oidc_discovery():
    # Minimal issuer discovery for JWT validation, NOT full OIDC implementation.
    return {
        "issuer": JWT_ISSUER,
        "jwks_uri": f"{JWT_DISCOVERY_BASE_URL}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/.well-known/jwks.json")
async def jwks(request: Request):
    numbers = request.app.state.signing_key.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": JWT_KEY_ID,
        "n": encode_rsa_number(numbers.n),
        "e": encode_rsa_number(numbers.e),
    }]}


@app.post("/auth/token")
async def auth_token(request: Request):
    # Only an existing fake session (or explicitly enabled fake impersonation)
    # can request a token. Never accept a freely supplied user ID.
    user = current_user_from_request(request)
    if user is None:
        return JSONResponse({"detail": "Not authenticated", "login": "/login"}, status_code=401)
    return {
        "access_token": create_identity_token(user),
        "token_type": "Bearer",
        "expires_in": JWT_TOKEN_LIFETIME_SECONDS,
    }


@app.get("/auth/verify")
async def verify_token(request: Request):
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        return JSONResponse({"detail": "Bearer token required"}, status_code=401)
    try:
        claims = jwt.decode(
            authorization[7:].strip(), request.app.state.signing_key.public_key(),
            algorithms=["RS256"], issuer=JWT_ISSUER, audience=JWT_AUDIENCE,
            options={"require": ["iss", "aud", "sub", "exp", "iat", "nbf"]},
        )
    except jwt.PyJWTError:
        return JSONResponse({"detail": "Invalid token"}, status_code=401)
    return {"valid": True, "claims": claims}



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


async def proxy_to_target(
    request: Request,
    path: str,
    user: dict[str, Any],
) -> tuple[Response, float]:
    """
    Proxy request to TARGET_SERVER.

    Returns:
        (response, proxied_server_ms)

    proxied_server_ms measures only the await of the upstream HTTP request,
    i.e. from handing the request to httpx until the complete upstream response
    has been received by this proxy.
    """
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
    # Strip caller-supplied fake identity JWT header (never trust external clients).
    headers.pop("x-easy-entra-jwt", None)
    if JWT_PROXY_BEARER:
        headers["authorization"] = f"Bearer {create_identity_token(user)}"
    if JWT_PROXY_IDENTITY_HEADER:
        headers["x-easy-entra-jwt"] = create_identity_token(user)

    http: httpx.AsyncClient = request.app.state.http

    upstream_started = time.perf_counter()
    try:
        upstream = await http.request(
            method=request.method,
            url=url,
            headers=headers,
            content=body,
        )
    except httpx.RequestError as e:
        proxied_server_ms = (time.perf_counter() - upstream_started) * 1000.0
        response = JSONResponse(
            status_code=502,
            content={
                "detail": "Target server request failed",
                "target_server": TARGET_SERVER,
                "reason": str(e),
            },
        )
        return response, proxied_server_ms

    proxied_server_ms = (time.perf_counter() - upstream_started) * 1000.0

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

    response = Response(
        content=upstream.content,
        status_code=upstream.status_code,
        headers=response_headers,
        media_type=upstream.headers.get("content-type"),
    )
    return response, proxied_server_ms


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    total_started = time.perf_counter()
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

    response, proxied_server_ms = await proxy_to_target(request, path, user)
    total_ms = (time.perf_counter() - total_started) * 1000.0

    print(
        f"[PROXY] {request.method} {request_path} "
        f"status={response.status_code} "
        f"total={total_ms:.2f}ms "
        f"proxied_server={proxied_server_ms:.2f}ms",
        flush=True,
    )

    return response
