# fake/main.py
"""
Fake Easy Entra ID pro lokální debug/development.

Účel:
    - chová se jako jednoduchá reverzní proxy před docker stackem
    - místo Microsoft Entra ID loginu zobrazí statickou stránku s výběrem uživatele
    - zvoleného uživatele uloží do cookie (cookie nese jen opaque token,
      session samotná žije v paměti procesu)
    - při proxyování požadavku dovnitř stacku doplní hlavičky:
        x-ms-client-principal
        x-ms-client-principal-id
        x-ms-client-principal-name
    - vydává vlastní RS256 JWT a publikuje JWKS, takže funguje jako
      plnohodnotný vydavatel identity pro auth_shield

Spolupráce s auth_shield
========================

auth_shield ověřuje příchozí JWT proti registrovaným vydavatelům. Fake je
jeden z nich, takže musí splnit stejný kontrakt jako reálné Entra ID:

    issuer    = JWT_ISSUER            (logická identita, ne adresa)
    jwks_uri  = JWT_DISCOVERY_BASE_URL + /.well-known/jwks.json
    audience  = JWT_AUDIENCE
    podpis    = RS256, kid = JWT_KEY_ID

Na straně auth_shield to odpovídá položce v `ISSUERS_JSON`:

    {
      "fake": {
        "issuer": "https://auth.dev.company.cz",
        "jwks_uri": "http://easy-entra-fake:8000/.well-known/jwks.json",
        "audience": ["internal-api"]
      }
    }

`/fake-health` vrací `issuer`, `audience` a `jwks_uri`, takže se hodnoty
nemusí opisovat ručně.

Použití:
    uvicorn main:app --host 0.0.0.0 --port 8000

Typické env:
    TARGET_SERVER=http://frontend:8000
    FAKE_USERS_JSON=/app/fake_users.json
    FAKE_LOGIN_HTML_PATH=/app/index.html
    FAKE_AUTH_COOKIE=fake_easy_entra_user
    FAKE_ALLOW_HEADER_IMPERSONATION=false
    FAKE_PASS_THROUGH_PREFIXES=/login,/fake-select-user,/fake-logout,/fake-users,/fake-health,/auth/login
    HTTP_TIMEOUT_SECONDS=30

JWT (určeno pro auth_shield):
    JWT_ISSUER=https://auth.dev.company.cz
    JWT_AUDIENCE=internal-api
    JWT_DISCOVERY_BASE_URL=http://easy-entra-fake:8000
    JWT_PRIVATE_KEY_FILE=/tmp/easy-entra-id-fake/jwt-private.pem
    JWT_KEY_ID=fake-shield-dev-1
    JWT_TOKEN_LIFETIME_SECONDS=900
    JWT_PROXY_MODE=bearer

`JWT_PROXY_MODE` určuje, jak se token předává upstreamu:

    bearer  Authorization: Bearer <JWT>   (vyžaduje auth_shield)
    header  x-easy-entra-jwt: <JWT>
    both    obojí
    none    jen EasyAuth principal hlavičky (původní chování)

Staré `JWT_PROXY_BEARER` / `JWT_PROXY_IDENTITY_HEADER` fungují dál a sčítají
se s `JWT_PROXY_MODE`.

Endpointy:
    GET  /login                        výběr fake uživatele
    POST /login, /fake-select-user     přihlášení jako zvolený uživatel
    GET  /fake-logout                  odhlášení
    GET  /fake-users                   seznam uživatelů (JSON)
    GET  /fake-health                  health check + issuer/jwks metadata
    GET  /.well-known/openid-configuration
    GET  /.well-known/jwks.json
    POST /auth/token                   vydání JWT pro aktuální fake session
    GET  /auth/verify                  ověření Bearer JWT
    *    /{path}                       proxy na TARGET_SERVER

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
# How the fake identity is propagated to the upstream (auth_shield).
#   bearer  - Authorization: Bearer <JWT>   (required by auth_shield)
#   header  - x-easy-entra-jwt: <JWT>
#   both    - both of the above
#   none    - only EasyAuth principal headers (legacy behaviour)
JWT_PROXY_MODE = os.getenv("JWT_PROXY_MODE", "bearer").strip().lower()
if JWT_PROXY_MODE not in {"bearer", "header", "both", "none"}:
    raise ValueError(
        "JWT_PROXY_MODE must be one of: bearer, header, both, none"
    )

# Legacy booleans kept for backwards compatibility. They are OR-ed with
# JWT_PROXY_MODE so existing compose files keep working.
JWT_PROXY_BEARER = (
    os.getenv("JWT_PROXY_BEARER", "false").lower() == "true"
    or JWT_PROXY_MODE in {"bearer", "both"}
)
JWT_PROXY_IDENTITY_HEADER = (
    os.getenv("JWT_PROXY_IDENTITY_HEADER", "false").lower() == "true"
    or JWT_PROXY_MODE in {"header", "both"}
)

if JWT_TOKEN_LIFETIME_SECONDS < 1 or JWT_TOKEN_LIFETIME_SECONDS > 86400:
    raise ValueError("JWT_TOKEN_LIFETIME_SECONDS must be between 1 and 86400")
if not JWT_ISSUER.startswith("https://") and not JWT_ISSUER.startswith("http://"):
    raise ValueError("JWT_ISSUER must be an absolute HTTP(S) URL")
if not JWT_DISCOVERY_BASE_URL.startswith(("https://", "http://")):
    raise ValueError("JWT_DISCOVERY_BASE_URL must be an absolute HTTP(S) URL")
# `iss` and `jwks_uri` are compared by exact match on the consumer side, so a
# trailing slash or query would silently break validation.
if JWT_ISSUER.endswith("/"):
    raise ValueError("JWT_ISSUER must not end with a trailing slash")
if JWT_DISCOVERY_BASE_URL.endswith("/"):
    raise ValueError("JWT_DISCOVERY_BASE_URL must not end with a trailing slash")


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
    """Zakóduje RSA parametr (n/e) do base64url bez paddingu, jak ho čeká JWKS."""
    return base64url_encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode("ascii")


def create_identity_token(user: dict[str, Any]) -> str:
    """
    Vytvoří RS256 JWT s Entra-like claimy pro daného fake uživatele.

    Token je podepsaný klíčem z app.state.signing_key a má `kid` shodný s JWKS,
    takže ho auth_shield i /auth/verify ověří stejně jako reálný Entra token.
    """
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

# Strojový login (`POST /auth/login`) vrací JWT přímo v těle odpovědi.
# Zapíná se explicitně, protože obchází proklikání formulářem.
FAKE_ENABLE_MACHINE_LOGIN = (
    os.getenv("FAKE_ENABLE_MACHINE_LOGIN", "false").lower() == "true"
)

PASS_THROUGH_PREFIXES = tuple(
    p.strip()
    for p in os.getenv(
        "FAKE_PASS_THROUGH_PREFIXES",
        "/login,/fake-select-user,/fake-logout,/fake-users,/fake-health,/auth/login",
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
    """
    Sjednotí zápis uživatele z JSONu do interního tvaru.

    Chybějící pole dopočítá (oid z id/emailu, preferred_username z emailu,
    tenant_id na "fake-tenant") a `roles` přijme i jako čárkou oddělený string.
    Původní objekt zůstává v `raw`.
    """
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
    """
    Dohledá uživatele podle libovolného identifikátoru.

    Přijímá id, oid, email, preferred_username i unique_name, aby šlo v URL,
    cookie i hlavičce `x-fake-user` použít cokoli z toho.
    """
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


def verify_user_password(user: dict[str, Any], password: str) -> bool:
    """
    Ověří heslo fake uživatele.

    Pokud má uživatel v JSONu `password`, porovnává se s ním. Jinak se
    uplatní dev konvence `password == email`, aby šel strojový login použít
    bez úprav datového souboru.

    Porovnání je konstantní v čase, aby nešlo heslo uhádnout po znacích.
    """
    expected = user["raw"].get("password")

    if not isinstance(expected, str) or not expected:
        expected = user["email"]

    return secrets.compare_digest(password, expected)


# In-memory session store pro fake login.
# Cookie obsahuje pouze náhodný opaque token, ne e-mail ani jiné claimy.
# Po restartu procesu se session ztratí, což je pro lokální debug v pořádku.
SESSION_BY_TOKEN: dict[str, str] = {}
TOKEN_BY_USER_ID: dict[str, str] = {}


def user_to_cookie_value(user: dict[str, Any]) -> str:
    """
    Vrátí opaque token pro cookie, případně založí novou session.

    Pro stejného uživatele se reusuje existující token, aby opakované přihlášení
    neakumulovalo session v paměti.
    """
    user_id = user["id"]

    existing_token = TOKEN_BY_USER_ID.get(user_id)
    if existing_token and SESSION_BY_TOKEN.get(existing_token) == user_id:
        return existing_token

    cookie_value = secrets.token_urlsafe(32)
    SESSION_BY_TOKEN[cookie_value] = user_id
    TOKEN_BY_USER_ID[user_id] = cookie_value
    return cookie_value


def user_from_cookie_value(cookie_value: str | None) -> dict[str, Any] | None:
    """Přeloží opaque cookie token na uživatele; neznámý token vrací None."""
    if not cookie_value:
        return None

    user_id = SESSION_BY_TOKEN.get(cookie_value)
    if not user_id:
        return None

    return find_user(user_id)


def forget_cookie_value(cookie_value: str | None) -> None:
    """Zruší session pro daný cookie token (logout)."""
    if not cookie_value:
        return

    user_id = SESSION_BY_TOKEN.pop(cookie_value, None)
    if user_id and TOKEN_BY_USER_ID.get(user_id) == cookie_value:
        TOKEN_BY_USER_ID.pop(user_id, None)


def current_user_from_request(request: Request) -> dict[str, Any] | None:
    """
    Určí aktuálního fake uživatele z requestu.

    Prioritu má hlavička `x-fake-user`, ale jen když je explicitně povolená
    přes FAKE_ALLOW_HEADER_IMPERSONATION. Jinak rozhoduje session cookie.
    """
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
    """
    Sestaví Entra-like claim sadu, kterou nese x-ms-client-principal.

    `scp` se bere z `scopes` v JSONu; ostatní claimy odpovídají tomu, co
    auth_shield očekává od EasyAuth hlaviček.
    """
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
    """
    Zakóduje principal do formátu App Service EasyAuth.

    Výsledkem je base64 JSON s `auth_typ`/`name_typ`/`role_typ` a polem `claims`,
    kde jsou všechny hodnoty stringy (listy spojené čárkou).
    """
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
    """
    Doplní do kopie hlaviček EasyAuth identitu zvoleného uživatele.

    Všechny příchozí `x-ms-client-principal*` hlavičky nejdřív zahodí, aby
    klient nemohl podstrčit cizí identitu.
    """
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
    """
    Načte index.html a vloží do něj data pro React UI.

    Data se serializují jako JSON a escapují (`&`, `<`, `>`), aby šla bezpečně
    vložit do `<script type="application/json">`. Při chybějícím template
    vrátí minimální náhradní HTML.
    """
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
    """
    Minimální OIDC discovery dokument.

    Slouží jen k tomu, aby si klient (auth_shield) našel `jwks_uri`.
    Nejde o plnohodnotnou OIDC implementaci.
    """
    # Minimal issuer discovery for JWT validation, NOT full OIDC implementation.
    return {
        "issuer": JWT_ISSUER,
        "jwks_uri": f"{JWT_DISCOVERY_BASE_URL}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
        "audiences_supported": [JWT_AUDIENCE],
    }


@app.get("/.well-known/jwks.json")
async def jwks(request: Request):
    """Publikuje veřejnou část podpisového RSA klíče ve formátu JWKS."""
    numbers = request.app.state.signing_key.public_key().public_numbers()
    return {"keys": [{
        "kty": "RSA", "use": "sig", "alg": "RS256", "kid": JWT_KEY_ID,
        "n": encode_rsa_number(numbers.n),
        "e": encode_rsa_number(numbers.e),
    }]}


@app.post("/auth/token")
async def auth_token(request: Request):
    """
    Vydá JWT pro aktuálně přihlášeného fake uživatele.

    Token se vydává jen na základě existující fake session (nebo explicitně
    povolené impersonace hlavičkou), nikdy pro uživatele zadaného v requestu.
    """
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


@app.post("/auth/login")
async def machine_login(request: Request):
    """
    Strojový login: e-mail + heslo -> JWT přímo v těle odpovědi.

    Určeno pro klienty, kteří neumí pracovat s cookie (skripty, CI, testy).
    Na rozdíl od `POST /login` nenastavuje session cookie a nevrací
    přesměrování, takže klient dostane token v jednom requestu.

    Heslo se ověřuje přes `verify_user_password`: pokud má uživatel
    v `fake_users.json` pole `password`, použije se to; jinak platí dev
    konvence `password == email`.

    Endpoint je vypnutý, dokud není nastaveno `FAKE_ENABLE_MACHINE_LOGIN=true`.
    """
    if not FAKE_ENABLE_MACHINE_LOGIN:
        return JSONResponse(
            {"detail": "Machine login is disabled"},
            status_code=404,
        )

    payload = await _read_login_payload(request)

    email = str(payload.get("email") or payload.get("user") or "").strip()
    password = str(payload.get("password") or "")

    if not email or not password:
        return JSONResponse(
            {"detail": "Both 'email' and 'password' are required"},
            status_code=400,
        )

    user = find_user(email)

    # Same response for unknown user and wrong password: no user enumeration.
    if user is None or not verify_user_password(user, password):
        return JSONResponse(
            {"detail": "Invalid credentials"},
            status_code=401,
        )

    return {
        "access_token": create_identity_token(user),
        "token_type": "Bearer",
        "expires_in": JWT_TOKEN_LIFETIME_SECONDS,
        "user": {
            "oid": user["oid"],
            "email": user["email"],
            "name": user["name"],
            "roles": user["roles"],
        },
    }


async def _read_login_payload(request: Request) -> dict[str, Any]:
    """
    Přečte přihlašovací údaje z JSONu i z form-encoded těla.

    JSON je primární formát pro strojové klienty; form-encoded je doplněk,
    aby šel endpoint použít i z `curl -d` bez hlavičky `content-type`.
    """
    content_type = request.headers.get("content-type", "").lower()

    if "application/json" in content_type:
        try:
            body = await request.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    if "form" in content_type:
        form = await request.form()
        return {key: str(value) for key, value in form.items()}

    return {}


@app.get("/auth/verify")
async def verify_token(request: Request):
    """
    Ověří Bearer JWT vydaný tímto fake issuerem.

    Kontroluje podpis, `iss`, `aud` a povinné claimy; při úspěchu vrátí
    dekódované claimy, jinak 401.
    """
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
    """
    Health check pro docker-compose a rychlé ověření, že fake běží.

    Vrací i `issuer` a `jwks_uri`, ze kterých se dá přímo sestavit
    `ISSUERS_JSON` pro auth_shield.
    """
    return {
        "ok": True,
        "service": "fake_easy_entra_id",
        "target_server": TARGET_SERVER,
        "users_count": len(load_fake_users()),
        "issuer": JWT_ISSUER,
        "audience": JWT_AUDIENCE,
        "jwks_uri": f"{JWT_DISCOVERY_BASE_URL}/.well-known/jwks.json",
        "key_id": JWT_KEY_ID,
        "proxy_mode": JWT_PROXY_MODE,
    }


@app.get("/fake-users")
async def fake_users():
    """Vrátí načtené fake uživatele jako JSON (pro debugging a testy)."""
    return {
        "users": load_fake_users(),
    }


@app.get("/login")
async def fake_login(request: Request):
    """Zobrazí přihlašovací stránku s výběrem fake uživatele."""
    return HTMLResponse(read_login_template(request))


@app.post("/login")
@app.post("/fake-select-user")
async def fake_select_user(
    request: Request,
    user: str = Form(...),
    next: str = Form(default="/"),
):
    """
    Přihlásí zvoleného fake uživatele a přesměruje na `next`.

    Hodnota `user` může být id, oid, email nebo preferred_username.
    Neznámý uživatel vrací 400 s chybou v UI.
    """
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
    """Zruší fake session a smaže cookie."""
    forget_cookie_value(request.cookies.get(FAKE_AUTH_COOKIE))
    response = RedirectResponse(next or "/login", status_code=303)
    response.delete_cookie(FAKE_AUTH_COOKIE)
    return response


def is_pass_through(path: str) -> bool:
    """True pro cesty, které patří fake aplikaci a nesmí se proxyovat."""
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
    # Connection-specific request headers do not belong on the upstream request.
    # httpx will calculate Host, Content-Length and transfer framing itself.
    request_excluded = {
        "host", "connection", "keep-alive", "proxy-connection",
        "proxy-authenticate", "proxy-authorization", "te", "trailer",
        "transfer-encoding", "upgrade", "content-length",
    }
    connection_tokens = {
        token.strip().lower()
        for token in headers.get("connection", "").split(",")
        if token.strip()
    }
    for key in list(headers):
        if key.lower() in request_excluded | connection_tokens:
            headers.pop(key, None)
    # The proxy sends decoded response.content. Request an uncompressed upstream
    # representation to avoid unnecessary decompression and metadata mismatches.
    headers["accept-encoding"] = "identity"

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

    # Never forward caller-supplied credentials. The fake is the identity
    # issuer, so it always replaces them with a token for the selected user.
    headers.pop("authorization", None)
    headers.pop("x-easy-entra-jwt", None)

    if JWT_PROXY_BEARER or JWT_PROXY_IDENTITY_HEADER:
        # One token per request: the same value goes to both carriers so a
        # consumer that reads either one sees the same identity.
        token = create_identity_token(user)

        if JWT_PROXY_BEARER:
            headers["authorization"] = f"Bearer {token}"
        if JWT_PROXY_IDENTITY_HEADER:
            headers["x-easy-entra-jwt"] = token

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

    # httpx transparently decompresses upstream.content. Never reuse the
    # upstream Content-Length or Content-Encoding with those decoded bytes.
    # Starlette will compute the correct Content-Length from response.content.
    excluded_headers = {
        "connection", "keep-alive", "proxy-connection",
        "proxy-authenticate", "proxy-authorization", "te", "trailer",
        "transfer-encoding", "upgrade", "content-length", "content-encoding",
    }
    connection_tokens = {
        token.strip().lower()
        for token in upstream.headers.get("connection", "").split(",")
        if token.strip()
    }
    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in excluded_headers | connection_tokens
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
    """
    Catch-all proxy na TARGET_SERVER.

    Bez přihlášeného uživatele přesměruje GET/HEAD na /login a ostatní metody
    odmítne 401. S uživatelem požadavek proxyuje a zaloguje celkový čas
    i čas strávený na upstreamu.
    """
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
