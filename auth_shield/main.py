from __future__ import annotations

"""
Auth Shield

Transparent authentication shield between EasyEntraID, application services,
and serverjsonata.

Request flow
============

External direction:

    client
      -> EasyEntraID
      -> Auth Shield /{app_id}/{path}
      -> registered application /{path}

The request must contain a valid EasyAuth header contract. The real Entra
access token is stored only in the in-memory TokenVault. The application
receives a short-lived opaque Shield handle instead:

    Authorization: Bearer shld_...

Internal direction:

    application
      -> Auth Shield /{path}
      -> serverjsonata /{path}

The application sends the Shield handle in Authorization. Auth Shield resolves
the handle, restores the original Entra access token, and forwards the request
to serverjsonata.

A single FastAPI application and a single catch-all route are used. The
direction is determined solely from the request headers.

IMPORTANT:
    TokenVault is process-local. Run exactly one Uvicorn worker unless the
    vault is replaced by a shared store such as Redis/Valkey.
"""

import asyncio
import base64
import binascii
import contextlib
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import AsyncIterator, Iterable
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ShieldSettings:
    corridor_upstream: str
    token_ttl_seconds: int
    max_token_entries: int
    request_timeout_seconds: float
    max_response_bytes: int

    @classmethod
    def from_env(cls) -> "ShieldSettings":
        return cls(
            corridor_upstream=os.getenv(
                "CORRIDOR_UPSTREAM",
                "http://serverjsonata:3000",
            ).rstrip("/"),
            token_ttl_seconds=int(os.getenv("TOKEN_TTL_SECONDS", "300")),
            max_token_entries=int(os.getenv("MAX_TOKEN_ENTRIES", "10000")),
            request_timeout_seconds=float(
                os.getenv("REQUEST_TIMEOUT_SECONDS", "60")
            ),
            max_response_bytes=int(
                os.getenv(
                    "MAX_RESPONSE_BYTES",
                    str(50 * 1024 * 1024),
                )
            ),
        )


ALLOWED_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "HEAD",
}

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

# These headers must never be blindly forwarded from the caller.
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-ms-token-aad-access-token",
    "x-ms-token-aad-refresh-token",
    "x-ms-token-aad-id-token",
    "x-ms-client-principal",
    "x-ms-client-principal-id",
    "x-ms-client-principal-name",
    "x-shield-app",
    "x-shield-principal-id",
    "x-shield-principal-name",
    "x-shield-expires-in",
    "x-shield-token-fingerprint",
}

EASYAUTH_MARKER_HEADERS = {
    "x-ms-client-principal",
    "x-ms-client-principal-id",
    "x-ms-client-principal-name",
}

SHIELD_TOKEN_PREFIX = "shld_"

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("auth_shield")


# ---------------------------------------------------------------------------
# Application registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApplicationRegistration:
    app_id: str
    upstream: str
    enabled: bool = True
    allowed_methods: frozenset[str] = frozenset(ALLOWED_METHODS)

    # Paths that this application's Shield handle may use in the internal
    # direction towards serverjsonata.
    allowed_corridor_prefixes: tuple[str, ...] = ("/graphql",)


def create_application_registry() -> dict[str, ApplicationRegistration]:
    """
    Build the application registry from the APPLICATIONS_JSON environment
    variable.

    Example:

        APPLICATIONS_JSON={
          "agents": {
            "upstream": "http://agents:8000",
            "allowed_methods": ["GET", "POST"],
            "allowed_corridor_prefixes": ["/graphql"]
          },
          "analytics": {
            "upstream": "http://analytics:8000"
          }
        }

    Required per application:
        upstream

    Optional:
        enabled
        allowed_methods
        allowed_corridor_prefixes
    """
    raw = os.getenv("APPLICATIONS_JSON")

    if not raw:
        raise RuntimeError(
            "APPLICATIONS_JSON environment variable is required"
        )

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"APPLICATIONS_JSON contains invalid JSON: {exc}"
        ) from exc

    if not isinstance(config, dict):
        raise RuntimeError(
            "APPLICATIONS_JSON must contain a JSON object"
        )

    applications: dict[str, ApplicationRegistration] = {}

    for app_id, value in config.items():
        if not isinstance(app_id, str) or not app_id.strip():
            raise RuntimeError(
                "APPLICATIONS_JSON contains an invalid application id"
            )

        if not isinstance(value, dict):
            raise RuntimeError(
                f"Application '{app_id}' configuration must be an object"
            )

        upstream = value.get("upstream")
        if not isinstance(upstream, str) or not upstream.strip():
            raise RuntimeError(
                f"Application '{app_id}' requires a non-empty 'upstream'"
            )

        enabled = value.get("enabled", True)
        if not isinstance(enabled, bool):
            raise RuntimeError(
                f"Application '{app_id}'.enabled must be boolean"
            )

        configured_methods = value.get(
            "allowed_methods",
            sorted(ALLOWED_METHODS),
        )
        if (
            not isinstance(configured_methods, list)
            or not all(
                isinstance(method, str)
                for method in configured_methods
            )
        ):
            raise RuntimeError(
                f"Application '{app_id}'.allowed_methods "
                "must be an array of strings"
            )

        allowed_methods = frozenset(
            method.upper()
            for method in configured_methods
        )

        unknown_methods = allowed_methods - ALLOWED_METHODS
        if unknown_methods:
            raise RuntimeError(
                f"Application '{app_id}' contains unsupported methods: "
                f"{sorted(unknown_methods)}"
            )

        configured_prefixes = value.get(
            "allowed_corridor_prefixes",
            ["/graphql"],
        )
        if (
            not isinstance(configured_prefixes, list)
            or not all(
                isinstance(prefix, str) and prefix.startswith("/")
                for prefix in configured_prefixes
            )
        ):
            raise RuntimeError(
                f"Application '{app_id}'.allowed_corridor_prefixes "
                "must be an array of absolute paths"
            )

        applications[app_id] = ApplicationRegistration(
            app_id=app_id,
            upstream=upstream.rstrip("/"),
            enabled=enabled,
            allowed_methods=allowed_methods,
            allowed_corridor_prefixes=tuple(configured_prefixes),
        )

    if not applications:
        raise RuntimeError(
            "APPLICATIONS_JSON must register at least one application"
        )

    return applications



# ---------------------------------------------------------------------------
# Token vault
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VaultEntry:
    principal: str
    app_id: str
    principal_id: str
    principal_name: str | None
    expires_at: float
    fingerprint: str


class TokenVault:
    def __init__(self, ttl_seconds: int, max_entries: int) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: dict[str, VaultEntry] = {}
        self._lock = asyncio.Lock()

    async def issue(
        self,
        *,
        principal: str,
        app_id: str,
        principal_id: str,
        principal_name: str | None,
    ) -> str:
        handle = SHIELD_TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = time.monotonic()

        entry = VaultEntry(
            principal=principal,
            app_id=app_id,
            principal_id=principal_id,
            principal_name=principal_name,
            expires_at=now + self.ttl_seconds,
            fingerprint=hashlib.sha256(
                principal.encode("utf-8")
            ).hexdigest()[:16],
        )

        async with self._lock:
            self._purge(now)

            if len(self._entries) >= self.max_entries:
                oldest = min(
                    self._entries,
                    key=lambda key: self._entries[key].expires_at,
                )
                del self._entries[oldest]

            self._entries[handle] = entry

        return handle

    async def resolve(self, handle: str) -> VaultEntry | None:
        now = time.monotonic()

        async with self._lock:
            self._purge(now)
            return self._entries.get(handle)

    async def count(self) -> int:
        async with self._lock:
            self._purge(time.monotonic())
            return len(self._entries)

    def _purge(self, now: float) -> None:
        expired = [
            key
            for key, value in self._entries.items()
            if value.expires_at <= now
        ]
        for key in expired:
            del self._entries[key]


# ---------------------------------------------------------------------------
# Runtime application state
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class AppState:
    settings: ShieldSettings
    http: httpx.AsyncClient
    vault: TokenVault
    applications: dict[str, ApplicationRegistration]


def runtime_state(request: Request) -> AppState:
    runtime = getattr(request.app.state, "runtime", None)

    if not isinstance(runtime, AppState):
        logger.critical("Auth Shield runtime state is not initialized")
        raise HTTPException(
            status_code=500,
            detail="Auth Shield runtime is not initialized",
        )

    return runtime


# ---------------------------------------------------------------------------
# Authentication contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EasyAuthIdentity:
    principal: str
    principal_id: str
    principal_name: str | None


def bearer(value: str | None) -> str | None:
    if not value:
        return None

    scheme, separator, token = value.partition(" ")

    if not separator:
        return None
    if scheme.lower() != "bearer":
        return None

    token = token.strip()
    return token or None


def decode_client_principal(value: str | None) -> dict | None:
    if not value:
        return None

    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.b64decode(value + padding)
        decoded = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
        return None

    return decoded if isinstance(decoded, dict) else None


def claim_from_client_principal(
    principal: dict | None,
    *claim_types: str,
) -> str | None:
    if not principal:
        return None

    claims = principal.get("claims")
    if not isinstance(claims, list):
        return None

    wanted = {item.lower() for item in claim_types}

    for claim in claims:
        if not isinstance(claim, dict):
            continue

        claim_type = str(
            claim.get("typ")
            or claim.get("type")
            or claim.get("claim")
            or ""
        ).lower()

        if claim_type not in wanted:
            continue

        value = claim.get("val", claim.get("value"))
        if value is not None:
            return str(value)

    return None


def has_easyauth_markers(request: Request) -> bool:
    return any(
        request.headers.get(header)
        for header in EASYAUTH_MARKER_HEADERS
    )


def extract_easyauth_identity(request: Request) -> EasyAuthIdentity:
    """
    Validate the EasyEntraID identity contract.

    Expected EasyEntraID headers:
      - x-ms-client-principal
      - x-ms-client-principal-id
      - x-ms-client-principal-name (optional)

    x-ms-client-principal is a Base64 encoded JSON principal and is the
    authoritative identity payload stored in the Shield vault.

    Missing or malformed contract data is treated as an infrastructure /
    gateway failure and therefore returns HTTP 500.
    """
    principal_b64 = request.headers.get("x-ms-client-principal")
    principal = decode_client_principal(principal_b64)

    principal_id = (
        request.headers.get("x-ms-client-principal-id")
        or claim_from_client_principal(
            principal,
            "oid",
            "sub",
            "objectidentifier",
            "http://schemas.microsoft.com/identity/claims/objectidentifier",
        )
    )

    principal_name = (
        request.headers.get("x-ms-client-principal-name")
        or claim_from_client_principal(
            principal,
            "preferred_username",
            "unique_name",
            "name",
            "email",
            "upn",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        )
    )

    problems: list[str] = []

    if not principal_b64:
        problems.append("x-ms-client-principal")
    elif principal is None:
        problems.append("valid x-ms-client-principal")

    if not principal_id:
        problems.append(
            "x-ms-client-principal-id or principal claim oid/sub"
        )

    if problems:
        request_id = request.headers.get(
            "x-request-id",
            secrets.token_hex(16),
        )

        logger.critical(
            "EasyEntraID contract failure; problems=%s path=%s request_id=%s",
            problems,
            request.url.path,
            request_id,
        )

        raise HTTPException(
            status_code=500,
            detail={
                "message": "EasyEntraID authentication contract failure",
                "problems": problems,
                "request_id": request_id,
            },
        )

    assert principal_b64 is not None
    assert principal_id is not None

    return EasyAuthIdentity(
        principal=principal_b64,
        principal_id=principal_id,
        principal_name=principal_name,
    )



# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------


def target_url(base: str, path: str, query: str) -> str:
    suffix = "/" + path.lstrip("/") if path else ""
    return f"{base}{suffix}" + (f"?{query}" if query else "")


def safe_headers(
    headers: Iterable[tuple[str, str]],
    target_host: str,
) -> dict[str, str]:
    output: dict[str, str] = {}

    for name, value in headers:
        lower = name.lower()

        if lower in HOP_BY_HOP:
            continue
        if lower in SENSITIVE_HEADERS:
            continue
        if lower == "host":
            continue

        output[lower] = value

    output["host"] = target_host
    return output


def path_allowed(
    path: str,
    prefixes: tuple[str, ...],
) -> bool:
    normalized = "/" + path.lstrip("/")

    return any(
        normalized == prefix
        or normalized.startswith(prefix.rstrip("/") + "/")
        for prefix in prefixes
    )


def registered_application(
    state: AppState,
    app_id: str,
) -> ApplicationRegistration:
    registration = state.applications.get(app_id)

    if registration is None or not registration.enabled:
        raise HTTPException(
            status_code=404,
            detail="Application is not registered",
        )

    return registration


async def request_body(request: Request) -> AsyncIterator[bytes]:
    async for chunk in request.stream():
        if chunk:
            yield chunk


async def forward(
    request: Request,
    *,
    base: str,
    path: str,
    headers: dict[str, str],
) -> Response:
    state = runtime_state(request)

    outbound = state.http.build_request(
        request.method,
        target_url(base, path, request.url.query),
        headers=headers,
        content=(
            None
            if request.method in {"GET", "HEAD"}
            else request_body(request)
        ),
    )

    try:
        upstream = await state.http.send(outbound, stream=True)
    except httpx.HTTPError:
        logger.exception(
            "Upstream request failed; target=%s path=%s",
            base,
            path,
        )
        return JSONResponse(
            status_code=502,
            content={"detail": "Upstream unavailable"},
        )

    response_headers = {
        key: value
        for key, value in upstream.headers.items()
        if key.lower()
        not in HOP_BY_HOP | {"content-length", "set-cookie"}
    }

    if request.method == "HEAD" or upstream.status_code in {204, 304}:
        await upstream.aclose()
        return Response(
            status_code=upstream.status_code,
            headers=response_headers,
        )

    async def stream() -> AsyncIterator[bytes]:
        total = 0

        try:
            async for chunk in upstream.aiter_bytes():
                total += len(chunk)

                if total > state.settings.max_response_bytes:
                    logger.error(
                        "Response limit exceeded; target=%s path=%s "
                        "limit=%s",
                        base,
                        path,
                        state.settings.max_response_bytes,
                    )
                    break

                yield chunk
        finally:
            await upstream.aclose()

    return StreamingResponse(
        stream(),
        status_code=upstream.status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Request direction handlers
# ---------------------------------------------------------------------------


def split_application_path(path: str) -> tuple[str, str]:
    normalized = path.strip("/")

    if not normalized:
        raise HTTPException(
            status_code=500,
            detail="Application id is missing from external request path",
        )

    app_id, separator, remainder = normalized.partition("/")

    return app_id, remainder if separator else ""


async def handle_external_request(
    request: Request,
    *,
    path: str,
    state: AppState,
) -> Response:
    identity = extract_easyauth_identity(request)

    app_id, application_path = split_application_path(path)
    registration = registered_application(state, app_id)

    if request.method not in registration.allowed_methods:
        raise HTTPException(
            status_code=405,
            detail="Method not allowed for application",
        )

    handle = await state.vault.issue(
        principal=identity.principal,
        app_id=registration.app_id,
        principal_id=identity.principal_id,
        principal_name=identity.principal_name,
    )

    headers = safe_headers(
        request.headers.items(),
        urlsplit(registration.upstream).netloc,
    )

    headers["authorization"] = f"Bearer {handle}"
    headers["x-shield-app"] = registration.app_id
    headers["x-shield-principal-id"] = identity.principal_id
    headers["x-shield-expires-in"] = str(
        state.settings.token_ttl_seconds
    )
    headers["x-request-id"] = request.headers.get(
        "x-request-id",
        secrets.token_hex(16),
    )

    if identity.principal_name:
        headers["x-shield-principal-name"] = identity.principal_name

    return await forward(
        request,
        base=registration.upstream,
        path=application_path,
        headers=headers,
    )


async def handle_internal_request(
    request: Request,
    *,
    path: str,
    state: AppState,
    handle: str,
) -> Response:
    entry = await state.vault.resolve(handle)

    if entry is None:
        raise HTTPException(
            status_code=401,
            detail="Expired or invalid Shield handle",
        )

    registration = registered_application(state, entry.app_id)

    if request.method not in registration.allowed_methods:
        raise HTTPException(
            status_code=405,
            detail="Method not allowed for application",
        )

    if not path_allowed(
        path,
        registration.allowed_corridor_prefixes,
    ):
        raise HTTPException(
            status_code=403,
            detail="Corridor path is not allowed for application",
        )

    headers = safe_headers(
        request.headers.items(),
        urlsplit(state.settings.corridor_upstream).netloc,
    )

    # Restore the EasyEntraID identity contract only at the trusted
    # corridor boundary.
    headers["x-ms-client-principal"] = entry.principal
    headers["x-ms-client-principal-id"] = entry.principal_id

    if entry.principal_name:
        headers["x-ms-client-principal-name"] = entry.principal_name

    headers["x-shield-app"] = entry.app_id
    headers["x-shield-principal-id"] = entry.principal_id
    headers["x-shield-token-fingerprint"] = entry.fingerprint
    headers["x-request-id"] = request.headers.get(
        "x-request-id",
        secrets.token_hex(16),
    )

    if entry.principal_name:
        headers["x-shield-principal-name"] = entry.principal_name

    return await forward(
        request,
        base=state.settings.corridor_upstream,
        path=path,
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = ShieldSettings.from_env()

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(settings.request_timeout_seconds),
        follow_redirects=False,
        limits=httpx.Limits(
            max_connections=200,
            max_keepalive_connections=50,
        ),
    ) as client:
        app.state.runtime = AppState(
            settings=settings,
            http=client,
            vault=TokenVault(
                ttl_seconds=settings.token_ttl_seconds,
                max_entries=settings.max_token_entries,
            ),
            applications=create_application_registry(),
        )

        logger.info(
            "Auth Shield started; applications=%s corridor=%s",
            list(app.state.runtime.applications),
            settings.corridor_upstream,
        )

        yield

        logger.info("Auth Shield stopped")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


app = FastAPI(
    title="Auth Shield",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request) -> dict:
    state = runtime_state(request)

    return {
        "ok": True,
        "applications": list(state.applications),
        "vault_entries": await state.vault.count(),
    }


@app.api_route(
    "/{path:path}",
    methods=sorted(ALLOWED_METHODS),
)
async def shield_proxy(
    request: Request,
    path: str,
) -> Response:
    """
    Transparent Shield endpoint.

    Direction is determined exclusively from the authentication headers:

    1. Authorization: Bearer shld_...
       -> internal request from an application
       -> resolve handle and forward to serverjsonata.

    2. EasyAuth-specific headers
       -> external request from EasyEntraID
       -> validate EasyAuth contract, issue Shield handle and forward to the
          registered application.

    Any request that cannot be unambiguously classified is treated as an
    infrastructure/gateway contract error and returns HTTP 500.
    """
    state = runtime_state(request)

    token = bearer(request.headers.get("authorization"))
    is_shield_request = bool(
        token and token.startswith(SHIELD_TOKEN_PREFIX)
    )
    has_easyauth = has_easyauth_markers(request)

    if is_shield_request and has_easyauth:
        request_id = request.headers.get(
            "x-request-id",
            secrets.token_hex(16),
        )

        logger.critical(
            "Ambiguous authentication contract; path=%s request_id=%s",
            request.url.path,
            request_id,
        )

        raise HTTPException(
            status_code=500,
            detail={
                "message": "Ambiguous authentication contract",
                "request_id": request_id,
            },
        )

    if is_shield_request:
        assert token is not None
        return await handle_internal_request(
            request,
            path=path,
            state=state,
            handle=token,
        )

    if has_easyauth:
        return await handle_external_request(
            request,
            path=path,
            state=state,
        )

    request_id = request.headers.get(
        "x-request-id",
        secrets.token_hex(16),
    )

    logger.critical(
        "Unknown authentication contract; path=%s request_id=%s",
        request.url.path,
        request_id,
    )

    raise HTTPException(
        status_code=500,
        detail={
            "message": "Unknown authentication contract",
            "request_id": request_id,
        },
    )
