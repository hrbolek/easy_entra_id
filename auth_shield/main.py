"""
Auth Shield

Transparent authentication shield between an identity issuer (easy_entra_id
or fake_easy_entra_id), backend applications and a hidden API.

Request flow
============

Ingress (issuer -> backend application):

    client
      -> easy_entra_id / fake_easy_entra_id
      -> Auth Shield /{app_id}/{path}          Authorization: Bearer <issuer JWT>
      -> registered application /{path}        Authorization: Bearer <Shield JWT>

Egress (backend application -> hidden API):

    application
      -> Auth Shield /{path}                   Authorization: Bearer <Shield JWT>
      -> corridor upstream /{path}             Authorization: Bearer <issuer JWT>

The backend application never sees the real issuer token. Shield verifies it,
stores it in the in-memory TokenVault under the `jti` of a Shield JWT, and
hands the application only that Shield JWT. On egress the Shield JWT is
verified again, the real token is looked up and attached to the outbound
request.

Shield is therefore both a consumer (validates issuer JWTs against trusted
issuers) and an issuer (signs its own Shield JWTs for backend applications).

A single FastAPI application and a single catch-all route are used. The
direction is determined solely from the `iss` claim of the bearer token.

Endpoints
=========

    GET /health                            liveness, applications, issuers
    GET /.well-known/openid-configuration  issuer + jwks_uri for backends
    GET /.well-known/jwks.json             Shield public signing keys
    *   /{path}                            catch-all proxy (both directions)

Configuration
=============

    APPLICATIONS_JSON              required; app_id -> upstream/methods/prefixes
    ISSUERS_JSON                   trusted issuers; empty disables JWT ingress
    CORRIDOR_UPSTREAM              default http://serverjsonata:3000
    SHIELD_ISSUER                  logical issuer identity of this Shield
    SHIELD_JWKS_BASE_URL           network base for the published jwks_uri
    SHIELD_SIGNING_KEY_FILE        persisted RSA key for Shield JWTs
    SHIELD_KEY_ID                  `kid` published in JWKS
    SHIELD_TOKEN_LIFETIME_SECONDS  Shield JWT lifetime, default 300
    SHIELD_TOKEN_SINGLE_USE        delete vault entry on first egress use
    TOKEN_TTL_SECONDS              max vault entry lifetime, default 300
    MAX_TOKEN_ENTRIES              default 10000
    REQUEST_TIMEOUT_SECONDS        default 60
    MAX_RESPONSE_BYTES             default 50 MiB
    LOG_LEVEL                      default INFO

`SHIELD_ISSUER` is a logical identity and must never be derived from a network
address or the `Host` header. `SHIELD_JWKS_BASE_URL` is only the address
published in the discovery document.

IMPORTANT:
    TokenVault is process-local. Run exactly one Uvicorn worker unless the
    vault is replaced by a shared store such as Redis/Valkey.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import AsyncIterator, Iterable
from urllib.parse import urlsplit

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from jwt.utils import base64url_encode


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

    # Identity of this Shield as a token issuer. `issuer` is the logical
    # identity that backends compare against; `jwks_base_url` is only the
    # network address published in the discovery document.
    issuer: str
    jwks_base_url: str
    signing_key_file: Path
    key_id: str
    token_lifetime_seconds: int

    @classmethod
    def from_env(cls) -> "ShieldSettings":
        """Načte konfiguraci z prostředí a doplní defaulty."""
        # Validate the raw values first: silently normalizing `iss` would let
        # Shield and a backend disagree about the exact expected string.
        issuer = os.getenv(
            "SHIELD_ISSUER",
            "https://auth-shield.internal",
        )
        jwks_base_url = os.getenv(
            "SHIELD_JWKS_BASE_URL",
            "http://auth_shield:8000",
        )

        _validate_absolute_url("SHIELD_ISSUER", issuer)
        _validate_absolute_url("SHIELD_JWKS_BASE_URL", jwks_base_url)

        token_lifetime_seconds = int(
            os.getenv("SHIELD_TOKEN_LIFETIME_SECONDS", "300")
        )
        if not 1 <= token_lifetime_seconds <= 86400:
            raise RuntimeError(
                "SHIELD_TOKEN_LIFETIME_SECONDS must be between 1 and 86400"
            )

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
            issuer=issuer,
            jwks_base_url=jwks_base_url,
            signing_key_file=Path(
                os.getenv(
                    "SHIELD_SIGNING_KEY_FILE",
                    "/tmp/auth-shield/signing-key.pem",
                )
            ),
            key_id=os.getenv("SHIELD_KEY_ID", "auth-shield-1"),
            token_lifetime_seconds=token_lifetime_seconds,
        )


def _validate_absolute_url(name: str, value: str) -> None:
    """
    Zkontroluje, že konfigurační URL je absolutní a bez query.

    `iss` i `jwks_uri` se porovnávají přesnou shodou, takže trailing slash
    nebo query by tiše rozbily validaci. Nevalidní hodnota shodí start.
    """
    parts = urlsplit(value)

    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise RuntimeError(f"{name} must be an absolute HTTP(S) URL")

    if parts.query or parts.fragment:
        raise RuntimeError(f"{name} must not contain a query or fragment")

    if value.endswith("/"):
        raise RuntimeError(f"{name} must not end with a trailing slash")


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

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("auth_shield")


# ---------------------------------------------------------------------------
# Trusted issuers (ingress validation)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrustedIssuer:
    """
    Jeden důvěryhodný vydavatel, proti kterému Shield ověřuje příchozí JWT.

    `issuer` je logická identita a porovnává se přesnou shodou s claimem `iss`.
    `jwks_uri` je trust anchor: odkud se stáhnou veřejné klíče. Nikdy se
    nebere z tokenu ani z nedůvěryhodného discovery dokumentu.
    """

    name: str
    issuer: str
    jwks_uri: str
    audiences: tuple[str, ...]


def create_issuer_registry() -> dict[str, TrustedIssuer]:
    """
    Načte důvěryhodné vydavatele z `ISSUERS_JSON`.

    Formát:

        ISSUERS_JSON={
          "fake": {
            "issuer": "https://auth.dev.company.cz",
            "jwks_uri": "http://easy-entra-fake:8000/.well-known/jwks.json",
            "audience": ["internal-api"]
          }
        }

    Prázdný nebo chybějící `ISSUERS_JSON` znamená, že ingress validace JWT
    není zapnutá (zůstává původní EasyAuth kontrakt).
    """
    raw = os.getenv("ISSUERS_JSON", "").strip()

    if not raw:
        return {}

    try:
        config = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"ISSUERS_JSON contains invalid JSON: {exc}"
        ) from exc

    if not isinstance(config, dict):
        raise RuntimeError("ISSUERS_JSON must contain a JSON object")

    issuers: dict[str, TrustedIssuer] = {}

    for name, value in config.items():
        if not isinstance(name, str) or not name.strip():
            raise RuntimeError("ISSUERS_JSON contains an invalid issuer name")

        if not isinstance(value, dict):
            raise RuntimeError(f"Issuer '{name}' configuration must be an object")

        issuer = value.get("issuer")
        if not isinstance(issuer, str) or not issuer.strip():
            raise RuntimeError(f"Issuer '{name}' requires a non-empty 'issuer'")

        jwks_uri = value.get("jwks_uri")
        if not isinstance(jwks_uri, str) or not jwks_uri.strip():
            raise RuntimeError(f"Issuer '{name}' requires a non-empty 'jwks_uri'")

        _validate_absolute_url(f"Issuer '{name}'.issuer", issuer)
        _validate_absolute_url(f"Issuer '{name}'.jwks_uri", jwks_uri)

        configured_audiences = value.get("audience", [])
        if isinstance(configured_audiences, str):
            configured_audiences = [configured_audiences]
        if not isinstance(configured_audiences, list) or not all(
            isinstance(item, str) and item.strip()
            for item in configured_audiences
        ):
            raise RuntimeError(
                f"Issuer '{name}'.audience must be an array of strings"
            )

        issuers[name] = TrustedIssuer(
            name=name,
            issuer=issuer.rstrip("/"),
            jwks_uri=jwks_uri,
            audiences=tuple(configured_audiences),
        )

    return issuers


class JwksCache:
    """
    Cache veřejných klíčů důvěryhodných vydavatelů.

    Klíče se stahují lazy při prvním tokenu daného vydavatele. Neznámý `kid`
    vynutí refresh, ale ne častěji než `min_refresh_seconds` — jinak by šlo
    přes náhodné `kid` zahltit cizí JWKS endpoint.
    """

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        min_refresh_seconds: float = 30.0,
    ) -> None:
        self._http = http
        self._min_refresh_seconds = min_refresh_seconds
        self._keys: dict[str, dict[str, object]] = {}
        self._fetched_at: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def signing_key(
        self,
        trusted: TrustedIssuer,
        kid: str | None,
    ) -> object | None:
        """
        Vrátí veřejný klíč pro daný `kid`.

        Při neznámém `kid` zkusí refresh (s rate limitem). Vrací None, když
        klíč není k dispozici ani po refreshi.
        """
        async with self._lock:
            key = self._lookup(trusted.name, kid)

            if key is not None:
                return key

            now = time.monotonic()
            last = self._fetched_at.get(trusted.name, 0.0)

            if now - last < self._min_refresh_seconds:
                return None

            await self._refresh(trusted)
            return self._lookup(trusted.name, kid)

    def _lookup(self, name: str, kid: str | None) -> object | None:
        keys = self._keys.get(name)

        if not keys:
            return None

        if kid is None:
            # Single-key JWKS without a kid header: use the only key.
            return next(iter(keys.values())) if len(keys) == 1 else None

        return keys.get(kid)

    async def _refresh(self, trusted: TrustedIssuer) -> None:
        try:
            response = await self._http.get(trusted.jwks_uri)
            response.raise_for_status()
            document = response.json()
        except (httpx.HTTPError, ValueError):
            logger.error(
                "JWKS fetch failed; issuer=%s jwks_uri=%s",
                trusted.name,
                trusted.jwks_uri,
            )
            self._fetched_at[trusted.name] = time.monotonic()
            return

        keys: dict[str, object] = {}

        for entry in document.get("keys", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("kty") != "RSA":
                continue

            kid = entry.get("kid")
            if not isinstance(kid, str):
                continue

            try:
                keys[kid] = jwt.PyJWK(entry, algorithm="RS256").key
            except jwt.PyJWTError:
                logger.warning(
                    "Skipping unusable JWKS entry; issuer=%s kid=%s",
                    trusted.name,
                    kid,
                )

        self._keys[trusted.name] = keys
        self._fetched_at[trusted.name] = time.monotonic()

        logger.info(
            "JWKS refreshed; issuer=%s keys=%s",
            trusted.name,
            sorted(keys),
        )


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    """Ověřený příchozí JWT a metadata potřebná pro vydání Shield JWT."""

    raw: str
    issuer: str
    subject: str
    audience: str
    roles: tuple[str, ...]
    scopes: tuple[str, ...]
    tenant_id: str | None
    expires_at: datetime


async def verify_incoming_token(
    request: Request,
    state: "AppState",
    token: str,
) -> VerifiedToken:
    """
    Ověří příchozí JWT proti registrovaným vydavatelům.

    Postup: přečte `iss` bez ověření podpisu, najde odpovídajícího
    důvěryhodného vydavatele, stáhne klíč podle `kid` a teprve pak ověří
    podpis, `iss`, `aud`, `exp` a `nbf`. `iss` se nikdy nebere jako důvěryhodný
    vstup — rozhoduje registr, ne token.
    """
    try:
        unverified = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False},
        )
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Malformed token")

    issuer_claim = unverified.get("iss")
    if not isinstance(issuer_claim, str):
        raise HTTPException(status_code=401, detail="Token has no issuer")

    trusted = next(
        (
            candidate
            for candidate in state.issuers.values()
            if candidate.issuer == issuer_claim.rstrip("/")
        ),
        None,
    )

    if trusted is None:
        logger.warning("Rejected token from unknown issuer; iss=%s", issuer_claim)
        raise HTTPException(status_code=401, detail="Untrusted token issuer")

    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    key = await state.jwks.signing_key(
        trusted,
        kid if isinstance(kid, str) else None,
    )

    if key is None:
        raise HTTPException(status_code=401, detail="Unknown signing key")

    # When the issuer has no configured audience, `aud` is not enforced here;
    # the claim is still required to be present.
    options = {
        "require": ["iss", "aud", "sub", "exp", "iat", "nbf"],
        "leeway": 60,
    }
    if not trusted.audiences:
        options["verify_aud"] = False

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=trusted.issuer,
            audience=trusted.audiences or None,
            options=options,
        )
    except jwt.PyJWTError as exc:
        logger.warning(
            "Token verification failed; issuer=%s reason=%s",
            trusted.name,
            type(exc).__name__,
        )
        raise HTTPException(status_code=401, detail="Invalid token")

    subject = claims.get("oid") or claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=401, detail="Token has no subject")

    raw_audience = claims.get("aud")
    if isinstance(raw_audience, list):
        raw_audience = raw_audience[0] if raw_audience else None

    return VerifiedToken(
        raw=token,
        issuer=trusted.issuer,
        subject=subject,
        audience=str(raw_audience or ""),
        roles=_as_tuple(claims.get("roles")),
        scopes=_as_tuple(claims.get("scp")),
        tenant_id=claims.get("tid") if isinstance(claims.get("tid"), str) else None,
        expires_at=datetime.fromtimestamp(claims["exp"], tz=timezone.utc),
    )


def _as_tuple(value: object) -> tuple[str, ...]:
    """Normalizuje claim na n-tici stringů (list, string i None)."""
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split() if item.strip())
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


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
# Shield token issuance
# ---------------------------------------------------------------------------


def load_signing_key(path: Path) -> rsa.RSAPrivateKey:
    """
    Načte nebo jednorázově vygeneruje podpisový RSA klíč Shieldu.

    Klíč se ukládá do `SHIELD_SIGNING_KEY_FILE`, aby tokeny přežily restart
    a aby všechny repliky podepisovaly stejně. Vytvoření je exkluzivní, takže
    souběžný start dvou kontejnerů klíč nepřepíše.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    if not path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(pem)
            logger.warning("Generated Shield signing key at %s", path)
        except FileExistsError:
            pass

    key = serialization.load_pem_private_key(path.read_bytes(), password=None)

    if not isinstance(key, rsa.RSAPrivateKey):
        raise RuntimeError("SHIELD_SIGNING_KEY_FILE must contain an RSA private key")

    return key


def encode_rsa_number(value: int) -> str:
    """Zakóduje RSA parametr (n/e) do base64url bez paddingu, jak ho čeká JWKS."""
    return base64url_encode(
        value.to_bytes((value.bit_length() + 7) // 8, "big")
    ).decode("ascii")


def create_shield_token(
    settings: ShieldSettings,
    signing_key: rsa.RSAPrivateKey,
    *,
    verified: VerifiedToken,
    app_id: str,
    jti: str,
) -> str:
    """
    Vydá Shield JWT pro backend aplikaci.

    Token je záměna: platí jen uvnitř kapsle a proti skrytému API neprojde,
    protože `iss` je Shield, ne vydavatel identity. `jti` slouží jako klíč
    do vaultu, kde je uložený reálný token.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "iss": settings.issuer,
        "aud": app_id,
        "sub": verified.subject,
        "azp": verified.issuer,
        "roles": list(verified.roles),
        "scp": list(verified.scopes),
        "jti": jti,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=settings.token_lifetime_seconds),
    }

    if verified.tenant_id:
        payload["tid"] = verified.tenant_id

    return jwt.encode(
        payload,
        signing_key,
        algorithm="RS256",
        headers={"kid": settings.key_id, "typ": "JWT"},
    )


# ---------------------------------------------------------------------------
# Token vault
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class VaultEntry:
    """
    Záznam ve vaultu: reálný token vydavatele pod `jti` Shield JWT.

    Backend aplikace dostane jen Shield JWT; reálný token zůstává tady a
    přiloží se až na egress request.
    """

    real_token: str
    app_id: str
    issuer: str
    subject: str
    expires_at: float
    fingerprint: str


class TokenVault:
    """
    Procesně lokální úložiště reálných tokenů pod `jti` Shield JWT.

    Backend aplikace nikdy nevidí reálný token — dostane Shield JWT, jehož
    `jti` je klíčem do tohoto vaultu. Vault drží jen to, co je potřeba pro
    egress výměnu, a záznam maže při expiraci (nebo při prvním použití,
    pokud je zapnutý single-use režim).
    """

    def __init__(
        self,
        ttl_seconds: int,
        max_entries: int,
        *,
        single_use: bool = False,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self.single_use = single_use
        self._entries: dict[str, VaultEntry] = {}
        self._lock = asyncio.Lock()

    async def issue(
        self,
        *,
        real_token: str,
        app_id: str,
        issuer: str,
        subject: str,
        token_expires_at: datetime,
    ) -> str:
        """
        Uloží reálný token a vrátí `jti`, které se vloží do Shield JWT.

        TTL se bere jako minimum z platnosti reálného tokenu a `ttl_seconds`,
        takže Shield nikdy nedrží token déle, než je jeho platnost.
        """
        jti = str(uuid.uuid4())
        now = time.monotonic()

        token_ttl = (token_expires_at - datetime.now(timezone.utc)).total_seconds()
        ttl = max(1.0, min(float(self.ttl_seconds), token_ttl))

        entry = VaultEntry(
            real_token=real_token,
            app_id=app_id,
            issuer=issuer,
            subject=subject,
            expires_at=now + ttl,
            fingerprint=hashlib.sha256(real_token.encode("utf-8")).hexdigest()[:16],
        )

        async with self._lock:
            self._purge(now)

            if len(self._entries) >= self.max_entries:
                oldest = min(
                    self._entries,
                    key=lambda key: self._entries[key].expires_at,
                )
                del self._entries[oldest]

            self._entries[jti] = entry

        return jti

    async def resolve(self, jti: str) -> VaultEntry | None:
        """
        Vrátí záznam pro `jti`, nebo None když expiroval / neexistuje.

        V single-use režimu se záznam při úspěšném vyzvednutí smaže, takže
        jeden Shield JWT nelze na egress použít dvakrát.
        """
        now = time.monotonic()

        async with self._lock:
            self._purge(now)
            entry = self._entries.get(jti)

            if entry is not None and self.single_use:
                del self._entries[jti]

            return entry

    async def count(self) -> int:
        """Počet platných (neexpirovaných) záznamů ve vaultu."""
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
    issuers: dict[str, TrustedIssuer]
    jwks: JwksCache
    signing_key: rsa.RSAPrivateKey


def runtime_state(request: Request) -> AppState:
    """
    Vrátí inicializovaný runtime stav aplikace.

    Když lifespan neproběhl (nebo se stav nepodařilo vytvořit), vrací 500,
    protože bez vaultu a registru aplikací nemá smysl pokračovat.
    """
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


def bearer(value: str | None) -> str | None:
    """
    Vytáhne token z `Authorization: Bearer <token>`.

    Vrací None pro chybějící hlavičku, jiné schéma i prázdný token.
    """
    if not value:
        return None

    scheme, separator, token = value.partition(" ")

    if not separator:
        return None
    if scheme.lower() != "bearer":
        return None

    token = token.strip()
    return token or None


# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------


def target_url(base: str, path: str, query: str) -> str:
    """Sestaví cílovou URL z base, cesty a query stringu."""
    suffix = "/" + path.lstrip("/") if path else ""
    return f"{base}{suffix}" + (f"?{query}" if query else "")


def safe_headers(
    headers: Iterable[tuple[str, str]],
    target_host: str,
) -> dict[str, str]:
    """
    Vyfiltruje hlavičky bezpečné pro přeposlání na upstream.

    Zahazuje hop-by-hop hlavičky, citlivé identitní hlavičky (SENSITIVE_HEADERS)
    a `Host`; ten nahradí `target_host`, aby odpovídal cíli.
    """
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
    """
    Ověří, že cesta spadá pod některý z povolených prefixů.

    Porovnává se po hranici segmentu, takže `/graphql` nepustí `/graphqlx`.
    """
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
    """Vrátí registraci aplikace; neznámá nebo vypnutá aplikace je 404."""
    registration = state.applications.get(app_id)

    if registration is None or not registration.enabled:
        raise HTTPException(
            status_code=404,
            detail="Application is not registered",
        )

    return registration


async def request_body(request: Request) -> AsyncIterator[bytes]:
    """Streamuje tělo příchozího requestu po chuncích (bez bufferování)."""
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
    """
    Provede samotné proxy volání na upstream a vrátí odpověď.

    Tělo requestu se streamuje (kromě GET/HEAD), odpověď se streamuje také
    a hlídá se limit `MAX_RESPONSE_BYTES`. Hop-by-hop a `Content-Length`
    hlavičky se z odpovědi zahazují, `Set-Cookie` se nepropouští.
    """
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
    """
    Rozdělí externí cestu na `app_id` a zbytek cesty pro aplikaci.

    `/whoami/api/x` -> ("whoami", "api/x"). Prázdná cesta je chyba kontraktu.
    """
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
    """
    Zpracuje požadavek přicházející od vydavatele identity (ingress).

    Ověří příchozí JWT proti registrovaným vydavatelům, najde registrovanou
    aplikaci podle `app_id`, zkontroluje povolenou metodu, uloží reálný token
    do vaultu a aplikaci předá Shield JWT. Reálný token se nikdy neposílá
    do aplikace.
    """
    token = bearer(request.headers.get("authorization"))

    if token is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    verified = await verify_incoming_token(request, state, token)

    app_id, application_path = split_application_path(path)
    registration = registered_application(state, app_id)

    if request.method not in registration.allowed_methods:
        raise HTTPException(
            status_code=405,
            detail="Method not allowed for application",
        )

    jti = await state.vault.issue(
        real_token=verified.raw,
        app_id=registration.app_id,
        issuer=verified.issuer,
        subject=verified.subject,
        token_expires_at=verified.expires_at,
    )

    shield_token = create_shield_token(
        state.settings,
        state.signing_key,
        verified=verified,
        app_id=registration.app_id,
        jti=jti,
    )

    headers = safe_headers(
        request.headers.items(),
        urlsplit(registration.upstream).netloc,
    )

    headers["authorization"] = f"Bearer {shield_token}"
    headers["x-shield-app"] = registration.app_id
    headers["x-shield-principal-id"] = verified.subject
    headers["x-shield-expires-in"] = str(
        state.settings.token_lifetime_seconds
    )
    headers["x-request-id"] = request.headers.get(
        "x-request-id",
        secrets.token_hex(16),
    )

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
    shield_token: str,
) -> Response:
    """
    Zpracuje požadavek z backend aplikace (egress, corridor).

    Ověří Shield JWT (podpis, `iss`, `aud`, expiraci), dohledá `jti` ve vaultu,
    zkontroluje, že aplikace smí danou metodu a že cesta spadá do povolených
    corridor prefixů, a teprve pak přiloží **reálný** token vydavatele.
    """
    claims = await verify_shield_token(state, shield_token)

    entry = await state.vault.resolve(claims["jti"])

    if entry is None:
        raise HTTPException(
            status_code=401,
            detail="Expired or invalid Shield token",
        )

    if entry.app_id != claims["aud"]:
        logger.critical(
            "Shield token audience mismatch; aud=%s vault_app=%s",
            claims["aud"],
            entry.app_id,
        )
        raise HTTPException(status_code=401, detail="Invalid Shield token")

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

    # The real issuer token is attached only here, at the trusted corridor
    # boundary. The application never had it.
    headers["authorization"] = f"Bearer {entry.real_token}"
    headers["x-shield-app"] = entry.app_id
    headers["x-shield-principal-id"] = entry.subject
    headers["x-shield-token-fingerprint"] = entry.fingerprint
    headers["x-request-id"] = request.headers.get(
        "x-request-id",
        secrets.token_hex(16),
    )

    return await forward(
        request,
        base=state.settings.corridor_upstream,
        path=path,
        headers=headers,
    )


def is_shield_token(state: AppState, token: str) -> bool:
    """
    Rozliší Shield JWT od tokenu vydavatele bez ověřování podpisu.

    Shield JWT pozná podle `iss` v neověřeném payloadu. Rozhodnutí je jen
    o směrování requestu; podpis se ověří až v odpovídajícím handleru.
    """
    try:
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False},
        )
    except jwt.PyJWTError:
        return False

    issuer = claims.get("iss")

    return isinstance(issuer, str) and issuer.rstrip("/") == state.settings.issuer


async def verify_shield_token(
    state: AppState,
    token: str,
) -> dict:
    """
    Ověří Shield JWT vydaný tímto Shieldem.

    Kontroluje podpis vlastním klíčem, `iss` proti konfiguraci a `aud` proti
    registrovaným aplikacím. Vrací claimy; `jti` slouží jako klíč do vaultu.
    """
    try:
        # `aud` is validated manually below against the application registry,
        # so PyJWT must not enforce it here.
        claims = jwt.decode(
            token,
            state.signing_key.public_key(),
            algorithms=["RS256"],
            issuer=state.settings.issuer,
            options={
                "require": ["iss", "aud", "sub", "exp", "iat", "nbf", "jti"],
                "verify_aud": False,
                "leeway": 60,
            },
        )
    except jwt.PyJWTError as exc:
        logger.warning(
            "Shield token verification failed; reason=%s",
            type(exc).__name__,
        )
        raise HTTPException(status_code=401, detail="Invalid Shield token")

    audience = claims.get("aud")
    if isinstance(audience, list):
        audience = audience[0] if audience else None

    if not isinstance(audience, str) or audience not in state.applications:
        raise HTTPException(status_code=401, detail="Invalid Shield token")

    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=401, detail="Invalid Shield token")

    return {**claims, "aud": audience, "jti": jti}


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Inicializuje runtime stav: settings, HTTP klient, vault, registry a klíč.

    Registr aplikací se čte z `APPLICATIONS_JSON`, důvěryhodní vydavatelé
    z `ISSUERS_JSON`. Nevalidní konfigurace shodí start, aby se aplikace
    nespustila v polovině nakonfigurovaném stavu.
    """
    settings = ShieldSettings.from_env()
    applications = create_application_registry()
    issuers = create_issuer_registry()
    signing_key = load_signing_key(settings.signing_key_file)

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
                single_use=(
                    os.getenv("SHIELD_TOKEN_SINGLE_USE", "false").lower()
                    == "true"
                ),
            ),
            applications=applications,
            issuers=issuers,
            jwks=JwksCache(client),
            signing_key=signing_key,
        )

        logger.info(
            "Auth Shield started; issuer=%s applications=%s issuers=%s "
            "corridor=%s",
            settings.issuer,
            list(applications),
            list(issuers),
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
    """Liveness endpoint: vrací registrované aplikace a počet záznamů ve vaultu."""
    state = runtime_state(request)

    return {
        "ok": True,
        "issuer": state.settings.issuer,
        "applications": list(state.applications),
        "issuers": list(state.issuers),
        "vault_entries": await state.vault.count(),
    }


@app.get("/.well-known/openid-configuration")
async def openid_configuration(request: Request) -> dict:
    """
    Minimální discovery dokument pro backend aplikace.

    `issuer` je logická identita Shieldu a musí přesně odpovídat claimu `iss`
    v Shield JWT. `jwks_uri` je jen síťová adresa, odkud si BA stáhne klíče;
    BA si ji má ověřit proti vlastní konfiguraci, ne jí bezhlavě věřit.
    """
    state = runtime_state(request)

    return {
        "issuer": state.settings.issuer,
        "jwks_uri": f"{state.settings.jwks_base_url}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


@app.get("/.well-known/jwks.json")
async def jwks(request: Request) -> dict:
    """Publikuje veřejnou část podpisového klíče Shieldu ve formátu JWKS."""
    state = runtime_state(request)
    numbers = state.signing_key.public_key().public_numbers()

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": state.settings.key_id,
                "n": encode_rsa_number(numbers.n),
                "e": encode_rsa_number(numbers.e),
            }
        ]
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

    1. Authorization: Bearer <Shield JWT>
       -> egress request from a backend application
       -> verify Shield JWT, resolve `jti` in the vault and forward the
          original issuer token to the corridor upstream.

    2. Authorization: Bearer <issuer JWT>
       -> ingress request from the identity issuer
       -> verify the token against trusted issuers, store the real token in
          the vault and forward a Shield JWT to the registered application.

    Any request that cannot be unambiguously classified is treated as an
    infrastructure/gateway contract error and returns HTTP 500.
    """
    state = runtime_state(request)

    token = bearer(request.headers.get("authorization"))

    if token is None:
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

    if is_shield_token(state, token):
        return await handle_internal_request(
            request,
            path=path,
            state=state,
            shield_token=token,
        )

    return await handle_external_request(
        request,
        path=path,
        state=state,
    )
