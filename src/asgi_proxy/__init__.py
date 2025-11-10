# proxy_app.py
import contextlib
import os
import asyncio
from typing import Iterable, Optional, List, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, APIRouter, Request, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import StreamingResponse, PlainTextResponse

import websockets
from websockets.client import connect as ws_connect


# Cílový server, kam se bude proxy-ovat
TARGET_SERVER = os.getenv("TARGET_SERVER", "http://whoami:8080").rstrip("/")

print(f"Proxy target server: {TARGET_SERVER}")

# Hop-by-hop hlavičky podle RFC 7230 – nepropagovat
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

def _sanitize_request_headers(headers: Iterable[Tuple[str, str]], target_host: str) -> dict:
    """
    Odstraní hop-by-hop hlavičky a nastaví správný Host pro upstream.
    """
    new_headers = {}
    for k, v in headers:
        lk = k.lower()
        if lk in HOP_BY_HOP_HEADERS:
            continue
        if lk == "host":
            new_headers["host"] = target_host
        else:
            new_headers[k] = v
    return new_headers

def _append_forwarded_headers(
    headers: dict, client_host: Optional[str], original_host: Optional[str], scheme: str
) -> dict:
    """
    Přidá X-Forwarded-* hlavičky pro debug a správnou rekonstruovatelnost URL.
    """
    if client_host:
        prev = headers.get("x-forwarded-for")
        headers["x-forwarded-for"] = f"{prev}, {client_host}" if prev else client_host
    if original_host and "x-forwarded-host" not in {k.lower(): v for k, v in headers.items()}:
        headers["x-forwarded-host"] = original_host
    headers["x-forwarded-proto"] = scheme
    return headers

def _filter_response_headers(headers: httpx.Headers, drop_content_length: bool = False) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for k, v in headers.items():
        lk = k.lower()
        if lk in HOP_BY_HOP_HEADERS:
            continue
        if drop_content_length and lk == "content-length":
            continue
        out.append((k, v))
    return out

def _build_target_url(base: str, path: str, query: str) -> str:
    # Zajistí, že path i query sedí. base už je bez trailing "/".
    if query:
        return f"{base}{path}?{query}"
    return f"{base}{path}"

def _http_to_ws_scheme(url: str) -> str:
    """
    http -> ws, https -> wss (pro WebSocket upstream)
    """
    parts = urlsplit(url)
    scheme = "wss" if parts.scheme == "https" else "ws"
    return urlunsplit((scheme, parts.netloc, parts.path, parts.query, parts.fragment))

def create_proxy_router():
    proxy_router = APIRouter()


    @proxy_router.api_route("/{full_path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"])
    async def http_proxy_root(request: Request, full_path: str):
        target = _build_target_url(TARGET_SERVER, request.url.path, request.url.query)
        target_host = urlsplit(TARGET_SERVER).netloc

        headers = _sanitize_request_headers(request.headers.items(), target_host=target_host)
        headers = _append_forwarded_headers(
            headers,
            client_host=request.client.host if request.client else None,
            original_host=request.headers.get("host"),
            scheme=request.url.scheme,
        )

        # (volitelně) streamuj i request body
        async def gen_body():
            async for chunk in request.stream():
                if chunk:
                    yield chunk

        has_body = request.method not in ("GET", "HEAD")

        client = httpx.AsyncClient(follow_redirects=False)
        try:
            # ➜ vyrobíme request a pošleme ho se stream=True
            req = client.build_request(
                request.method,
                target,
                headers=headers,
                content=(gen_body() if has_body else None),
            )
            resp = await client.send(req, stream=True)

            # hlavičky do odpovědi (bez hop-by-hop a bez Content-Length u streamu)
            response_headers = _filter_response_headers(resp.headers)
            response_headers = [(k, v) for k, v in response_headers if k.lower() != "content-length"]

            if request.method == "HEAD" or resp.status_code in (204, 304):
                # u bez-tělových odpovědí jen zavřeme a vrátíme
                await resp.aclose()
                await client.aclose()
                return Response(status_code=resp.status_code, headers=dict(response_headers))

            async def body_iter():
                try:
                    async for chunk in resp.aiter_bytes():
                        if chunk:
                            yield chunk
                finally:
                    # zavřít stream i klienta po doslání
                    await resp.aclose()
                    await client.aclose()

            return StreamingResponse(
                body_iter(),
                status_code=resp.status_code,
                headers=dict(response_headers),
            )

        except httpx.HTTPError as e:
            # cleanup při chybě
            with contextlib.suppress(Exception):
                await client.aclose()
            return PlainTextResponse(f"Upstream error: {e!r}", status_code=502)
                
                
                
    @proxy_router.websocket("/{full_path:path}")
    async def websocket_proxy(websocket: WebSocket, full_path: str):
        """
        WebSocket reverse proxy.
        Vytvoří WS spojení k TARGET_SERVER (se správným ws/wss schématem) a pumpuje oběma směry.
        """
        await websocket.accept()

        # Sestavení cílové WS URL
        target_http_url = _build_target_url(TARGET_SERVER, websocket.url.path, websocket.url.query or "")
        target_ws_url = _http_to_ws_scheme(target_http_url)

        # Přenést případné subprotokoly
        raw_subprotocols = websocket.headers.get("sec-websocket-protocol")
        subprotocols: Optional[List[str]] = None
        if raw_subprotocols:
            subprotocols = [p.strip() for p in raw_subprotocols.split(",") if p.strip()]

        # Hlavičky pro upstream (bez hop-by-hop)
        target_host = urlsplit(TARGET_SERVER).netloc
        upstream_headers = _sanitize_request_headers(websocket.headers.items(), target_host=target_host)
        upstream_headers = _append_forwarded_headers(
            upstream_headers,
            client_host=websocket.client.host if websocket.client else None,
            original_host=websocket.headers.get("host"),
            scheme="https" if target_ws_url.startswith("wss://") else "http",
        )

        try:
            async with ws_connect(
                target_ws_url,
                extra_headers=upstream_headers,
                subprotocols=subprotocols,
                open_timeout=20,
                close_timeout=20,
                max_size=None,   # bez limitu velikosti zprávy
            ) as upstream_ws:

                # Pokud upstream vybral subprotocol, pošleme ho klientovi (už jsme acceptli bez subprotocolu,
                # ale Starlette/ASGI neumožňuje pozdější změnu; pokud potřebuješ strict, řeš `accept(subprotocol=...)` předem).
                # Pro jednoduchost necháme bez enforcementu.

                async def client_to_upstream():
                    try:
                        while True:
                            msg = await websocket.receive()
                            if "text" in msg:
                                await upstream_ws.send(msg["text"])
                            elif "bytes" in msg:
                                await upstream_ws.send(msg["bytes"])
                            elif msg.get("type") == "websocket.disconnect":
                                await upstream_ws.close()
                                break
                    except WebSocketDisconnect:
                        try:
                            await upstream_ws.close()
                        finally:
                            return
                    except Exception:
                        try:
                            await upstream_ws.close()
                        finally:
                            return

                async def upstream_to_client():
                    try:
                        async for msg in upstream_ws:
                            if isinstance(msg, (bytes, bytearray)):
                                await websocket.send_bytes(msg)
                            else:
                                await websocket.send_text(msg)
                    except Exception:
                        try:
                            await websocket.close()
                        finally:
                            return

                await asyncio.gather(client_to_upstream(), upstream_to_client())

        except Exception as e:
            # Pokud se nepodaří navázat WS do upstreamu
            try:
                await websocket.close(code=1011, reason=f"Upstream error: {e}")
            except Exception:
                pass

    return proxy_router