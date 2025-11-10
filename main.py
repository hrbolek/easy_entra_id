# proxy_app.py
import contextlib
import os
import asyncio
from typing import Iterable, Optional, List, Tuple
from fastapi import FastAPI, APIRouter, Request, WebSocket, WebSocketDisconnect, Response

from src.asgi_proxy import create_proxy_router


app = FastAPI(title="FastAPI Reverse Proxy (HTTP + WS)")

from src.easyauth import create_entra_router, EntraIDClient, EntraEasyAuthMiddleware

AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "<TENANT_ID>")
AUD    = "api://<YOUR_API_ID_URI>"  # nebo client_id API
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "AZURE_CLIENT_ID")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "AZURE_CLIENT")

entra_router = create_entra_router(
    tenant_id=AZURE_TENANT_ID,
    client_id=AZURE_CLIENT_ID,
    client_secret=AZURE_CLIENT_SECRET,
    login_path="/login",
    callback_path="/auth",
)

entra_client = EntraIDClient(tenant_id=AZURE_TENANT_ID, audience=AUD)

app.add_middleware(
    EntraEasyAuthMiddleware,
    entra_client=entra_client,
    pass_through=("/login", "/auth", "/login/", "/auth/"),
    login_path="/login",                      # nebo jméno route, pokud používáš url_for("entra_login")
    # external_base_url="https://app.example.com",  # za reverse proxy
    redirect_on_unauth=True,
)

app.include_router(entra_router)

proxy_router = create_proxy_router()

app.include_router(proxy_router)

