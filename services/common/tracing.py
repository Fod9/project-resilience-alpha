"""Traçage distribué minimal : identifiant de requête propagé de bout en bout.

Le bord (edge) génère ou réutilise un `X-Request-ID`; chaque service le reprend
et le réinjecte dans ses journaux, ses en-têtes de réponse et ses appels
sortants. C'est ce qui permet de corréler un événement du WAF, une décision du
détecteur et une action de remédiation sur la même trace.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from typing import Any

TRACE_HEADER = "X-Request-ID"
TRACE_HEADER_BYTES = b"x-request-id"
FORWARDED_FOR_HEADER_BYTES = b"x-forwarded-for"
REAL_IP_HEADER_BYTES = b"x-real-ip"

_TRACE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

_trace_id: ContextVar[str] = ContextVar("trace_id", default="")
_client_ip: ContextVar[str] = ContextVar("client_ip", default="")
_redteam_marker: ContextVar[str] = ContextVar("redteam_marker", default="")
_identity: ContextVar[str] = ContextVar("identity", default="")
_route_label: ContextVar[str] = ContextVar("route_label", default="")


def set_identity(value: str | None) -> None:
    """Renseigne l'identité authentifiée, utilisée par le journal d'accès."""
    _identity.set(value or "")


def current_identity() -> str:
    return _identity.get()


def set_route_label(value: str | None) -> None:
    _route_label.set(value or "")


def current_route_label() -> str:
    return _route_label.get()


def new_trace_id() -> str:
    return uuid.uuid4().hex


def set_trace_id(candidate: str | None) -> str:
    """Reprend l'identifiant amont s'il est conforme, sinon en génère un."""
    if candidate and _TRACE_PATTERN.match(candidate):
        trace_id = candidate
    else:
        trace_id = new_trace_id()
    _trace_id.set(trace_id)
    return trace_id


def current_trace_id() -> str:
    return _trace_id.get()


def current_client_ip() -> str:
    return _client_ip.get()


def set_redteam_marker(marker: str | None) -> None:
    _redteam_marker.set(marker or "")


def current_redteam_marker() -> str:
    return _redteam_marker.get()


def extract_client_ip(headers: dict[bytes, bytes], fallback: str = "") -> str:
    """Détermine l'IP d'origine.

    `X-Forwarded-For` est renseigné par le bord, qui écrase systématiquement
    l'en-tête reçu du client. On prend la première adresse de la liste.
    """
    forwarded = headers.get(FORWARDED_FOR_HEADER_BYTES)
    if forwarded:
        first = forwarded.decode("latin-1").split(",")[0].strip()
        if first:
            return first
    real_ip = headers.get(REAL_IP_HEADER_BYTES)
    if real_ip:
        value = real_ip.decode("latin-1").strip()
        if value:
            return value
    return fallback


class TraceMiddleware:
    """Middleware ASGI pur (sans dépendance à Starlette)."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        raw_headers = scope.get("headers") or []
        header_map = {key.lower(): value for key, value in raw_headers}

        raw_trace = header_map.get(TRACE_HEADER_BYTES)
        trace_id = set_trace_id(raw_trace.decode("latin-1") if raw_trace else None)

        client = scope.get("client") or ("", 0)
        fallback_ip = client[0] if client and client[0] else ""
        _client_ip.set(extract_client_ip(header_map, fallback_ip))

        marker = header_map.get(b"x-redteam-marker")
        if marker:
            set_redteam_marker(marker.decode("latin-1"))

        state = scope.setdefault("state", {})
        state["trace_id"] = trace_id

        async def send_wrapper(message: dict) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((TRACE_HEADER_BYTES, trace_id.encode("latin-1")))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
