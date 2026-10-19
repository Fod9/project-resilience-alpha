"""Client HTTP sortant : délais bornés, réessais, coupe-circuit simple.

Le moteur de remédiation et le détecteur dépendent d'autres composants ; un
appel sortant ne doit jamais bloquer indéfiniment ni masquer une panne. Chaque
appel échoue vite et proprement, et l'échec est journalisé pour le jury.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .logging_setup import EventLogger
from .tracing import TRACE_HEADER, current_trace_id


@dataclass
class CircuitBreaker:
    """Ouvre le circuit après `threshold` échecs consécutifs, pendant `cooldown`."""

    threshold: int = 5
    cooldown: float = 30.0
    _failures: int = 0
    _opened_at: float = 0.0
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def is_open(self) -> bool:
        if self._opened_at == 0.0:
            return False
        if time.monotonic() - self._opened_at >= self.cooldown:
            return False
        return True

    async def record_success(self) -> None:
        async with self._lock:
            self._failures = 0
            self._opened_at = 0.0

    async def record_failure(self) -> None:
        async with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                self._opened_at = time.monotonic()


class ServiceClient:
    """Client JSON minimal, avec traçage propagé et réessais bornés."""

    def __init__(
        self,
        base_url: str,
        *,
        events: EventLogger,
        timeout: float = 5.0,
        retries: int = 2,
        backoff: float = 0.25,
        name: str = "",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.name = name or self.base_url
        self.events = events
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.breaker = CircuitBreaker()
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ServiceClient":
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(self.timeout),
            headers={"User-Agent": "AlphaPay/1.0"},
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {TRACE_HEADER: current_trace_id()}
        if extra:
            headers.update(extra)
        return headers

    async def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        raise_for_status: bool = True,
    ) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("ServiceClient doit etre utilise comme gestionnaire de contexte")
        if self.breaker.is_open:
            self.events.warn(
                "http.circuit_open",
                f"circuit ouvert, appel a {self.name} abandonne",
                target=self.name,
                path=path,
            )
            raise httpx.ConnectError(f"coupe-circuit ouvert pour {self.name}")

        attempt = 0
        last_error: Exception | None = None
        while attempt <= self.retries:
            attempt += 1
            started = time.perf_counter()
            try:
                response = await self._client.request(
                    method,
                    path,
                    json=json_body,
                    params=params,
                    headers=self._headers(headers),
                    timeout=timeout or self.timeout,
                )
                duration_ms = round((time.perf_counter() - started) * 1000, 2)
                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"{response.status_code} sur {self.name}{path}",
                        request=response.request,
                        response=response,
                    )
                await self.breaker.record_success()
                self.events.emit(
                    "http.outbound",
                    target=self.name,
                    method=method,
                    path=path,
                    status=response.status_code,
                    duration_ms=duration_ms,
                    attempt=attempt,
                )
                if raise_for_status:
                    response.raise_for_status()
                return response
            except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                last_error = exc
                await self.breaker.record_failure()
                if attempt > self.retries:
                    break
                await asyncio.sleep(self.backoff * (2 ** (attempt - 1)))

        self.events.error(
            "http.outbound_failed",
            f"echec de l'appel a {self.name}{path} : {last_error}",
            target=self.name,
            method=method,
            path=path,
            attempts=attempt,
        )
        if last_error is None:  # pragma: no cover - defensive
            raise RuntimeError("echec d'appel sans exception enregistree")
        raise last_error

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        response = await self.request("GET", path, **kwargs)
        return response.json()

    async def post_json(self, path: str, json_body: Any = None, **kwargs: Any) -> Any:
        response = await self.request("POST", path, json_body=json_body, **kwargs)
        if not response.content:
            return None
        return response.json()


class UpstreamError(RuntimeError):
    """Réponse d'erreur structurée renvoyée par un service amont.

    Conserve le code et le corps du problème (RFC 9457) pour que l'appelant
    puisse propager un refus métier légitime : un solde insuffisant n'est pas
    une indisponibilité : au lieu de tout confondre en erreur 502.
    """

    def __init__(self, status: int, payload: Any, url: str) -> None:
        self.status = status
        self.payload = payload if isinstance(payload, dict) else {}
        self.url = url
        super().__init__(
            f"{status} sur {url} : {self.payload.get('detail') or self.payload.get('title') or ''}"
        )

    @property
    def code(self) -> str:
        return str(self.payload.get("code") or "erreur_amont")

    @property
    def detail(self) -> str:
        return str(self.payload.get("detail") or self.payload.get("title") or "refusé par l'amont")


async def request_json(
    method: str,
    url: str,
    *,
    json_body: Any = None,
    raw_body: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    raise_for_status: bool = True,
) -> Any:
    """Appel JSON ponctuel vers une URL absolue.

    Complète `ServiceClient`, qui convient aux appels répétés vers un même
    amont. Ici, la connexion est ouverte puis refermée à chaque appel : c'est le
    bon compromis pour les échanges peu fréquents (notification du moteur de
    remédiation, interrogation de la télémétrie) et pour les appels dont le
    corps doit être transmis **octet pour octet**, cas d'une signature HMAC qui
    porte sur le corps exact.

    L'identifiant de trace courant est propagé dans l'en-tête `X-Request-ID`.
    """
    entetes = {TRACE_HEADER: current_trace_id()}
    if headers:
        entetes.update(headers)

    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        if raw_body is not None:
            response = await client.request(
                method, url, content=raw_body, headers=entetes
            )
        else:
            response = await client.request(
                method, url, json=json_body, headers=entetes
            )
        contenu: Any = None
        if response.content:
            try:
                contenu = response.json()
            except ValueError:
                contenu = {"detail": response.text[:500]}
        if raise_for_status and response.status_code >= 400:
            raise UpstreamError(response.status_code, contenu, url)
        return contenu
