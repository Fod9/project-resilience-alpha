"""Fabrique d'application : câble journalisation, traçage, erreurs et santé.

Chaque service se contente de décrire ses routes ; tout le reste est identique
et provient d'ici. C'est ce qui garantit que le moteur de remédiation peut
sonder n'importe quel composant de la même manière.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI

from .config import CommonSettings, env_str
from .db import close_pool, init_pool, ping
from .errors import install_error_handlers
from .health import ReadinessCheck, install_standard_routes
from .logging_setup import EventLogger, setup_logging
from .metrics import HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_TOTAL
from .tracing import (
    TraceMiddleware,
    current_client_ip,
    current_identity,
    current_route_label,
    current_trace_id,
)

#: Chemins exclus du journal d'accès : ils sont interrogés toutes les quelques
#: secondes par les sondes et noieraient le trafic applicatif réel.
SILENT_PATHS = frozenset({"/healthz", "/readyz", "/metrics", "/openapi.json"})


class AccessLogMiddleware:
    """Émet un événement `http.request` par requête, au format du socle commun.

    C'est la source de la majorité des 18 variables observées par le détecteur
    d'anomalies : volumétrie, taux d'erreur, latence, diversité des identités.
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        service_name: str,
        events: EventLogger,
    ) -> None:
        self.app = app
        self.service_name = service_name
        self.events = events

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in SILENT_PATHS:
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        etat = {"code": 0}

        async def send_suivi(message):  # type: ignore[no-untyped-def]
            if message["type"] == "http.response.start":
                etat["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_suivi)
        finally:
            duree = time.perf_counter() - started
            statut = etat["code"] or 500
            methode = scope.get("method", "")
            route = current_route_label() or _route_depuis_chemin(path)
            HTTP_REQUESTS_TOTAL.labels(
                service=self.service_name,
                method=methode,
                route=route,
                status=str(statut),
            ).inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(
                service=self.service_name,
                method=methode,
                route=route,
            ).observe(duree)
            self.events.emit(
                "http.request",
                method=methode,
                path=path,
                route=route,
                status=statut,
                duration_ms=round(duree * 1000, 3),
                source_ip=current_client_ip(),
                identity=current_identity(),
            )


def _route_depuis_chemin(path: str) -> str:
    """Réduit un chemin à sa première ressource : `/payments/42` → `/payments`."""
    morceaux = [m for m in path.split("/") if m]
    if not morceaux:
        return "/"
    return "/" + morceaux[0]


StartupHook = Callable[[], Awaitable[None]]
ShutdownHook = Callable[[], Awaitable[None]]


@dataclass
class ServiceContext:
    app: FastAPI
    settings: CommonSettings
    events: EventLogger


def build_app(
    *,
    service_name: str,
    version: str,
    title: str,
    description: str = "",
    readiness_checks: dict[str, ReadinessCheck] | None = None,
    on_startup: StartupHook | None = None,
    on_shutdown: ShutdownHook | None = None,
    with_database: bool = False,
) -> ServiceContext:
    settings = CommonSettings.load(service_name)
    logger = setup_logging(settings)
    events = EventLogger(logger)

    checks: dict[str, ReadinessCheck] = dict(readiness_checks or {})
    if with_database:
        checks.setdefault("postgres", ping)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        if with_database:
            dsn = env_str("DATABASE_URL", required=True)
            await init_pool(
                dsn,
                min_size=int(env_str("DB_POOL_MIN", "1")),
                max_size=int(env_str("DB_POOL_MAX", "8")),
            )
        if on_startup is not None:
            await on_startup()
        events.emit("service.started", version=version)
        try:
            yield
        finally:
            events.emit("service.stopping", version=version)
            if on_shutdown is not None:
                await on_shutdown()
            if with_database:
                await close_pool()

    app = FastAPI(
        title=title,
        description=description,
        version=version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    app.add_middleware(TraceMiddleware)
    app.add_middleware(
        AccessLogMiddleware,
        service_name=service_name,
        events=events,
    )
    install_error_handlers(app)
    install_standard_routes(
        app,
        service_name=service_name,
        version=version,
        readiness_checks=checks,
    )

    return ServiceContext(app=app, settings=settings, events=events)
