"""Points de contrôle de santé et de disponibilité, identiques partout.

  * `/healthz` : vivacité : le processus répond. Ne teste rien d'externe.
  * `/readyz`  : disponibilité : exécute les sondes fournies par le service.
  * `/metrics` : exposition Prometheus.
  * `/version` : identification du service et de sa version.

Le passage du moteur de remédiation à l'état « rétabli » s'appuie sur ces
points de contrôle, il est donc essentiel qu'ils soient honnêtes : `/readyz`
ne doit pas répondre 200 si une dépendance vitale est en panne.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import FastAPI, Response
from fastapi.responses import JSONResponse

from .metrics import metrics_response
from .tracing import current_trace_id

ReadinessCheck = Callable[[], Awaitable[bool]]


def install_standard_routes(
    app: FastAPI,
    *,
    service_name: str,
    version: str,
    readiness_checks: dict[str, ReadinessCheck] | None = None,
    started_at: float | None = None,
) -> None:
    checks: dict[str, ReadinessCheck] = dict(readiness_checks or {})

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "service": service_name, "version": version})

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> JSONResponse:
        if not checks:
            return JSONResponse({"status": "ready", "service": service_name, "checks": {}})

        results = await asyncio.gather(
            *(check() for check in checks.values()), return_exceptions=True
        )
        detail: dict[str, Any] = {}
        healthy = True
        for name, result in zip(checks, results, strict=True):
            if isinstance(result, BaseException):
                detail[name] = {"ok": False, "error": str(result)}
                healthy = False
            else:
                detail[name] = {"ok": bool(result)}
                healthy = healthy and bool(result)

        payload = {
            "status": "ready" if healthy else "degraded",
            "service": service_name,
            "version": version,
            "checks": detail,
        }
        return JSONResponse(payload, status_code=200 if healthy else 503)

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        return metrics_response()

    @app.get("/version", include_in_schema=False)
    async def version_endpoint() -> JSONResponse:
        return JSONResponse(
            {
                "service": service_name,
                "version": version,
                "trace_id": current_trace_id(),
            }
        )
