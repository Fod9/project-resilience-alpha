"""Erreurs applicatives et réponses au format RFC 9457 (problem+json).

Toutes les erreurs renvoyées par les services ont la même forme, ce qui rend
les journaux et les tests prévisibles :

    {
      "type": "https://alphapay.local/problemes/insufficient-funds",
      "title": "Fonds insuffisants",
      "status": 409,
      "code": "insufficient_funds",
      "detail": "Le compte source ne couvre pas le montant demandé.",
      "trace_id": "8f3c…"
    }
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .tracing import current_trace_id

PROBLEM_BASE = "https://alphapay.local/problemes"
CONTENT_TYPE = "application/problem+json"


class AppError(Exception):
    """Erreur métier maîtrisée."""

    def __init__(
        self,
        status_code: int,
        code: str,
        title: str,
        detail: str = "",
        **extra: Any,
    ) -> None:
        super().__init__(detail or title)
        self.status_code = status_code
        self.code = code
        self.title = title
        self.detail = detail
        self.extra = extra

    def to_problem(self) -> dict[str, Any]:
        problem: dict[str, Any] = {
            "type": f"{PROBLEM_BASE}/{self.code.replace('_', '-')}",
            "title": self.title,
            "status": self.status_code,
            "code": self.code,
            "detail": self.detail,
            "trace_id": current_trace_id(),
        }
        if self.extra:
            problem.update(self.extra)
        return problem


def problem_response(
    status_code: int,
    code: str,
    title: str,
    detail: str = "",
    **extra: Any,
) -> JSONResponse:
    problem: dict[str, Any] = {
        "type": f"{PROBLEM_BASE}/{code.replace('_', '-')}",
        "title": title,
        "status": status_code,
        "code": code,
        "detail": detail,
        "trace_id": current_trace_id(),
    }
    if extra:
        problem.update(extra)
    return JSONResponse(status_code=status_code, content=problem, media_type=CONTENT_TYPE)


# --- Raccourcis utilisés dans les services ---------------------------------


def unauthorized(detail: str = "Authentification requise.") -> AppError:
    return AppError(401, "unauthorized", "Authentification requise", detail)


def forbidden(detail: str = "Droits insuffisants.") -> AppError:
    return AppError(403, "forbidden", "Acces refuse", detail)


def not_found(detail: str = "Ressource introuvable.") -> AppError:
    return AppError(404, "not_found", "Ressource introuvable", detail)


def conflict(code: str, title: str, detail: str = "", **extra: Any) -> AppError:
    return AppError(409, code, title, detail, **extra)


def unprocessable(code: str, title: str, detail: str = "", **extra: Any) -> AppError:
    return AppError(422, code, title, detail, **extra)


def bad_request(code: str, title: str, detail: str = "", **extra: Any) -> AppError:
    return AppError(400, code, title, detail, **extra)


def unavailable(code: str, title: str, detail: str = "", **extra: Any) -> AppError:
    return AppError(503, code, title, detail, **extra)


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_problem(),
            media_type=CONTENT_TYPE,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return problem_response(
            422,
            "validation_failed",
            "Requete invalide",
            "Un ou plusieurs champs sont invalides.",
            errors=[
                {
                    "loc": [str(part) for part in error.get("loc", [])],
                    "msg": error.get("msg", ""),
                    "type": error.get("type", ""),
                }
                for error in exc.errors()
            ],
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return problem_response(
            exc.status_code,
            f"http_{exc.status_code}",
            str(exc.detail),
            "",
        )

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        return problem_response(
            500,
            "internal_error",
            "Erreur interne",
            "Une erreur inattendue a interrompu le traitement.",
        )
