"""Journalisation structurée : JSON sur la sortie standard et dans un fichier.

Chaque ligne est un objet JSON autonome, ce qui permet à Promtail de
l'expédier tel quel vers Loki et au service de télémétrie de calculer les
features sans analyse fragile. Le format est un contrat : voir
`docs/DESIGN.md` section 2.2 pour les features qui en dépendent.

Format d'une ligne :

    {
      "ts": "2026-10-19T09:12:31.412+00:00",
      "level": "INFO",
      "service": "api-payment",
      "logger": "api-payment",
      "event": "http.request",
      "trace_id": "8f3c…",
      "source_ip": "192.168.137.42",
      "fields": { "method": "POST", "path": "/payments", "status": 201, ... }
    }
"""

from __future__ import annotations

import datetime
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

from .config import CommonSettings
from .tracing import (
    current_client_ip,
    current_redteam_marker,
    current_trace_id,
)

EVENT_ATTR = "event"
FIELDS_ATTR = "fields"

#: Événements produits par les services et consommés par la télémétrie.
EVENT_HTTP_REQUEST = "http.request"
EVENT_AUTH_ATTEMPT = "auth.attempt"
EVENT_TOKEN_EVENT = "auth.token"
EVENT_LEDGER_TRANSACTION = "ledger.transaction"
EVENT_LEDGER_INTEGRITY = "ledger.integrity"
EVENT_ADMIN_ACTION = "admin.action"


class JsonFormatter(logging.Formatter):
    def __init__(self, service_name: str) -> None:
        super().__init__()
        self.service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "service": self.service_name,
            "logger": record.name,
            "event": getattr(record, EVENT_ATTR, "log"),
            "trace_id": current_trace_id(),
        }

        source_ip = current_client_ip()
        if source_ip:
            payload["source_ip"] = source_ip

        marker = current_redteam_marker()
        if marker:
            payload["redteam_marker"] = marker

        fields = getattr(record, FIELDS_ATTR, None)
        if fields:
            payload["fields"] = _jsonable(fields)

        message = record.getMessage()
        if message:
            payload["message"] = message

        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


def _jsonable(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def setup_logging(settings: CommonSettings) -> logging.Logger:
    """Configure la journalisation racine du service. Idempotent."""
    root = logging.getLogger()
    root.setLevel(settings.log_level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    formatter = JsonFormatter(settings.service_name)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    log_dir = Path(settings.log_dir)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / f"{settings.service_name}.jsonl",
            maxBytes=settings.log_rotate_bytes,
            backupCount=settings.log_rotate_backups,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:  # pragma: no cover - dépend du montage de volume
        root.warning(
            "journalisation vers fichier indisponible (%s) : %s",
            log_dir,
            exc,
            extra={EVENT_ATTR: "logging.file_unavailable", FIELDS_ATTR: {"path": str(log_dir)}},
        )

    # On produit nos propres événements d'accès structurés : les journaux
    # d'accès d'uvicorn feraient doublon et ne contiennent pas les champs utiles.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    return logging.getLogger(settings.service_name)


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.INFO,
    message: str = "",
    **fields: Any,
) -> None:
    """Émet un événement structuré, exploitable par la télémétrie et Loki."""
    logger.log(level, message, extra={EVENT_ATTR: event, FIELDS_ATTR: fields})


class EventLogger:
    """Petit adaptateur pour éviter de répéter le nom du service partout."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    def emit(self, event: str, **fields: Any) -> None:
        log_event(self._logger, event, **fields)

    def warn(self, event: str, message: str = "", **fields: Any) -> None:
        log_event(self._logger, event, level=logging.WARNING, message=message, **fields)

    def error(self, event: str, message: str = "", **fields: Any) -> None:
        log_event(self._logger, event, level=logging.ERROR, message=message, **fields)

    def debug(self, event: str, **fields: Any) -> None:
        log_event(self._logger, event, level=logging.DEBUG, **fields)
