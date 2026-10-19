"""Configuration commune, lue depuis l'environnement.

Aucun secret n'a de valeur par défaut : une variable manquante lève une erreur
au démarrage plutôt que de laisser le service tourner dans un état dégradé
silencieux.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

_TRUE = {"1", "true", "yes", "on", "vrai"}
_FALSE = {"0", "false", "no", "off", "faux"}


class ConfigError(RuntimeError):
    """Variable d'environnement manquante ou invalide."""


def env_str(name: str, default: str | None = None, *, required: bool = False) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        if required and default is None:
            raise ConfigError(f"variable d'environnement obligatoire absente : {name}")
        return "" if default is None else default
    return value


def env_int(name: str, default: int, *, required: bool = False) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        if required:
            raise ConfigError(f"variable d'environnement obligatoire absente : {name}")
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} doit être un entier, reçu {raw!r}") from exc


def env_float(name: str, default: float, *, required: bool = False) -> float:
    raw = os.getenv(name)
    if raw is None or raw == "":
        if required:
            raise ConfigError(f"variable d'environnement obligatoire absente : {name}")
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} doit être un nombre, reçu {raw!r}") from exc


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ConfigError(f"{name} doit être un booléen, reçu {raw!r}")


def env_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class CommonSettings:
    """Réglages présents dans tous les services."""

    service_name: str
    log_level: str
    log_dir: str
    log_rotate_bytes: int
    log_rotate_backups: int
    demo_mode: bool
    dry_run: bool
    hmac_secret: str
    tz: str

    @classmethod
    def load(cls, default_service_name: str) -> "CommonSettings":
        return cls(
            service_name=env_str("SERVICE_NAME", default_service_name),
            log_level=env_str("LOG_LEVEL", "INFO").upper(),
            log_dir=env_str("LOG_DIR", "/var/log/alphapay"),
            log_rotate_bytes=env_int("LOG_ROTATE_BYTES", 20 * 1024 * 1024),
            log_rotate_backups=env_int("LOG_ROTATE_BACKUPS", 3),
            demo_mode=env_bool("DEMO_MODE", True),
            dry_run=env_bool("DRY_RUN", False),
            hmac_secret=env_str("HMAC_SECRET", "", required=True),
            tz=env_str("TZ", "Europe/Paris"),
        )
