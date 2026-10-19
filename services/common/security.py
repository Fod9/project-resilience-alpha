"""Primitives de sécurité partagées : signatures de webhook et jetons.

Aucune de ces fonctions n'écrit quoi que ce soit : elles se contentent de
vérifier des preuves d'authenticité de manière à temps constant.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Mapping

ADMIN_TOKEN_HEADER = "x-admin-token"

#: En-tête réellement envoyé par Falcosidekick et par Alertmanager.
#: En-têtes acceptés, par ordre de préférence.
#:
#: `authorization` est présent parce qu'Alertmanager ne permet pas de définir
#: d'en-tête personnalisé sur un webhook : il ne sait produire qu'un en-tête
#: `Authorization` (schéma + identifiant). On accepte donc la forme
#: `Authorization: <schéma> <secret>` en plus des formes explicites.
SIGNATURE_HEADER_NAMES = (
    "x-alphapay-signature",
    "authorization",
)


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def compute_signature(secret: str, body: bytes) -> str:
    """Signature HMAC-SHA256 d'un corps de requête, en hexadécimal."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def format_signature(secret: str, body: bytes) -> str:
    return f"hmac-sha256={compute_signature(secret, body)}"


def hash_token(token: str) -> str:
    """Empreinte d'un jeton avant stockage : on ne conserve jamais le clair."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def verify_webhook(
    secret: str,
    headers: Mapping[str, str],
    body: bytes,
) -> bool:
    """Valide une notification entrante.

    Trois formes acceptées, toutes comparées à temps constant :
      1. `hmac-sha256=<hex>` — signature du corps (forme recommandée) ;
      2. `<hex>` — signature du corps sans préfixe (Alertmanager, Prometheus) ;
      3. le secret partagé lui-même (Falcosidekick, qui n'implémente pas HMAC).
    """
    if not secret:
        return False

    provided = ""
    for name in SIGNATURE_HEADER_NAMES:
        value = headers.get(name) or headers.get(name.title())
        if value:
            provided = value.strip()
            break
    if not provided:
        return False

    # Forme `Authorization: <schéma> <secret>` : seul le dernier segment porte
    # la preuve, le schéma n'est qu'une étiquette de transport.
    if " " in provided and not provided.startswith("hmac-sha256="):
        fourni_schema = provided.split(" ", 1)[1].strip()
        if fourni_schema:
            provided = fourni_schema

    if provided.startswith("hmac-sha256="):
        provided = provided.split("=", 1)[1]
        return constant_time_equals(compute_signature(secret, body), provided)

    if constant_time_equals(compute_signature(secret, body), provided):
        return True

    return constant_time_equals(secret, provided)


def verify_admin_token(expected: str, provided: str | None) -> bool:
    if not expected or not provided:
        return False
    return constant_time_equals(expected, provided)


def redact(value: str, keep: int = 4) -> str:
    """Réduit une valeur à ses derniers caractères pour les journaux."""
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return f"{'*' * (len(value) - keep)}{value[-keep:]}"
