"""Bibliothèque partagée des services AlphaPay.

Regroupe les préoccupations transverses afin que chaque service se comporte
de manière identique : journalisation structurée, traçage, erreurs, sécurité,
accès à la base de données, métriques et points de contrôle de santé.
"""

from __future__ import annotations

__all__ = [
    "config",
    "db",
    "errors",
    "health",
    "logging_setup",
    "metrics",
    "security",
    "tracing",
]
