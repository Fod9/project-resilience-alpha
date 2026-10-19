"""Métriques Prometheus partagées.

Les noms suivent la convention `<domaine>_<objet>_<unité>` et restent stables :
les tableaux de bord Grafana et les règles d'alerte s'appuient dessus.
"""

from __future__ import annotations

from fastapi import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# --- Trafic HTTP -----------------------------------------------------------

HTTP_REQUESTS_TOTAL = Counter(
    "alphapay_http_requests_total",
    "Nombre de requêtes HTTP traitées par les services AlphaPay.",
    ["service", "method", "route", "status"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "alphapay_http_request_duration_seconds",
    "Durée de traitement des requêtes HTTP.",
    ["service", "method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# --- Authentification ------------------------------------------------------

AUTH_ATTEMPTS_TOTAL = Counter(
    "alphapay_auth_attempts_total",
    "Tentatives d'authentification par résultat.",
    ["service", "outcome"],
)

TOKENS_REVOKED_TOTAL = Counter(
    "alphapay_tokens_revoked_total",
    "Jetons révoqués par le service d'authentification.",
    ["service", "reason"],
)

# --- Grand livre -----------------------------------------------------------

LEDGER_TRANSACTIONS_TOTAL = Counter(
    "alphapay_ledger_transactions_total",
    "Transactions enregistrées par le grand livre.",
    ["service", "status"],
)

LEDGER_IMBALANCE_CENTS = Gauge(
    "alphapay_ledger_imbalance_cents",
    "Écart de la somme des débits et crédits. Doit rester à zéro.",
    ["service"],
)

# --- Détection -------------------------------------------------------------

ANOMALY_SCORE = Gauge(
    "alphapay_anomaly_score",
    "Score d'anomalie courant produit par le détecteur (0 = nominal).",
    ["service"],
)

ANOMALY_SCORE_MAX = Gauge(
    "alphapay_anomaly_score_max",
    "Score d'anomalie maximal observé depuis le démarrage.",
    ["service"],
)

ANOMALY_THRESHOLD = Gauge(
    "alphapay_anomaly_threshold",
    "Seuil de décision calibré sur le trafic nominal.",
    ["service"],
)

ANOMALY_ANOMALOUS = Gauge(
    "alphapay_anomaly_anomalous",
    "1 si la dernière fenêtre est jugée anormale, 0 sinon.",
    ["service"],
)

FEATURE_VALUE = Gauge(
    "alphapay_feature_value",
    "Valeur courante d'une feature de télémétrie.",
    ["service", "feature"],
)

# --- Remédiation -----------------------------------------------------------

REMEDIATION_INCIDENTS_TOTAL = Counter(
    "alphapay_remediation_incidents_total",
    "Incidents ouverts par le moteur de remédiation, par sévérité.",
    ["service", "severity"],
)

REMEDIATION_ACTIONS_TOTAL = Counter(
    "alphapay_remediation_actions_total",
    "Actions de remédiation exécutées.",
    ["service", "action", "status"],
)

REMEDIATION_MTTD_SECONDS = Gauge(
    "alphapay_remediation_mttd_seconds",
    "Délai entre le début de l'attaque et la détection.",
    ["service"],
)

REMEDIATION_MTTR_SECONDS = Gauge(
    "alphapay_remediation_mttr_seconds",
    "Délai total entre le début de l'attaque et le rétablissement vérifié.",
    ["service"],
)

REMEDIATION_STATE = Gauge(
    "alphapay_remediation_state",
    "État courant de la machine d'état : 1 sur l'état actif, 0 sur les autres.",
    ["service", "state"],
)

REMEDIATION_VERIFICATION_PASSED = Gauge(
    "alphapay_remediation_verification_passed",
    "1 si la dernière vérification de rétablissement est passée, 0 sinon.",
    ["service"],
)

SERVICE_UP = Gauge(
    "alphapay_service_up",
    "Disponibilité perçue d'un composant surveillé (1 = joignable).",
    ["service", "component"],
)


def metrics_response() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
