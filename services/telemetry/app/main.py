"""AlphaPay : télémétrie : des journaux aux 18 variables observées.

Rôle dans l'architecture
------------------------
Ce service est la source unique des variables que le détecteur consomme. Il
suit en continu les journaux structurés écrits par l'ensemble des composants
(bordure, services applicatifs, journal d'audit ModSecurity), les agrège sur une
fenêtre glissante et publie le vecteur obtenu à la fois en HTTP et sous forme de
métriques Prometheus.

Pourquoi un service dédié plutôt que du LogQL directement dans le détecteur :
la logique d'agrégation devient testable hors ligne, elle est réutilisée telle
quelle par l'entraînement, et la défaillance de Loki n'empêche pas la détection
de fonctionner.

Horodatage : l'heure d'ingestion est utilisée par défaut. Les journaux JSON
portent bien un champ `ts`, mais le journal d'audit ModSecurity n'expédie qu'une
date locale sans fuseau ; s'appuyer sur l'heure d'ingestion évite toute
ambiguïté de fuseau. Une garde écarte les horodatages manifestement aberrants.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import time
from typing import Any

from common.app import build_app
from common.config import env_int, env_str
from common.features import FEATURE_NAMES, Agregateur, Evenement, Reference

from .tailer import SuiveurDeFichiers

VERSION = "1.0.0"

async def _demarrer() -> None:
    """Démarre la boucle d'agrégation avec le cycle de vie de l'application."""
    global _tache
    _tache = asyncio.create_task(_boucle())


async def _arreter() -> None:
    global _tache
    if _tache is not None:
        _tache.cancel()
        _tache = None


ctx = build_app(
    service_name="telemetry",
    version=VERSION,
    title="AlphaPay : Télémétrie",
    description="Agrégation des journaux en variables observées pour la détection d'anomalies.",
    on_startup=_demarrer,
    on_shutdown=_arreter,
)
app = ctx.app
events = ctx.events

_tache: asyncio.Task[None] | None = None

LOG_DIR = env_str("LOG_DIR", "/var/log/alphapay")
MODSEC_LOG = env_str("MODSEC_LOG", f"{LOG_DIR}/edge-modsec.log")
WINDOW_SECONDS = env_int("WINDOW_SECONDS", 60)
WINDOW_STRIDE_SECONDS = env_int("WINDOW_STRIDE_SECONDS", 10)
HISTORY_MAX = env_int("HISTORY_MAX", 360)
ECART_TEMPOREL_TOLERE = 300.0

#: La télémétrie ne se consomme pas elle-même : ses propres requêtes HTTP
#: fausseraient la variable `requests_per_token`.
SERVICES_IGNORES = frozenset({"telemetry"})

_reference = Reference()
_agregateur = Agregateur(window_seconds=WINDOW_SECONDS, reference=_reference)
_historique: list[dict[str, Any]] = []
_dernier_vecteur: dict[str, float] = {nom: 0.0 for nom in FEATURE_NAMES}
_derniere_fenetre: dict[str, Any] = {
    "window_start": None,
    "window_end": None,
    "event_counts": {},
    "features": dict(_dernier_vecteur),
}
_compteurs: dict[str, int] = {}


# =============================================================================
#  Lecture des journaux
# =============================================================================


def _liste_fichiers() -> list[str]:
    try:
        entrees = sorted(os.listdir(LOG_DIR))
    except OSError:
        return []
    fichiers = []
    for entree in entrees:
        if not entree.endswith(".jsonl"):
            continue
        service = entree[: -len(".jsonl")]
        if service in SERVICES_IGNORES:
            continue
        fichiers.append(os.path.join(LOG_DIR, entree))
    if os.path.isfile(MODSEC_LOG):
        fichiers.append(MODSEC_LOG)
    return fichiers


def _horodatage(champ: Any, defaut: float) -> float:
    if not isinstance(champ, str) or not champ:
        return defaut
    try:
        quand = dt.datetime.fromisoformat(champ)
    except ValueError:
        return defaut
    if quand.tzinfo is None:
        quand = quand.replace(tzinfo=dt.timezone.utc)
    valeur = quand.timestamp()
    if abs(defaut - valeur) > ECART_TEMPOREL_TOLERE:
        return defaut
    return valeur


def _normaliser(chemin: str, ligne: str, maintenant: float) -> Evenement | None:
    try:
        charge = json.loads(ligne)
    except json.JSONDecodeError:
        return None
    if not isinstance(charge, dict):
        return None

    if chemin.endswith("edge-modsec.log"):
        transaction = charge.get("transaction")
        if not isinstance(transaction, dict):
            return None
        familles: set[str] = set()
        for message in transaction.get("messages") or []:
            details = message.get("details") or {}
            familles.update(details.get("tags") or [])
        return Evenement(
            ts=maintenant,
            source="modsec",
            kind="modsec.transaction",
            fields={
                "client_ip": transaction.get("client_ip"),
                "uri": (transaction.get("request") or {}).get("uri"),
                "interrupted": bool(transaction.get("is_interrupted")),
                "http_code": (transaction.get("response") or {}).get("http_code"),
                "familles": sorted(familles),
            },
        )

    service = charge.get("service") or os.path.basename(chemin).replace(".jsonl", "")
    evenement = charge.get("event") or ""
    champs = charge.get("fields") or {}
    if not isinstance(champs, dict):
        champs = {}
    else:
        champs = dict(champs)

    # L'adresse source et le marqueur d'exercice sont portés par l'enveloppe du
    # journal, et non par les champs métier. Sans cette réintégration, les
    # variables d'adresse resteraient vides et le confinement n'aurait aucune
    # cible à désigner : c'est la panne silencieuse la plus coûteuse du dispositif.
    if not champs.get("source_ip") and charge.get("source_ip"):
        champs["source_ip"] = charge.get("source_ip")
    if not champs.get("redteam_marker") and charge.get("redteam_marker"):
        champs["redteam_marker"] = charge.get("redteam_marker")

    quand = _horodatage(charge.get("ts"), maintenant)

    if service == "edge":
        return Evenement(ts=quand, source="edge", kind="http.request", fields=champs)
    if evenement == "auth.attempt":
        return Evenement(
            ts=quand,
            source="service",
            kind="auth.attempt",
            fields={
                "identity": champs.get("identity"),
                "outcome": champs.get("outcome"),
                "source_ip": champs.get("source_ip"),
                "role": champs.get("role"),
            },
        )
    if evenement == "http.request":
        return Evenement(
            ts=quand,
            source="service",
            kind="http.request",
            fields={
                "identity": champs.get("identity"),
                "route": champs.get("route"),
                "status": champs.get("status"),
                "source_ip": champs.get("source_ip"),
            },
        )
    return None


# =============================================================================
#  Boucle d'agrégation
# =============================================================================


def _publier_metriques(vecteur: dict[str, float]) -> None:
    from common.metrics import FEATURE_VALUE

    for nom, valeur in vecteur.items():
        FEATURE_VALUE.labels(service="telemetry", feature=nom).set(float(valeur))


def _cycle(suiveur: SuiveurDeFichiers) -> None:
    maintenant = time.time()
    lus = suiveur.lire()
    for chemin, ligne in lus:
        evenement = _normaliser(chemin, ligne, maintenant)
        if evenement is None:
            continue
        _agregateur.ajouter(evenement)
        _compteurs[evenement.source] = _compteurs.get(evenement.source, 0) + 1

    _agregateur.purger(maintenant)
    vecteur = _agregateur.vecteur()
    _agregateur.enrichir_reference()

    global _dernier_vecteur
    _dernier_vecteur = vecteur
    _publier_metriques(vecteur)

    fenetre = {
        "window_start": dt.datetime.fromtimestamp(
            maintenant - WINDOW_SECONDS, dt.timezone.utc
        ).isoformat(),
        "window_end": dt.datetime.fromtimestamp(maintenant, dt.timezone.utc).isoformat(),
        "window_seconds": WINDOW_SECONDS,
        "events_in_window": len(_agregateur),
        "event_counts": dict(_compteurs),
        "features": {nom: round(float(valeur), 6) for nom, valeur in vecteur.items()},
        "diagnostics": _agregateur.diagnostics(),
        # Tant que la mémoire longue n'est pas établie, la fenêtre est signalée
        # comme non exploitable : le détecteur l'ignorera plutôt que de produire
        # une anomalie fantôme à chaque redémarrage.
        "warming_up": not _reference.prete,
    }
    _derniere_fenetre.clear()
    _derniere_fenetre.update(fenetre)
    _historique.append(fenetre)
    if len(_historique) > HISTORY_MAX:
        del _historique[: len(_historique) - HISTORY_MAX]


async def _boucle() -> None:
    suiveur = SuiveurDeFichiers(_liste_fichiers())
    suiveur.amorcer()
    events.emit("telemetry.started", files=len(suiveur.chemins))
    dernier_cycle = 0.0
    while True:
        await asyncio.sleep(1.0)
        maintenant = time.monotonic()
        if maintenant - dernier_cycle < WINDOW_STRIDE_SECONDS:
            continue
        dernier_cycle = maintenant
        # La liste des journaux est relue a chaque cycle. Les services creent leur
        # fichier au premier evenement ecrit, et le repertoire lui-meme peut etre
        # monte apres le demarrage : une liste figee au lancement laisserait la
        # telemetrie surveiller zero fichier pour toujours, en silence.
        nouveaux = suiveur.ajouter(_liste_fichiers())
        if nouveaux:
            events.emit(
                "telemetry.files_added",
                files=len(nouveaux),
                total=len(suiveur.chemins),
            )
        try:
            _cycle(suiveur)
        except Exception as erreur:  # noqa: BLE001 : la boucle ne doit jamais mourir
            events.warn(
                "telemetry.cycle_failed",
                message="échec d'un cycle d'agrégation",
                error=str(erreur),
            )


# =============================================================================
#  Interface
# =============================================================================


@app.get("/features/current", tags=["telemetrie"])
async def fenetre_courante() -> dict[str, Any]:
    return dict(_derniere_fenetre)


@app.get("/features/history", tags=["telemetrie"])
async def historique(limit: int = 60) -> dict[str, Any]:
    limit = min(max(limit, 1), HISTORY_MAX)
    return {"windows": _historique[-limit:]}


@app.get("/features/names", tags=["telemetrie"])
async def noms() -> dict[str, Any]:
    return {"features": list(FEATURE_NAMES), "count": len(FEATURE_NAMES)}


@app.get("/sources", tags=["telemetrie"])
async def sources() -> dict[str, Any]:
    return {
        "log_dir": LOG_DIR,
        "modsec_log": MODSEC_LOG,
        "events_total": dict(_compteurs),
        "reference": {
            "known_ips": len(_reference.ips_connues),
            "observations": _reference.observations,
            "mean_outgoing_bytes": round(_reference.moyenne_sortante, 2),
        },
    }
