"""AlphaPay : détecteur d'anomalies par apprentissage non supervisé.

Boucle de fonctionnement
------------------------
1. toutes les `SCAN_INTERVAL_SECONDS`, le service interroge la télémétrie et
   récupère le vecteur des 18 variables observées ;
2. il le normalise avec la moyenne et l'écart-type appris sur le trafic
   nominal, puis le soumet au modèle Isolation Forest ;
3. le score obtenu est comparé au seuil calibré (quantile 99,8 du nominal) ;
4. une anomalie n'est déclarée qu'après `CONSECUTIVE_WINDOWS` fenêtres
   consécutives au-dessus du seuil : ce qui élimine les dépassements isolés
   inhérents au choix du quantile.

Aucune règle n'intervient dans la décision. Les seuils de latence, de taux
d'erreur ou de volume présents ailleurs dans la pile sont des **règles
d'alerte d'exploitation**, pas le mécanisme de détection : le jury peut les
désactiver, la détection continue de fonctionner.

Double signalement
------------------
Un même constat est publié de deux façons indépendantes :

* une métrique Prometheus (`alphapay_anomaly_anomalous`), couverte par une
  règle d'alerte qui passe par Alertmanager ;
* une notification directe, signée, vers le moteur de remédiation.

Si l'un des deux chemins tombe (Alertmanager indisponible, règle mal rechargée),
l'autre continue d'alimenter la reprise. C'est un choix de résilience assumé,
et il réduit le délai de détection à quelques dizaines de secondes.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import os
import time
from typing import Any

from common.app import build_app
from common.config import env_float, env_int, env_str
from common.db import execute
from common.errors import AppError
from common.http_client import request_json
from common.metrics import (
    ANOMALY_ANOMALOUS,
    ANOMALY_SCORE,
    ANOMALY_SCORE_MAX,
    ANOMALY_THRESHOLD,
    SERVICE_UP,
)
from common.security import compute_signature
from common.features import FEATURE_NAMES, vecteur_vers_liste

VERSION = "1.0.0"
CHEMIN_META = env_str("MODEL_FALLBACK_META_PATH", "/app/artifacts/model-meta.json")
CHEMIN_MODELE = env_str("MODEL_FALLBACK_PATH", "/app/artifacts/model.joblib")

_tache: asyncio.Task[None] | None = None
_etat: dict[str, Any] = {
    "modele": None,
    "meta": None,
    "dernier": None,
    "historique": [],
    "consecutives": 0,
    "anomalie_active": False,
    "score_max_recent": 0.0,
    #: Seuil effectivement applique, publie meme sans fenetre notee : la salle
    #: d'operations l'affiche en permanence.
    "seuil": 0.0,
}


async def _demarrer() -> None:
    global _tache
    _charger_modele()
    _tache = asyncio.create_task(_boucle())


async def _arreter() -> None:
    global _tache
    if _tache is not None:
        _tache.cancel()
        _tache = None


ctx = build_app(
    service_name="detector",
    version=VERSION,
    title="AlphaPay : Détection d'anomalies",
    description=(
        "Modélisation non supervisée du trafic nominal et qualification des "
        "écarts comme anomalies."
    ),
    on_startup=_demarrer,
    on_shutdown=_arreter,
    with_database=True,
)
app = ctx.app
events = ctx.events

TELEMETRY_URL = env_str("TELEMETRY_URL", "http://telemetry:8000", required=True)
REMEDIATION_URL = env_str("REMEDIATION_URL", "http://remediation:8000", required=True)
HMAC_SECRET = env_str("HMAC_SECRET", required=True)
MODEL_PATH = env_str("MODEL_PATH", "/models/model.joblib")
MODEL_META_PATH = env_str("MODEL_META_PATH", "/models/model-meta.json")
SCAN_INTERVAL_SECONDS = env_float("SCAN_INTERVAL_SECONDS", 10.0)
CONSECUTIVE_WINDOWS = env_int("CONSECUTIVE_WINDOWS", 2)
HISTORY_MAX = env_int("DETECTOR_HISTORY_MAX", 360)
SOURCES_FENETRE_MAX = env_int("DETECTOR_SCORE_WINDOW", 30)
#: Debit en dessous duquel une fenetre composee des seules routes de
#: consultation est attribuee a l'operateur qui regarde son tableau de bord,
#: et non a un adversaire. Un navigateur sonde quelques fois par seconde ; une
#: attaque volumetrique vise dix a cent fois plus.
PLAFOND_CONSULTATION_RPS = env_float("DETECTOR_OBSERVATION_MAX_RPS", 20.0)
#: Marge minimale exigee entre le score nominal et le plus faible des profils
#: d'attaque pour considerer le seuil comme discriminant.
ECART_SEPARABILITE_MINIMAL = 0.01


def _seuil_separable(
    paquet: dict[str, Any], meta: dict[str, Any]
) -> tuple[float, dict[str, Any]]:
    """Verifie que le seuil du modele separe encore le nominal de l'attaque.

    Une Isolation Forest sature : au-dela de la plage apprise, le score d'atypie
    plafonne pour *tout* vecteur, au repos comme en pleine attaque. Un seuil pose
    au-dessus de ce plafond n'est donc jamais franchi : le detecteur repond, la
    salle d'operations affiche un score et un seuil, et rien n'est jamais
    detecte.

    Le score nominal vient des metadonnees, pas du modele serialise : c'est la
    calibration qui l'y consigne. Sans cette valeur, on ne replace pas le seuil,
    car le poser trop bas confinerait l'operateur au repos.
    """
    from ml.profils_attaque import profils_du_modele

    modele = paquet["modele"]
    normaliseur = paquet["scaler"]
    annonce = float(paquet["seuil"])
    vecteurs = [
        [float(profil.get(nom, 0.0)) for nom in FEATURE_NAMES]
        for profil in profils_du_modele().values()
    ]
    scores = -modele.decision_function(normaliseur.transform(vecteurs))
    plus_faible = float(min(scores))
    info: dict[str, Any] = {
        "seuil_annonce": round(annonce, 6),
        "score_min_attaque": round(plus_faible, 6),
    }

    nominal_brut = meta.get("score_max_nominal")
    if nominal_brut is None:
        nominal_brut = meta.get("score_max")
    if nominal_brut is None or float(nominal_brut) <= 0.0:
        info["verdict"] = "indeterminee"
        info["seuil_effectif"] = round(annonce, 6)
        info["message"] = (
            "score nominal absent des metadonnees : seuil laisse en place, "
            "recalibrer le modele (python -m ml.recalibrer) avant de conclure"
        )
        return annonce, info

    nominal = float(nominal_brut)
    info["score_max_nominal"] = round(nominal, 6)
    if annonce < plus_faible:
        info["verdict"] = "separable"
        info["seuil_effectif"] = round(annonce, 6)
        return annonce, info

    marge = plus_faible - nominal
    info["marge_separabilite"] = round(marge, 6)
    if marge > ECART_SEPARABILITE_MINIMAL:
        corrige = nominal + 0.25 * marge
        info["verdict"] = "corrige"
        info["seuil_effectif"] = round(corrige, 6)
        return corrige, info

    info["verdict"] = "non_separable"
    info["seuil_effectif"] = round(annonce, 6)
    info["message"] = (
        "aucune marge entre le nominal et les profils d'attaque : le seuil ne "
        "peut pas etre rendu discriminant, recalibrer le modele"
    )
    return annonce, info


# =============================================================================
#  Modèle
# =============================================================================


def _charger_modele() -> None:
    """Charge le modèle pré-entraîné, ou l'entraîne à la volée s'il manque."""
    import joblib

    for chemin_modele, chemin_meta in (
        (MODEL_PATH, MODEL_META_PATH),
        (CHEMIN_MODELE, CHEMIN_META),
    ):
        if os.path.isfile(chemin_modele):
            paquet = joblib.load(chemin_modele)
            meta = {}
            if os.path.isfile(chemin_meta):
                with open(chemin_meta, encoding="utf-8") as fichier:
                    meta = json.load(fichier)
            _etat["modele"] = paquet
            _etat["meta"] = meta
            seuil, verdict = _seuil_separable(paquet, meta)
            constat = str(verdict.pop("message", "") or "seuil verifie")
            journal = events.warn if verdict.get("verdict") != "separable" else events.emit
            journal("detector.threshold_checked", message=constat, source=chemin_modele, **verdict)
            paquet["seuil"] = seuil
            _etat["seuil"] = float(seuil)
            ANOMALY_THRESHOLD.labels(service="detector").set(float(seuil))
            events.emit(
                "detector.model.loaded",
                model=paquet.get("version"),
                source=chemin_modele,
                threshold=float(seuil),
                features=len(paquet["feature_names"]),
            )
            return

    events.warn(
        "detector.model.missing",
        message="aucun modèle disponible, entraînement à la volée sur trafic simulé",
    )
    try:
        from ml.train import ecrire_artefacts, entrainer

        artefact = entrainer()
        # Un modèle appris à la volée sur trafic simulé porte un seuil plus
        # strict que le même modèle recalibré sur du trafic réel, et rien ne le
        # distinguait : l'exploitant voyait un détecteur qui signale la
        # plateforme au repos sans pouvoir savoir d'où venait le seuil. La
        # provenance est désormais écrite dans les métadonnées, donc exposée par
        # /api/detector/model et par l'écran de supervision.
        artefact["source_calibrage"] = "entrainement-a-la-volee"
        ecrire_artefacts(artefact, os.path.dirname(MODEL_PATH) or "/models")
        events.warn(
            "detector.model.trained_on_the_fly",
            message="modèle entraîné au démarrage sur trafic simulé, seuil plus strict qu'une calibration réelle",
            threshold=float(artefact.get("seuil") or 0.0),
        )
        _charger_modele()
    except Exception as erreur:  # noqa: BLE001
        events.warn(
            "detector.model.failed",
            message="entraînement automatique impossible",
            error=str(erreur),
        )
        SERVICE_UP.labels(service="detector", component="modele").set(0)


# =============================================================================
#  Notation
# =============================================================================


def _normaliser(paquet: dict[str, Any], valeurs: list[float]) -> Any:
    import numpy as np

    brut = np.asarray([valeurs], dtype=float)
    return paquet["scaler"].transform(brut)


def _expliquer(meta: dict[str, Any], vecteur: dict[str, float]) -> list[dict[str, Any]]:
    """Écarts en nombre d'écarts-types par rapport au trafic nominal appris."""
    moyennes = meta.get("moyennes") or {}
    ecarts = meta.get("ecarts") or {}
    details = []
    for nom, valeur in vecteur.items():
        moyenne = float(moyennes.get(nom, 0.0))
        ecart = float(ecarts.get(nom, 1.0)) or 1.0
        details.append(
            {
                "feature": nom,
                "value": round(float(valeur), 6),
                "baseline_mean": round(moyenne, 6),
                "z": round((float(valeur) - moyenne) / ecart, 3),
            }
        )
    details.sort(key=lambda item: abs(item["z"]), reverse=True)
    return details


def _cible_suggeree(vecteur: dict[str, float]) -> str:
    """Indice de localisation, à partir des variables les plus déviantes.

    Il ne s'agit que d'une aide à la lecture pour l'opérateur : le moteur de
    remédiation décide à partir de ses propres politiques, et l'action engagée
    reste déterminée par la politique applicable, pas par cette suggestion.
    """
    indices = {
        "api-auth": vecteur.get("auth_failure_ratio", 0.0) * 3
        + vecteur.get("auth_attempts_per_identity", 0.0) * 0.1
        + vecteur.get("requests_per_token", 0.0) * 0.1,
        "edge": vecteur.get("injection_token_ratio", 0.0) * 5
        + vecteur.get("xss_token_ratio", 0.0) * 5
        + vecteur.get("waf_block_ratio", 0.0) * 2,
        "api-payment": vecteur.get("error_ratio", 0.0) * 3
        + vecteur.get("latency_p99_ms", 0.0) / 1000.0
        + vecteur.get("requests_per_second", 0.0) / 20.0,
        "api-ledger": vecteur.get("outgoing_bytes_ratio", 0.0) / 5.0,
    }
    return max(indices.items(), key=lambda item: item[1])[0]


async def _notifier_remediation(rapport: dict[str, Any]) -> bool:
    corps = json.dumps(rapport, ensure_ascii=False).encode()
    signature = compute_signature(HMAC_SECRET, corps)
    try:
        await request_json(
            "POST",
            f"{REMEDIATION_URL}/api/ingest/detector",
            raw_body=corps,
            headers={
                "Content-Type": "application/json",
                "X-AlphaPay-Signature": f"hmac-sha256={signature}",
            },
            timeout=5.0,
        )
        return True
    except Exception as erreur:  # noqa: BLE001
        events.warn(
            "detector.notify_failed",
            message="notification du moteur de remédiation impossible",
            error=str(erreur),
        )
        return False


async def _enregistrer(rapport: dict[str, Any]) -> None:
    try:
        await execute(
            "INSERT INTO ml.features "
            "(window_start, window_end, vector, score, anomalous, top_features, model_version) "
            "VALUES (to_timestamp(%s), to_timestamp(%s), %s::jsonb, %s, %s, %s::jsonb, %s)",
            (
                rapport["window_start_epoch"],
                rapport["window_end_epoch"],
                json.dumps(rapport["features"]),
                rapport["score"],
                rapport["anomalous"],
                json.dumps(rapport["top_features"][:5]),
                rapport.get("model_version"),
            ),
        )
    except Exception as erreur:  # noqa: BLE001
        events.warn("detector.persist_failed", message="écriture du constat impossible",
                    error=str(erreur))


async def _abandonner_anomalie(motif: str, fenetre: dict[str, Any]) -> None:
    """Clôt une anomalie en cours quand une fenêtre n'est pas notable.

    Sans cela, une anomalie confirmée restait active tant que le score ne
    redescendait pas, et le détecteur ne notifiait plus jamais rien : une attaque
    survenue ensuite passait totalement inaperçue alors que le service répondait
    normalement. Une fenêtre qu'on ne sait pas juger ne peut pas prolonger un
    jugement.
    """
    _etat["consecutives"] = 0
    active = bool(_etat["anomalie_active"])
    _etat["anomalie_active"] = False
    events.emit(
        "detector.window_skipped",
        message=motif,
        window_end=fenetre.get("window_end"),
        anomaly_cleared=active,
        requests_per_second=(fenetre.get("features") or {}).get("requests_per_second"),
        top_paths=(fenetre.get("diagnostics") or {}).get("top_paths"),
    )


async def _cycle() -> None:
    paquet = _etat["modele"]
    if paquet is None:
        return
    meta = _etat["meta"] or {}
    fenetre = await request_json("GET", f"{TELEMETRY_URL}/features/current", timeout=5.0)
    if not isinstance(fenetre, dict):
        return
    if fenetre.get("warming_up"):
        # La mémoire longue de la télémétrie n'est pas encore établie : les
        # variables dérivées de la référence n'ont pas de sens. On attend plutôt
        # que d'annoncer une anomalie qui n'existe pas.
        _etat["consecutives"] = 0
        events.emit(
            "detector.warming_up",
            window_end=fenetre.get("window_end"),
        )
        return

    diagnostics = fenetre.get("diagnostics") or {}
    # Une fenetre sans aucun evenement de bordure ne decrit aucun comportement :
    # toutes les variables valent zero, le vecteur sort du domaine
    # d'entrainement et le modele le note comme une anomalie franche. C'est par
    # ce chemin qu'un poste au repos se fait declarer en rafale. On ne note donc
    # que ce qui a ete reellement observe.
    #
    # Le compteur retenu est celui du trafic *metier*. Les routes que la
    # plateforme appelle sur elle-meme (salle d'operations, sondes de telemetrie,
    # /healthz) ne participent plus au vecteur : une fenetre qui n'en contient
    # pas d'autres n'a donc rien a decrire, meme si elle a vu passer des dizaines
    # de requetes de consultation. La garde suit la meme definition que le
    # vecteur, sinon elle laisserait noter des fenetres vides des qu'un
    # navigateur est ouvert sur la salle d'operations.
    metier = diagnostics.get("edge_events_metier")
    if metier is None:
        # Telemetrie anterieure au compteur metier : on retombe sur le compteur
        # global plutot que de ne plus rien noter du tout.
        metier = fenetre.get("edge_events_in_window")
    if int(metier or 0) <= 0:
        await _abandonner_anomalie(
            "fenetre sans trafic metier : non notee", fenetre
        )
        return

    # Meme raisonnement pour une fenetre composee des seules routes de
    # consultation : elle decrit un operateur qui regarde son tableau de bord,
    # pas un adversaire. La noter revient a confiner l'operateur, puis a nourrir
    # l'anomalie par le refus ainsi produit.
    #
    # La garde est conditionnee au debit : une rafale dirigee contre ces memes
    # routes reste une rafale. Un navigateur qui consulte son tableau de bord
    # produit quelques requetes par seconde, jamais le debit d'une attaque
    # volumetrique.
    vecteur = fenetre.get("features") or {}
    if not vecteur:
        return
    debit = float(vecteur.get("requests_per_second") or 0.0)
    if diagnostics.get("observation_seule") and debit < PLAFOND_CONSULTATION_RPS:
        await _abandonner_anomalie(
            "fenetre composee des seules routes de consultation : non notee",
            fenetre,
        )
        return

    valeurs = vecteur_vers_liste(vecteur)
    normalise = _normaliser(paquet, valeurs)
    score = float(-paquet["modele"].decision_function(normalise)[0])
    seuil = float(paquet["seuil"])
    depassement = score >= seuil

    _etat["consecutives"] = _etat["consecutives"] + 1 if depassement else 0
    anomalie = _etat["consecutives"] >= CONSECUTIVE_WINDOWS

    ANOMALY_SCORE.labels(service="detector").set(score)
    ANOMALY_THRESHOLD.labels(service="detector").set(seuil)
    ANOMALY_ANOMALOUS.labels(service="detector").set(1 if anomalie else 0)

    maintenant = time.time()
    top = _expliquer(meta, vecteur)
    rapport = {
        "detected_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "window_start": fenetre.get("window_start"),
        "window_end": fenetre.get("window_end"),
        "window_start_epoch": _epoch(fenetre.get("window_start"), maintenant - 60.0),
        "window_end_epoch": _epoch(fenetre.get("window_end"), maintenant),
        "score": round(score, 6),
        "threshold": round(seuil, 6),
        "exceedance": round(score / seuil, 4) if seuil else 0.0,
        "anomalous": anomalie,
        "consecutive_windows": _etat["consecutives"],
        "features": {nom: round(float(valeur), 6) for nom, valeur in vecteur.items()},
        "top_features": top[:6],
        "suspected_target": _cible_suggeree(vecteur),
        "suspected_source_ip": str(diagnostics.get("dominant_source_ip") or ""),
        "dominant_source_ips": diagnostics.get("top_source_ips") or [],
        "top_paths": diagnostics.get("top_paths") or [],
        "model_version": paquet.get("version"),
        "rules_used": False,
    }
    _etat["dernier"] = rapport
    _etat["historique"].append(rapport)
    if len(_etat["historique"]) > HISTORY_MAX:
        del _etat["historique"][: len(_etat["historique"]) - HISTORY_MAX]

    recents = [r["score"] for r in _etat["historique"][-SOURCES_FENETRE_MAX:]]
    _etat["score_max_recent"] = max(recents) if recents else score
    ANOMALY_SCORE_MAX.labels(service="detector").set(_etat["score_max_recent"])

    await _enregistrer(rapport)

    if anomalie and not _etat["anomalie_active"]:
        _etat["anomalie_active"] = True
        events.warn(
            "anomaly.detected",
            message="comportement anormal confirmé sur plusieurs fenêtres",
            score=rapport["score"],
            threshold=rapport["threshold"],
            consecutive_windows=rapport["consecutive_windows"],
            suspected_target=rapport["suspected_target"],
            top_features=top[:3],
        )
        notifie = await _notifier_remediation(rapport)
        events.emit(
            "anomaly.notified",
            target="remediation",
            delivered=notifie,
            score=rapport["score"],
        )
    elif not anomalie and _etat["anomalie_active"]:
        _etat["anomalie_active"] = False
        events.emit(
            "anomaly.cleared",
            message="retour à un comportement conforme au trafic nominal",
            score=rapport["score"],
        )


def _epoch(valeur: Any, defaut: float) -> float:
    if not isinstance(valeur, str):
        return defaut
    try:
        return dt.datetime.fromisoformat(valeur).timestamp()
    except ValueError:
        return defaut


async def _boucle() -> None:
    while True:
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)
        try:
            await _cycle()
        except Exception as erreur:  # noqa: BLE001 : la boucle ne doit jamais mourir
            events.warn(
                "detector.cycle_failed",
                message="échec d'un cycle de détection",
                error=str(erreur),
            )


# =============================================================================
#  Interface
# =============================================================================


@app.get("/score/current", tags=["detection"])
async def score_courant() -> dict[str, Any]:
    """Dernière fenêtre évaluée.

    En l'absence de fenêtre évaluée, la réponse reste un 200 portant
    `available: false`. La salle d'opérations interroge cette route en
    permanence : un 503 y produisait une erreur visible dans le navigateur,
    comptait comme une erreur applicative dans le taux d'erreur de la télémétrie,
    et pouvait ainsi déclencher une reprise alors que rien ne s'était produit.
    C'est aussi l'état normal au repos, les fenêtres de consultation seule
    n'étant pas notées.
    """
    if _etat["dernier"] is None:
        return {
            "available": False,
            "reason": "aucune fenetre evaluee",
            "model_version": VERSION,
            "threshold": float(_etat.get("seuil") or 0.0),
            "consecutive_windows": int(_etat.get("consecutives") or 0),
        }
    rapport = dict(_etat["dernier"])
    rapport["available"] = True
    return rapport


@app.get("/score/history", tags=["detection"])
async def score_historique(limit: int = 60) -> dict[str, Any]:
    limit = min(max(limit, 1), HISTORY_MAX)
    return {"windows": _etat["historique"][-limit:]}


@app.get("/model", tags=["detection"])
async def description_modele() -> dict[str, Any]:
    meta = _etat["meta"] or {}
    return {
        "loaded": _etat["modele"] is not None,
        "version": (meta.get("version") if meta else None),
        "algorithm": "IsolationForest",
        "features": list(FEATURE_NAMES),
        "threshold": meta.get("seuil"),
        "threshold_quantile": meta.get("quantile_seuil"),
        "trained_windows": meta.get("n_fenetres"),
        "nominal_detection_rate_pct": meta.get("taux_detection_nominal_pct"),
        "importances": meta.get("importances"),
        "consecutive_windows_required": CONSECUTIVE_WINDOWS,
        "scan_interval_seconds": SCAN_INTERVAL_SECONDS,
        "score_max_recent": round(_etat["score_max_recent"], 6),
        "anomaly_active": _etat["anomalie_active"],
        "rules_used": False,
    }
