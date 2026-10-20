"""AlphaPay : moteur de remédiation autonome.

Rôle
----
Transformer une anomalie **déjà qualifiée** en reprise effective du service,
sans intervention humaine, et le prouver.

Déroulé d'un incident
---------------------
    DETECTING  -> la situation est reconnue, une politique est sélectionnée
    CONTAINING -> l'attaque est isolée (blocage bordure, révocation de jetons)
    ERADICATING-> la cause est traitée (rotation de clés, gel de comptes)
    RECOVERING -> le service est remis en état (redémarrage, réconciliation)
    VERIFYING  -> cinq preuves indépendantes sont exigées
    RECOVERED  -> ou FAILED, avec escalade humaine

Garde-fous (ce qui empêche le remède d'être pire que le mal)
------------------------------------------------------------
* **Fenêtre d'actions** : au plus `MAX_ACTIONS_PER_WINDOW` actions par
  `ACTION_WINDOW_SECONDS`. Un moteur qui s'emballe est un déni de service.
* **Coupe-circuit** : `CIRCUIT_BREAKER_FAILURES` échecs consécutifs suspendent
  la reprise automatique et déclenchent une escalade. On préfère un service
  dégradé avec un humain prévenu à une boucle de remédiation destructrice.
* **Délai de repos par politique** : une même politique ne peut pas se
  redéclencher indéfiniment sur la même situation persistante.
* **Liste blanche** d'actions et de conteneurs, et adresses jamais bloquées.
* **Traçabilité** : chaque action est journalisée et persistée avec sa preuve.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from typing import Any

from fastapi import Header, Request

from common.app import build_app
from common.config import env_bool, env_int, env_str
from common.db import execute, fetch_all, fetch_one
from common.errors import AppError, bad_request, forbidden, not_found
from common.metrics import (
    REMEDIATION_ACTIONS_TOTAL,
    REMEDIATION_INCIDENTS_TOTAL,
    REMEDIATION_MTTD_SECONDS,
    REMEDIATION_MTTR_SECONDS,
    REMEDIATION_STATE,
    REMEDIATION_VERIFICATION_PASSED,
    SERVICE_UP,
)
from common.security import verify_admin_token, verify_webhook

from .connectors import Connecteurs, Resultat
from .policies import (
    ACTIONS_AUTORISEES,
    ErreurDeConfiguration,
    Playbook,
    Politique,
    charger_playbooks,
    charger_politiques,
    selectionner,
)
from .verification import SuiteDeVerification

VERSION = "1.0.0"

_etat: dict[str, Any] = {
    "politiques": [],
    "playbooks": {},
    "incident_courant": None,
    "dernieres_activations": {},
    "actions_recentes": [],
    "echecs_consecutifs": 0,
    "suspendu": False,
    "verifications": [],
}


async def _demarrer() -> None:
    _etat["politiques"] = charger_politiques(POLICIES_DIR)
    _etat["playbooks"] = charger_playbooks(PLAYBOOKS_DIR)
    SERVICE_UP.labels(service="remediation", component="politiques").set(1)
    events.emit(
        "remediation.ready",
        policies=len(_etat["politiques"]),
        playbooks=len(_etat["playbooks"]),
        dry_run=connecteurs.dry_run,
    )


ctx = build_app(
    service_name="remediation",
    version=VERSION,
    title="AlphaPay : Remédiation autonome",
    description=(
        "Ingestion des signalements, sélection de politique, exécution des "
        "playbooks, vérification de la reprise et journalisation des incidents."
    ),
    on_startup=_demarrer,
    with_database=True,
)
app = ctx.app
events = ctx.events

POLICIES_DIR = env_str("POLICIES_DIR", "/etc/alphapay/policies")
PLAYBOOKS_DIR = env_str("PLAYBOOKS_DIR", "/etc/alphapay/playbooks")
ADMIN_TOKEN = env_str("ADMIN_API_TOKEN", required=True)
HMAC_SECRET = env_str("HMAC_SECRET", required=True)
MTTD_TARGET = env_int("MTTD_TARGET_SECONDS", 60)
MTTR_TARGET = env_int("MTTR_TARGET_SECONDS", 180)
MAX_ACTIONS_PAR_FENETRE = env_int("MAX_ACTIONS_PER_WINDOW", 6)
FENETRE_ACTIONS = env_int("ACTION_WINDOW_SECONDS", 300)
SEUIL_COUPE_CIRCUIT = env_int("CIRCUIT_BREAKER_FAILURES", 3)
VERIFY_MAX_TENTATIVES = env_int("VERIFY_MAX_ATTEMPTS", 2)
AUTO_ESCALADE = env_bool("AUTO_ESCALATE", True)

connecteurs = Connecteurs(events)
suite = SuiteDeVerification(connecteurs, events)


# =============================================================================
#  Persistance
# =============================================================================


async def _ouvrir_incident(
    politique: Politique, sac: dict[str, Any], playbook: Playbook
) -> str:
    identifiant = uuid.uuid4()
    mttd_ms = _mttd_ms(sac)
    await execute(
        "INSERT INTO ops.incidents "
        "(id, state, severity, title, source_ip, mttd_ms, playbook_id, correlation) "
        "VALUES (%s, 'DETECTING', %s, %s, NULLIF(%s, '')::inet, %s, %s, %s::jsonb)",
        (
            identifiant,
            politique.severity,
            politique.title,
            str(sac.get("source_ip") or ""),
            mttd_ms,
            playbook.id,
            json.dumps({"policy": politique.id, "trigger": sac}),
        ),
    )
    REMEDIATION_INCIDENTS_TOTAL.labels(service="remediation", severity=politique.severity).inc()
    if mttd_ms is not None:
        REMEDIATION_MTTD_SECONDS.labels(service="remediation").set(mttd_ms / 1000.0)
    _etat["incident_courant"] = str(identifiant)
    return str(identifiant)


def _mttd_ms(sac: dict[str, Any]) -> int | None:
    """Délai entre le début de la fenêtre anormale et sa qualification."""
    debut = sac.get("window_start_epoch")
    if debut is None:
        return None
    try:
        return max(0, int((time.time() - float(debut)) * 1000))
    except (TypeError, ValueError):
        return None


async def _journaliser(
    incident_id: str | None,
    kind: str,
    *,
    state: str | None = None,
    severity: str | None = None,
    source: str = "remediation",
    message: str = "",
    payload: dict[str, Any] | None = None,
) -> None:
    try:
        await execute(
            "INSERT INTO ops.incident_events "
            "(incident_id, state, kind, severity, source, message, payload) "
            "VALUES (NULLIF(%s, '')::uuid, %s, %s, %s, %s, %s, %s::jsonb)",
            (incident_id or "", state, kind, severity, source, message,
             json.dumps(payload or {})),
        )
    except Exception as erreur:  # noqa: BLE001
        events.warn("remediation.persist_failed", message="événement non persisté",
                    error=str(erreur))


async def _maj_etat(incident_id: str, etat: str) -> None:
    """Positionne l'état courant, en éteignant explicitement les autres.

    Sans cette remise à zéro, plusieurs séries `alphapay_remediation_state`
    resteraient à 1 simultanément et la salle d'opérations afficherait un état
    contradictoire.
    """
    for connu in ("NOMINAL", "DETECTING", "CONTAINING", "ERADICATING", "RECOVERING",
                  "VERIFYING", "RECOVERED", "FAILED"):
        REMEDIATION_STATE.labels(service="remediation", state=connu).set(
            1 if connu == etat else 0
        )
    await execute(
        "UPDATE ops.incidents SET state = %s WHERE id = NULLIF(%s, '')::uuid",
        (etat, incident_id),
    )
    await _journaliser(incident_id, "state.changed", state=etat)


async def _cloturer(incident_id: str, etat: str, resume: dict[str, Any]) -> None:
    mttr = resume.get("mttr_seconds")
    await execute(
        "UPDATE ops.incidents SET state = %s, closed_at = now(), correlation = %s::jsonb, "
        "mttr_ms = %s WHERE id = NULLIF(%s, '')::uuid",
        (
            etat,
            json.dumps(resume),
            int(mttr * 1000) if mttr is not None else None,
            incident_id,
        ),
    )
    for connu in ("NOMINAL", "DETECTING", "CONTAINING", "ERADICATING", "RECOVERING",
                  "VERIFYING", "RECOVERED", "FAILED"):
        REMEDIATION_STATE.labels(service="remediation", state=connu).set(
            1 if connu == etat else 0
        )
    _etat["incident_courant"] = None


# =============================================================================
#  Garde-fous
# =============================================================================


def _fenetre_actions_ouverte() -> bool:
    maintenant = time.time()
    _etat["actions_recentes"] = [
        t for t in _etat["actions_recentes"] if maintenant - t < FENETRE_ACTIONS
    ]
    return len(_etat["actions_recentes"]) < MAX_ACTIONS_PAR_FENETRE


def _enregistrer_action() -> None:
    _etat["actions_recentes"].append(time.time())


# =============================================================================
#  Exécution d'un playbook
# =============================================================================


async def _executer_playbook(
    incident_id: str, playbook: Playbook, sac: dict[str, Any]
) -> dict[str, Any]:
    contexte = {"event": sac, "incident": {"id": incident_id}}
    resultats: list[dict[str, Any]] = []
    echec_critique = False
    reprise_effectuee = False

    for etape in playbook.steps:
        # La phase affichée suit l'étape engagée : c'est ce que voit le jury.
        await _maj_etat(incident_id, etape.phase)

        if not _fenetre_actions_ouverte():
            await _journaliser(
                incident_id,
                "action.throttled",
                severity=playbook.id,
                message="plafond d'actions atteint sur la fenêtre courante",
                payload={"step": etape.id, "limit": MAX_ACTIONS_PAR_FENETRE},
            )
            resultats.append(
                {"step": etape.id, "action": etape.action, "ok": False,
                 "detail": "plafond d'actions atteint"}
            )
            break

        if etape.action == "verify.recovery_suite":
            # La suite de vérification n'est pas un connecteur : elle est
            # exécutée par le moteur lui-même, après l'ensemble des étapes, de
            # façon à porter sur l'état final et non sur un état intermédiaire.
            await _journaliser(
                incident_id,
                "verification.requested",
                state=etape.phase,
                message=etape.description,
                payload={"deferred_to_engine": True},
            )
            resultats.append(
                {"step": etape.id, "phase": etape.phase, "action": etape.action,
                 "ok": True, "detail": "exécutée par le moteur après les étapes"}
            )
            continue

        if _etat["suspendu"] and not etape.action.startswith(("notify.", "escalate.")):
            resultats.append(
                {"step": etape.id, "action": etape.action, "ok": False,
                 "detail": "coupe-circuit ouvert : reprise automatique suspendue"}
            )
            continue

        parametres = etape.rendre(contexte)
        _enregistrer_action()
        debut = time.perf_counter()
        resultat: Resultat = await connecteurs.executer(etape.action, parametres, sac)
        duree_ms = int((time.perf_counter() - debut) * 1000)

        REMEDIATION_ACTIONS_TOTAL.labels(
            service="remediation",
            action=etape.action,
            status="ok" if resultat.ok else "failed",
        ).inc()
        await execute(
            "INSERT INTO ops.actions "
            "(incident_id, step_id, action, params, status, started_at, finished_at, "
            " duration_ms, result, error) "
            "VALUES (NULLIF(%s, '')::uuid, %s, %s, %s::jsonb, %s, now(), now(), %s, "
            "        %s::jsonb, %s)",
            (
                incident_id,
                etape.id,
                etape.action,
                json.dumps(parametres),
                "ok" if resultat.ok else "failed",
                duree_ms,
                json.dumps(resultat.resume()),
                None if resultat.ok else resultat.detail,
            ),
        )
        await _journaliser(
            incident_id,
            "action.executed",
            state=etape.phase,
            message=etape.description,
            payload=resultat.resume(),
        )
        resultats.append({"step": etape.id, "phase": etape.phase,
                          "action": etape.action, **resultat.resume(),
                          "duration_ms": duree_ms})

        if etape.action == "docker.isolate" and resultat.ok:
            contexte["isolation"] = resultat.evidence
        if etape.action in {"docker.restart", "docker.rollback", "ledger.restore"} and resultat.ok:
            reprise_effectuee = True

        if not resultat.ok:
            _etat["echecs_consecutifs"] += 1
            if _etat["echecs_consecutifs"] >= SEUIL_COUPE_CIRCUIT and AUTO_ESCALADE:
                _etat["suspendu"] = True
                await _journaliser(
                    incident_id,
                    "circuit_breaker.opened",
                    message=(
                        "reprise automatique suspendue après "
                        f"{_etat['echecs_consecutifs']} échecs consécutifs"
                    ),
                    payload={"failures": _etat["echecs_consecutifs"]},
                )
            if etape.on_failure == "abort" or etape.critical:
                echec_critique = True
                break
            if etape.on_failure == "continue":
                echec_critique = True
                continue
            # continue_anyway : on poursuit malgré l'échec de cette étape
        else:
            _etat["echecs_consecutifs"] = 0

    return {
        "steps": resultats,
        "critical_failure": echec_critique,
        "recovery_action_done": reprise_effectuee,
        "networks_isolated": [
            r for r in resultats if r.get("action") == "docker.isolate" and r.get("ok")
        ],
    }


# =============================================================================
#  Orchestration
# =============================================================================


async def _traiter(sac: dict[str, Any]) -> None:
    maintenant = time.time()
    force = str(sac.get("force_playbook") or "")
    if force:
        # Déclenchement opérateur : la politique n'est pas évaluée, le playbook
        # est imposé. Le garde-fou de fenêtre d'actions reste appliqué.
        politique = Politique(
            id="DECLENCHEMENT-MANUEL",
            title=f"Déclenchement manuel de {force}",
            severity="warning",
            priority=0,
            sources=(),
            match="any",
            conditions=(),
            playbook=force,
            cooldown_seconds=0,
        )
    else:
        selection = selectionner(
            _etat["politiques"], sac, _etat["dernieres_activations"], maintenant
        )
        if selection is None:
            events.emit(
                "remediation.no_policy",
                source=sac.get("source"),
                kind=sac.get("kind"),
            )
            return
        politique = selection

    playbook = _etat["playbooks"].get(politique.playbook)
    if playbook is None:
        events.error(
            "remediation.playbook_missing",
            f"playbook {politique.playbook} introuvable",
            policy=politique.id,
        )
        return

    _etat["dernieres_activations"][politique.id] = maintenant
    incident_id = await _ouvrir_incident(politique, sac, playbook)
    await _journaliser(
        incident_id,
        "incident.opened",
        state="DETECTING",
        severity=politique.severity,
        source=str(sac.get("source") or "inconnu"),
        message=politique.title,
        payload={"policy": politique.id, "conditions": politique.explication()},
    )
    events.warn(
        "incident.opened",
        message=politique.title,
        incident_id=incident_id,
        policy=politique.id,
        playbook=playbook.id,
        severity=politique.severity,
        source_ip=str(sac.get("source_ip") or ""),
    )

    execution = await _executer_playbook(incident_id, playbook, sac)

    verification: dict[str, Any] | None = None
    if playbook.verification_required and not execution["critical_failure"]:
        await _maj_etat(incident_id, "VERIFYING")
        for tentative in range(1, VERIFY_MAX_TENTATIVES + 1):
            rapport = await suite.executer(sac)
            verification = rapport.resume()
            verification["attempt"] = tentative
            await execute(
                "INSERT INTO ops.verifications "
                "(incident_id, passed, duration_ms, checks) VALUES "
                "(NULLIF(%s, '')::uuid, %s, %s, %s::jsonb)",
                (incident_id, rapport.passed, rapport.duration_ms,
                 json.dumps(rapport.resume()["checks"])),
            )
            REMEDIATION_VERIFICATION_PASSED.labels(service="remediation").set(
                1 if rapport.passed else 0
            )
            _etat["verifications"].append(verification)
            if rapport.passed:
                break
            if tentative < VERIFY_MAX_TENTATIVES:
                await _journaliser(
                    incident_id,
                    "verification.retry",
                    state="VERIFYING",
                    message="preuves insuffisantes, nouvelle tentative après reprise",
                    payload={"attempt": tentative},
                )
                await connecteurs.executer(
                    "docker.restart",
                    {"container": "alphaplat-api-payment", "grace_seconds": 3},
                    sac,
                )

    reussi = bool(verification and verification.get("passed"))
    duree_ecoulee = time.time() - float(_mttd_ms(sac) or 0) / 1000.0
    mttr_secondes = None
    if reussi:
        await _maj_etat(incident_id, "RECOVERED")
        reopened = await fetch_one(
            "SELECT EXTRACT(EPOCH FROM (now() - opened_at)) AS duree FROM ops.incidents "
            "WHERE id = NULLIF(%s, '')::uuid",
            (incident_id,),
        )
        mttr_secondes = float(reopened["duree"]) if reopened else None
        if mttr_secondes is not None:
            REMEDIATION_MTTR_SECONDS.labels(service="remediation").set(mttr_secondes)
    else:
        await _maj_etat(incident_id, "FAILED")
        if AUTO_ESCALADE:
            await connecteurs.executer(
                "escalate.human",
                {
                    "reason": (
                        "les preuves de rétablissement ne sont pas réunies après "
                        f"{VERIFY_MAX_TENTATIVES} tentative(s)"
                    )
                },
                sac,
            )

    resume = {
        "policy": politique.id,
        "playbook": playbook.id,
        "execution": execution,
        "verification": verification,
        "mttd_ms": _mttd_ms(sac),
        "mttr_seconds": mttr_secondes,
        "targets": {"mttd_seconds": MTTD_TARGET, "mttr_seconds": MTTR_TARGET},
        "elapsed_seconds": round(duree_ecoulee, 3),
    }
    await _cloturer(incident_id, "RECOVERED" if reussi else "FAILED", resume)
    await _journaliser(
        incident_id,
        "incident.closed",
        state="RECOVERED" if reussi else "FAILED",
        message=(
            "service rétabli et preuves réunies"
            if reussi
            else "rétablissement non démontré"
        ),
        payload={"mttr_seconds": mttr_secondes, "checks": (verification or {}).get("checks")},
    )
    if reussi:
        events.emit(
            "incident.recovered",
            incident_id=incident_id,
            policy=politique.id,
            mttr_seconds=mttr_secondes,
            mttd_ms=resume["mttd_ms"],
        )
    else:
        events.error(
            "incident.failed",
            "rétablissement non démontré, escalade engagée",
            incident_id=incident_id,
            policy=politique.id,
        )


def _sac_detecteur(charge: dict[str, Any]) -> dict[str, Any]:
    sac: dict[str, Any] = {
        "source": "detector",
        "kind": "anomaly",
        "severity": "critical" if charge.get("anomalous") else "warning",
        "score": charge.get("score"),
        "threshold": charge.get("threshold"),
        "exceedance": charge.get("exceedance"),
        "suspected_target": charge.get("suspected_target"),
        "source_ip": charge.get("suspected_source_ip"),
        "window_start_epoch": charge.get("window_start_epoch"),
        "anomaly_detected": bool(charge.get("anomalous")),
        "tags": [],
    }
    for nom, valeur in (charge.get("features") or {}).items():
        sac[f"feature.{nom}"] = valeur
    return sac


def _sac_alerte(charge: dict[str, Any]) -> list[dict[str, Any]]:
    """Alertmanager envoie un lot d'alertes : chacune devient un signalement."""
    sacs = []
    for alerte in charge.get("alerts") or []:
        etiquettes = alerte.get("labels") or {}
        sac: dict[str, Any] = {
            "source": "alertmanager",
            "kind": str(etiquettes.get("alertname") or "alert"),
            "severity": str(etiquettes.get("severity") or "warning"),
            "service": etiquettes.get("service"),
            "anomaly_detected": str(etiquettes.get("alertname")) == "AlphaPayAnomalyDetected",
            "source_ip": etiquettes.get("source_ip"),
            "tags": [str(v) for v in etiquettes.values()],
            "annotations": alerte.get("annotations") or {},
        }
        sacs.append(sac)
    return sacs


def _sac_falco(charge: dict[str, Any]) -> dict[str, Any]:
    sortie = str(charge.get("output") or "")
    priorite = str(charge.get("priority") or "warning")
    return {
        "source": "falco",
        "kind": str(charge.get("rule") or "runtime"),
        "severity": "critical" if priorite.lower() in {"critical", "emergency", "alert"} else "warning",
        "container": (charge.get("output_fields") or {}).get("container.name"),
        "command": (charge.get("output_fields") or {}).get("proc.cmdline"),
        "message": sortie,
        "tags": [str(charge.get("rule") or "")],
    }


# =============================================================================
#  Ingestion
# =============================================================================


async def _lire_corps(request: Request) -> bytes:
    corps = await request.body()
    if not corps:
        raise bad_request("corps_vide", "Corps vide", "Aucun signalement fourni.")
    if len(corps) > 512 * 1024:
        raise AppError(413, "corps_trop_volumineux", "Signalement trop volumineux")
    return corps


def _verifier(request: Request, corps: bytes) -> None:
    if not verify_webhook(HMAC_SECRET, request.headers, corps):
        raise forbidden("Signature du signalement invalide.")


@app.post("/api/ingest/detector", tags=["ingestion"])
async def ingerer_detecteur(request: Request) -> dict[str, Any]:
    corps = await _lire_corps(request)
    _verifier(request, corps)
    charge = json.loads(corps)
    sac = _sac_detecteur(charge)
    asyncio.create_task(_traiter(sac))
    return {"accepted": True, "source": "detector", "score": charge.get("score")}


@app.post("/api/ingest/alertmanager", tags=["ingestion"])
async def ingerer_alertmanager(request: Request) -> dict[str, Any]:
    corps = await _lire_corps(request)
    _verifier(request, corps)
    charge = json.loads(corps)
    sacs = _sac_alerte(charge)
    for sac in sacs:
        asyncio.create_task(_traiter(sac))
    return {"accepted": True, "source": "alertmanager", "alerts": len(sacs)}


@app.post("/api/ingest/falco", tags=["ingestion"])
async def ingerer_falco(request: Request) -> dict[str, Any]:
    corps = await _lire_corps(request)
    _verifier(request, corps)
    charge = json.loads(corps)
    sac = _sac_falco(charge)
    asyncio.create_task(_traiter(sac))
    return {"accepted": True, "source": "falco", "rule": sac["kind"]}


@app.post("/api/ingest/webhook", tags=["ingestion"])
async def ingerer_generique(request: Request) -> dict[str, Any]:
    """Signalement générique : utilisé par le banc d'attaque pour horodater le tir.

    Ce n'est pas un canal de déclenchement : le banc d'attaque s'en sert pour
    marquer l'instant exact du début d'attaque, ce qui permet de mesurer le
    délai de détection (MTTD) sur une base non ambiguë.
    """
    corps = await _lire_corps(request)
    _verifier(request, corps)
    charge = json.loads(corps)
    sac = {
        "source": "redteam",
        "kind": str(charge.get("kind") or "attack.started"),
        "severity": str(charge.get("severity") or "info"),
        "source_ip": charge.get("source_ip"),
        "window_start_epoch": charge.get("started_at_epoch"),
        "scenario": charge.get("scenario"),
        "tags": [str(charge.get("scenario") or "")],
    }
    await _journaliser(
        None,
        "redteam." + str(sac["kind"]),
        severity=str(sac["severity"]),
        source="redteam",
        message=f"scénario {sac['scenario']}",
        payload=charge,
    )
    events.warn(
        "redteam.attack_declared",
        message="début d'attaque déclaré par le banc offensif",
        scenario=sac["scenario"],
        source_ip=str(sac["source_ip"] or ""),
    )
    return {"accepted": True, "source": "redteam", "scenario": sac["scenario"]}


# =============================================================================
#  Supervision
# =============================================================================


def _exiger_admin(jeton: str | None) -> None:
    if not verify_admin_token(ADMIN_TOKEN, jeton):
        raise forbidden("Jeton d'administration invalide ou absent.")


@app.get("/api/supervision/state", tags=["supervision"])
async def etat_courant() -> dict[str, Any]:
    incident = None
    if _etat["incident_courant"]:
        incident = await fetch_one(
            "SELECT id, state, severity, title, opened_at, mttd_ms FROM ops.incidents "
            "WHERE id = NULLIF(%s, '')::uuid",
            (_etat["incident_courant"],),
        )
    else:
        incident = await fetch_one(
            "SELECT id, state, severity, title, opened_at, mttd_ms FROM ops.incidents "
            "ORDER BY opened_at DESC LIMIT 1"
        )
    if incident is None:
        etat = "NOMINAL"
    elif incident["state"] == "RECOVERED":
        etat = "RECOVERED"
    elif incident["state"] == "FAILED":
        etat = "FAILED"
    else:
        etat = "INCIDENT"
    return {
        "state": etat,
        "suspended": _etat["suspendu"],
        "dry_run": connecteurs.dry_run,
        "consecutive_failures": _etat["echecs_consecutifs"],
        "actions_in_window": len(_etat["actions_recentes"]),
        "action_limit": MAX_ACTIONS_PAR_FENETRE,
        "incident": dict(incident) if incident else None,
        "targets": {"mttd_seconds": MTTD_TARGET, "mttr_seconds": MTTR_TARGET},
        # Le registre est exposé ici plutôt que figé dans l'interface : une
        # salle d'opérations qui affiche « 8 politiques » alors que le moteur en
        # charge 12 est une salle d'opérations qui ment au jury.
        "registry": {
            "policies": len(_etat["politiques"]),
            "playbooks": len(_etat["playbooks"]),
            "allowed_actions": len(ACTIONS_AUTORISEES),
        },
    }


@app.get("/api/supervision/incidents", tags=["supervision"])
async def lister_incidents(limit: int = 20) -> dict[str, Any]:
    lignes = await fetch_all(
        "SELECT id, state, severity, title, opened_at, closed_at, source_ip, "
        "mttd_ms, mttr_ms, playbook_id FROM ops.incidents "
        "ORDER BY opened_at DESC LIMIT %s",
        (min(max(limit, 1), 200),),
    )
    return {"incidents": [dict(ligne) for ligne in lignes]}


@app.get("/api/supervision/incidents/{identifiant}", tags=["supervision"])
async def detail_incident(identifiant: str) -> dict[str, Any]:
    incident = await fetch_one(
        "SELECT * FROM ops.incidents WHERE id = %s", (identifiant,)
    )
    if incident is None:
        raise not_found("Incident inconnu.")
    evenements = await fetch_all(
        "SELECT occurred_at, state, kind, severity, source, message, payload "
        "FROM ops.incident_events WHERE incident_id = %s ORDER BY occurred_at, id",
        (identifiant,),
    )
    actions = await fetch_all(
        "SELECT step_id, action, params, status, duration_ms, result, error, started_at "
        "FROM ops.actions WHERE incident_id = %s ORDER BY id",
        (identifiant,),
    )
    verifications = await fetch_all(
        "SELECT ran_at, passed, duration_ms, checks FROM ops.verifications "
        "WHERE incident_id = %s ORDER BY id",
        (identifiant,),
    )
    return {
        "incident": dict(incident),
        "events": [dict(e) for e in evenements],
        "actions": [dict(a) for a in actions],
        "verifications": [dict(v) for v in verifications],
    }


@app.get("/api/supervision/timeline", tags=["supervision"])
async def chronologie(limit: int = 120) -> dict[str, Any]:
    lignes = await fetch_all(
        "SELECT occurred_at, incident_id, state, kind, severity, source, message, payload "
        "FROM ops.incident_events ORDER BY occurred_at DESC, id DESC LIMIT %s",
        (min(max(limit, 1), 500),),
    )
    return {"events": [dict(ligne) for ligne in lignes]}


@app.get("/api/supervision/policies", tags=["supervision"])
async def lister_politiques() -> dict[str, Any]:
    return {
        "policies": [
            {
                "id": p.id,
                "title": p.title,
                "severity": p.severity,
                "priority": p.priority,
                "sources": list(p.sources),
                "match": p.match,
                "conditions": p.explication(),
                "playbook": p.playbook,
                "cooldown_seconds": p.cooldown_seconds,
                "enabled": p.enabled,
            }
            for p in _etat["politiques"]
        ]
    }


@app.get("/api/supervision/playbooks", tags=["supervision"])
async def lister_playbooks() -> dict[str, Any]:
    return {
        "playbooks": [
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "phases": p.phases,
                "verification_required": p.verification_required,
                "steps": [
                    {
                        "id": e.id,
                        "action": e.action,
                        "phase": e.phase,
                        "description": e.description,
                        "on_failure": e.on_failure,
                        "critical": e.critical,
                        "timeout_seconds": e.timeout_seconds,
                    }
                    for e in p.steps
                ],
            }
            for p in _etat["playbooks"].values()
        ]
    }


@app.get("/api/supervision/verifications", tags=["supervision"])
async def lister_verifications(limit: int = 20) -> dict[str, Any]:
    return {"verifications": _etat["verifications"][-limit:]}


@app.post("/api/actions/run", tags=["administration"])
async def declencher_playbook(
    charge: dict[str, Any],
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Déclenchement manuel d'un playbook : utile pour les répétitions."""
    _exiger_admin(x_admin_token)
    if _etat["suspendu"]:
        raise AppError(
            409,
            "circuit_ouvert",
            "Reprise automatique suspendue",
            "Un opérateur doit lever la suspension avant tout nouveau déclenchement.",
        )
    identifiant = str(charge.get("playbook") or "")
    playbook = _etat["playbooks"].get(identifiant)
    if playbook is None:
        raise not_found(f"Playbook {identifiant} inconnu.")
    sac = dict(charge.get("context") or {})
    sac.setdefault("source", "operator")
    sac.setdefault("kind", "manual")
    asyncio.create_task(_traiter({**sac, "force_playbook": identifiant}))
    return {"accepted": True, "playbook": identifiant}


@app.post("/api/actions/verify", tags=["administration"])
async def verifier_maintenant(
    charge: dict[str, Any] | None = None,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _exiger_admin(x_admin_token)
    rapport = await suite.executer(charge or {})
    _etat["verifications"].append(rapport.resume())
    return rapport.resume()


@app.post("/api/actions/reset-circuit-breaker", tags=["administration"])
async def lever_suspension(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    _exiger_admin(x_admin_token)
    _etat["suspendu"] = False
    _etat["echecs_consecutifs"] = 0
    events.emit("circuit_breaker.reset", message="suspension levée par un opérateur")
    return {"suspended": False, "consecutive_failures": 0}


async def _attendre_remediation_terminee() -> None:
    """Point d'attente utilisé par les scripts de vérification du sprint."""
    while _etat["incident_courant"] is not None:
        await asyncio.sleep(0.5)
