#!/usr/bin/env python3
"""Mise en forme du détail d'un incident, pour le rapport de bout en bout.

Lu depuis l'entrée standard (réponse JSON de `/api/supervision/incidents/{id}`),
écrit sur la sortie standard. Séparé du script shell pour que la mise en forme
ne dépende pas des règles d'échappement du shell.
"""

from __future__ import annotations

import json
import sys

ACTIONS_ATTENDUES = {
    "edge.block_ip": "confinement de la source",
    "auth.revoke_by_source": "révocation des jetons émis depuis la source",
    "auth.rotate_signing_key": "rotation de la clé de signature",
    "docker.restart": "redémarrage du service",
    "docker.wait_healthy": "attente du retour à un état sain",
    "ledger.snapshot": "instantané du grand livre",
    "ledger.reconcile": "réconciliation comptable",
    "ledger.freeze_account": "gel du compte visé",
    "verify.recovery_suite": "vérification de bout en bout",
    "notify.operator": "trace dans la salle d'opérations",
}


def secondes(millisecondes: object) -> str:
    if millisecondes is None:
        return "non mesuré"
    try:
        return f"{float(millisecondes) / 1000.0:.1f} s"
    except (TypeError, ValueError):
        return "non mesuré"


def main() -> int:
    try:
        charge = json.load(sys.stdin)
    except Exception:
        print("  [AVERT] détail illisible")
        return 0

    incident = charge.get("incident") or {}
    print(f"  politique      : {incident.get('policy_id') or '-'}")
    print(f"  playbook       : {incident.get('playbook_id') or '-'}")
    print(f"  état final     : {incident.get('state')}")
    print(f"  délai détection: {secondes(incident.get('mttd_ms'))}")
    print(f"  délai reprise  : {secondes(incident.get('mttr_ms'))}")

    actions = charge.get("actions") or []
    if actions:
        print("  actions exécutées :")
        for action in actions:
            nom = str(action.get("action") or "")
            role = ACTIONS_ATTENDUES.get(nom, "")
            duree = action.get("duration_ms")
            print(
                f"    - {nom:<24} {str(action.get('status') or ''):<8} "
                f"{(str(duree) + ' ms') if duree is not None else '':<10} {role}"
            )

    verifications = charge.get("verifications") or []
    for verification in verifications:
        resultat = "réussie" if verification.get("passed") else "en échec"
        print(f"  vérification   : {resultat} ({verification.get('duration_ms')} ms)")
        for controle in verification.get("checks") or []:
            marque = "ok" if controle.get("passed") else "ECHEC"
            print(f"    - [{marque}] {controle.get('name')} : {controle.get('evidence')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
