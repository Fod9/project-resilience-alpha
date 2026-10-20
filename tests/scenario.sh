#!/usr/bin/env bash
# =============================================================================
#  scenario.sh : déclenchement direct d'un playbook
# =============================================================================
#  Ce script joue le rôle du détecteur : il pousse un signalement d'anomalie
#  signé vers le moteur de remédiation, exactement comme le ferait le service
#  `detector`. Il sert à isoler un problème : vérifier qu'un playbook fonctionne
#  sans dépendre de la production de télémétrie ni du modèle.
#
#  Utilisation :
#      bash tests/scenario.sh A1
#      bash tests/scenario.sh A2 192.168.137.20
#      bash tests/scenario.sh A3
#
#  Le signalement est signé avec HMAC_SECRET : le moteur refuse toute
#  notification non signée, y compris depuis ce script.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-A1}"
SOURCE_IP="${2:-192.168.137.20}"
CIBLE="${CIBLE:-http://localhost}"
# Le chemin passe par la bordure : `/api/ops/` y est ramené sous `/api/`, ce qui
# permet d'utiliser ce script aussi bien depuis le poste hôte que depuis un
# conteneur du réseau applicatif.
CHEMIN_INGESTION="${CHEMIN_INGESTION:-/api/ops/ingest/detector}"

HMAC="$(sed -n 's/^HMAC_SECRET=//p' "$RACINE/.env" | head -1)"
if [ -z "$HMAC" ]; then
    echo "HMAC_SECRET introuvable : exécuter scripts/seed-secrets.sh" >&2
    exit 1
fi

# Le signalement porte exactement le même contrat que celui du détecteur :
# des variables observées sous le préfixe `feature.`, l'adresse d'origine
# pressentie, et l'horodatage de la fenêtre anormale.
python3 - "$SCENARIO" "$SOURCE_IP" "$HMAC" "$CIBLE" "$CHEMIN_INGESTION" "$RACINE" <<'PY'
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

scenario, source_ip, secret, cible, chemin, racine = sys.argv[1:7]

# Les profils viennent du meme module que celui utilise par la calibration :
# une seule definition des valeurs d'attaque, donc aucune derive possible entre
# ce que le banc rejoue et ce sur quoi le seuil est verifie.
sys.path.insert(0, racine)
from ml.profils_attaque import CIBLES, PROFILS  # noqa: E402

variables = PROFILS.get(scenario)

if variables is None:
    print(f"scénario inconnu : {scenario} (attendu A1, A2 ou A3)", file=sys.stderr)
    raise SystemExit(2)

charge = {
    "detected_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    "window_start_epoch": time.time() - 60.0,
    "anomalous": True,
    "score": 0.42,
    "threshold": 0.1175,
    "exceedance": 3.6,
    "suspected_target": CIBLES.get(scenario, "api-payment"),
    "suspected_source_ip": source_ip,
    "features": variables,
    "top_features": [],
    "model_version": "isolation-forest-v1",
    "rules_used": False,
}

corps = json.dumps(charge).encode("utf-8")
signature = hmac.new(secret.encode(), corps, hashlib.sha256).hexdigest()

requete = urllib.request.Request(
    f"{cible}{chemin}",
    data=corps,
    method="POST",
    headers={
        "Content-Type": "application/json",
        "X-AlphaPay-Signature": f"hmac-sha256={signature}",
    },
)
try:
    with urllib.request.urlopen(requete, timeout=15) as reponse:
        print(f"signalement {scenario} accepté : {reponse.read().decode('utf-8', 'replace')}")
except urllib.error.HTTPError as erreur:
    print(f"refusé ({erreur.code}) : {erreur.read().decode('utf-8', 'replace')[:400]}")
    raise SystemExit(1)
except Exception as erreur:  # noqa: BLE001
    print(f"moteur injoignable sur {cible} : {erreur}")
    raise SystemExit(1)
PY
