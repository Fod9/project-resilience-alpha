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
python3 - "$SCENARIO" "$SOURCE_IP" "$HMAC" "$CIBLE" "$CHEMIN_INGESTION" <<'PY'
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request

scenario, source_ip, secret, cible, chemin = sys.argv[1:6]

# Valeurs choisies pour franchir les seuils des politiques concernées.
variables = {
    "A1": {
        "requests_per_second": 142.0, "error_ratio": 0.62, "latency_p95_ms": 1840.0,
        "latency_p99_ms": 4120.0, "unique_source_ips": 6.0, "source_ip_entropy": 0.41,
        "auth_failure_ratio": 0.12, "auth_attempts_per_identity": 2.0,
        "unique_identities": 8.0, "injection_token_ratio": 0.0, "xss_token_ratio": 0.0,
        "avg_payload_bytes": 412.0, "payload_bytes_stddev": 96.0,
        "endpoint_entropy": 0.36, "requests_per_token": 3.0,
        "outgoing_bytes_ratio": 1.4, "new_source_ip_ratio": 0.0, "waf_block_ratio": 0.04,
    },
    "A2": {
        "requests_per_second": 34.0, "error_ratio": 0.48, "latency_p95_ms": 320.0,
        "latency_p99_ms": 610.0, "unique_source_ips": 3.0, "source_ip_entropy": 0.22,
        "auth_failure_ratio": 0.88, "auth_attempts_per_identity": 42.0,
        "unique_identities": 63.0, "injection_token_ratio": 0.0, "xss_token_ratio": 0.0,
        "avg_payload_bytes": 208.0, "payload_bytes_stddev": 24.0,
        "endpoint_entropy": 0.18, "requests_per_token": 0.4,
        "outgoing_bytes_ratio": 1.1, "new_source_ip_ratio": 0.02, "waf_block_ratio": 0.02,
    },
    "A3": {
        "requests_per_second": 19.0, "error_ratio": 0.71, "latency_p95_ms": 480.0,
        "latency_p99_ms": 900.0, "unique_source_ips": 2.0, "source_ip_entropy": 0.15,
        "auth_failure_ratio": 0.05, "auth_attempts_per_identity": 1.0,
        "unique_identities": 2.0, "injection_token_ratio": 0.34, "xss_token_ratio": 0.11,
        "avg_payload_bytes": 1180.0, "payload_bytes_stddev": 340.0,
        "endpoint_entropy": 0.44, "requests_per_token": 6.0,
        "outgoing_bytes_ratio": 11.5, "new_source_ip_ratio": 0.0, "waf_block_ratio": 0.46,
    },
}.get(scenario)

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
    "suspected_target": {"A1": "api-payment", "A2": "api-auth", "A3": "api-payment"}[scenario],
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
