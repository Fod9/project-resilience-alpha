#!/usr/bin/env bash
# =============================================================================
#  recalibrer-detecteur.sh : recalibre le detecteur sur les mesures de la pile
# =============================================================================
#  Usage :
#      bash scripts/recalibrer-detecteur.sh
#
#  Ce script existe parce que la sequence manuelle a un piege : le dossier de
#  sortie de la calibration n'existe que si la calibration a abouti, et une
#  redirection `cat /tmp/nouveau/model.joblib > /models/model.joblib` cree la
#  cible meme quand la source est absente. Le detecteur chargeait alors un
#  fichier de zero octet et partait en boucle de redemarrage.
#
#  Ici : la calibration tourne d'abord, son code de retour est verifie, le
#  fichier produit est controle avant d'etre installe, et l'installation se fait
#  par `cp` apres un `rm` explicite. Rien n'est ecrit dans le volume si la
#  calibration refuse.
#
#  Pre-requis : l'historique de telemetrie doit contenir une agression mesuree,
#  c'est-a-dire une attaque rejouee depuis la reconstruction de la telemetrie.
#  Sans elle, la calibration refuse, et c'est voulu : le modele se choisit sur
#  des faits, pas sur des profils theoriques.
# =============================================================================
set -euo pipefail

# Le script se place a la racine du depot : `docker compose` y lit son fichier,
# et l'appelant peut l'invoquer depuis n'importe ou.
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE"

SORTIE="/tmp/calibration-detecteur"
CONTENEUR="${CONTENEUR_DETECTEUR:-detector}"
TELEMETRIE="${TELEMETRIE_URL:-http://telemetry:8000}"

echo "== etat de la pile"
docker compose ps --format '{{.Name}}\t{{.Status}}' | grep -E "detector|telemetry|remediation" || true

echo
echo "== calibration sur les mesures (${TELEMETRIE})"
docker compose exec -T "$CONTENEUR" rm -rf "$SORTIE"
docker compose exec -T "$CONTENEUR" python -m ml.recalibrer "$TELEMETRIE" "$SORTIE"

echo
echo "== controle du fichier produit"
docker compose exec -T "$CONTENEUR" test -s "$SORTIE/model.joblib"
docker compose exec -T "$CONTENEUR" test -s "$SORTIE/model-meta.json"
docker compose exec -T "$CONTENEUR" ls -la "$SORTIE"

echo
echo "== installation dans le volume du detecteur"
docker compose exec -T "$CONTENEUR" rm -f /models/model.joblib /models/model-meta.json
docker compose exec -T "$CONTENEUR" cp "$SORTIE/model.joblib" /models/model.joblib
docker compose exec -T "$CONTENEUR" cp "$SORTIE/model-meta.json" /models/model-meta.json
docker compose exec -T "$CONTENEUR" ls -la /models

echo
echo "== redemarrage du detecteur"
docker compose restart "$CONTENEUR"
sleep 20
docker compose logs --tail 6 "$CONTENEUR"

echo
echo "== verification de la separation"
docker compose exec -T "$CONTENEUR" python -m ml.verifier_separation "$TELEMETRIE" || true

echo
echo "Termine. Rejouez une attaque, la salle d'operations doit passer en Incident."
