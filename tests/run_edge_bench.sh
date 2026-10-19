#!/bin/bash
# =============================================================================
#  Banc d'essai isolé de la bordure.
# =============================================================================
#  Monte deux amonts factices (web et api-auth) sur un réseau dédié, construit
#  l'image de la bordure, la démarre, puis exécute tests/edge_smoke.sh.
#
#  Aucun montage de fichier de l'hôte n'est utilisé : l'environnement de test
#  peut viser un démon Docker distant, qui ne partage pas ce système de
#  fichiers. Tout est embarqué dans les images.
#
#  Usage : tests/run_edge_bench.sh
# =============================================================================
set -uo pipefail

export DOCKER_HOST="${DOCKER_HOST:-tcp://dind:23757}"
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
RESEAU=alphapay-bench
HOTE="${HOTE:-dind}"

echo "--- nettoyage"
docker rm -f t-edge t-web t-auth t-pay >/dev/null 2>&1
docker network rm "$RESEAU" >/dev/null 2>&1
docker volume rm t-logs t-dyn >/dev/null 2>&1

echo "--- reseau"
docker network create "$RESEAU" >/dev/null

echo "--- amonts factices"
docker build -q -t alphaplat-dummy:test "$RACINE/tests/dummy_backend" >/dev/null 2>&1
docker run -d --name t-web  --network "$RESEAU" --network-alias web \
    alphaplat-dummy:test 8080 >/dev/null
docker run -d --name t-auth --network "$RESEAU" --network-alias api-auth \
    alphaplat-dummy:test 8000 >/dev/null
docker run -d --name t-pay --network "$RESEAU" --network-alias api-payment \
    alphaplat-dummy:test 8000 >/dev/null

echo "--- preparation des volumes"
docker volume create t-logs >/dev/null
docker volume create t-dyn  >/dev/null
# Reproduit exactement ce que fait le service `init-perms` de la pile :
# journaux partages en 1777, liste de blocage appartient a nginx (101) et au
# groupe applicatif (10001) en 0770.
docker run --rm --user root -v t-logs:/l alpine:3.20 \
    sh -c 'mkdir -p /l && chmod 1777 /l && ls -ld /l'
docker run --rm --user root -v t-dyn:/d alpine:3.20 \
    sh -c 'mkdir -p /d && chown 101:10001 /d && chmod 0770 /d && ls -ld /d'

echo "--- construction de la bordure"
docker build -q -t alphaplat-edge:test "$RACINE/infra/edge" >/dev/null 2>&1

echo "--- demarrage de la bordure"
docker run -d --name t-edge --network "$RESEAU" -p 18080:8080 -p 18443:8443 \
    -e NGINX_ENTRYPOINT_QUIET_LOGS=1 \
    -e MODSEC_AUDIT_LOG=/var/log/alphapay/edge-modsec.log \
    -v t-logs:/var/log/alphapay -v t-dyn:/etc/nginx/dynamic \
    alphaplat-edge:test >/dev/null

for i in $(seq 1 30); do
    sleep 1
    ETAT=$(python3 -c "
import urllib.request
try:
    urllib.request.urlopen('http://${HOTE}:18080/healthz', timeout=2)
    print('ok')
except Exception:
    print('attente')
" 2>/dev/null)
    [ "$ETAT" = "ok" ] && break
done
echo "--- bordure prete apres ${i}s"

bash "$RACINE/tests/edge_smoke.sh" "$HOTE" 18080 18443
CODE=$?

# ---------------------------------------------------------------------------
#  Mise à jour de la liste de blocage sans redémarrage de la bordure.
#  On bloque l'adresse du client de test lui-même : c'est la seule preuve
#  directe que le filtre agit, puisque `$remote_addr` est l'adresse de pair
#  réelle. L'adresse est débloquée immédiatement après.
# ---------------------------------------------------------------------------
echo
echo "=== 6. Liste de blocage a chaud ==="
CLIENT_IP=$(docker exec t-edge sh -c 'tail -1 /var/log/alphapay/edge.jsonl' |
    sed -n 's/.*"source_ip":"\([^"]*\)".*/\1/p')

demander() {
    python3 -c "
import sys, urllib.request, urllib.error
try:
    print(urllib.request.urlopen('http://${HOTE}:18080/api/auth/sonde', timeout=8).status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print('ERR')
"
}

AVANT=$(demander)
echo "  avant blocage (${CLIENT_IP}) : ${AVANT}"

docker exec t-edge sh -c "printf '${CLIENT_IP} 1;\n' > /etc/nginx/dynamic/blocklist.map"
sleep 4
TEMOIN=$(docker exec t-edge sh -c 'cat /etc/nginx/dynamic/reload-witness.json 2>/dev/null')
PENDANT=$(demander)
echo "  temoin de rechargement        : ${TEMOIN}"
echo "  pendant blocage               : ${PENDANT}"

docker exec t-edge sh -c 'rm -f /etc/nginx/dynamic/blocklist.map'
sleep 4
APRES=$(demander)
echo "  apres deblocage               : ${APRES}"

BILAN_BLOCAGE="echec"
if [ "$AVANT" = "200" ] && [ "$PENDANT" = "403" ] && [ "$APRES" = "200" ]; then
    BILAN_BLOCAGE="ok"
fi
echo "  blocage a chaud               : ${BILAN_BLOCAGE}"
[ "$BILAN_BLOCAGE" = "ok" ] || CODE=1

echo
echo "--- journal d'acces (derniere ligne)"
docker exec t-edge sh -c 'tail -1 /var/log/alphapay/edge.jsonl' 2>/dev/null
echo "--- temoin de rechargement"
docker exec t-edge sh -c 'cat /etc/nginx/dynamic/reload-witness.json 2>/dev/null'

exit $CODE
