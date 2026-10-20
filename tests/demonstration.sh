#!/usr/bin/env bash
# =============================================================================
#  demonstration.sh : rejoue la sequence complete de detection et de reprise
# =============================================================================
#  Enchaine, dans l'ordre, tout ce qu'il faut pour prouver qu'une attaque est
#  detectee par le modele et que la plateforme se remet en etat sans
#  intervention :
#
#    1. verifie que la telemetrie n'est pas en echauffement (sinon le detecteur
#       ignore les fenetres et aucun score n'est calcule) ;
#    2. genere une charge nominale VARIEe, plafonnee volontairement bien en
#       dessous de l'intensite de l'attaque ;
#    3. recalibre le modele sur ce regime legitime ;
#    4. verifie que le repos reste sous le seuil ;
#    5. lance l'attaque A1 depuis un conteneur distinct ;
#    6. mesure si le score franchit le seuil et si un incident s'ouvre.
#
#  Usage :
#      bash tests/demonstration.sh
#      bash tests/demonstration.sh http://127.0.0.1
#
#  Le plafond de la charge nominale est le point delicat. Apprendre au modele
#  que 120 requetes par seconde sont normales rend toute attaque volumetrique
#  indetectable : elle ressemble alors au regime de croisiere. Les paliers
#  s'arretent donc a 10 req/s, quand l'attaque en produit plus de cent.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="${1:-http://127.0.0.1}"
COMPOSE="docker compose -f $RACINE/docker-compose.yml"

BLEU="\033[1;34m"; VERT="\033[1;32m"; ROUGE="\033[1;31m"; NEUTRE="\033[0m"
titre() { printf "\n${BLEU}=== %s ===${NEUTRE}\n" "$1"; }
ok()    { printf "  ${VERT}[ OK ]${NEUTRE}  %s\n" "$1"; }
echec() { printf "  ${ROUGE}[ECHEC]${NEUTRE} %s\n" "$1"; }

sonde() { # nom_du_conteneur, code_python
    docker exec "$1" python -c "$2"
}

# -----------------------------------------------------------------------------
titre "1. La telemetrie est-elle prete ?"
# Chaque redemarrage de la telemetrie remet toutes les fenetres en echauffement,
# et le detecteur les ignore alors completement. Mesurer dans cet etat revient a
# mesurer un systeme qui ne regarde pas.
prete=0
for _ in 1 2 3 4 5; do
    etat=$(sonde alphaplat-detector "
import urllib.request, json
d = json.load(urllib.request.urlopen('http://telemetry:8000/features/current', timeout=10))
print(d.get('warming_up'))
" 2>/dev/null | tr -d '[:space:]')
    if [ "$etat" = "False" ]; then prete=1; break; fi
    sleep 12
done
if [ "$prete" -eq 1 ]; then
    ok "la telemetrie est prete (warming_up = False)"
else
    echec "la telemetrie est toujours en echauffement : attendez une minute et relancez"
    exit 1
fi

# -----------------------------------------------------------------------------
titre "2. Charge nominale variee, plafonnee a 10 req/s"
palier() { # pause entre deux requetes, nombre de tours
    docker exec alphaplat-web sh -c \
        "i=0; while [ \$i -lt $2 ]; do
             wget -qO- http://edge:8080/api/ledger/integrity >/dev/null 2>&1
             wget -qO- http://edge:8080/api/supervision/state >/dev/null 2>&1
             i=\$((i+1)); sleep $1
         done" >/dev/null 2>&1
    ok "palier pause=${1}s termine"
}
palier 1.0 45   # ~2 req/s
palier 0.5 60   # ~4 req/s
palier 0.2 60   # ~10 req/s   <- on s'arrete ici, l'attaque est bien au-dela
sleep 20

sonde alphaplat-detector "
import urllib.request, json, statistics as st
d = json.load(urllib.request.urlopen('http://telemetry:8000/features/history?limit=400', timeout=25))
w = [f for f in (d.get('windows') or []) if f.get('features')]
r = [f['features'].get('requests_per_second') or 0 for f in w]
print('  fenetres %d | rps min %.2f max %.2f ecart-type %.3f' % (len(w), min(r), max(r), st.pstdev(r)))
"

# -----------------------------------------------------------------------------
titre "3. Recalibrage du modele"
sonde alphaplat-detector "
import sys
sys.argv = ['x', 'http://telemetry:8000', '/models']
from ml import recalibrer
recalibrer.main()
" 2>&1 | grep -E "seuil|score nominal|depassements" || echec "recalibrage impossible"

$COMPOSE restart detector >/dev/null 2>&1
sleep 30

# -----------------------------------------------------------------------------
titre "4. Le repos est-il sous le seuil ?"
sonde alphaplat-detector "
import urllib.request, json
d = json.load(urllib.request.urlopen('http://127.0.0.1:8000/score/current', timeout=10))
print('  score %.4f | seuil %.4f | anomalie %s' % (d.get('score') or 0, d.get('threshold') or 0, d.get('anomalous')))
"

# -----------------------------------------------------------------------------
titre "5. Attaque A1 depuis un conteneur distinct"
HMAC=$(grep -E "^HMAC_SECRET=" "$RACINE/.env" | cut -d= -f2)
docker rm -f alphaplat-demo-attaquant >/dev/null 2>&1
docker run --rm --name alphaplat-demo-attaquant --memory 768m \
    --network alphaplat-edge alphaplat-redteam:1.0.0 \
    --scenario A1 --target http://edge:8080 --duree 60 --declare --observer-secondes 20 \
    --secret "$HMAC" 2>&1 | tail -6
docker rm -f alphaplat-demo-attaquant >/dev/null 2>&1
sleep 25

# -----------------------------------------------------------------------------
titre "6. Le seuil est-il franchi ?"
sonde alphaplat-detector "
import json, urllib.request, joblib, numpy as np
from common.features import FEATURE_NAMES
a = joblib.load('/models/model.joblib')
m, s, seuil = a['modele'], a['scaler'], float(a['seuil'])
d = json.load(urllib.request.urlopen('http://telemetry:8000/features/history?limit=400', timeout=25))
w = [f for f in (d.get('windows') or []) if f.get('features')]
X = np.array([[float(f['features'].get(k, 0)) for k in FEATURE_NAMES] for f in w])
sc = -m.decision_function(s.transform(X))
au_dessus = int((sc > seuil).sum())
print('  seuil %.5f | score max %.5f' % (seuil, float(sc.max())))
print('  AU-DESSUS DU SEUIL : %d / %d' % (au_dessus, len(w)))
print('  VERDICT :', 'le modele a detecte l attaque' if au_dessus else 'NON DETECTEE')
"

titre "7. Incidents enregistres"
$COMPOSE exec -T postgres psql -U postgres -d alphapay -c \
    "select substr(id::text,1,8) as id, state, playbook_id, mttd_ms, mttr_ms,
            to_char(opened_at,'HH24:MI:SS') as ouvert
     from ops.incidents order by opened_at desc limit 4"

printf "\n${BLEU}Tableau de bord : %s/ops${NEUTRE}\n" "$CIBLE"
printf "${BLEU}Tirets cadratins interdits dans les libelles affiches.${NEUTRE}\n\n"
