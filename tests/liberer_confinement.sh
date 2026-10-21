#!/usr/bin/env bash
# Libere les confinements en cours : adresses et signatures.
#
# Utile sous Docker Desktop : la redirection des ports publics reecrit la source
# de toute connexion entrante en l'adresse de la passerelle du sous-reseau, si
# bien que l'adresse de l'attaquant et celle de l'operateur sont confondues. Le
# confinement epargne desormais l'adresse qui consulte la salle d'operations et
# s'appuie sur la signature du banc offensif ; ce script leve les deux formes.
#
# Usage : bash tests/liberer_confinement.sh [base-de-la-bordure]
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="${1:-http://127.0.0.1}"
TOKEN="$(grep '^ADMIN_API_TOKEN=' "$RACINE/.env" | cut -d= -f2-)"

if [ -z "$TOKEN" ]; then
  echo "ADMIN_API_TOKEN introuvable dans $RACINE/.env" >&2
  exit 1
fi

libere() {
  printf '%s -> ' "$1"
  curl -s -X POST "$CIBLE/api/ops/actions/unblock" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Token: $TOKEN" \
    -d "$2" | python3 -c "
import json, sys
try:
    reponse = json.load(sys.stdin)
except json.JSONDecodeError:
    print('reponse illisible')
    raise SystemExit
if reponse.get('ok'):
    print('liberee' if not reponse.get('skipped') else 'deja libre')
else:
    print(reponse.get('detail') or reponse.get('title') or reponse)
"
}

etat="$(curl -s "$CIBLE/api/supervision/blocklist")"
adresses="$(printf '%s' "$etat" | python3 -c "
import json, sys
charge = json.load(sys.stdin)
print(' '.join(entree['ip'] for entree in charge.get('blocked', []) if entree.get('ip')))
")"
signatures="$(printf '%s' "$etat" | python3 -c "
import json, sys
charge = json.load(sys.stdin)
print('|'.join(entree['signature'] for entree in charge.get('blocked', []) if entree.get('signature')))
")"

if [ -z "$adresses" ] && [ -z "$signatures" ]; then
  echo "aucun confinement en cours"
  exit 0
fi

for adresse in $adresses; do
  libere "$adresse" "$(python3 -c "import json,sys; print(json.dumps({'ip': sys.argv[1]}))" "$adresse")"
done

if [ -n "$signatures" ]; then
  ancien_ifs="$IFS"
  IFS='|'
  for signature in $signatures; do
    libere "signature $signature" "$(python3 -c "import json,sys; print(json.dumps({'signature': sys.argv[1]}))" "$signature")"
  done
  IFS="$ancien_ifs"
fi

echo
echo "restant : $(curl -s "$CIBLE/api/supervision/blocklist")"
