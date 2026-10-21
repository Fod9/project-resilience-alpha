#!/usr/bin/env bash
# Libere toutes les adresses presentement confinees.
#
# Utile sous Docker Desktop pour Mac : la redirection des ports publics reecrit la
# source de toute connexion entrante en l'adresse de la passerelle de la machine
# virtuelle (192.168.65.1). Le banc et le navigateur de l'operateur partagent donc
# la meme adresse, et le confinement par adresse coupe les deux. Sur la cible
# Windows, les adresses different et ce script ne sert qu'en cas d'erreur.
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

adresses="$(curl -s "$CIBLE/api/supervision/blocklist" | python3 -c "
import json, sys
charge = json.load(sys.stdin)
print(' '.join(entree.get('ip', '') for entree in charge.get('blocked', [])))
")"

if [ -z "$adresses" ]; then
  echo "aucune adresse confinee"
  exit 0
fi

for adresse in $adresses; do
  printf '%s -> ' "$adresse"
  curl -s -X POST "$CIBLE/api/ops/actions/unblock" \
    -H "Content-Type: application/json" \
    -H "X-Admin-Token: $TOKEN" \
    -d "{\"ip\": \"$adresse\"}" | python3 -c "
import json, sys
reponse = json.load(sys.stdin)
if reponse.get('ok'):
    print('liberee')
else:
    print(reponse.get('detail') or reponse.get('title') or reponse)
"
done

curl -s "$CIBLE/api/supervision/blocklist"
echo
