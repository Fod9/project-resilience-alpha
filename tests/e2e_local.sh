#!/usr/bin/env bash
# =============================================================================
#  e2e_local.sh — parcours complet sur un démon Docker isolé
# =============================================================================
#  Variante de `e2e.sh` pour l'environnement de test où la pile tourne sur un
#  démon Docker distant.
#
#  Différence essentielle avec le parcours nominal : l'attaque ne peut pas partir
#  du poste de test lui-même. Deux raisons :
#
#    * toutes les requêtes issues de ce poste partagent la même adresse vue par
#      la bordure : bloquer l'attaquant bloquerait aussi le client légitime, et
#      la vérification finale échouerait à tort ;
#    * le moteur de remédiation exécute lui-même les sondes de vérification : il
#      ne peut donc pas être l'attaquant.
#
#  L'attaque est donc lancée depuis un conteneur applicatif au repos, dont
#  l'adresse est distincte de celle du client de test comme de celle du moteur.
#  Sur le poste hôte du sujet, c'est le poste attaquant qui joue ce rôle, et
#  `tests/e2e.sh` s'applique directement.
#
#      bash tests/e2e_local.sh A2
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCENARIO="${1:-A2}"
ATTAQUANT="${ATTAQUANT:-alphaplat-assistant}"
BARRIERE="${CIBLE:-http://dind}"
DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"
export DOCKER_HOST

PASS=0
FAIL=0
ok()    { printf '  [ OK ]   %s\n' "$1"; PASS=$((PASS + 1)); }
echec() { printf '  [ECHEC]  %s\n' "$1"; FAIL=$((FAIL + 1)); }
etape() { printf '\n=== %s ===\n' "$1"; }

HMAC="$(sed -n 's/^HMAC_SECRET=//p' "$RACINE/.env" | head -1)"
MOT_DE_PASSE="$(sed -n 's/^PROBE_PASSWORD=//p' "$RACINE/.env" | head -1)"

appel() {
    python3 - "$1" "$2" "${3:-}" "${4:-}" <<'PY'
import json, ssl, sys, urllib.error, urllib.request
url, methode, corps, jeton = (list(sys.argv[1:5]) + ["", "", "", ""])[:4]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
entetes = {"Content-Type": "application/json"}
if jeton:
    entetes["Authorization"] = "Bearer " + jeton
try:
    with urllib.request.urlopen(
        urllib.request.Request(url, data=corps.encode() if corps else None,
                               method=methode, headers=entetes),
        timeout=20, context=ctx) as reponse:
        print(reponse.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as erreur:
    print(json.dumps({"__http_error__": erreur.code,
                      "corps": erreur.read().decode("utf-8", "replace")[:300]}))
except Exception as exc:
    print(json.dumps({"__erreur__": str(exc)}))
PY
}

valeur() { python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('$1',''))" 2>/dev/null; }

# -----------------------------------------------------------------------------
etape "0. Disponibilité de la bordure"
for _ in $(seq 1 40); do
    REPONSE_SANTE="$(appel "$BARRIERE/healthz" GET)"
    printf '%s' "$REPONSE_SANTE" | grep -q 'ok' && break
    sleep 3
done
if printf '%s' "$REPONSE_SANTE" | grep -q 'ok'; then
    ok "la bordure répond"
else
    echec "la bordure ne répond pas sur $BARRIERE"
fi

# -----------------------------------------------------------------------------
etape "1. Transaction nominale avant incident"
JETON="$(appel "$BARRIERE/api/auth/token" POST \
    "{\"username\":\"client01\",\"password\":\"$MOT_DE_PASSE\"}" | valeur access_token)"
if [ -n "$JETON" ]; then ok "jeton d'accès obtenu"; else echec "jeton non obtenu"; fi

REF="E2E-AVANT-$(date +%s)"
REP="$(appel "$BARRIERE/api/payments" POST \
    "{\"source_account\":\"CUST-000001\",\"destination_account\":\"MERCHANT-0001\",\"amount_cents\":120,\"currency\":\"EUR\",\"reference\":\"$REF\"}" "$JETON")"
if printf '%s' "$REP" | grep -q 'payment_id\|"status"'; then
    ok "paiement nominal accepté"
else
    echec "paiement nominal refusé : $(printf '%s' "$REP" | head -c 200)"
fi

INTEGRITE="$(appel "$BARRIERE/api/ledger/integrity" GET)"
if printf '%s' "$INTEGRITE" | grep -q '"balanced": *true'; then
    ok "grand livre équilibré avant incident"
else
    echec "grand livre déséquilibré : $(printf '%s' "$INTEGRITE" | head -c 200)"
fi

# -----------------------------------------------------------------------------
etape "2. Lancement de l'attaque $SCENARIO"
# Le banc offensif tourne dans son propre conteneur, sur un des réseaux de la
# bordure : son adresse est donc distincte de celle du client de test comme de
# celle du moteur de remédiation, qui exécute les sondes de vérification.
docker build -q -t alphaplat-redteam:1.0.0 "$RACINE/redteam" >/dev/null 2>&1
RESEAU="$(docker inspect -f '{{range $nom, $conf := .NetworkSettings.Networks}}{{$nom}} {{end}}' \
    alphaplat-edge 2>/dev/null | tr ' ' '\n' | grep -v '^$' | head -1)"
printf '  réseau utilisé        : %s\n' "$RESEAU"
docker rm -f alphaplat-redteam-ephemere >/dev/null 2>&1

docker run -d --name alphaplat-redteam-ephemere --network "$RESEAU" \
    alphaplat-redteam:1.0.0 --scenario "$SCENARIO" --target http://edge:8080 \
    --duree 70 --declare --secret "$HMAC" >/tmp/attaque-locale.log 2>&1
sleep 3
IP_ATTAQUANT="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
    alphaplat-redteam-ephemere 2>/dev/null | awk '{print $1}')"
printf '  adresse de l attaquant : %s\n' "$IP_ATTAQUANT"
if [ -z "$IP_ATTAQUANT" ]; then
    printf '  journal du banc offensif :\n'
    sed -n '1,6p' /tmp/attaque-locale.log
    echec "le banc offensif n'a pas démarré"
fi
sleep 9

# -----------------------------------------------------------------------------
etape "3. Détection et remédiation autonomes"
INCIDENT=""
ETAT_JSON=""
for _ in $(seq 1 240); do
    ETAT_JSON="$(appel "$BARRIERE/api/supervision/state" GET)"
    printf '%s' "$ETAT_JSON" | grep -q '"state": *"RECOVERED"\|"state":"RECOVERED"' && break
    printf '%s' "$ETAT_JSON" | grep -q '"state": *"FAILED"\|"state":"FAILED"' && break
    sleep 2
done
ETAT_FINAL="$(printf '%s' "$ETAT_JSON" | valeur state)"
printf '  état final du moteur : %s\n' "$ETAT_FINAL"
if [ "$ETAT_FINAL" = "RECOVERED" ]; then
    ok "le moteur a clos l'incident en « rétabli », sans intervention humaine"
else
    echec "état final inattendu : $ETAT_FINAL"
fi

# -----------------------------------------------------------------------------
etape "4. Détail de l'incident"
INCIDENT="$(appel "$BARRIERE/api/supervision/incidents?limit=1" GET \
    | python3 -c "import json,sys;d=json.load(sys.stdin);i=d.get('incidents') or [];print(i[0]['id'] if i else '')" 2>/dev/null)"
if [ -n "$INCIDENT" ]; then
    appel "$BARRIERE/api/supervision/incidents/$INCIDENT" GET \
        | python3 "$RACINE/tests/rapport_incident.py"
    DETAIL="$(appel "$BARRIERE/api/supervision/incidents/$INCIDENT" GET)"
    if printf '%s' "$DETAIL" | grep -q '"passed": *true'; then
        ok "suite de vérification réussie"
    else
        echec "suite de vérification non réussie"
    fi
else
    echec "aucun incident retrouvé"
fi

# -----------------------------------------------------------------------------
etape "5. Confinement de la source"
if [ -n "$INCIDENT" ]; then
    if appel "$BARRIERE/api/supervision/incidents/$INCIDENT" GET | grep -q "edge.block_ip"; then
        ok "une action de blocage d'adresse figure dans le journal de l'incident"
    else
        echec "aucune action de blocage enregistrée"
    fi
fi

# -----------------------------------------------------------------------------
etape "6. Service disponible après reprise"
REF="E2E-APRES-$(date +%s)"
REP="$(appel "$BARRIERE/api/payments" POST \
    "{\"source_account\":\"CUST-000001\",\"destination_account\":\"MERCHANT-0001\",\"amount_cents\":120,\"currency\":\"EUR\",\"reference\":\"$REF\"}" "$JETON")"
if printf '%s' "$REP" | grep -q 'payment_id\|"status"'; then
    ok "paiement accepté après reprise"
else
    echec "paiement refusé après reprise : $(printf '%s' "$REP" | head -c 200)"
fi

INTEGRITE="$(appel "$BARRIERE/api/ledger/integrity" GET)"
if printf '%s' "$INTEGRITE" | grep -q '"balanced": *true'; then
    ok "grand livre resté équilibré"
else
    echec "grand livre déséquilibré après incident"
fi

docker rm -f alphaplat-redteam-ephemere >/dev/null 2>&1

printf '\n======================================================\n'
printf 'reussis : %d   echecs : %d\n' "$PASS" "$FAIL"
printf '======================================================\n'
[ "$FAIL" -eq 0 ] || exit 1
exit 0
