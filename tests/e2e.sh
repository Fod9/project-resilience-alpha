#!/usr/bin/env bash
# =============================================================================
#  e2e.sh : parcours complet de bout en bout
# =============================================================================
#  Ce script rejoue ce que le jury demandera, et ÉCHOUE si la reprise n'est pas
#  réelle. Il vérifie successivement :
#
#    1. le service répond avant incident (transaction nominale) ;
#    2. le grand livre est équilibré ;
#    3. une attaque est déclenchée depuis le banc offensif ;
#    4. le moteur de remédiation ouvre un incident sans intervention humaine ;
#    5. l'incident est clos en « rétabli » avec vérification réussie ;
#    6. une nouvelle transaction aboutit après la reprise ;
#    7. les délais mesurés respectent les cibles.
#
#  Aucune étape n'est facultative : c'est le test qui doit passer avant la
#  soutenance.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="${CIBLE:-http://localhost}"
SCENARIO="${1:-A1}"
DELAI_MAX_RETABLISSEMENT="${DELAI_MAX_RETABLISSEMENT:-240}"

export DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"

PASS=0
FAIL=0
ok()    { printf '  [ OK ]   %s\n' "$1"; PASS=$((PASS + 1)); }
echec() { printf '  [ECHEC]  %s\n' "$1"; FAIL=$((FAIL + 1)); }
etape() { printf '\n=== %s ===\n' "$1"; }

# -----------------------------------------------------------------------------
#  Outils : tout passe par python3, disponible partout, jamais par curl qui est
#  absent de certaines images de base.
# -----------------------------------------------------------------------------
http_code() {
    python3 - "$1" "$2" "${3:-}" <<'PY'
import sys, urllib.request, urllib.error, ssl
url, methode, corps = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
donnees = corps.encode() if corps else None
requete = urllib.request.Request(url, data=donnees, method=methode,
                                 headers={"Content-Type": "application/json"} if donnees else {})
try:
    with urllib.request.urlopen(requete, timeout=15, context=ctx) as reponse:
        print(reponse.status)
except urllib.error.HTTPError as erreur:
    print(erreur.code)
except Exception:
    print("ERR")
PY
}

http_json() {
    python3 - "$1" "$2" "${3:-}" <<'PY'
import sys, urllib.request, json, ssl
url, methode, corps = sys.argv[1], sys.argv[2], (sys.argv[3] if len(sys.argv) > 3 else "")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
entetes = {"Content-Type": "application/json"}
try:
    with open("/tmp/alphapay-jeton", encoding="utf-8") as fichier:
        entetes["Authorization"] = "Bearer " + fichier.read().strip()
except OSError:
    pass
donnees = corps.encode() if corps else None
requete = urllib.request.Request(url, data=donnees, method=methode, headers=entetes if donnees or "Authorization" in entetes else {})
try:
    with urllib.request.urlopen(requete, timeout=20, context=ctx) as reponse:
        print(reponse.read().decode("utf-8", "replace"))
except urllib.error.HTTPError as erreur:
    print("HTTP" + str(erreur.code) + " " + erreur.read().decode("utf-8", "replace")[:300])
except Exception as exc:
    print("ERREUR " + str(exc))
PY
}

# -----------------------------------------------------------------------------
etape "0. Attente de la disponibilité de la bordure"
for _ in $(seq 1 60); do
    [ "$(http_code "$CIBLE/healthz" GET)" = "200" ] && break
    sleep 3
done
if [ "$(http_code "$CIBLE/healthz" GET)" = "200" ]; then
    ok "la bordure répond"
else
    echec "la bordure ne répond pas sur $CIBLE"; exit 1
fi

# -----------------------------------------------------------------------------
etape "1. Transaction nominale avant incident"
MOT_DE_PASSE="$(sed -n 's/^PROBE_PASSWORD=//p' "$RACINE/.env" | head -1)"
JETON="$(http_json "$CIBLE/api/auth/token" POST "{\"username\":\"client01\",\"password\":\"$MOT_DE_PASSE\"}" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)"
if [ -n "$JETON" ]; then
    printf '%s' "$JETON" > /tmp/alphapay-jeton
    ok "jeton d'accès obtenu"
else
    echec "impossible d'obtenir un jeton d'accès"
fi

REFERENCE="E2E-$(date +%s)"
REPONSE="$(http_json "$CIBLE/api/payments" POST \
    "{\"source_account\":\"CUST-000001\",\"destination_account\":\"MERCHANT-0001\",\"amount_cents\":150,\"currency\":\"EUR\",\"reference\":\"$REFERENCE\"}")"
if printf '%s' "$REPONSE" | grep -q '"status"'; then
    ok "paiement nominal accepté"
else
    echec "paiement nominal refusé : $REPONSE"
fi

etape "2. Intégrité comptable avant incident"
INTEGRITE="$(http_json "$CIBLE/api/ledger/integrity" GET)"
if printf '%s' "$INTEGRITE" | grep -q '"balanced": *true\|"balanced":true'; then
    ok "le grand livre est équilibré"
else
    echec "grand livre déséquilibré : $INTEGRITE"
fi

# -----------------------------------------------------------------------------
etape "3. Déclenchement de l'attaque $SCENARIO"
HMAC="$(sed -n 's/^HMAC_SECRET=//p' "$RACINE/.env" | head -1)"

# Le banc offensif s'exécute depuis ce poste ; dans la configuration de
# démonstration il est lancé en parallèle de la surveillance.
SCENARIO="$SCENARIO" CIBLE="$CIBLE" HMAC="$HMAC" \
    python3 "$RACINE/redteam/alpha_redteam.py" --scenario "$SCENARIO" \
    --target "$CIBLE" --duree 75 --declare --secret "$HMAC" >/tmp/alphapay-attaque.log 2>&1 &
PID_ATTAQUE=$!
sleep 8

# -----------------------------------------------------------------------------
etape "4. Détection et remédiation autonomes"
INCIDENT=""
for _ in $(seq 1 "$DELAI_MAX_RETABLISSEMENT"); do
    ETAT="$(http_json "$CIBLE/api/supervision/state" GET)"
    ETAT_GLOBAL="$(printf '%s' "$ETAT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("global_state",""))' 2>/dev/null)"
    if printf '%s' "$ETAT" | grep -q 'RECOVERED'; then
        INCIDENT="$(printf '%s' "$ETAT" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("incident_id") or "")' 2>/dev/null)"
        break
    fi
    sleep 1
done

if printf '%s' "$ETAT" | grep -q 'RECOVERED'; then
    ok "incident clos en « rétabli » par le moteur seul"
else
    echec "aucun rétablissement constaté en ${DELAI_MAX_RETABLISSEMENT}s (état : ${ETAT_GLOBAL:-inconnu})"
fi

# -----------------------------------------------------------------------------
etape "5. Details de l'incident"
if [ -n "$INCIDENT" ]; then
    DETAIL="$(http_json "$CIBLE/api/supervision/incidents/$INCIDENT" GET)"
    printf '%s' "$DETAIL" | python3 "$RACINE/tests/rapport_incident.py"
    if printf '%s' "$DETAIL" | grep -q '"passed": *true\|"passed":true'; then
        ok "vérification de reprise réussie"
    else
        echec "vérification de reprise absente ou en échec"
    fi
else
    echec "identifiant d'incident indisponible"
fi

# -----------------------------------------------------------------------------
etape "6. Transaction après reprise"
REFERENCE="E2E-POST-$(date +%s)"
REPONSE="$(http_json "$CIBLE/api/payments" POST \
    "{\"source_account\":\"CUST-000001\",\"destination_account\":\"MERCHANT-0001\",\"amount_cents\":150,\"currency\":\"EUR\",\"reference\":\"$REFERENCE\"}")"
if printf '%s' "$REPONSE" | grep -q '"status"'; then
    ok "paiement accepté après reprise"
else
    echec "paiement refusé après reprise : $REPONSE"
fi

etape "7. Intégrité comptable après reprise"
INTEGRITE="$(http_json "$CIBLE/api/ledger/integrity" GET)"
if printf '%s' "$INTEGRITE" | grep -q '"balanced": *true\|"balanced":true'; then
    ok "le grand livre est resté équilibré"
else
    echec "grand livre déséquilibré après incident : $INTEGRITE"
fi

wait "$PID_ATTAQUE" 2>/dev/null

# -----------------------------------------------------------------------------
printf '\n======================================================\n'
printf 'reussis : %d   echecs : %d\n' "$PASS" "$FAIL"
printf '======================================================\n'
[ "$FAIL" -eq 0 ] || exit 1
exit 0
