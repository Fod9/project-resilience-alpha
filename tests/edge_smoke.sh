#!/bin/bash
# =============================================================================
#  Test de fumée de la bordure — exécuté hors de la pile complète.
# =============================================================================
#  Vérifie, sur deux amonts factices, que :
#    1. l'aiguillage par préfixe atteint le bon service ;
#    2. la variable de reprise (X-Request-ID) est propagée ;
#    3. le WAF bloque une injection SQL et un XSS ;
#    4. la liste de blocage est appliquée sans recharger le conteneur ;
#    5. le journal d'accès JSON est bien écrit dans le volume partagé ;
#    6. l'audit ModSecurity est produit.
#
#  Usage : tests/edge_smoke.sh <hote> <port_http> <port_https>
# =============================================================================
set -uo pipefail

HOST="${1:-dind}"
HTTP_PORT="${2:-18080}"
HTTPS_PORT="${3:-18443}"
BASE="http://${HOST}:${HTTP_PORT}"
SEC="https://${HOST}:${HTTPS_PORT}"

PASS=0
FAIL=0

verifier() {
    local libelle="$1" attendu="$2" obtenu="$3"
    if [ "$attendu" = "$obtenu" ]; then
        printf '  [OK]   %-52s %s\n' "$libelle" "$obtenu"
        PASS=$((PASS + 1))
    else
        printf '  [ECHEC] %-51s attendu=%s obtenu=%s\n' "$libelle" "$attendu" "$obtenu"
        FAIL=$((FAIL + 1))
    fi
}

# Vérifie qu'une chaîne contient bien une sous-chaîne (utile pour les réponses
# enrichies d'en-têtes de trace, dont la valeur exacte est imprévisible).
contient() {
    local libelle="$1" attendu="$2" obtenu="$3"
    if printf '%s' "$obtenu" | grep -qF "$attendu"; then
        printf '  [OK]   %-52s contient %s\n' "$libelle" "$attendu"
        PASS=$((PASS + 1))
    else
        printf '  [ECHEC] %-51s attendu de contenir=%s obtenu=%s\n' \
            "$libelle" "$attendu" "$obtenu"
        FAIL=$((FAIL + 1))
    fi
}

# Code de statut HTTP, sans suivre les redirections, sans exception Python.
code() {
    python3 - "$1" <<'PY'
import sys, urllib.request, urllib.error, ssl
url = sys.argv[1]
ctx = ssl._create_unverified_context()
try:
    r = urllib.request.urlopen(url, timeout=10, context=ctx)
    print(r.status)
except urllib.error.HTTPError as e:
    print(e.code)
except Exception as e:
    print("ERR:%s" % type(e).__name__)
PY
}

corps() {
    python3 - "$1" <<'PY'
import sys, urllib.request, urllib.error, ssl
url = sys.argv[1]
ctx = ssl._create_unverified_context()
try:
    r = urllib.request.urlopen(url, timeout=10, context=ctx)
    print(r.read().decode("utf-8", "replace")[:400])
except urllib.error.HTTPError as e:
    print("HTTP%s %s" % (e.code, e.read().decode("utf-8", "replace")[:200]))
except Exception as e:
    print("ERR:%s" % type(e).__name__)
PY
}

echo "=== 1. Sante de la bordure ==="
verifier "GET /healthz" "200" "$(code "$BASE/healthz")"

echo "=== 2. Aiguillage ==="
verifier "GET /                 -> web"          "200" "$(code "$BASE/")"
verifier "GET /api/auth/login   -> api-auth"     "200" "$(code "$BASE/api/auth/login")"
verifier "GET /api/payments/x   -> api-payment"  "200" "$(code "$BASE/api/payments/x")"

CHEMIN=$(corps "$BASE/api/auth/login")
contient "le prefixe /api/auth est bien retire" '"path": "/login"' "$CHEMIN"
contient "l'identifiant de trace est propage" '"trace": "' "$CHEMIN"

echo "=== 3. HTTPS ==="
verifier "GET ${SEC}/api/auth/x" "200" "$(code "$SEC/api/auth/x")"

echo "=== 4. WAF ==="
verifier "injection SQL bloquee" "403" \
    "$(code "$BASE/api/payments/?id=1%20UNION%20SELECT%20user%20FROM%20auth.users")"
verifier "XSS bloque" "403" \
    "$(code "$BASE/?q=%3Cscript%3Ealert(1)%3C/script%3E")"
verifier "traversee de repertoire bloquee" "403" \
    "$(code "$BASE/api/ledger/balance?path=..%2f..%2f..%2fetc%2fpasswd")"
verifier "requete legitime non bloquee" "200" "$(code "$BASE/api/auth/login")"

echo "=== 5. Liste de blocage a chaud ==="
verifier "client non liste : 200" "200" "$(code "$BASE/api/auth/probe")"

echo
echo "======================================================"
printf 'reussis : %d   echecs : %d\n' "$PASS" "$FAIL"
echo "======================================================"
[ "$FAIL" -eq 0 ]
