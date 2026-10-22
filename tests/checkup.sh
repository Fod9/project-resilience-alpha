#!/usr/bin/env bash
# =============================================================================
#  checkup.sh : controle complet de la plateforme AlphaPay, de bout en bout
# =============================================================================
#  A lancer apres un demarrage, et notamment apres un premier demarrage a froid
#  sur une machine vierge : c'est le seul moment ou les defauts d'initialisation
#  se manifestent.
#
#  Usage :
#      bash tests/checkup.sh                    # controle complet
#      CIBLE=http://127.0.0.1 bash tests/checkup.sh
#
#  Sortie : une ligne par controle, OK ou ECHEC, puis un bilan.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="${CIBLE:-http://127.0.0.1}"
export DOCKER_HOST="${DOCKER_HOST:-}"

OK=0
ECHEC=0

controle() {
    local libelle="$1" resultat="$2" attendu="$3"
    if [ "$resultat" = "$attendu" ]; then
        printf '  [ OK ]   %-52s %s\n' "$libelle" "$resultat"
        OK=$((OK + 1))
    else
        printf '  [ECHEC]  %-52s %s (attendu %s)\n' "$libelle" "$resultat" "$attendu"
        ECHEC=$((ECHEC + 1))
    fi
}

code() {
    local resultat
    resultat=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$1" 2>/dev/null)
    printf '%s' "${resultat:-000}"
}

echo "=============================================================="
echo " Controle de la plateforme AlphaPay"
echo " Cible : $CIBLE"
echo "=============================================================="

echo
echo "--- 1. Conteneurs ---"
total=$(docker compose -f "$RACINE/docker-compose.yml" ps -q 2>/dev/null | wc -l | tr -d ' ')
sains=$(docker compose -f "$RACINE/docker-compose.yml" ps --format '{{.Status}}' 2>/dev/null | grep -c 'healthy' || true)
echo "  conteneurs lances : $total, declares sains : $sains"
for service in postgres api-auth api-payment api-ledger telemetry detector remediation assistant web edge; do
    etat=$(docker compose -f "$RACINE/docker-compose.yml" ps --format '{{.Service}} {{.Status}}' 2>/dev/null | grep "^$service " | head -1)
    printf '  %s\n' "${etat:-$service : ABSENT}"
done

echo
echo "--- 2. Base de donnees : roles applicatifs ---"
roles=$(docker exec alphaplat-postgres psql -U postgres -d alphapay -tAc \
    "select count(*) from pg_roles where rolname like 'svc_%'" 2>/dev/null | tr -d ' ')
controle "roles svc_* crees" "${roles:-0}" "7"
tables=$(docker exec alphaplat-postgres psql -U postgres -d alphapay -tAc \
    "select count(*) from information_schema.tables where table_schema in ('auth','ledger','ops','ml','rag')" 2>/dev/null | tr -d ' ')
# 18 = 16 tables du schema d'origine, plus les deux tables de l'authentification
# faciale (auth.face_templates et auth.face_attempts) ajoutees par 04-face.sql.
# Si la migration n'a pas ete appliquee a une base existante, ce controle tombe a
# 16 : voir la procedure R8 de docs/RUNBOOKS.md.
controle "tables applicatives"          "${tables:-0}" "18"
invariant=$(docker exec alphaplat-postgres psql -U postgres -d alphapay -tAc \
    "select count(*) from ledger.accounts a where a.balance_cents <> (select coalesce(sum(case when e.direction='D' then e.amount_cents else -e.amount_cents end),0) from ledger.entries e join ledger.transactions t on t.id=e.transaction_id where e.account_id=a.id and t.status='settled')" 2>/dev/null | tr -d ' ')
controle "invariant comptable (0 = coherent)" "${invariant:-?}" "0"

echo
echo "--- 3. Services applicatifs, directement ---"
for service in api-auth api-payment api-ledger telemetry detector remediation assistant; do
    sante=$(docker exec "alphaplat-$service" python -c \
        "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/healthz',timeout=5).status)" 2>/dev/null || echo "000")
    pret=$(docker exec "alphaplat-$service" python -c \
        "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/readyz',timeout=5).status)" 2>/dev/null || echo "000")
    printf '  %-14s /healthz %s   /readyz %s\n' "$service" "$sante" "$pret"
done

echo
echo "--- 4. Chaine complete, a travers la bordure ---"
controle "page de paiement"           "$(code "$CIBLE/")" "200"
controle "tableau de bord"            "$(code "$CIBLE/ops")" "200"
controle "sante de la bordure"        "$(code "$CIBLE/healthz")" "200"
controle "integrite du grand livre"   "$(code "$CIBLE/api/ledger/integrity")" "200"
controle "etat de la remediation"     "$(code "$CIBLE/api/supervision/state")" "200"
controle "score du detecteur"         "$(code "$CIBLE/api/detector/score/current")" "200"
controle "fenetre de variables"       "$(code "$CIBLE/api/telemetry/features/current")" "200"
controle "assistant documentaire"     "$(code "$CIBLE/api/assistant/status")" "200"

echo
echo "--- 5. Authentification et paiement reels ---"
reponse=$(curl -s -m 15 -X POST "$CIBLE/api/auth/token" \
    -H 'Content-Type: application/json' \
    -d '{"username":"client01","password":"AlphaPay-Client-2026!"}' 2>/dev/null)
if printf '%s' "$reponse" | grep -q 'access_token'; then
    printf '  [ OK ]   %-52s jeton obtenu\n' "authentification client01"
    OK=$((OK + 1))
    jeton=$(printf '%s' "$reponse" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    paiement=$(curl -s -m 20 -X POST "$CIBLE/api/payments" \
        -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $jeton" \
        -d '{"source_account":"CUST-000001","destination_account":"MERCHANT-0001","amount_cents":100,"reference":"checkup"}' 2>/dev/null)
    # Un corps d'erreur au format problem+json contient lui aussi un champ
    # "status" : le controle comptait donc un paiement refuse comme un succes.
    # C'est l'identifiant du paiement qui distingue un reglement abouti.
    if printf '%s' "$paiement" | grep -q '"payment_id"'; then
        printf '  [ OK ]   %-52s %s\n' "paiement de bout en bout" "$(printf '%s' "$paiement" | head -c 70)..."
        OK=$((OK + 1))
    else
        printf '  [ECHEC]  %-52s %s\n' "paiement de bout en bout" "$(printf '%s' "$paiement" | head -c 140)"
        ECHEC=$((ECHEC + 1))
    fi
else
    printf '  [ECHEC]  %-52s %s\n' "authentification client01" "$(printf '%s' "$reponse" | head -c 140)"
    ECHEC=$((ECHEC + 1))
fi

echo
echo "--- 6. Interface servie ---"
bundle=$(curl -s -m 10 "$CIBLE/" 2>/dev/null | grep -oE '/assets/[^"]+\.js' | head -1)
if [ -n "$bundle" ]; then
    printf '  [ OK ]   %-52s %s\n' "bundle JavaScript reference" "$bundle"
    OK=$((OK + 1))
    controle "bundle servi" "$(code "$CIBLE$bundle")" "200"
else
    printf '  [ECHEC]  %-52s aucune reference de bundle\n' "bundle JavaScript reference"
    ECHEC=$((ECHEC + 1))
fi

echo
echo "--- 7. Modele de detection ---"
modele=$(docker exec alphaplat-detector python -c \
    "import urllib.request,json;d=json.load(urllib.request.urlopen('http://127.0.0.1:8000/model',timeout=10));print(d.get('version'),d.get('threshold'))" 2>/dev/null || echo "indisponible")
printf '  modele charge : %s\n' "$modele"

echo
echo "=============================================================="
printf ' reussis : %s   echecs : %s\n' "$OK" "$ECHEC"
echo "=============================================================="
[ "$ECHEC" -eq 0 ] && exit 0 || exit 1
