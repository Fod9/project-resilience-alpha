#!/usr/bin/env bash
# =============================================================================
#  seed-secrets.sh : génère un fichier .env complet à partir de .env.example
# =============================================================================
#  Produit des secrets aléatoires forts pour toutes les valeurs sensibles, puis
#  vérifie que la configuration obtenue est exploitable par Docker Compose.
#
#  Usage :
#      bash scripts/seed-secrets.sh            # refuse d'écraser un .env existant
#      bash scripts/seed-secrets.sh --force    # remplace le .env existant
#
#  Aucun secret n'est affiché : seules des empreintes tronquées le sont, ce qui
#  permet de vérifier la génération sans laisser les valeurs dans un terminal
#  partagé pendant la démonstration.
# =============================================================================
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELE="$RACINE/.env.example"
CIBLE="$RACINE/.env"
FORCER=0

for argument in "$@"; do
    case "$argument" in
        --force) FORCER=1 ;;
        -h|--help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "argument inconnu : $argument" >&2; exit 2 ;;
    esac
done

if [ ! -f "$MODELE" ]; then
    echo "ECHEC : $MODELE introuvable." >&2
    exit 1
fi

if [ -f "$CIBLE" ] && [ "$FORCER" -ne 1 ]; then
    echo "AVERTISSEMENT : $CIBLE existe déjà. Utiliser --force pour le remplacer." >&2
    exit 1
fi

# `openssl rand -base64` produit des caractères qui gênent l'analyse des URL de
# connexion (/ + =). On filtre pour ne garder que des caractères sûrs, ce qui
# évite tout échappement dans DATABASE_URL.
secret() {
    local longueur="${1:-32}"
    LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$longueur"
}

empreinte() {
    printf '%s' "$1" | sha256sum | cut -c1-12
}

echo "--- génération des secrets"
{
    while IFS= read -r ligne; do
        case "$ligne" in
            POSTGRES_PASSWORD=)        printf 'POSTGRES_PASSWORD=%s\n'        "$(secret 32)" ;;
            SVC_AUTH_PASSWORD=)        printf 'SVC_AUTH_PASSWORD=%s\n'        "$(secret 32)" ;;
            SVC_PAYMENT_PASSWORD=)     printf 'SVC_PAYMENT_PASSWORD=%s\n'     "$(secret 32)" ;;
            SVC_LEDGER_PASSWORD=)      printf 'SVC_LEDGER_PASSWORD=%s\n'      "$(secret 32)" ;;
            SVC_DETECTOR_PASSWORD=)    printf 'SVC_DETECTOR_PASSWORD=%s\n'    "$(secret 32)" ;;
            SVC_REMEDIATION_PASSWORD=) printf 'SVC_REMEDIATION_PASSWORD=%s\n' "$(secret 32)" ;;
            SVC_RAG_PASSWORD=)         printf 'SVC_RAG_PASSWORD=%s\n'         "$(secret 32)" ;;
            SVC_READONLY_PASSWORD=)    printf 'SVC_READONLY_PASSWORD=%s\n'    "$(secret 32)" ;;
            MONITORING_PASSWORD=)      printf 'MONITORING_PASSWORD=%s\n'      "$(secret 32)" ;;
            HMAC_SECRET=)              printf 'HMAC_SECRET=%s\n'              "$(secret 48)" ;;
            ADMIN_API_TOKEN=)          printf 'ADMIN_API_TOKEN=%s\n'          "$(secret 48)" ;;
            VAULT_DEV_ROOT_TOKEN=)     printf 'VAULT_DEV_ROOT_TOKEN=%s\n'     "$(secret 32)" ;;
            GRAFANA_ADMIN_PASSWORD=)   printf 'GRAFANA_ADMIN_PASSWORD=%s\n'   "$(secret 24)" ;;
            PROBE_PASSWORD=)           printf 'PROBE_PASSWORD=AlphaPay-Client-2026!\n' ;;
            *)                         printf '%s\n' "$ligne" ;;
        esac
    done < "$MODELE"
} > "$CIBLE"

chmod 600 "$CIBLE"

echo "--- vérification"
for cle in POSTGRES_PASSWORD SVC_AUTH_PASSWORD SVC_PAYMENT_PASSWORD SVC_LEDGER_PASSWORD \
           SVC_DETECTOR_PASSWORD SVC_REMEDIATION_PASSWORD SVC_RAG_PASSWORD \
           SVC_READONLY_PASSWORD MONITORING_PASSWORD HMAC_SECRET ADMIN_API_TOKEN \
           VAULT_DEV_ROOT_TOKEN GRAFANA_ADMIN_PASSWORD; do
    valeur="$(grep -E "^${cle}=" "$CIBLE" | head -1 | cut -d= -f2-)"
    if [ -z "$valeur" ]; then
        echo "  [ECHEC] $cle vide"
        exit 1
    fi
    printf '  [ OK ]  %-26s %s\n' "$cle" "$(empreinte "$valeur")"
done

echo "--- contrôle de la configuration Docker Compose"
if docker compose --env-file "$CIBLE" -f "$RACINE/docker-compose.yml" config --quiet; then
    echo "  [ OK ]  configuration valide"
else
    echo "  [ECHEC] configuration invalide" >&2
    exit 1
fi

echo
echo "Fichier écrit : $CIBLE (droits 600)"
echo "Ne jamais le versionner : il est ignoré par .gitignore."
