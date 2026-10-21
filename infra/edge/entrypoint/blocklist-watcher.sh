#!/bin/sh
# =============================================================================
#  AlphaPay : surveillant de la liste de blocage de la bordure
# =============================================================================
#  Le moteur de remédiation n'a pas d'accès privilégié au conteneur de bordure :
#  il ne peut ni exécuter de commande dedans, ni recharger nginx. Le seul canal
#  est le volume partagé.
#
#  Ce surveillant ferme la boucle : il observe /etc/nginx/dynamic, déclenche un
#  rechargement à chaque changement, et publie un témoin horodaté contenant
#  l'empreinte de la liste appliquée et le résultat. Le moteur de remédiation
#  lit ce témoin pour *vérifier* que la règle est réellement active, au lieu de
#  supposer que l'écriture d'un fichier suffit.
#
#  Le témoin est un fichier JSON d'une seule ligne pour rester lisible par un
#  simple `cat` comme par un client HTTP.
# =============================================================================

set -u

DIR="/etc/nginx/dynamic"
MAP="$DIR/blocklist.map"
#: Liste des signatures confinees (agent utilisateur du banc offensif). Elle est
#: suivie comme la liste d'adresses : un changement dans l'une ou l'autre doit
#: provoquer le rechargement, sans quoi un confinement par signature resterait
#: lettre morte.
SIGNATURES="$DIR/agents.map"
WITNESS="$DIR/reload-witness.json"
JOURNAL="/var/log/alphapay/edge-reload.log"

fingerprint() {
    total=""
    for fichier in "$MAP" "$SIGNATURES"; do
        if [ -f "$fichier" ]; then
            total="$total$(md5sum "$fichier" 2>/dev/null | cut -d' ' -f1)"
        else
            total="$total""absent"
        fi
    done
    if [ -n "$total" ]; then
        printf '%s' "$total" | md5sum | cut -d' ' -f1
    else
        printf 'absent'
    fi
}

published=""

while true; do
    current="$(fingerprint)"

    if [ "$current" != "$published" ]; then
        # Laisser le temps à l'écriture d'être complète avant de tester.
        sleep 0.5

        if nginx -t >/dev/null 2>&1; then
            if nginx -s reload >/dev/null 2>&1; then
                result="applied"
            else
                result="reload-failed"
            fi
        else
            result="config-invalid"
        fi

        stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf '{"ts":"%s","fingerprint":"%s","result":"%s"}\n' \
            "$stamp" "$current" "$result" > "$WITNESS"

        printf '%s %s %s\n' "$stamp" "$result" "$current" >> "$JOURNAL" 2>/dev/null || true

        # En cas d'échec on ne mémorise pas l'empreinte : la tentative sera
        # rejouée au prochain tour, ce qui permet une réparation externe.
        if [ "$result" = "applied" ]; then
            published="$current"
        fi
    fi

    sleep 1
done
