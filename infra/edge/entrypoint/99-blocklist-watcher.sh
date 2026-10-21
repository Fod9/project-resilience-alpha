#!/bin/sh
# Démarre le surveillant de liste de blocage en arrière-plan.
#
# Les scripts de /docker-entrypoint.d sont exécutés par l'entrée officielle de
# l'image nginx, avant le remplacement du processus par nginx lui-même. Un
# processus lancé ici reste donc vivant dans le conteneur, aux côtés de nginx.
set -eu

# La carte des signatures doit exister pour que `include` trouve un fichier :
# nginx refuse un `include` sans correspondance. Elle est créée *seulement* si
# elle est absente : la tronquer à chaque démarrage libérerait silencieusement
# le banc offensif à chaque redémarrage de la bordure.
SIGNATURES=/etc/nginx/dynamic/agents.map
if [ ! -f "$SIGNATURES" ]; then
    : > "$SIGNATURES"
fi

/usr/local/share/alphapay/blocklist-watcher.sh &

exit 0
