#!/bin/sh
# Démarre le surveillant de liste de blocage en arrière-plan.
#
# Les scripts de /docker-entrypoint.d sont exécutés par l'entrée officielle de
# l'image nginx, avant le remplacement du processus par nginx lui-même. Un
# processus lancé ici reste donc vivant dans le conteneur, aux côtés de nginx.
set -eu

/usr/local/share/alphapay/blocklist-watcher.sh &

exit 0
