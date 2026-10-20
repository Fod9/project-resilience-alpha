FROM pgvector/pgvector:pg16

LABEL org.opencontainers.image.title="AlphaPay : PostgreSQL"
LABEL org.opencontainers.image.description="Base de données de la plateforme de paiement fictive PROJECT RESILIENCE-ALPHA"

# Les scripts d'initialisation sont intégrés à l'image plutôt que montés :
# c'est ce qui rend la pile déployable telle quelle sur un démon Docker
# distant, dans WSL2 ou dans une VM, sans dépendre du chemin du dépôt sur
# l'hôte. `docker-entrypoint-initdb.d` n'est exécuté que sur un volume vide.
COPY 01-schema.sql   /docker-entrypoint-initdb.d/01-schema.sql
COPY 02-roles.sh     /docker-entrypoint-initdb.d/02-roles.sh
COPY 03-seed.sql     /docker-entrypoint-initdb.d/03-seed.sql

# 02-roles.sh doit être exécutable pour que l'entrée officielle l'invoque avec
# bash plutôt que de le sourcer (le script utilise `set -e`). Ses fins de ligne
# sont normalisées : préparé depuis Windows, le script arriverait en CRLF et
# l'entrée le refuserait, laissant la base sans rôles applicatifs.
RUN sed -i 's/\r$//' /docker-entrypoint-initdb.d/02-roles.sh \
 && chmod 0644 /docker-entrypoint-initdb.d/01-schema.sql \
 && chmod 0755 /docker-entrypoint-initdb.d/02-roles.sh \
 && chmod 0644 /docker-entrypoint-initdb.d/03-seed.sql

# Les rôles applicatifs n'existent qu'après l'exécution des scripts ci-dessus ;
# l'authentification reste `scram-sha-256` pour les connexions TCP.
