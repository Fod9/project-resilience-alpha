# Application de la migration faciale sur une base existante

Les scripts de `infra/db/` sont montés dans `docker-entrypoint-initdb.d` et ne sont
joués qu'à l'initialisation d'un volume vide. Un script ajouté après la création
de la base n'est donc jamais exécuté, et les tables qu'il crée n'existent pas.

Symptôme, sur une pile reconstruite sans recréer le volume : l'enregistrement d'un
gabarit facial répond `503 face_schema_absent` (auparavant une erreur interne
`500` illisible), avec pour seule trace utile dans le journal du service :

```
psycopg.errors.UndefinedTable: relation "auth.face_templates" does not exist
```

## Correction sans perte de données

```bash
docker exec -i alphaplat-postgres psql -U postgres -d alphapay < infra/db/04-face.sql
```

Le fichier est idempotent : le rejouer sur une base à jour ne produit que des
`NOTICE ... skipping` et ne touche aucune donnée existante.

## Vérification

```bash
docker exec alphaplat-postgres psql -U postgres -d alphapay -c \
  "SELECT to_regclass('auth.face_templates'), has_schema_privilege('svc_auth','public','USAGE');"
```

Deux `t` : la table existe et le service d'authentification peut nommer le type
`vector`, qui vit dans le schéma `public`.

## Variante destructive

`docker compose down -v` puis `up -d` rejoue toutes les migrations, au prix du
contenu de la base : comptes nominatifs créés par `scripts/creer-compte.sh` et
gabarits faciaux inclus, à recréer ensuite.
