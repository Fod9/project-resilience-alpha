# Manuel de procédures : PROJECT RESILIENCE-ALPHA

Procédures d'exploitation de la plateforme AlphaPay (22 services, 5
réseaux cloisonnés). Chaque procédure précise son objectif, son
déclencheur, ses étapes avec les commandes exactes, le résultat attendu
et la vérification. Le répertoire de travail est la racine du projet
(`/opt/data/projects/resilience-alpha`) ; la variable d'environnement
`CIBLE` désigne l'URL publique de la bordure (par défaut
`http://localhost`, ou `https://localhost` avec les certificats
auto-signés). Pour le détail des politiques
et des playbooks du moteur, se reporter à `runbooks/PLAYBOOKS.md` ; pour
les arbitrages, la PCA/PRA et la mise en regard réglementaire, à
`GOUVERNANCE.md`.

Nota sur les noms : les commandes `docker compose stop/start ...` utilisent
le **nom de service** tel que défini dans `docker-compose.yml` (par
exemple `edge`, `postgres`, `api-ledger`, `detector`, `remediation`) ; les
commandes `docker logs` et `docker exec` utilisent le **nom de
conteneur**, préfixé `alphaplat-` (par exemple `alphaplat-edge`,
`alphaplat-detector`, `alphaplat-remediation`). L'index des procédures
figure ci-dessous.

Nota sur l'accès au moteur (bordure) : la **lecture** d'état passe par
`GET $CIBLE/api/supervision/...` (état, incidents, chronologie,
vérifications), sans jeton. Les **commandes** d'administration (rejouer la
suite de vérification, relâcher la suspension, déclencher un playbook)
passent par le préfixe public `/api/ops/` de la bordure, réécrit vers
`/api/actions/...` du moteur de remédiation, et exigent l'en-tête
`X-Admin-Token`, dont la valeur est `ADMIN_API_TOKEN` dans `.env`.

- **R1** : Démarrage à froid de la pile
- **R2** : Diagnostic d'un service indisponible
- **R3** : Lecture d'un incident de remédiation
- **R4** : Déblocage d'une adresse par erreur
- **R5** : Réinitialisation complète
- **R6** : Export des preuves pour le jury
- **R7** : Sauvegarde et restauration du grand livre

Nota : l'exécution réelle des playbooks est activée par
`DEMO_MODE=true` dans `.env` ; en `DEMO_MODE=false`, le moteur reste en
`DRY_RUN` et ne change que l'étape d'exécution. Toute commande humaine
sur le moteur (relâcher la suspension, réexécuter la vérification,
déclencher un playbook) passe par l'API publique `/api/ops/actions/...`
de la bordure, sous l'en-tête `X-Admin-Token`, dont la valeur est
`ADMIN_API_TOKEN` dans `.env` ; la consultation de l'état reste publique
(`/api/supervision/...`).

## R1 : Démarrage à froid de la pile

**Objectif** : mettre en service les 22 services depuis un hôte
préparé, puis vérifier la santé de la bordure et du moteur.

**Déclencheur** : hôte préparé (Docker, compose v2), fichier `.env`
présent (sinon, R1b).

1. Contrôles préalables : capacité de calcul, ports libres, validité du
   fichier de composition.

   ```bash
   ./scripts/preflight.sh
   docker compose config --quiet
   ss -ltn | grep -E ':(80|443|3000|9090)\b' || echo "ports libres"
   ```

   **Résultat attendu** : le préflight affiche un bilan vert (compose
   v2, cœurs, mémoire, disque, ports) ; `config` ne remonte aucune
   erreur.

2. Démarrage orchestré : l'entrée attend l'initialisation des réseaux et
   du coffre de secrets avant de lancer les services.

   ```bash
   docker compose up -d --wait
   docker compose ps
   ```

   **Résultat attendu** : 18 conteneurs en statut `running`, santé ok (les services d'amorçage s'arrêtent une fois leur tâche faite)
   sur les services qui en déclarent.

3. Vérification de la bordure et du moteur :

   ```bash
   curl -s "$CIBLE/healthz"
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/state"
   ```

   **Vérification** : `/healthz` renvoie 200 `alphapay-edge ok` ;
   `/api/supervision/state` renvoie l'état du moteur (étape, dernier
   signalement, refroidissements, disjoncteur).

4. Vérification de l'initialisation du coffre (mode développement) :

   ```bash
   docker exec alphaplat-vault vault status -address=http://127.0.0.1:8200
   docker exec alphaplat-vault vault read -field=root_token \
     -address=http://127.0.0.1:8200 secret/metier | wc -c
   ```

   **Vérification** : le coffre expose les secrets de métier ; le jeton
   racine est présent (mode développement).

5. Vérification de l'apprentissage du détecteur (30 à 60 s) :

   ```bash
   curl -s "$CIBLE/api/detector/score/current"
   curl -s "$CIBLE/api/detector/score/history?limit=5"
   ```

   **Vérification** : l'état de la fenêtre passe d'`apprenant` à
   `normal` ; le score reste bas en régime nominal.

**R1b : Préparation du fichier de secrets (hôte neuf)**

```bash
./scripts/seed-secrets.sh   # refuse l'écrasement sans --force
```

Le script génère `.env` (droit 600) depuis `.env.example` et n'affiche
que des empreintes tronquées (12 caractères de sha256), jamais les
secrets. **Vérification** : le fichier existe avec tous les champs
obligatoires ; le préflight ne signale plus de secret manquant.

## R2 : Diagnostic d'un service indisponible

**Objectif** : identifier le service à l'origine de l'incident et
distinguer une cause applicative (image, déploiement) d'une cause
infra (réseau, dépendance, conteneur).

**Déclencheur** : alerte Prometheus `AlphaPayServiceDown`, perte de
réponse d'un service, ou étape de vérification du moteur bloquée.

1. État global de l'orchestration :

   ```bash
   docker compose ps --format "table {{.Name}}\t{{.Status}}"
   ```

   **Résultat attendu** : un conteneur en `Restarting (N)`, `Exited` ou
   sans santé `ok` est mis en évidence.

2. Journal du conteneur suspect. `SVC` est le nom de service complet
   (`edge`, `api-ledger`, `detector`, ...) ; son conteneur porte le préfixe
   `alphaplat-` :

   ```bash
   docker logs --since 15m alphaplat-SVC
   docker logs alphaplat-remediation | grep -i "$SVC\|recherche" | tail -20
   ```

3. Circuit complet du moteur et actions du dernier incident : l'état
   courant expose la suspension, les échecs consécutifs (disjoncteur) et
   l'incident en cours ; le détail de cet incident expose ses actions :

   ```bash
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/state"
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/incidents?limit=1"
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/incidents/ID_INCIDENT"
   ```

   **Vérification** : l'état expose l'incident en cours et le compteur
   d'échecs consécutifs ; le détail distingue un redémarrage (phase
   recherche / remise en état) d'un isolement de bordure.

4. Isolation réseau du conteneur (cause infra) :

   ```bash
   docker network inspect alphaplat-app --format \
     '{{range .NetworkSettings.Endpoints}}{{.Aliases}} {{end}}'
   ```

   **Vérification** : le conteneur est rattaché au réseau attendu ; un
   conteneur récent a une adresse différente, que la bordure suit grâce
   au TTL du résolveur.

5. Si le moteur est en disjoncteur (trois échecs de suite sur le même
   service), consulter `disjoncteur_ouvert` dans
   `/api/supervision/state` ; la reprise ne reprendra que lorsque le
   service sera de nouveau joignable, sinon intervenir ou escalader
   manuellement.

## R3 : Lecture d'un incident de remédiation

**Objectif** : comprendre ce que le moteur a fait pour un incident
donné : politique déclenchée, signalement, actions, vérifications,
délais, restitution.

**Déclencheur** : lecture a posteriori après un incident, ou
préparation du point de situation.

1. Liste des incidents (borne de détection, délai MTTD/MTTR, playbook) :

   ```bash
   curl -s "$CIBLE/api/supervision/incidents?limit=10"
   ```

2. Détail de l'incident (remplacer `ID_INCIDENT`) : le point de lecture
   principal, qui regroupe d'un seul appel l'incident, sa chronologie
   d'événements, les actions exécutées et les vérifications :

   ```bash
   curl -s "$CIBLE/api/supervision/incidents/ID_INCIDENT"
   ```

   La réponse expose `incident` (état, sévérité, `mttd_ms`, `mttr_ms`,
   `source_ip`, `playbook_id`), `events` (chronologie horodatée de
   l'événement au retour à la normale), `actions` (étapes, paramètres,
   statut, durée) et `verifications` (points de contrôle de
   restitution).

3. Chronologie globale du moteur (tous incidents confondus) et dernières
   vérifications en fenêtre glissante :

   ```bash
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/timeline?limit=120"
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/supervision/verifications?limit=5"
   ```

4. Rejouer la suite de vérification de restitution à la demande (commande
   d'administration, en-tête `X-Admin-Token`) :

   ```bash
   curl -s -X POST -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/ops/actions/verify"
   ```

**Vérification** : le détail porte la politique (par exemple
`POL-A3-INJECTION`), l'adresse d'origine et les bornes de détection ;
les vérifications sont toutes passées (`passed: true`) ; les délais
`mttd_ms` et `mttr_ms` respectent les cibles (inférieurs à 60 s et 180 s,
cibles exposées par `/api/supervision/state`).

## R4 : Déblocage d'une adresse par erreur

**Objectif** : lever un blocage d'adresse IP imposé à tort par la
bordure, avec trace horodatée, et vérifier que la bordure a bien
rechargé sa configuration.

**Déclencheur** : un client légitime (ou un opérateur) est bloqué par la
bordure alors qu'il n'est pas à l'origine de l'attaque.

Le blocage d'adresse est géré par le fichier
`/etc/nginx/dynamic/blocklist.map` du conteneur de bordure ; le
surveillant interne recharge nginx à chaque changement et publie un
témoin horodaté (`/etc/nginx/dynamic/reload-witness.json`, champs
`ts`, `fingerprint`, `result`). L'échéance et le motif de chaque
blocage sont tenus à part, dans
`/etc/nginx/dynamic/blocklist-state.json`. Ce mécanisme est décrit
dans `GOUVERNANCE.md` et `runbooks/PLAYBOOKS.md`.

**Voie normale : l'échéance.** Tout blocage porte un `ttl_seconds`
(900 s par défaut) et le moteur libère les adresses arrivées à
échéance toutes les `EDGE_PURGE_SECONDS` (30 s). Aucune intervention
n'est donc nécessaire : attendre l'échéance suffit, et l'événement
`edge.block_released` en trace la levée.

**Voie explicite : la libération immédiate.** Lorsque l'attente n'est
pas acceptable, demander la levée au moteur de remédiation. La route
est indépendante du coupe-circuit : un opérateur confiné par erreur
doit pouvoir se rétablir sans dépendre de l'automatisme qui l'a
confiné.

1. Constater les blocages en cours (adresse, échéance, motif) :

   ```bash
   curl -s http://127.0.0.1/api/supervision/blocklist
   ```

2. Demander la levée, avec le jeton d'administration :

   ```bash
   curl -s -X POST http://127.0.0.1/api/ops/actions/unblock \
     -H "Content-Type: application/json" \
     -H "X-Admin-Token: $ADMIN_API_TOKEN" \
     -d '{"ip": "192.168.137.20"}'
   ```

   Le résultat porte la preuve du rechargement (`edge_reload`) et la
   liste des blocages restants (`restantes`). Le même geste existe sous
   forme de playbook (`PB-DEBLOCAGE`, action `edge.unblock_ip`).

3. Vérifier que la bordure a bien appliqué la nouvelle liste :

   ```bash
   docker exec alphaplat-edge \
     'cat /etc/nginx/dynamic/reload-witness.json'
   ```

   **Résultat attendu** : le témoin porte `result: "applied"` et
   l'empreinte (`fingerprint`) du nouveau fichier ; le journal
   `/var/log/alphapay/edge-reload.log` du conteneur trace le
   rechargement.

4. Vérifier que l'adresse est de nouveau admise par la bordure :
   réenvoyer une requête représentant ce client et s'assurer qu'elle
   n'est plus rejetée (code 403 « bloqué »).

**Voie de secours : la main dans le conteneur.** Si le moteur est
lui-même indisponible :

```bash
docker exec alphaplat-edge sh -c \
  'sed -i "/192\.168\.137\.20/d" /etc/nginx/dynamic/blocklist.map'
```

(remplacer l'adresse cible ; une liste vide est valide et signifie
« aucun blocage »). Retirer aussi l'entrée correspondante de
`blocklist-state.json`, sans quoi une purge ultérieure tentera de
libérer une adresse déjà libérée.

**Vérification** : le témoin de rechargement est `applied` ; la requête
de l'adresse anciennement bloquée aboutit ; aucun régression sur les
autres blocages en cours.

**Ce qu'il ne faut pas faire** : ajouter l'adresse de l'opérateur à la
main dans `blocklist.map` pour la retirer, ni élargir `NEVER_BLOCK_IPS`
à une plage entière sans motif écrit. Une adresse protégée se déclare
dans `NEVER_BLOCK_IPS` (adresses exactes, par exemple le poste
d'opération) ou `NEVER_BLOCK_NETWORKS` (réseaux de la plateforme), et
tout refus est journalisé en `edge.block_refused`.

## R5 : Réinitialisation complète

**Objectif** : remettre la plateforme à l'état initial, propre, pour une
répétition de démonstration ou un retour à la normale après incident.

**Déclencheur** : fin d'exercice, incident critique, ou préparation du
passage devant le jury.

1. Arrêter et supprimer l'orchestration :

   ```bash
   docker compose down --remove-orphans
   ```

2. Réinitialiser les volumes persistants (données du grand livre,
   instantanés, états) :

   ```bash
   docker volume ls | grep alphaplat
   docker volume rm alphapay_alphaplat-pgdata
   docker volume rm alphapay_alphaplat-ledger-snapshots
   ```

   Les données du grand livre sont portées par le volume `pgdata`, les
   instantanés par le volume de snapshots. En mode développement, le
   coffre de secrets n'a pas à être conservé : il est réinitialisé au
   démarrage.

3. Reprendre le démarrage complet en suivant R1 (préflight, `up`,
   vérifications bordure / moteur / détecteur).

4. Vérifier l'état propre :

   ```bash
   curl -s "$CIBLE/healthz"
   curl -s "$CIBLE/api/supervision/state"
   curl -s "$CIBLE/api/supervision/incidents?limit=5"
   ```

**Vérification** : la bordure est saine ; l'état du moteur ne porte
aucun incident, aucun blocage, aucun compte gelé ; le détecteur est en
apprentissage puis en régime nominal. Les certificats auto-signés sont
reconstruits à l'ouverture des conteneurs.

## R6 : Export des preuves pour le jury

**Objectif** : produire un dossier de preuves reproductible attestant la
chaîne complète détection → réaction → restitution, et les délais
MTTD / MTTR.

**Déclencheur** : préparation du passage devant le jury.

1. Lancer l'exercice de bout en bout (le script joue l'attaque, attend
   la détection, et échoue si la reprise n'est pas réelle) :

   ```bash
   CIBLE=http://localhost DELAI_MAX_RETABLISSEMENT=240 bash tests/e2e.sh A1
   ```

   Le premier argument est le scénario (`A1`, `A2` ou `A3`, défaut
   `A1`) ; `CIBLE` est l'URL cible ; `DELAI_MAX_RETABLISSEMENT` le
   délai maximal de rétablissement en secondes.

2. Pour chaque scénario d'attaque, jouer la mise en œuvre du scénario
   et vérifier la réaction :

   ```bash
   bash tests/scenario.sh A1 192.168.137.20   # rafale volumétrique
   bash tests/scenario.sh A2 192.168.137.20   # bourrage d'identités
   bash tests/scenario.sh A3 192.168.137.20   # injection + exfiltration
   ```

   Le deuxième argument est l'adresse d'origine de l'attaque
   (défaut `192.168.137.20`).

3. Capturer l'état du moteur et les incidents (chaque incident porte ses
   délais `mttd_ms` / `mttr_ms`) :

   ```bash
   curl -s "$CIBLE/api/supervision/state"
   curl -s "$CIBLE/api/supervision/incidents?limit=20"
   ```

4. Capturer les preuves de restitution (six points de contrôle) :
   santé des services, transaction synthétique de bout en bout,
   intégrité comptable, confinement effectif, intégrité d'image,
   intégrité d'authentification. Le déclenchement de la suite de
   vérification est une commande d'administration (en-tête
   `X-Admin-Token`) ; la liste des rapports et l'intégrité comptable sont
   publics :

   ```bash
   curl -s -X POST -H "X-Admin-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/ops/actions/verify"
   curl -s "$CIBLE/api/supervision/verifications?limit=5"
   curl -s "$CIBLE/api/ledger/integrity"
   ```

5. Regrouper les résultats et les exporter :

   ```bash
   bash tests/e2e.sh A1 > preuve_e2e.txt
   curl -s "$CIBLE/api/supervision/incidents" > preuve_incidents.json
   docker logs alphaplat-detector --since 30m > preuve_detector.log
   docker logs alphaplat-remediation --since 30m > preuve_remediation.log
   ```

**Vérification** : le rapport de bout en bout est « vert » (MTTD < 60 s,
MTTR < 180 s, vérifications réussies) ; les six preuves de restitution
sont rassemblées ; le journal du moteur porte l'intégrale des actions,
y compris les actions refusées, avec identifiant de suivi.

## R7 : Sauvegarde et restauration du grand livre

**Objectif** : garantir la persistance et l'intégrité comptable du grand
livre : instantanés d'état (application) et sauvegarde de base de
données.

**Déclencheur** : avant maintenance, avant réinitialisation (R5), ou sur
alerte `AlphaPayLedgerImbalance` (intégrité comptable).

1. Prendre un instantané d'état du grand livre via l'API du service de
   grand livre (volume de snapshots monté en écriture). Les routes
   d'administration du grand livre exigent l'en-tête `X-Internal-Token`
   (valeur : `ADMIN_API_TOKEN`) :

   ```bash
   curl -s -X POST -H "X-Internal-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/ledger/admin/snapshot"
   curl -s -H "X-Internal-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/ledger/admin/snapshots"
   ```

   **Résultat attendu** : un instantané est créé (horodatage,
   empreinte) ; la liste des instantanés est renvoyée.

2. Sauvegarder la base de données PostgreSQL (volume `pgdata`). La base
   est accessible avec l'utilisateur `postgres` ; `pg_dumpall` exige un
   serveur en service, donc la base doit être en marche :

   ```bash
   mkdir -p backup
   docker exec alphaplat-postgres pg_dumpall -U postgres > backup/ledger.sql
   sha256sum backup/ledger.sql
   ```

   **Résultat attendu** : un fichier `backup/ledger.sql` est produit sur
   l'hôte ; son empreinte sha256 est consignée pour la traçabilité.

3. Vérifier l'intégrité comptable avant toute restauration :

   ```bash
   curl -s -H "X-Admin-Token: $ADMIN_API_TOKEN" "$CIBLE/api/ledger/integrity"
   ```

   **Vérification** : la cohérence interne du grand livre est attestée
   (quatre requêtes d'intégrité) ; aucun déséquilibre n'est signalé.

4. Restaurer depuis l'instantané d'application (si besoin) :

   ```bash
   curl -s -X POST -H "X-Internal-Token: $ADMIN_API_TOKEN" \
        "$CIBLE/api/ledger/admin/restore"
   ```

   ou restaurer la base depuis le fichier de sauvegarde (base en service
   ; le flux `psql` lit l'archive depuis l'hôte via le flux standard
   d'entrée du conteneur) :

   ```bash
   docker exec -i alphaplat-postgres psql -U postgres -v ON_ERROR_STOP=1 \
     -f - < backup/ledger.sql
   ```

   **Vérification** : l'instantané ou la sauvegarde est intègre ; la
   cohérence comptable est de nouveau attestée ; les soldes de référence
   sont restaurés.
