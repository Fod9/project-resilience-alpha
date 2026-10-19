# Manuel de procédures — PROJECT RESILIENCE-ALPHA

Procédures d'exploitation de la plateforme AlphaPay (23 conteneurs, 5
réseaux cloisonnés). Chaque procédure précise son objectif, son
déclencheur, ses étapes avec les commandes exactes, le résultat attendu et
la vérification. Les actions du moteur de remédiation (politiques et
playbooks) sont décrites dans `runbooks/PLAYBOOKS.md` ; ce manuel couvre
les actions d'exploitation humaine.

Environnement de référence : poste hôte Windows 10/11 avec Docker Desktop
(WSL2, 4 cœurs, 16 Go, 50 Go), dépôt racine `resilience-alpha/`. Les
commandes sont exécutées depuis la racine du dépôt.

## Index

| Réf. | Procédure | Déclencheur |
|------|-----------|-------------|
| R1 | Démarrage à froid de la pile | Mise en service, après arrêt total, avant une démonstration |
| R2 | Diagnostic d'un service indisponible | Alerte `AlphaPayServiceDown` ou `/healthz` non conforme |
| R3 | Lecture d'un incident de remédiation | Incident à analyser dans la salle d'opérations ou en API |
| R4 | Déblocage d'une adresse par erreur | Adresse légitime bloquée par la bordure |
| R5 | Réinitialisation complète de la plateforme | État incontrôlable, contamination des volumes |
| R6 | Export des preuves pour le jury | Avant la soutenance du vendredi |
| R7 | Sauvegarde et restauration du grand livre | Cycle de sauvegarde, sinistre sur la base de données |

---

## R1 — Démarrage à froid de la pile

**Objectif.** Amener l'ensemble de la plateforme à l'état nominal et le
vérifier avant tout usage.

**Déclencheur.** Mise en service, retour d'un arrêt total, ou préparation
d'une session de démonstration.

### Étapes

1. Contrôle d'environnement (prérequis de la machine hôte) :
   ```bash
   bash scripts/preflight.sh
   ```
   Vérifie Docker, Docker Compose v2, cœurs (>= 4), mémoire (>= 12 Go),
   disque (>= 30 Go), ports libres (80, 443, 3000, 9090), présence du
   fichier `.env` et cohérence de la définition Compose.
2. Si `.env` n'existe pas, générer les secrets :
   ```bash
   bash scripts/seed-secrets.sh
   ```
   Produit un `.env` à partir de `.env.example` (refus d'écrasement sans
   `--force`), droits 600, et affiche les empreintes (tronquées) des
   valeurs sans jamais afficher les secrets.
3. Vérifier la présence de l'artefact du modèle ; sinon l'entraîner
   (environ 30 s) :
   ```bash
   test -f ml/artifacts/model.joblib || python3 ml/train.py
   ```
4. Lancer la pile :
   ```bash
   docker compose up -d --build
   ```
5. Attendre la convergence des états :
   ```bash
   docker compose ps
   ```
   Puis, en contrôlant la santé de bout en bout :
   ```bash
   bash tests/edge_smoke.sh
   ```

### Résultat attendu

Les 23 conteneurs sont démarrés, la bordure répond sur le port 443 et les
profils de démonstration (3000, 9090) exposent Grafana et Prometheus.

### Vérification

- `docker compose ps` : tous les services dans l'état `running`, les
  services avec santé dans l'état `healthy` (le conteneur `init-perms`
  s'arrête après exécution, ce qui est normal).
- `tests/edge_smoke.sh` : la bordure répond, le WAF est actif, la
  redirection HTTP vers HTTPS fonctionne.
- Le front de démonstration est joignable et le tableau de bord d'exploitation
  affiche l'état nominal.

---

## R2 — Diagnostic d'un service indisponible

**Objectif.** Déterminer pourquoi un service ne répond pas et, si le moteur
n'a pas déjà traité l'incident, le remettre en état avec preuve.

**Déclencheur.** Alerte Prometheus `AlphaPayServiceDown` (conteneur hors
ligne depuis 20 s) ou échec du contrôle de santé `GET /healthz` ou
`/readyz` sur la bordure, le front ou un des services applicatifs.

### Étapes

1. Constater l'état des conteneurs :
   ```bash
   docker compose ps
   ```
2. Récupérer les journaux du service fautif (ex. `api-ledger`) :
   ```bash
   docker compose logs --since 10m api-ledger
   ```
3. Consulter les incidents récents du moteur pour savoir s'il a déjà
   traité l'indisponibilité (politique `POL-EXPL-INDISPONIBLE`, playbook
   `PB-REDEMARRAGE-SERVICE`) :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/incidents?limit=10" | python3 -m json.tool
   ```
4. Si le moteur n'a pas pris le relais (échec d'exécution,
   `DRY_RUN=true`, coupe-circuit), redémarrer manuellement le service :
   ```bash
   docker compose restart api-ledger
   ```
   puis attendre la santé :
   ```bash
   docker compose ps api-ledger
   ```
5. Exécuter la suite de vérification pour confirmer le rétablissement :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -X POST "https://localhost/api/ops/actions/verify.recovery_suite" \
     -H "Content-Type: application/json" -d '{}'
   ```

### Résultat attendu

Le service redevient `healthy`, l'état global repasse au nominal et la
suite de vérification produit les six preuves conformes (santé,
transaction synthétique, intégrité comptable, confinement, dérive
d'image, intégrité de l'authentification).

### Vérification

- `docker compose ps` : le service `healthy`.
- `GET https://localhost/api/ops/state` : `global_state` nominal.
- Incidents récents sans incident en cours ; si l'incident s'est terminé
  en `ESCALATED`, le moteur a cessé d'automatiser : le redémarrage manuel
   et la vérification (étapes 4-5) sont alors obligatoires.

---

## R3 — Lecture d'un incident de remédiation

**Objectif.** Retracer, sur un incident du moteur, la politique déclenchée,
le playbook exécuté, les actions, les preuves et les délais MTTD/MTTR.

**Déclencheur.** Analyse d'après-incident, question du jury, ou incident
à documenter avant export (procédure R6).

### Étapes

1. Liste des incidents :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/incidents?limit=20" | python3 -m json.tool
   ```
2. Détail d'un incident (remplacer `INCIDENT_ID`) :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/incidents/INCIDENT_ID" > /tmp/incident.json
   python3 tests/rapport_incident.py < /tmp/incident.json
   ```
   Le rapport affiche la politique, le playbook, l'état final, le délai de
   détection, le délai de reprise, et chaque action avec son statut et sa
   durée.
3. Chronologie détaillée si nécessaire :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/incidents/INCIDENT_ID/timeline" | python3 -m json.tool
   ```
4. Journal des actions (y compris refusés, avec l'identifiant de suivi)
   dans Loki, filtré sur `alphapay` et l'incident.

### Résultat attendu

Un incident se lit en quatre points : `state=RECOVERED` (sinon
`RECOVERING` ou `ESCALATED`), `mttd_ms` < 60 000, `mttr_ms` < 180 000,
et les six preuves de la suite de vérification passées.

### Vérification

- L'état `RECOVERED` n'est jamais obtenu sans le passage des six
  preuves ; un `ESCALATED` signale trois échecs consécutifs d'exécution
  (coupe-circuit) et exige une intervention opérateur.
- Croiser le rapport avec la chronologie : chaque phase (confinement,
  éradication, remise en état, vérification) doit apparaître dans
  l'ordre, sans phase manquante inexpliquée.

---

## R4 — Déblocage d'une adresse par erreur

**Objectif.** Lever le blocage de bordure d'une adresse bloquée à tort, et
s'assurer que la levée est réellement appliquée par la bordure.

**Déclencheur.** Une adresse légitime reçoit des réponses 403/429
indûment, ou un contournement est signalé par un client ; jamais pour une
adresse de la liste blanche (poste hôte, postes d'encadrement, réseau
d'administration), dont le blocage est refusé et journalisé par le moteur.

### Étapes

1. Constater le blocage : consulter la liste de blocage active et le
   témoin de rechargement publié par la bordure :
   ```bash
   docker compose exec edge cat /etc/nginx/dynamic/blocklist.map
   docker compose exec edge cat /etc/nginx/dynamic/reload-witness.json
   ```
2. Retirer l'adresse de la liste (édition du fichier partagé, par exemple
   depuis un conteneur du réseau d'administration) :
   ```bash
   docker compose exec edge sh -c \
     "grep -v 'ADRESSE_A_DEBLOQUER' /etc/nginx/dynamic/blocklist.map \
      > /tmp/bl && mv /tmp/bl /etc/nginx/dynamic/blocklist.map"
   ```
   (Le surveillant de bordure détecte le changement, relance le
   rechargement de la configuration nginx et publie un nouveau témoin.)
3. Attendre le témoin :
   ```bash
   docker compose exec edge cat /etc/nginx/dynamic/reload-witness.json
   docker compose logs --since 2m edge | grep -i reload
   ```

### Résultat attendu

Le témoin affiche le nouvel empreinte de la liste et le résultat
`applied` ; la bordure a rechargé sa configuration.

### Vérification

- Le témoin est la preuve : une règle (ou sa levée) n'est active que si
  le rechargement a abouti ; un témoin `reload-failed` ou
  `config-invalid` signifie que la configuration n'a pas changé.
- Rejouer une requête depuis l'adresse débloquée : elle doit être admise.
- L'opération reste journalisée (journal des rechargements, journal du
  moteur) ; ne jamais supposer qu'un fichier modifié est une règle
  appliquée.

---

## R5 — Réinitialisation complète de la plateforme

**Objectif.** Repartir d'un état propre, y compris des volumes persistants,
et redémarrer l'ensemble de la pile.

**Déclencheur.** État incontrôlable de la plateforme (base corrompue,
secrets compromis, volumes sales) ou préparation d'un replay de
démo vierge.

### Étapes

1. Arrêter la pile :
   ```bash
   docker compose down
   ```
2. Supprimer les volumes persistants :
   ```bash
   docker compose down -v
   ```
   (Effets : base PostgreSQL, journaux, instantanés du grand livre,
   artefacts Loki/Grafana/Prometheus, coffre, modèle, état de bordure.)
3. Régénérer le fichier `.env` si nécessaire :
   ```bash
   bash scripts/seed-secrets.sh --force
   ```
4. Reconstruire les certificats internes :
   ```bash
   bash scripts/gen-certs.sh
   ```
5. Relancer la pile :
   ```bash
   docker compose up -d --build
   ```
6. Réentraîner le modèle si l'artefact n'a pas survécu à la suppression
   des volumes :
   ```bash
   python3 ml/train.py
   ```
7. Vérifier :
   ```bash
   bash tests/edge_smoke.sh
   ```

### Résultat attendu

Une plateforme vierge : données réinitialisées, secrets régénérés, modèle
réentraîné, bordure saine, état nominal dans la salle d'opérations.

### Vérification

- `docker compose ps` : convergence complète des 23 conteneurs.
- Le tableau de bord affiche l'état nominal et les compteurs remis à
  zéro.
- La suite de vérification `verify.recovery_suite` (cf. R2, étape 5)
  produit les six preuves conformes.

---

## R6 — Export des preuves pour le jury

**Objectif.** Produire un dossier de preuve complet avant la soutenance :
scénarios rejoués, MTTD/MTTR mesurés, rapports d'incident, intégrité
comptable.

**Déclencheur.** Préparation de la soutenance (vendredi), répétition
générale.

### Étapes

1. S'assurer de l'état nominal (procédure R1, étapes 4-5).
2. Jouer les trois scénarios d'attaque depuis le banc offensif
   (cible bornée, marquage horodaté, durée et volume plafonnés ; le banc
   refuse de cibler une adresse hors du périmètre autorisé) :
   ```bash
   bash tests/scenario.sh A1
   bash tests/scenario.sh A2 192.168.137.20
   bash tests/scenario.sh A3
   ```
3. Exécuter la vérification bout en bout pour chaque scénario : elle
   contrôle, sans rien négliger, que le service répond avant l'incident,
   que le grand livre est équilibré, que l'attaque a déclenché un incident
   sans intervention humaine, que l'incident s'est clôturé « rétabli »
   avec vérification réussie, qu'une nouvelle transaction réussit après
   l'incident, et que les délais mesurés respectent les cibles
   (défaut : rétablissement en 240 s) :
   ```bash
   bash tests/e2e.sh A1
   bash tests/e2e.sh A2
   bash tests/e2e.sh A3
   ```
4. Exporter les rapports d'incidents et les délais :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/state" > evidence/state.json
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     "https://localhost/api/ops/incidents?limit=50" > evidence/incidents.json
   ```
5. Capturer l'intégrité comptable (quatre requêtes de contrôle, zéro
   ligne attendue) et les extraits des tableaux de bord (résilience :
   MTTD/MTTR, score du détecteur, chronologie ; métier : transactions,
   soldes).

### Résultat attendu

Un dossier reprenant, pour chaque scénario : l'incident ouvert et clôturé
`RECOVERED`, le MTTD mesuré < 60 s, le MTTR mesuré < 180 s, le passage
des six preuves, l'équilibre du grand livre avant et après.

### Vérification

- La boucle de preuve `tests/e2e.sh` échoue si le rétablissement n'est
  pas réel : elle est l'argument central devant le jury.
- Les cibles (MTTD < 60 s, MTTR < 180 s) apparaissent dans
  `evidence/state.json` et sur le tableau de bord de résilience.
- Conserver `evidence/` dans le dépôt de livraison (`Code.zip`).

---

## R7 — Sauvegarde et restauration du grand livre

**Objectif.** Produire une sauvegarde restaurable du grand livre (base
PostgreSQL : journal des jambes, soldes, journal d'audit d'authentification
en ajout seul), et la restaurer en cas de sinistre.

**Déclencheur.** Cycle de sauvegarde périodique, avant une modification
majeure, ou sinistre (base illisible, volume perdu).

### Étapes — Sauvegarde

1. Produire un instantané applicatif via le moteur (dépose un instantané
   dans le volume dédié `alphaplat-ledger-snapshots`) :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -X POST "https://localhost/api/ops/actions/ledger.snapshot" \
     -H "Content-Type: application/json" -d '{}'
   ```
2. Produire le dump horodaté de la base :
   ```bash
   DATE=$(date +%Y%m%dT%H%M%SZ)
   docker compose exec postgres pg_dumpalphapay -U alphapay \
     -f "/backup/dump-$DATE.sql"
   ```
   (Le rôle de service ne porte que les privilèges nécessaires ; le dump
   est produit par le conteneur de base lui-même, sans exposer la base au
   réseau d'administration.)
3. Sortir le dump hors de la machine de démonstration :
   ```bash
   docker compose cp postgres:/backup/dump-$DATE.sql ./backups/dump-$DATE.sql
   ```

### Étapes — Restauration

1. Stopper la pile :
   ```bash
   docker compose down
   ```
2. Restaurer le volume de la base depuis le dump :
   ```bash
   docker compose up -d postgres
   docker compose cp backups/dump-$DATE.sql postgres:/backup/restore.sql
   docker compose exec postgres psql -U alphapay -d alphapay \
     -f /backup/restore.sql
   ```
3. Relancer la pile :
   ```bash
   docker compose up -d --build
   ```
4. Vérifier l'intégrité comptable : recalcule des soldes depuis le
   journal des jambes, puis la suite de vérification :
   ```bash
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -X POST "https://localhost/api/ops/actions/ledger.reconcile" \
     -H "Content-Type: application/json" -d '{}'
   curl -sk -H "Authorization: Bearer $ADMIN_API_TOKEN" \
     -X POST "https://localhost/api/ops/actions/verify.recovery_suite" \
     -H "Content-Type: application/json" -d '{}'
   ```

### Résultat attendu

Le grand livre est restauré, les soldes recalculés depuis le journal des
jambes, l'intégrité comptable conforme (quatre requêtes de contrôle à
zéro ligne), et l'état global repasse au nominal.

### Vérification

- Le journal d'audit d'authentification est en ajout seul, garanti par les
  privilèges SQL (aucun droit de mise à jour ni de suppression) : une
  restauration ne peut le réécrire, seulement le reconstituer.
- La preuve d'intégrité est la même qu'en exploitation normale : on ne
  déclare la restauration réussie que si la suite de vérification passe.
- Conserver au moins deux dumps horodatés hors de la machine, le plus
  récent datant de moins d'un cycle.

---

## Annexe — Rappels d'arbitrage applicables à l'exploitation

- Mode simulé (`DRY_RUN=true`) actif par défaut : en mode réel
  (`DEMO_MODE=true`), l'état est affiché en permanence dans la salle
  d'opérations ; ne pas changer de mode en cours d'incident.
- Couvre-feu : 6 actions automatiques maximum par fenêtre de 300 s ;
  au-delà, le moteur s'arrête et escalade — l'opérateur reprend la main.
- Toute action réversible expire à son échéance (blocage : 900 s par
  défaut) ; un blocage pérenne exige un renouvellement explicite.
- Les gels de compte (A3) ne sont jamais levés automatiquement : la
  décision appartient à un humain après contrôle.
