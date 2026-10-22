# PROJECT RESILIENCE-ALPHA : AlphaPay

> Plateforme de paiement fictive à **reprise autonome** · Workshop national EPSI BAC+5
> Sprint d'ingénierie 4 jours · Session Octobre 2026

AlphaPay est une plateforme de paiement **entièrement fictive** dont l'objet est de
démontrer une chose : un système d'information critique peut encaisser un incident de
sécurité et **revenir seul à un état opérationnel vérifié**, sans qu'un humain
n'intervienne.

Un conteneur redémarré ne constitue pas une reprise. La plateforme ne déclare un
rétablissement qu'après avoir **prouvé** que le service répond de nouveau de bout en
bout : une transaction synthétique aboutit, le grand livre reste équilibré, et la
source de l'attaque est effectivement filtrée.

---

## Sommaire

- [Démarrage rapide](#démarrage-rapide)
- [Ce que fait la plateforme](#ce-que-fait-la-plateforme)
- [Les cinq piliers](#les-cinq-piliers)
- [Scénarios d'attaque](#scénarios-dattaque)
- [Architecture](#architecture)
- [Points d'entrée](#points-dentrée)
- [Sécurité et limites assumées](#sécurité-et-limites-assumées)
- [Dépannage](#dépannage)
- [Organisation du dépôt](#organisation-du-dépôt)
- [Livrables du workshop](#livrables-du-workshop)

---

## Démarrage rapide

### Prérequis

| Élément | Minimum | Remarque |
|---|---|---|
| Docker Desktop (Windows 10/11) avec WSL2 | 4 cœurs | Le poste hôte du sujet |
| Mémoire allouée à Docker | **12 Go** | 18 conteneurs, dont un modèle de langage local |
| Espace disque libre | 30 Go | Images et volumes |
| `git`, `bash` | : | WSL2 fournit les deux |

Sous Docker Desktop, réglez *Settings → Resources* sur au moins 4 cœurs et 12 Go avant
de démarrer. C'est de loin la première cause d'échec de démarrage.

### Mise en route

```bash
git clone <url-du-depot> resilience-alpha
cd resilience-alpha

# 1. Générer les secrets locaux (aucun secret n'est versionné)
bash scripts/seed-secrets.sh

# 2. Vérifier que la machine peut héberger la pile
bash scripts/preflight.sh

# 3. Construire et démarrer
docker compose build
docker compose up -d

# 4. Suivre le démarrage (le premier lancement installe les modèles : comptez 5 à 10 min)
docker compose ps
docker compose logs -f remediation detector
```

Une fois la pile démarrée :

| Accès | Adresse |
|---|---|
| Interface de paiement (client) | `https://localhost/` |
| Salle d'opérations (jury) | `https://localhost/ops` |
| Tableaux de bord Grafana | `http://localhost:3000` |
| Métriques Prometheus | `http://localhost:9090` |

Le certificat est auto-signé et propre à votre installation : le navigateur affichera
un avertissement. Il est normal et attendu ; le certificat n'est pas signé par une
autorité publique parce que la plateforme est fictive et cloisonnée.

Comptes de démonstration (mot de passe `AlphaPay-Client-2026!` pour les clients) :

| Compte | Rôle | Usage |
|---|---|---|
| `client01`, `client02`, `client03` | client | Effectuer un paiement |
| `operateur` | opérateur | Consultation de la salle d'opérations |
| `admin` | administrateur | Actions d'administration |

### Arrêt et remise à zéro

```bash
docker compose down            # arrêt, les données sont conservées
docker compose down -v         # arrêt + effacement des volumes (repart de zéro)
```

---

## Ce que fait la plateforme

1. **Le service fonctionne.** Un client se connecte et effectue un paiement. La
   transaction est enregistrée en partie double dans le grand livre.
2. **Le service est attaqué.** Depuis un poste distinct, un scénario offensif est
   déclenché (voir [Scénarios d'attaque](#scénarios-dattaque)).
3. **Le comportement dévie.** Chaque seconde, la télémétrie agrège les journaux de la
   bordure, des services et du WAF en 18 variables observées sur une fenêtre glissante
   de 60 secondes.
4. **Le modèle détecte.** Un modèle non supervisé : entraîné sur du trafic nominal, sans
   jamais voir d'attaque : compare la fenêtre courante à la normale apprise et déclare
   l'anomalie, en indiquant les variables qui l'expliquent.
5. **Le moteur décide.** Une politique déclarative fait correspondre l'anomalie à un
   playbook. Le playbook contient, dans l'ordre, les phases de confinement, d'éradication
   et de remise en état.
6. **Le moteur agit.** Chaque action est exécutée par un connecteur soumis à liste
   blanche, avec délai d'expiration, limitation de fréquence et coupe-circuit.
7. **Le moteur vérifie.** Une transaction synthétique est rejouée de bout en bout via la
   bordure, l'intégrité comptable est recontrôlée et le filtrage de la source est
   confirmé. **Ce n'est qu'à cette condition que l'incident est clos en « rétabli ».**
8. **Le jury voit tout.** La salle d'opérations affiche l'état avant, pendant et après,
   ainsi que le délai de détection et le délai de rétablissement mesurés.

---

## Les cinq piliers

| Pilier | Mise en œuvre dans ce dépôt |
|---|---|
| **Développement** | Microservices FastAPI, API REST documentées (OpenAPI), interface React + Tailwind CSS, grand livre en partie double, moteur de politiques et playbooks |
| **Infrastructure** | Docker Compose, playbooks Ansible, reverse proxy, isolation réseau par zone (5 réseaux), durcissement des conteneurs |
| **IA / Data** | Modèle non supervisé (Isolation Forest) + variante autoencodeur, assistant documentaire local (RAG : LangChain + Ollama + pgvector) |
| **Cybersécurité** | WAF ModSecurity + OWASP CRS, détection d'exécution Falco, gestion des secrets Vault, banc offensif Red Team, moindre privilège SQL |
| **Gouvernance** | Analyse de risques EBIOS Risk Manager, PCA/PRA, mise en regard NIS2 et DORA, arbitrages explicites |

---

## Scénarios d'attaque

Trois scénarios sont fournis, exécutables depuis le poste attaquant. Ils se distinguent
par ce qu'ils cherchent à obtenir, et donc par la réponse qu'ils appellent.

### A1 : Rafale volumétrique distribuée

Objectif de l'attaquant : saturer la plateforme de paiement pour la rendre indisponible.

Signature observée : débit de requêtes très supérieur à la normale, taux d'erreur en
hausse, latence qui s'effondre ou s'envole, répartition des adresses qui se concentre.

Réponse attendue : blocage de l'adresse d'origine à la bordure, révocation des jetons
émis depuis cette adresse, redémarrage du service de paiement, vérification de bout en
bout.

### A2 : Réutilisation d'identités compromises

Objectif de l'attaquant : tester des couples identifiant/mot de passe volés à grande
échelle, puis utiliser les accès obtenus.

Signature observée : taux d'échec d'authentification très élevé, nombre d'identités
distinctes sollicitées en forte hausse, tentatives par identité anormales.

Réponse attendue : confinement de la source, **rotation de la clé de signature** : ce qui
invalide instantanément l'ensemble des jetons émis : redémarrage du service
d'authentification, vérification.

### A3 : Injection applicative et tentative d'exfiltration

Objectif de l'attaquant : exploiter une entrée non filtrée, puis extraire des données.

Signature observée : proportion de requêtes portant une charge d'injection détectée par
le WAF, taux de blocage par le WAF, volume sortant rapporté à la tendance habituelle.

Réponse attendue : blocage de la source, gel du compte visé, instantané du grand livre,
réconciliation comptable, vérification.

### Exécution

```bash
cd redteam

# A1 : rafale volumétrique, 90 secondes
python3 alpha_redteam.py --scenario A1 --cible https://<adresse-du-poste-hote> \
    --duree 90 --declarer --suivre

# A2 : réutilisation d'identités
python3 alpha_redteam.py --scenario A2 --cible https://<adresse-du-poste-hote> \
    --duree 60 --declarer --suivre

# A3 : injection et exfiltration
python3 alpha_redteam.py --scenario A3 --cible https://<adresse-du-poste-hote> \
    --duree 60 --declarer --suivre
```

L'option `--suivre` interroge la salle d'opérations et affiche, à la fin, le délai de
détection, le délai de rétablissement, les actions exécutées et le résultat des
vérifications.

> L'option `--declarer` transmet l'instant de départ de l'attaque, ce qui permet de
> mesurer le délai de détection depuis le début réel de l'attaque. Elle exige la
> variable `ALPHAPAY_HMAC_SECRET` et n'est utilisée que pour l'instrumentation du banc
> d'essai : **l'attaque elle-même ne se sert d'aucun secret**.

### Rejouer sans le banc offensif

```bash
bash tests/scenario.sh A1          # joue le rôle du détecteur et déclenche le playbook
```

Cette commande est utile lorsque la bordure ou le détecteur doivent être laissés de
côté pour isoler un problème.

---

## Architecture

Vingt-trois composants répartis sur cinq réseaux cloisonnés. Le document
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) détaille les choix et leurs
justifications ; la conception fine (schéma de données, contrats, politiques, modèle)
est dans [`docs/DESIGN.md`](docs/DESIGN.md).

```
   Poste attaquant            Poste hôte (Windows + WSL2)                    Poste jury
        │                             │                                          │
        │  https://<hôte>/            │                                          │
        ▼                             ▼                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────────┐
   │  BORDURE : ModSecurity + OWASP CRS, reverse proxy, journalisation JSON          │
   └───────────────┬─────────────────────────────────────────────┬───────────────────┘
                   │                                             │
        ┌──────────▼──────────┐                        ┌─────────▼─────────┐
        │  Interface React    │                        │  api-auth         │
        │  /pay  ·  /ops      │                        │  api-payment      │
        └──────────┬──────────┘                        │  api-ledger       │
                   │                                   └─────────┬─────────┘
                   │                                             │
   ┌───────────────▼─────────────────────────────────────────────▼───────────────────┐
   │  TÉLÉMÉTRIE          →  18 variables observées / 60 s                           │
   │  DÉTECTEUR           →  modèle non supervisé, score + explication               │
   │  REMÉDIATION         →  politiques, playbooks, connecteurs, vérification        │
   └───────────────┬─────────────────────────────────────────────────────────────────┘
                   │
   ┌───────────────▼─────────────────────────────────────────────────────────────────┐
   │  SOCLE : PostgreSQL + pgvector · Prometheus · Grafana · Loki · Falco · Vault     │
   └─────────────────────────────────────────────────────────────────────────────────┘
```

### Composants

| Service | Rôle | Port interne |
|---|---|---|
| `edge` | WAF ModSecurity + OWASP CRS, reverse proxy, journal JSON | 8080, 8443 |
| `web` | Interface React (paiement client et salle d'opérations) | 8080 |
| `api-auth` | Authentification, jetons JWT RS256, cycle de vie des clés | 8000 |
| `api-payment` | Orchestration des paiements, règles métier, plafonds | 8000 |
| `api-ledger` | Grand livre en partie double, intégrité, instantanés | 8000 |
| `telemetry` | Agrégation des journaux en 18 variables observées | 8000 |
| `detector` | Détection non supervisée, score et explication | 8000 |
| `remediation` | Politiques, playbooks, connecteurs, vérification de reprise | 8000 |
| `assistant` | Assistant documentaire local (RAG) | 8000 |
| `postgres` | PostgreSQL 16 + pgvector | 5432 |
| `prometheus`, `alertmanager` | Métriques et acheminement des alertes | 9090, 9093 |
| `loki`, `promtail`, `grafana` | Journaux centralisés et tableaux de bord | 3100, 3000 |
| `falco`, `falcosidekick` | Détection d'exécution des conteneurs | 2801 |
| `vault` | Coffre de secrets | 8200 |
| `ollama` | Modèle de langage local | 11434 |
| `docker-proxy` | Accès restreint au démon Docker pour la remédiation | 2375 |

---

## Points d'entrée

### Publics (derrière la bordure, donc filtrés par le WAF)

| Méthode | Chemin | Rôle |
|---|---|---|
| `POST` | `/api/auth/token` | Obtenir un jeton d'accès |
| `POST` | `/api/auth/token/refresh` | Rafraîchir un jeton |
| `GET` | `/api/auth/users/me` | Profil du porteur du jeton |
| `POST` | `/api/payments` | Créer un paiement |
| `GET` | `/api/payments/{id}` | Consulter un paiement |
| `GET` | `/api/payments` | Historique des paiements |
| `GET` | `/api/payments/limits` | Plafonds appliqués |
| `GET` | `/api/ledger/accounts` | Comptes et soldes |
| `GET` | `/api/ledger/integrity` | Contrôle d'intégrité comptable |
| `GET` | `/api/supervision/state` | État courant de la salle d'opérations |
| `GET` | `/api/supervision/incidents` | Incidents et délais mesurés |
| `GET` | `/api/supervision/timeline` | Chronologie des événements |
| `GET` | `/api/supervision/policies` | Politiques et playbooks chargés |
| `GET` | `/api/detector/score/current` | Score d'anomalie courant et explication |
| `POST` | `/api/assistant/ask` | Poser une question à l'assistant documentaire |

### Internes (jamais exposés, réseau `net-app` ou `net-mgmt` uniquement)

| Méthode | Chemin | Émetteur |
|---|---|---|
| `POST` | `/api/ingest/detector` | Détecteur d'anomalies |
| `POST` | `/api/ingest/alertmanager` | Alertmanager |
| `POST` | `/api/ingest/falco` | Falcosidekick |
| `POST` | `/api/ingest/webhook` | Instrumentation du banc d'essai |
| `POST` | `/api/actions/run` | Déclenchement manuel d'un playbook (jeton d'administration) |

Chaque service expose `/healthz`, `/readyz` et `/metrics`.

---

## Sécurité et limites assumées

Le durcissement appliqué est décrit en détail dans
[`docs/GOUVERNANCE.md`](docs/GOUVERNANCE.md). En résumé :

**Ce qui est en place**

- WAF applicatif ModSecurity v3 avec le Core Rule Set OWASP 4, paranoïa 1 ;
- cinq réseaux Docker cloisonnés, dont trois internes (données, supervision, gestion) ;
- un rôle PostgreSQL par service, au moindre privilège ; le journal d'audit est en
  **ajout seul**, garanti par les privilèges SQL eux-mêmes et non par convention ;
- conteneurs sans privilèges, systèmes de fichiers en lecture seule, capacités retirées ;
- secrets hors du dépôt, générés localement par `scripts/seed-secrets.sh` ;
- accès au démon Docker médiatisé par un proxy en liste blanche ;
- aucune donnée, clé ou document réel : l'intégralité du contenu est fictive.

**Ce qui est assumé et documenté**

| Sujet | Limite | Traitement |
|---|---|---|
| Vault | Mode développement : le coffre est déverrouillé et non persisté | Acceptable pour un exercice cloisonné ; la mise en service réelle est décrite dans la note de gouvernance |
| Certificats | Auto-signés, générés dans l'image | Importables par le poste client ; voir la note de gouvernance |
| Jetons d'accès | Un jeton d'accès reste valide jusqu'à son expiration, même après révocation de la source | Durée volontairement courte ; la rotation de la clé de signature invalide l'ensemble des jetons immédiatement |
| Blocage d'adresse | Repose sur l'écriture d'un fichier relu par la bordure | Un témoin de rechargement horodaté rend l'opération vérifiable, jamais supposée |
| Modèle local | Modèle de quelques milliards de paramètres, non affiné | Suffisant pour la synthèse documentaire ; ses limites sont explicitées dans l'interface |

---

## Dépannage

| Symptôme | Cause probable | Correction |
|---|---|---|
| `docker compose up` échoue au démarrage | `.env` absent | `bash scripts/seed-secrets.sh` |
| Erreur mémoire pendant la construction | Docker Desktop limité à moins de 12 Go | *Settings → Resources*, puis redémarrage de Docker |
| `https://localhost` refuse la connexion | La bordure attend ses amonts | `docker compose logs edge`, puis `docker compose ps` |
| Aucune anomalie n'est jamais détectée | Le détecteur n'a pas de modèle | `docker compose logs detector` : il s'entraîne au premier démarrage, comptez 30 secondes |
| Le détecteur déclare des anomalies en permanence | Il vient de démarrer et sa mémoire longue n'est pas encore établie | Attendez dix minutes de trafic nominal, ou redémarrez `detector` |
| `grafana` affiche « pas de données » | Prometheus vient de démarrer | Attendez un cycle de collecte (5 secondes) |
| Les tableaux de bord restent vides | Le service ciblé n'est pas démarré | `docker compose ps`, colonne `STATUS` |
| Le blocage d'adresse n'a aucun effet | Le surveillant de la bordure n'a pas rechargé | `docker compose logs edge \| grep reload` |
| L'assistant répond lentement | Le modèle se charge au premier appel | Patientez : le premier appel peut prendre une minute |

---

## Organisation du dépôt

```
resilience-alpha/
├── docker-compose.yml           Orchestration des 22 services
├── .env.example                 Modèle de configuration (aucun secret réel)
├── docs/
│   ├── ARCHITECTURE.md          Architecture, choix techniques et justifications
│   ├── DESIGN.md                Conception détaillée : données, API, politiques, modèle
│   ├── DESIGN-SYSTEM.md         Direction artistique et jetons d'interface
│   ├── GOUVERNANCE.md           EBIOS RM, PCA/PRA, NIS2, DORA, arbitrages
│   ├── RUNBOOKS.md              Procédures d'exploitation et de reprise
│   └── runbooks/                Fiches de procédure détaillées
├── infra/
│   ├── db/                      Schéma, rôles SQL, jeu de démonstration
│   ├── edge/                    Bordure WAF : modèles nginx, règles CRS, surveillant
│   ├── policies/                Politiques de réaction (déclaratif)
│   ├── playbooks/               Playbooks de remédiation (déclaratif)
│   ├── prometheus/              Collecte et règles d'alerte
│   ├── alertmanager/            Acheminement des alertes vers la remédiation
│   ├── loki/, promtail/         Journaux centralisés
│   ├── grafana/                 Sources de données et tableaux de bord
│   └── falco/                   Règles de détection d'exécution
├── services/
│   ├── common/                  Socle partagé : journalisation, traçage, base, métriques,
│   │                            calcul des 18 variables observées
│   ├── api-auth/                Authentification et jetons
│   ├── api-payment/             Paiement
│   ├── api-ledger/              Grand livre
│   ├── telemetry/               Agrégation de la télémétrie
│   ├── detector/                Détection non supervisée
│   ├── remediation/             Moteur de remédiation autonome
│   └── assistant/               Assistant documentaire (RAG)
├── frontend/                    Interface React + Tailwind CSS
├── ml/                          Génération de trafic nominal, entraînement, variante
├── redteam/                     Banc offensif
├── ansible/                     Déploiement et remise en état
├── scripts/                     Amorçage des secrets, contrôles de pré-vol
├── tests/                       Tests de fumée, tests de bout en bout, banc de la bordure
└── deliverables/                Dossier, présentation et clip chrono
```

---

## Livrables du workshop

| Livrable exigé | Emplacement | État |
|---|---|---|
| `Code.zip` : sources, historique Git, README | racine du dépôt | produit |
| `Dossier.pdf` : ingénierie et gouvernance, 8 pages | `deliverables/` | produit |
| `Pres.pptx` : présentation de soutenance | `deliverables/` | produit |
| `VidChrono.mp4` : démonstration continue, 90 secondes | `deliverables/` | produit |
| Démonstrateur live | pile complète, `docker compose up -d` | opérationnel |

---

## Vérifier l'ensemble

```bash
bash scripts/preflight.sh         # cohérence de l'environnement
bash tests/e2e.sh                # pile démarrée : parcours complet et reprise autonome
bash tests/edge_smoke.sh         # bordure seule
```

`tests/e2e.sh` déroule le parcours attendu par le jury : transaction nominale, attaque,
détection, remédiation autonome, vérification, mesure des délais : et **échoue** si le
service n'est pas réellement rétabli. C'est le test qui doit passer avant la soutenance.
