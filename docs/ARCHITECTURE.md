# PROJECT RESILIENCE-ALPHA : Architecture système

> **AlphaPay** : plateforme de paiement fictive · *Cyber-résilience et reprise autonome*
> Workshop national EPSI BAC+5 · Sprint d'ingénierie 4 jours · Session Octobre 2026

---

## 1. Objectif d'architecture

Démontrer, sur un périmètre maîtrisé, qu'un SI critique **détecte une anomalie,
décide et exécute une action corrective, puis revient seul à un état de service
vérifié** : sans intervention humaine.

Exigences structurantes extraites du sujet :

| # | Exigence | Traduction architecturale |
|---|----------|---------------------------|
| E1 | Plateforme de paiement simulée, conteneurisée | 3 services métier + SGBD + SPA React, tout en Docker Compose |
| E2 | Transaction déclenchée depuis un ordinateur **distinct** du PC Hôte | Client d'attaque + client légitime hors stack, sur le PC Attaquant |
| E3 | Incident de sécurité **contrôlé** provoqué par le consortium | Scripts Red Team reproductibles, idempotents, bornés |
| E4 | Détection **par modèle ML**, pas par règles codées en dur | *Isolation Forest* entraîné sur baseline + score explicable |
| E5 | Remédiation **autonome**, décision + exécution par le système | Policy Engine + Playbooks + Executor (aucun humain) |
| E6 | Un redémarrage de conteneur **ne constitue pas** une preuve | Vérification end-to-end + intégrité des données obligatoires |
| E7 | Rétablissement démontré par une **nouvelle transaction qui aboutit** | Test synthétique de récupération (synthetic transaction probe) |
| E8 | Dashboard : état **avant / pendant / après**, composants, événements, alertes, avancement | Supervision temps réel + timeline de remédiation |
| E9 | 5 domaines obligatoires : DEV, INFRA, IA/Data, CYBER, GOUVERNANCE | 5 piliers versionnés dans le même dépôt |
| E10 | PC Hôte Windows 10/11 + Docker Desktop/WSL2, 4 cœurs / 16 Go / 50 Go | Budget RAM cible < 8 Go pour toute la stack |
| E11 | Aucune donnée, clé ou service réel | Données synthétiques, secrets *dev-only* générés localement |
| E12 | Offensif limité au SI fictif et aux machines autorisées | Cibles forcées sur le réseau du PA `192.168.137.0/24` |

---

## 2. Vue d'ensemble

```
                        PC ATTAQUANT (distinct)                    PC HÔTE (Windows + Docker Desktop / WSL2)
                        ┌───────────────────────┐                  ┌──────────────────────────────────────────────┐
                        │ redteam/ attack CLI   │                  │                                              │
                        │  - flood / inject     │   PA RESILIENCE  │            ┌──────────── EDGE ────────────┐    │
                        │  - credential stuffing│◄──G<n> 192.168.  │    :443    │  nginx + ModSecurity + CRS   │    │
                        │  - exfiltration probe │   137.0/24       │◄──────────►│  (WAF, TLS, reverse proxy)   │    │
                        │ client_paiement (lég.)│                  │            └───┬───────┬──────────┬───────┘    │
                        └───────────────────────┘                  │                │       │          │            │
                                                                   │        ┌───────▼──┐ ┌──▼──────┐ ┌─▼──────────┐ │
                                                                   │        │  web     │ │api-auth │ │api-payment │ │
                                                                   │        │ React+TW │ │ FastAPI │ │  FastAPI   │ │
                                                                   │        └──────────┘ └────┬────┘ └─────┬──────┘ │
                                                                   │                          │            │        │
                                                                   │                     ┌────▼────────────▼────┐   │
                                                                   │                     │    api-ledger        │   │
                                                                   │                     │  (double-entrée)     │   │
                                                                   │                     └──────────┬───────────┘   │
                                                                   │                                │               │
                                                                   │                     ┌──────────▼───────────┐   │
                                                                   │                     │ postgres + pgvector  │   │
                                                                   │                     └──────────────────────┘   │
                                                                   │                                                │
   ┌─────────────────────────── BOUCLE DE REMÉDIATION AUTONOME ──┴────────────────────────────────────────────────┐│
   │                                                                                                               ││
   │  ┌──────────┐  métriques  ┌──────────────┐  alertes  ┌──────────────────────┐   actions   ┌────────────────┐  ││
   │  │ Cibles   ├────────────►│ Prometheus + ├──────────►│                      │────────────►│ docker-socket- │  ││
   │  │ services │             │ Alertmanager │           │  REMEDIATION ENGINE  │             │ proxy          │  ││
   │  └──────────┘             └──────────────┘           │  1. Ingest           │             └────────────────┘  ││
   │  ┌──────────┐  logs       ┌──────────────┐           │  2. Corrèle          │   actions   ┌────────────────┐  ││
   │  │ Cibles   ├────────────►│ Loki+Promtail├───event──►│  3. Policy Engine    │────────────►│  Vault (secrets│  ││
   │  └──────────┘             └──────────────┘           │  4. Playbook exec    │             └────────────────┘  ││
   │  ┌──────────┐  syscalls   ┌──────────────┐           │  5. VÉRIFICATION e2e │   actions   ┌────────────────┐  ││
   │  │Conteneurs├────────────►│ Falco +      ├──event──►│  6. Rétablissement   │────────────►│  Ansible       │  ││
   │  └──────────┘             │ Falcosidekick│           └──────────┬───────────┘             └────────────────┘  ││
   │                           └──────────────┘                      │                                             ││
   │                           ┌──────────────┐                      │ événements + métriques                      ││
   │                           │ DETECTOR ML  ├──────────────────────┘                                             ││
   │                           │ IsolationF.  │                                                                    ││
   │                           └──────┬───────┘                                                                    ││
   │                                  │                                                                           ││
   │                           ┌──────▼───────┐   ┌──────────────┐   ┌──────────────┐                              ││
   │                           │  GRAFANA     │   │  ASSISTANT   │   │  OLLAMA      │                              ││
   │                           │  dashboards  │◄──┤  RAG         │◄──┤  LLM local   │                              ││
   │                           └──────────────┘   └──────────────┘   └──────────────┘                              ││
   └───────────────────────────────────────────────────────────────────────────────────────────────────────────────┘│
                                                                                                                    │
   └────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Découpage en services

18 conteneurs, 6 réseaux Docker cloisonnés (défense en profondeur : un conteneur
compromis ne voit que son réseau).

| # | Service | Techno | Rôle | Réseaux | RAM cible |
|---|---------|--------|------|---------|-----------|
| 1 | `edge` | nginx + ModSecurity + OWASP CRS | WAF applicatif, TLS, reverse proxy, injection de corrélation (`X-Request-ID`), blacklist dynamique d'IP | `net-edge`, `net-app` | 200 Mo |
| 2 | `web` | React 18 + Vite + Tailwind CSS, servi par nginx | SPA : `/pay` (client de paiement) et `/ops` (supervision) | `net-edge` | 60 Mo |
| 3 | `api-auth` | FastAPI (Python 3.12) | Authentification JWT, utilisateurs, MFA simulé, rate-limit par identité, révocation de tokens | `net-app`, `net-data` | 150 Mo |
| 4 | `api-payment` | FastAPI | Orchestration du paiement : validation, appel ledger, idempotence, statuts | `net-app`, `net-data` | 150 Mo |
| 5 | `api-ledger` | FastAPI | Tenue de compte en partie double, soldes, snapshots, réconciliation | `net-data` | 150 Mo |
| 6 | `postgres` | pgvector/pgvector:pg16 | SGBD relationnel + `pgvector` (RAG) | `net-data` | 400 Mo |
| 7 | `detector` | FastAPI + scikit-learn | Détection d'anomalies ML (Isolation Forest), explicabilité, score API | `net-app`, `net-obs`, `net-data` | 350 Mo |
| 8 | `remediation` | FastAPI | **Cœur du sujet** : ingestion, corrélation, policy engine, playbooks, vérification e2e, orchestration | `net-app`, `net-mgmt`, `net-data` | 250 Mo |
| 9 | `assistant` | FastAPI + LangChain | Assistant opérateur RAG (post-mortem, procédures, architecture) : **lecture seule** | `net-app`, `net-data` | 300 Mo |
| 10 | `ollama` | ollama/ollama | LLM local + modèle d'embedding | `net-app` | 2,5 Go (modèle 3B, quantifié) |
| 11 | `prometheus` | prom/prometheus | Collecte métriques, règles d'alerte | `net-obs` | 250 Mo |
| 12 | `alertmanager` | prom/alertmanager | Routage, inhibition, silences → webhook remediation | `net-obs`, `net-app` | 50 Mo |
| 13 | `loki` | grafana/loki | Centralisation des journaux | `net-obs` | 300 Mo |
| 14 | `promtail` | grafana/promtail | Agent de collecte des logs conteneurs | `net-obs`, socket Docker | 80 Mo |
| 15 | `grafana` | grafana/grafana | Dashboards supervision + SOC + remédiation | `net-obs`, `net-app` | 200 Mo |
| 16 | `falco` | falcosecurity/falco | Détection runtime (exécution suspecte, écriture hors périmètre, shell dans conteneur) | hôte (eBPF) | 150 Mo |
| 17 | `falcosidekick` | falcosecurity/falcosidekick | Fan-out des événements Falco → Loki + remediation | `net-obs`, `net-app` | 40 Mo |
| 18 | `docker-proxy` | tecnativa/docker-socket-proxy | Accès **restreint** à l'API Docker (whitelist d'endpoints) pour l'executor | `net-mgmt` | 20 Mo |
| 19 | `vault` | hashicorp/vault (mode dev) | Coffre à secrets, secrets dynamiques, rotation | `net-mgmt`, `net-app` | 100 Mo |

**Budget RAM total : ≈ 6,3 Go** → compatible avec le PC Hôte imposé (16 Go, dont
Windows + Docker Desktop). `ollama` est le seul poste lourd : il est isolé derrière
un profil Compose `ai` et peut être déporté sur le **PC de délestage IA** (voir §9).

---

## 4. Segmentation réseau

| Réseau | Type | Membres | Justification |
|--------|------|---------|---------------|
| `net-edge` | bridge | `edge`, `web` | Zone exposée. Seul `edge` publie des ports sur l'hôte. |
| `net-app` | bridge interne | `edge`, `web`, `api-*`, `remediation`, `detector`, `assistant`, `ollama`, `alertmanager`, `falcosidekick`, `grafana`, `vault` | Plan applicatif. Non routable depuis l'extérieur. |
| `net-data` | bridge interne | `api-auth`, `api-payment`, `api-ledger`, `postgres`, `detector`, `remediation`, `assistant` | Zone données. **Aucun accès Internet**, aucun service exposé. |
| `net-obs` | bridge interne | `prometheus`, `alertmanager`, `loki`, `promtail`, `grafana`, `detector`, `falcosidekick` | Plan supervision. Isolé du plan données. |
| `net-mgmt` | bridge interne | `remediation`, `docker-proxy`, `vault` | Plan d'administration privilégié. Seul `remediation` y accède. |
| `dind-socket` | volume | `docker-proxy` | Socket Docker monté **en lecture/écriture pour le proxy uniquement** ; les autres conteneurs n'y ont pas accès. |

Règle appliquée : `remediation` est le **seul** composant capable d'agir sur
l'infrastructure. Il le fait exclusivement via `docker-proxy` (endpoints filtrés)
et via les API d'administration des services. Il n'a pas d'accès direct au socket.

---

## 5. Flux nominal (chemin d'un paiement)

```
Client (PC Attaquant)                 edge(WAF)      api-payment        api-ledger      postgres
        │                                 │               │                  │              │
        │  POST /api/auth/token           │               │                  │              │
        ├────────────────────────────────►│  (CRS)        │                  │              │
        │                                 ├──► api-auth ──┼─ JWT (RS256) ────┼──────────────┤
        │◄──────────── token ─────────────┤               │                  │              │
        │                                 │               │                  │              │
        │  POST /api/payments             │               │                  │              │
        │  Authorization: Bearer …        │               │                  │              │
        │  Idempotency-Key: uuid          │               │                  │              │
        ├────────────────────────────────►│  filtrage     │                  │              │
        │                                 │  CRS + RL     ├─ vérif JWT ──────┤              │
        │                                 │               ├─ débit compte émetteur ────────►│
        │                                 │               ├─ crédit compte bénéficiaire ───►│
        │                                 │               │  (écriture double-entrée,      │
        │                                 │               │   somme des jambes = 0)        │
        │◄── 201 {payment_id, status:settled} ───────────┤                  │              │
        │                                 │               │                  │              │
```

Chaque service expose `/metrics` (Prometheus), `/healthz` (liveness), `/readyz`
(readiness) et émet des logs **JSON structurés** (`trace_id`, `service`, `event`,
`severity`) vers stdout, collectés par Promtail.

---

## 6. Chaîne de cyber-résilience (le cœur du sujet)

### 6.1 Machine à états du service

```
   ┌──────────┐   anomalie    ┌───────────┐  containment  ┌────────────┐
   │ NOMINAL  │──────────────►│ DETECTING │──────────────►│ CONTAINING │
   └──────────┘               └───────────┘               └─────┬──────┘
        ▲                                                       │
        │                                          ┌────────────▼────────────┐
        │                                          │ ERADICATING (+ rotate)  │
        │                                          └────────────┬────────────┘
        │                                                       │
        │                  ┌───────────────┐   probe OK   ┌─────▼──────┐
        │                  │  VERIFYING    │◄─────────────┤ RECOVERING │
        │                  └───┬───────┬───┘              └────────────┘
        │      probe KO        │       │  probe OK + intégrité OK
        └──────────────────────┘       ▼
              (escalade)          ┌──────────────────┐
                                  │ RECOVERED        │  → retour NOMINAL + journal
                                  └──────────────────┘
```

- **MTTD** (Mean Time To Detect) : horodatage de la première anomalie détectée
  moins le premier octet de l'attaque → mesuré par le détecteur.
- **MTTR** (Mean Time To Recover) : horodatage `NOMINAL` rétabli (après
  vérification) moins la détection → mesuré par le moteur de remédiation.

### 6.2 Boucle autonome : séquence détaillée

| Étape | Acteur | Action | Sortie observable |
|-------|--------|--------|-------------------|
| 1 | PC Attaquant | `redteam attack --scenario burst-injection` | trafic anormal sur `edge` |
| 2 | `edge` (WAF) | ModSecurity CRS bloque les requêtes signatures connues, laisse passer le volumétrique | logs `modsec` + `403` sur attaques signées |
| 3 | `promtail`/`loki`, `prometheus` | Logs et métriques agrégés | `rate(http_requests_total[1m])` ↑, `p95_latency` ↑, `error_ratio` ↑ |
| 4 | `falco` | Détecte un comportement runtime anormal si l'attaque atteint le conteneur (ex. `exec` d'un shell, lecture de `/etc/shadow`, connexion sortante inhabituelle) | événement Falco |
| 5 | `detector` (ML) | Fenêtre glissante de 60 s → vecteur de 18 features → **Isolation Forest** → score normalisé ∈ [0,1] + top-3 features contributives | `POST /score` → `{score: 0.87, anomalous: true, top_features: [...]}` |
| 6 | `prometheus` | Règle `AnomalyScoreHigh` (score > seuil calibré) déclenche | alerte → `alertmanager` |
| 7 | `alertmanager` | Route vers `remediation` (webhook) | `POST /api/ingest/alert` |
| 8 | `remediation` | Corrèle alertes + événements Falco sur une fenêtre → construit un **incident** | incident ouvert, état `DETECTING` |
| 9 | `remediation` Policy Engine | Sélectionne le playbook via politiques déclaratives (source IP, entité, sévérité, domaine) | playbook `pb-isolate-and-recover` sélectionné |
| 10 | `remediation` Executor | Exécute les étapes **sans humain** : blocage IP au WAF, révocation des tokens de la source, mise en quarantaine du conteneur suspecté, rollback si image altérée, rotation du secret exposé | ordres d'action tracés |
| 11 | `remediation` Verifier | Lance la **suite de vérification** : santé, transaction synthétique, intégrité du grand livre, contrôle que la source est bien bloquée | `recovery.json` |
| 12 | `remediation` | Si tout est OK → `RECOVERED`, publie `recovery.completed` (MTTD, MTTR, actions) sinon escalade + retour en `RECOVERING` | dashboard mis à jour |
| 13 | Client légitime | émet une **nouvelle transaction** → `201 settled` | **preuve de reprise** |

### 6.3 Garanties de non-trivialité (exigence E6)

Le moteur **refuse** de déclarer un rétablissement si l'une des conditions
suivantes est fausse : un simple `restart` échoue donc systématiquement à la
vérification :

1. `GET /healthz` + `/readyz` = 200 sur tous les services de la chaîne.
2. Descente **complète** d'une transaction synthétique
   `création → débit → crédit → règlement`.
3. **Intégrité comptable** : somme des jambes du grand livre = 0 sur la période,
   aucune transaction orpheline, aucun solde négatif non autorisé.
4. **Contrôle de confinement** : la source de l'attaque reçoit toujours `403`/`429`.
5. **Contrôle de dérive** : l'image et la configuration du conteneur remis en
   service correspondent à l'empreinte de référence (détection d'une altération
   persistante type « persistance par modification d'image »).

---

## 7. Scénarios d'attaque retenus

Trois scénarios crédibles, reproductibles, techniques et explicables. Chacun est
exécutable indépendamment et présente une réponse **différente** : c'est
précisément ce que le sujet demande de démontrer.

| ID | Scénario | Technique | Effet provoqué | Réponse attendue du système |
|----|----------|-----------|----------------|-----------------------------|
| **A1** | `burst-injection` | Rafale volumétrique (600 req/s) + injections SQLi/`UNION SELECT` et XSS sur `/api/payments` | Latence p95 ↑ ×12, taux d'erreur 5xx ↑, score d'anomalie > seuil ; CRS bloque les requêtes signées | Rate-limit adaptatif + blacklist IP au WAF + quarantaine si saturation, puis reprise |
| **A2** | `credential-stuffing` | 1 200 tentatives d'authentification sur des comptes synthétiques avec un dictionnaire de mots de passe faibles | Ratio `401` sur `/api/auth/token` ↑, entropie des identités ↑ | Révocation des tokens de la source, verrouillage temporaire des comptes ciblés, blocage IP, rotation du secret de signature si compromis |
| **A3** | `privilege-exfiltration` | Utilisation d'un token sur-privilégié pour lire des données hors périmètre (endpoint d'administration) + tentative d'exfiltration | Événement Falco (accès inhabituel), volume sortant anormal, `403` applicatif | Révocation immédiate du token, retrait des privilèges superflus, isolation du conteneur, rotation des clés, restauration depuis snapshot si données altérées |

> **A3 est le scénario retenu pour le Clip Chrono** : il est visuellement lisible
> (un token légitime qui bascule en tentative d'exfiltration), il produit un
> événement Falco exploitable, et sa remédiation touche **trois** domaines
> (CYBER, IA, INFRA) : bon terrain de démonstration.

Toutes les cibles sont **forcées** sur `192.168.137.0/24` (le PA du groupe) et
`redteam/attack.py` refuse de démarrer si la cible sort de ce préfixe ou resolve
vers une IP publique.

---

## 8. Contrats d'interface

### 8.1 Événement interne normalisé (bus léger)

Pas de broker lourd (budget RAM) : les événements transitent par webhooks HTTP
signés (HMAC-SHA256, secret Vault) et par le tableau `incident_events` en base.

```json
{
  "event_id": "uuid4",
  "occurred_at": "2026-10-19T14:03:11.412Z",
  "source": "detector|falco|prometheus|remediation|waf|api-*",
  "kind": "anomaly.detected|runtime.suspicious|alert.firing|action.executed|recovery.completed",
  "severity": "info|low|medium|high|critical",
  "trace_id": "uuid4",
  "incident_id": "uuid4|null",
  "payload": { "…": "spécifique au kind" },
  "signature": "hmac-sha256-hex"
}
```

### 8.2 Politique de remédiation (déclaratif, versionné)

```yaml
# infra/policies/01-volumetric.yaml
id: pol-volumetric-burst
priority: 100
match:
  any:
    - kind: anomaly.detected
      feature: requests_per_second
      op: ">"
      value: 300
      within: 60s
    - kind: alert.firing
      alertname: HighErrorRate
      labels: {severity: critical}
guardrails:
  max_actions_per_window: 6
  window: 300s
  dry_run: false
playbook: pb-contain-rate-limit
```

### 8.3 Playbook (unités d'exécution)

```yaml
# infra/playbooks/pb-contain-rate-limit.yaml
id: pb-contain-rate-limit
description: Confiner une source abusive puis vérifier le rétablissement
steps:
  - id: block_source
    action: waf.block_ip
    params: {ip: "${incident.source_ip}", ttl: 900}
    on_failure: continue
  - id: throttle
    action: edge.set_rate_limit
    params: {scope: "${incident.source_ip}", rps: 5}
  - id: revoke_tokens
    action: auth.revoke_by_source
    params: {source_ip: "${incident.source_ip}"}
  - id: verify
    action: verify.recovery_suite
    params: {require: [health, synthetic_tx, ledger_integrity, containment]}
    on_failure: escalate
```

### 8.4 Conventions d'API

- `/api/auth/token` : `POST`, `application/x-www-form-urlencoded` ou JSON, renvoie `{access_token, token_type, expires_in}` (JWT RS256, `kid` en en-tête).
- `/api/payments` : `POST`, en-tête `Idempotency-Key` obligatoire, renvoie `201` + `{payment_id, status, amount, currency, settled_at}`.
- `/api/payments/{id}` : `GET`, renvoie l'état du paiement.
- `/api/ledger/accounts/{id}/balance` : `GET`, réservé au rôle `service` ou `auditor`.
- `/api/ops/*` : **supervision** consommée par le dashboard, protégée par le rôle `operator`, jamais exposée sans authentification.
- Erreurs : `application/problem+json` (RFC 9457).
- Corrélation : `X-Request-ID` généré par le WAF s'il est absent, propagé par tous les services, journalisé partout.

---

## 9. Stratégie de déploiement & portabilité

### 9.1 PC Hôte (cible imposée)

Windows 10/11 + **Docker Desktop avec backend WSL2**, PA Wi-Fi *sans fil mobile*
`RESILIENCE-G<n>` (typiquement `192.168.137.1` pour le PC Hôte).

```powershell
# 1. PA mobile Windows
netsh wlan set hostednetwork mode=allow ssid=RESILIENCE-G1 key=...
# 2. WSL2 : mémoire bornée pour laisser respirer Windows
#    %UserProfile%\.wslconfig
#    [wsl2]
#    memory=10GB
#    processors=4
```

Déploiement : `docker compose --profile ai up -d --build` depuis WSL2, dans le
dépôt cloné. `scripts/preflight.ps1` / `scripts/preflight.sh` vérifient
Docker, WSL2, RAM disponible, versions et l'absence de conflits de ports.

### 9.2 PC de délestage IA (optionnel)

Si la RAM du PC Hôte est insuffisante, `ollama` est déporté : le service est
retiré du profil Compose, et `ASSISTANT_OLLAMA_BASE_URL` pointe vers
`http://<ip-pa-groupe>:11434`. Le modèle local n'est alors plus hébergé par le PC
Hôte, conformément au §4 du sujet.

### 9.3 Portabilité WAF / conteneur

- Aucune dépendance à un chemin Windows : tous les volumes sont relatifs au dépôt.
- Toutes les images sont épinglées par **digest** (`image@sha256:…`) pour la
  reproductibilité.
- `falco` nécessite le noyau de l'hôte ; en WSL2 il est lancé avec le pilote
  moderne eBPF et un `privileged: true` documenté (aucun accès hôte non borné
  au-delà du nécessaire).

### 9.4 Limite mesurée : adresse source sous Docker Desktop pour Mac

Sur la cible imposée (Windows 10/11 + Docker Desktop / WSL2, PA mobile), le PC
attaquant conserve son adresse : le poste hôte est `192.168.137.1` et l'attaquant
`192.168.137.20`, donc le confinement par adresse ne vise que l'attaquant.

Sous **Docker Desktop pour Mac**, la redirection des ports publics réécrit la
source de toute connexion entrante en `192.168.65.1`, la passerelle de la machine
virtuelle. Mesure faite sur un tir A1 depuis un poste distinct : la fenêtre du
détecteur porte **880 requêtes, toutes de `192.168.65.1`**, attaquant et
navigateur de l'opérateur confondus. Le confinement par adresse, correct dans son
principe, coupe donc les deux à la fois.

Deux conséquences assumées :

- la démonstration sur Mac perd la sélectivité du confinement ; elle la retrouve
  sur la cible Windows, où les adresses diffèrent ;
- l'opérateur confiné se libère par la route d'administration prévue pour ce cas,
  `POST /api/ops/actions/unblock`, qui reste joignable depuis une adresse bloquée
  (voir RUNBOOKS R4) ; les assertions de confinement restent vérifiables.

L'identification par la signature du banc (`User-Agent: AlphaPay-RedTeam/1.0`,
en-tête `X-Alphapay-Redteam`) existe déjà dans les journaux de bordure et
permettrait un confinement sélectif même derrière une passerelle, au prix d'un
critère de confinement qui ne serait plus l'adresse.

---

## 10. Traçabilité exigences → composants

| Exigence | Composant(s) | Livrable associé |
|----------|--------------|------------------|
| E1, E10 | `docker-compose.yml`, `frontend/`, `services/api-*` | `Code.zip`, démonstrateur |
| E2, E3, E12 | `redteam/`, PA `RESILIENCE-G<n>` | `Code.zip`, clip chrono |
| E4 | `services/detector`, `ml/train.py` | `Dossier.pdf` §IA |
| E5, E6, E7 | `services/remediation`, `infra/policies`, `infra/playbooks` | `Dossier.pdf` §Résilience, démo |
| E8 | `frontend/` `/ops`, `grafana/` | Clip chrono, démo |
| E9 | 5 piliers du dépôt | `Dossier.pdf`, `Pres.pptx` |
| E11 | `secrets/`, Vault dev, `.gitignore` | Note de conformité |
| Gouvernance | `docs/governance/` (EBIOS, PCA/PRA, NIS2/DORA) | `Dossier.pdf` §Gouvernance |

---

## 11. Décisions techniques et arbitrages (ADR condensés)

| Décision | Alternatives écartées | Raison |
|----------|----------------------|--------|
| Détection par **Isolation Forest** (scikit-learn) | Règles seuils codées en dur ; autoencodeur profond | Non supervisé (pas de jeu d'attaque étiqueté), léger (< 5 Mo), entraînable en < 2 s, explicable par écart aux features. Un autoencodeur PyTorch est fourni en variante comparative (`ml/autoencoder.py`) mais n'est pas le chemin critique. |
| **Loki** plutôt qu'Elastic Stack | ELK / OpenSearch | Le sujet exclut explicitement Elastic vu la RAM du PC Hôte ; Loki est ~10× plus léger pour un usage démonstrateur. |
| **Falco** comme capteur SOC | Wazuh (OpenSearch) | Wazuh impose un indexeur Java lourd (≥ 4 Go) ; Falco détecte le runtime conteneur en ~150 Mo et alimente Loki. |
| **Vault dev + SOPS/age** | Vault HA, cloud KMS | Pas de secret réel (E11) ; Vault dev démontre les secrets dynamiques et la rotation, SOPS chiffre les valeurs au repos dans le dépôt. |
| **pgvector** pour le RAG | Chroma, Qdrant dédié | Évite un conteneur supplémentaire ; un seul SGBD à opérer. |
| **Ollama** avec modèle ≤ 3B quantifié | API cloud (interdite, E11) | Exigence de modèle local ; tient dans le budget RAM ; API exposable au PC de délestage. |
| **Webhooks HMAC** comme bus | Kafka, RabbitMQ | Budget RAM, sobriété opérationnelle ; suffisant pour un flux d'événements de sécurité à faible débit. |
| **Blacklist IP dynamique au WAF** | iptables sur l'hôte | Ne sort pas du périmètre du PC, reproductible, ne nécessite pas de privilège hôte pour agir. |

---

## 12. Risques d'architecture et parades

| Risque | Impact | Parade |
|--------|--------|--------|
| Falco ne démarre pas sous WSL2 (noyau) | SOC runtime indisponible | Repli documenté sur la détection via Loki + règles `exec`/`file` dans Falco en mode `modern_ebpf` avec `CAP_SYS_ADMIN` ; le scénario A3 reste détectable par l'API d'audit applicative. |
| Ollama trop lent sur le PC Hôte | Assistant RAG inutilisable en démo | Profil `ai` séparé + déport sur PC de délestage + cache de réponses pré-calculées pour les 20 questions les plus probables du jury. |
| Faux positifs du détecteur sur trafic légitime | Remédiation déclenchée sans attaque | Seuil calibré au 99,5ᵉ centile de la baseline + hystérésis (`2` fenêtres consécutives) + mode `dry_run` par défaut hors démonstration. |
| Remédiation trop agressive (blocage du PC du jury) | Démo cassée | Guardrails : whitelist d'IP non bloquables (`net-mgmt`, postes coachs), `max_actions_per_window`, TTL sur tout blocage. |
| Perte de données pendant l'incident | Transaction perdue | Idempotence (`Idempotency-Key`), journal d'écriture, snapshots du grand livre + réconciliation. |

---

*Document d'architecture : v1.0 : profile `vibe`*
