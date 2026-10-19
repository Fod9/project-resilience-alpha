# PROJECT RESILIENCE-ALPHA : Conception détaillée

> AlphaPay · Conception technique, modèles, contrats, plan de sprint
> Complément de `ARCHITECTURE.md` : v1.0

---

## 1. Modèle de données

SGBD unique : PostgreSQL 16 + `pgvector`. Quatre schémas logiques, un rôle SQL par
service (moindre privilège).

### 1.1 Rôles et cloisonnement

| Rôle SQL | Services | Droits |
|----------|----------|--------|
| `svc_auth` | api-auth | `USAGE, SELECT, INSERT, UPDATE` sur `auth.*` |
| `svc_payment` | api-payment | `SELECT, INSERT, UPDATE` sur `ledger.transactions`, `ledger.entries` ; `SELECT` sur `ledger.accounts` |
| `svc_ledger` | api-ledger | `ALL` sur `ledger.*` (sauf `DROP`) |
| `svc_detector` | detector | `INSERT` sur `ml.features` ; `SELECT` sur `ops.incident_events` |
| `svc_remediation` | remediation | `ALL` sur `ops.*` ; `SELECT` sur tout le reste |
| `svc_rag` | assistant | `SELECT` sur `rag.*` |
| `svc_readonly` | assistant (LLM) | `SELECT` uniquement, aucun `INSERT/UPDATE/DELETE` |
| `monitoring` | prometheus, grafana | `SELECT` (exporter `postgres_exporter`) |

Aucun service n'utilise le superutilisateur `postgres` en exécution.

### 1.2 Schéma `auth`

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

CREATE SCHEMA IF NOT EXISTS auth;

CREATE TABLE auth.users (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username         TEXT UNIQUE NOT NULL,
  email            TEXT UNIQUE NOT NULL,
  password_hash    TEXT NOT NULL,                        -- argon2id
  role             TEXT NOT NULL DEFAULT 'customer'
                     CHECK (role IN ('customer','service','operator','auditor','admin')),
  mfa_secret       TEXT,
  failed_attempts  INT  NOT NULL DEFAULT 0,
  locked_until     TIMESTAMPTZ,
  is_active        BOOLEAN NOT NULL DEFAULT TRUE,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth.refresh_tokens (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id        UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  token_hash     TEXT NOT NULL,                          -- sha256(token)
  source_ip      INET,
  user_agent     TEXT,
  scope          TEXT NOT NULL DEFAULT 'customer',
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  revoked_at     TIMESTAMPTZ,
  revoked_reason TEXT
);
CREATE INDEX idx_refresh_user   ON auth.refresh_tokens(user_id);
CREATE INDEX idx_refresh_source ON auth.refresh_tokens(source_ip);
CREATE INDEX idx_refresh_active ON auth.refresh_tokens(expires_at) WHERE revoked_at IS NULL;

-- Journal d'audit inaltérable en écriture applicative (append-only via privilèges)
CREATE TABLE auth.audit_log (
  id          BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor_id    UUID,
  actor_role  TEXT,
  source_ip   INET,
  action      TEXT NOT NULL,                             -- token.issue, token.revoke, login.failure…
  outcome     TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
  trace_id    UUID,
  details     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_audit_time   ON auth.audit_log(occurred_at DESC);
CREATE INDEX idx_audit_action ON auth.audit_log(action);
CREATE INDEX idx_audit_source ON auth.audit_log(source_ip);
```

**Révocation de clé de signature** : la table `auth.signing_keys` porte les paires
RS256 avec état (`active`, `retired`, `compromised`) ; `auth.rotate_signing_key`
génère une nouvelle paire et marque l'ancienne `compromised`, ce qui invalide
immédiatement tous les JWT émis : action clé du scénario A2.

```sql
CREATE TABLE auth.signing_keys (
  kid         TEXT PRIMARY KEY,
  private_pem TEXT NOT NULL,          -- chiffré par Vault transit en production
  public_pem  TEXT NOT NULL,
  state       TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('active','retired','compromised')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at  TIMESTAMPTZ
);
```

### 1.3 Schéma `ledger` (partie double)

```sql
CREATE SCHEMA IF NOT EXISTS ledger;

CREATE TABLE ledger.accounts (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id  UUID,
  code           TEXT UNIQUE NOT NULL,          -- CUST-000123, SYS-SETTLEMENT
  label          TEXT NOT NULL,
  currency       CHAR(3) NOT NULL DEFAULT 'EUR',
  balance_cents  BIGINT NOT NULL DEFAULT 0,
  status         TEXT NOT NULL DEFAULT 'active'
                   CHECK (status IN ('active','frozen','closed')),
  version        BIGINT NOT NULL DEFAULT 0,     -- verrou optimiste
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ledger.transactions (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idempotency_key  TEXT UNIQUE,
  kind             TEXT NOT NULL CHECK (kind IN ('transfer','settlement','fee','adjustment')),
  status           TEXT NOT NULL CHECK (status IN ('pending','settled','failed','reverted')),
  amount_cents     BIGINT NOT NULL CHECK (amount_cents > 0),
  currency         CHAR(3) NOT NULL,
  source_account   UUID REFERENCES ledger.accounts(id),
  target_account   UUID REFERENCES ledger.accounts(id),
  source_ip        INET,
  trace_id         UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  settled_at       TIMESTAMPTZ,
  metadata         JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_tx_created ON ledger.transactions(created_at DESC);
CREATE INDEX idx_tx_status  ON ledger.transactions(status);

CREATE TABLE ledger.entries (      -- jambes
  id             BIGSERIAL PRIMARY KEY,
  transaction_id UUID NOT NULL REFERENCES ledger.transactions(id) ON DELETE CASCADE,
  account_id     UUID NOT NULL REFERENCES ledger.accounts(id),
  direction      CHAR(1) NOT NULL CHECK (direction IN ('D','C')),
  amount_cents   BIGINT NOT NULL CHECK (amount_cents > 0),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_entries_tx      ON ledger.entries(transaction_id);
CREATE INDEX idx_entries_account ON ledger.entries(account_id);
```

**Invariant comptable** (vérifié par la suite de remédiation) :

```sql
-- 1. Chaque transaction réglée est équilibrée
SELECT t.id FROM ledger.transactions t
JOIN ledger.entries e ON e.transaction_id = t.id
WHERE t.status = 'settled'
GROUP BY t.id
HAVING SUM(CASE WHEN e.direction='D' THEN e.amount_cents ELSE -e.amount_cents END) <> 0;
-- doit renvoyer 0 ligne

-- 2. La somme des jambes de tout le grand livre est nulle
SELECT SUM(CASE WHEN direction='D' THEN amount_cents ELSE -amount_cents END)
FROM ledger.entries;  -- doit valoir 0

-- 3. Les soldes matérialisés sont cohérents avec les jambes
SELECT a.id FROM ledger.accounts a
LEFT JOIN ledger.entries e ON e.account_id = a.id
GROUP BY a.id, a.balance_cents
HAVING a.balance_cents <> COALESCE(SUM(CASE WHEN e.direction='D'
                                            THEN e.amount_cents
                                            ELSE -e.amount_cents END), 0);
-- doit renvoyer 0 ligne

-- 4. Aucune transaction orpheline (sans jambe) non annulée
SELECT id FROM ledger.transactions t
WHERE t.status IN ('settled','pending')
  AND NOT EXISTS (SELECT 1 FROM ledger.entries e WHERE e.transaction_id = t.id);
-- doit renvoyer 0 ligne
```

### 1.4 Schéma `ops` (remédiation)

```sql
CREATE SCHEMA IF NOT EXISTS ops;

CREATE TABLE ops.incidents (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reference     TEXT UNIQUE NOT NULL,            -- INC-2026-0001
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  state         TEXT NOT NULL CHECK (state IN
                  ('DETECTING','CONTAINING','ERADICATING','RECOVERING',
                   'VERIFYING','RECOVERED','FAILED','ESCALATED')),
  attack_ts     TIMESTAMPTZ,                     -- 1er octet de l'attaque (via marqueur Red Team)
  detected_ts   TIMESTAMPTZ,
  recovered_ts  TIMESTAMPTZ,
  mttd_ms       INT,
  mttr_ms       INT,
  source_ip     INET,
  playbook_id   TEXT,
  policy_id     TEXT,
  correlation   JSONB NOT NULL DEFAULT '{}'::jsonb,
  opened_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at     TIMESTAMPTZ
);
CREATE INDEX idx_inc_state ON ops.incidents(state);
CREATE INDEX idx_inc_open  ON ops.incidents(opened_at DESC);

CREATE TABLE ops.incident_events (
  id          BIGSERIAL PRIMARY KEY,
  incident_id UUID REFERENCES ops.incidents(id) ON DELETE CASCADE,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  state       TEXT,
  kind        TEXT NOT NULL,
  severity    TEXT,
  source      TEXT NOT NULL,
  trace_id    UUID,
  message     TEXT,
  payload     JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_evt_inc  ON ops.incident_events(incident_id, occurred_at);
CREATE INDEX idx_evt_time ON ops.incident_events(occurred_at DESC);

CREATE TABLE ops.actions (
  id          BIGSERIAL PRIMARY KEY,
  incident_id UUID REFERENCES ops.incidents(id) ON DELETE CASCADE,
  step_id     TEXT NOT NULL,
  action      TEXT NOT NULL,
  params      JSONB NOT NULL DEFAULT '{}'::jsonb,
  status      TEXT NOT NULL CHECK (status IN ('running','ok','failed','skipped')),
  attempt     INT NOT NULL DEFAULT 1,
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  duration_ms INT,
  result      JSONB,
  error       TEXT
);

CREATE TABLE ops.verifications (
  id          BIGSERIAL PRIMARY KEY,
  incident_id UUID REFERENCES ops.incidents(id) ON DELETE CASCADE,
  ran_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  passed      BOOLEAN NOT NULL,
  duration_ms INT,
  checks      JSONB NOT NULL                  -- [{name, passed, evidence, ms}]
);

CREATE TABLE ops.blocklist (
  id         BIGSERIAL PRIMARY KEY,
  ip         INET NOT NULL,
  reason     TEXT NOT NULL,
  incident_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  released_at TIMESTAMPTZ,
  active     BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE UNIQUE INDEX idx_block_active ON ops.blocklist(ip) WHERE active;
```

### 1.5 Schémas `ml` et `rag`

```sql
CREATE SCHEMA IF NOT EXISTS ml;
CREATE TABLE ml.features (
  id           BIGSERIAL PRIMARY KEY,
  window_start TIMESTAMPTZ NOT NULL,
  window_end   TIMESTAMPTZ NOT NULL,
  vector       JSONB NOT NULL,               -- {feature: value}
  score        DOUBLE PRECISION,
  anomalous    BOOLEAN,
  top_features JSONB,                        -- [{feature, value, z}]
  model_version TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_feat_time  ON ml.features(window_start DESC);
CREATE INDEX idx_feat_anom  ON ml.features(anomalous) WHERE anomalous;

CREATE TABLE ml.models (
  version       TEXT PRIMARY KEY,
  algo          TEXT NOT NULL,
  trained_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  n_samples     INT,
  threshold     DOUBLE PRECISION,
  hyperparams   JSONB,
  metrics       JSONB,
  feature_names JSONB NOT NULL,
  artifact_sha  TEXT
);

CREATE SCHEMA IF NOT EXISTS rag;
CREATE TABLE rag.documents (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source     TEXT UNIQUE NOT NULL,      -- chemin relatif dans le dépôt
  title      TEXT NOT NULL,
  doc_type   TEXT NOT NULL,             -- architecture|runbook|procedure|pca_pra|api|glossaire
  sha256     TEXT NOT NULL,
  ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE rag.chunks (
  id          BIGSERIAL PRIMARY KEY,
  document_id UUID NOT NULL REFERENCES rag.documents(id) ON DELETE CASCADE,
  ordinal     INT NOT NULL,
  heading     TEXT,
  content     TEXT NOT NULL,
  tokens      INT,
  embedding   vector(768)
);
CREATE INDEX idx_chunk_doc ON rag.chunks(document_id);
CREATE INDEX idx_chunk_vec ON rag.chunks USING hnsw (embedding vector_cosine_ops);
```

---

## 2. Conception du détecteur ML

### 2.1 Principe

Détection **non supervisée** : on ne dispose pas de jeu d'attaques étiqueté, et le
sujet interdit les règles codées en dur. On modélise donc la **normalité** et on
mesure l'écart.

- **Algorithme retenu** : *Isolation Forest* (`sklearn.ensemble.IsolationForest`).
  Il isole les observations par partitions aléatoires : une observation anormale
  est isolée en moins de coupures. Non supervisé, robuste en grande dimension,
  entraînement en quelques secondes, modèle sérialisé < 5 Mo, aucune GPU.
- **Variante comparative fournie** : autoencodeur dense (`ml/autoencoder.py`,
  PyTorch) : l'erreur de reconstruction sert de score. Objectif : répondre à une
  question de jury sur les alternatives, pas de chemin critique.

### 2.2 Vecteur de features (18 dimensions, fenêtre 60 s)

| # | Feature | Source | Sens de l'anomalie |
|---|---------|--------|--------------------|
| 1 | `requests_per_second` | `http_requests_total` | volumétrie ↑ |
| 2 | `error_ratio` | ratio 4xx+5xx | ↑ |
| 3 | `latency_p95_ms` | histogramme edge | ↑ |
| 4 | `latency_p99_ms` | histogramme edge | ↑ |
| 5 | `unique_source_ips` | logs edge | ↑ (distribué) ou ↓ (concentré) |
| 6 | `source_ip_entropy` | logs edge | ↓ en rafale concentrée |
| 7 | `auth_failure_ratio` | logs api-auth | ↑ |
| 8 | `auth_attempts_per_identity` | logs api-auth | ↑ (stuffing) |
| 9 | `unique_identities` | logs api-auth | ↑ |
| 10 | `injection_token_ratio` | inspection payload edge | ↑ |
| 11 | `xss_token_ratio` | inspection payload edge | ↑ |
| 12 | `avg_payload_bytes` | logs edge | ↑ |
| 13 | `payload_bytes_stddev` | logs edge | ↑ |
| 14 | `endpoint_entropy` | logs edge | ↑ (balayage) |
| 15 | `requests_per_token` | logs | ↑ |
| 16 | `outgoing_bytes_ratio` | `container_network_transmit_bytes_total` | ↑ (exfiltration) |
| 17 | `new_source_ip_ratio` | IP hors baseline | ↑ |
| 18 | `waf_block_ratio` | logs ModSecurity | ↑ |

### 2.3 Entraînement et calibration

```
python -m ml.train --baseline-minutes 60 --out ml/artifacts/model.joblib
```

1. **Génération de la baseline** : `redteam/baseline_traffic.py` produit 60 min de
   trafic **légitime** reproductible (charge de poisson λ=8 req/s, latence
   log-normale, 40 identités, 6 endpoints, 12 % d'erreurs métier normales).
2. **Agrégation** en fenêtres de 60 s → 60 vecteurs × 18 features.
3. **Standardisation** (`StandardScaler`) puis `IsolationForest(n_estimators=200,
   max_samples='auto', contamination=0.02, random_state=42)`.
4. **Score normalisé** :

   ```
   raw   = -model.decision_function(X)          # > 0 ⇒ s'éloigne de la normale
   score = 1 / (1 + exp(-k * (raw - μ_median)))  # k calibré sur la baseline
   ```
   `score ∈ [0,1]`, et `score > seuil` ⇒ anomalie.
5. **Seuil** = 99,5ᵉ centile des scores obtenus sur la baseline,
   borné à `[0.55 ; 0.85]` pour éviter un seuil dégénéré.
6. **Hystérésis** : 2 fenêtres consécutives au-dessus du seuil avant de déclencher
   (limite les faux positifs).

### 2.4 Explicabilité (« sur quelles bases le modèle distingue »)

Deux niveaux, tous deux exposés par l'API et affichés au jury :

- **Local** : pour la fenêtre courante, écart normalisé de chaque feature par
  rapport à la baseline (`z_i = (x_i − μ_i) / σ_i`) ; les 3 plus grands `|z|` sont
  renvoyés comme `top_features`. C'est l'explication montrée en direct.
- **Global** : *permutation importance* recalculée sur un jeu d'anomalies
  synthétiques (`ml/evaluate.py`) : classement des features les plus
  discriminantes, à documenter dans le dossier.

### 2.5 Robustesse

- Rejet des fenêtres creuses (< 5 requêtes) → évite les scores instables la nuit.
- Empoisonnement : la baseline est **figée** (hash SHA-256 publiée) ; aucune
  ré-écriture automatique du modèle. Fait notable pour la partie gouvernance.
- Dérive : `ml/evaluate.py` recalcule le taux de faux positifs sur 30 min de
  trafic nominal : critère de sortie du sprint J2.

### 2.6 API du détecteur

```
GET  /score/current        → {score, anomalous, top_features, window, model_version}
POST /score                → body {features:{…}} → score (usage interne/tests)
GET  /model                → {version, algo, threshold, metrics, feature_names}
POST /ingest/window        → alimente la fenêtre (appelé par un collecteur)
GET  /healthz /readyz /metrics
```

---

## 3. Conception de l'assistant RAG

### 3.1 Corpus (tout est interne au dépôt : exigence E11)

| Type | Sources |
|------|---------|
| `architecture` | `docs/ARCHITECTURE.md`, `docs/DESIGN.md` |
| `runbook` | `docs/runbooks/*.md` (un par scénario d'attaque, un par procédure d'urgence) |
| `procedure` | `docs/procedures/*.md` (exploitation, sauvegarde, rotation de secrets) |
| `pca_pra` | `docs/governance/03-pca-pra.md` |
| `api` | OpenAPI générés des services |
| `glossaire` | `docs/glossaire.md` (reprend et étend les sigles du sujet) |

### 3.2 Chaîne

```
question ──► garde-fou d'entrée ──► embedding (nomic-embed-text, 768d)
                                        │
                        pgvector : top-5 similarité cosinus + MMR
                                        │
                     prompt borné (contexte ≤ 6 000 caractères)
                                        │
                        Ollama : llama3.2:3b (quantifié Q4)
                                        │
              garde-fou de sortie ──► réponse + citations [doc#chunk]
```

- **Découpage** : 800 caractères, recouvrement 120, découpe sur frontière de titre
  ou de paragraphe ; le titre de section est conservé comme métadonnée `heading`.
- **Recherche** : `top_k=5`, puis *Maximal Marginal Relevance* (λ=0,7) pour éviter
  5 extraits quasi identiques.
- **Prompt système** (extrait) : « Tu es l'assistant d'exploitation d'AlphaPay. Tu
  réponds **uniquement** à partir du CONTEXTE fourni. Tu ne proposes jamais
  d'action offensive ni d'exécution de commande. Si le contexte ne contient pas la
  réponse, tu réponds exactement : *Je ne dispose pas de cette information dans la
  documentation du système.* Tu cites systématiquement tes sources sous la forme
  `[source#ordinal]`. »
- **Garde-fous** : question ≤ 1 000 caractères ; filtre de motifs d'injection
  (« ignore les instructions », « système », « execute », …) ; refus hors périmètre ;
  débit limité à 10 questions/min ; le compte PostgreSQL utilisé est
  `svc_readonly` (aucun droit d'écriture) ; aucun outil exposé au LLM (pas de
  *function calling*) : l'assistant ne peut **rien** déclencher.
- **Dégradation** : si Ollama est indisponible, l'API renvoie
  `503 {detail:"assistant_indisponible", retrieval_only:[…]}` avec les extraits
  pertinents : le post-mortem reste exploitable (`ASSISTANT_MODE=retrieval_only`).

### 3.3 API

```
POST /api/assistant/ask    {question} → {answer, citations[], latency_ms, model}
GET  /api/assistant/health
POST /api/assistant/reindex            (rôle operator, relance l'ingestion)
```

---

## 4. Conception du moteur de remédiation

### 4.1 Modules

| Module | Responsabilité |
|--------|----------------|
| `ingest` | Réception des webhooks signés (Alertmanager, Falcosidekick, détecteur) + validation HMAC + déduplication |
| `correlate` | Fenêtre glissante (120 s) : regroupe les signaux par `source_ip` / entité / trace en un **incident** unique |
| `policy` | Chargement des politiques YAML, évaluation des prédicats, sélection par priorité, contrôle des *guardrails* |
| `plan` | Résolution du playbook, substitution des variables `${incident.*}`, construction du plan d'exécution |
| `execute` | Exécution séquentielle, `on_failure`, retries, timeout par étape, journalisation `ops.actions` |
| `connectors/*` | Connecteurs d'action (voir §4.3) |
| `verify` | Suite de vérification (voir §4.4) |
| `state` | Machine à états, transitions, horodatage MTTD/MTTR |
| `api` | API de supervision consommée par le dashboard `/ops` |
| `metrics` | Exposition Prometheus |

### 4.2 Politiques et playbooks fournis

| ID politique | Déclencheur | Playbook | Scénario |
|--------------|-------------|----------|----------|
| `pol-volumetric-burst` | `requests_per_second > 300` ou `error_ratio > 0.25` sur 60 s | `pb-contain-rate-limit` | A1 |
| `pol-sqli-xss` | `waf_block_ratio > 0.15` + `injection_token_ratio > 0.05` | `pb-block-and-rotate` | A1 |
| `pol-auth-stuffing` | `auth_failure_ratio > 0.6` + `auth_attempts_per_identity > 20` | `pb-revoke-and-lock` | A2 |
| `pol-privilege-exfil` | événement Falco `Warning/Critical` **ou** `outgoing_bytes_ratio > 5` | `pb-isolate-and-restore` | A3 |
| `pol-data-integrity` | échec du contrôle d'intégrité du grand livre | `pb-ledger-restore` | A3 |
| `pol-fallback` | anomalie `high` sans politique spécifique | `pb-conservative-isolate` | : |

### 4.3 Journal des actions (whitelist fermée)

| Action | Connecteur | Effet | Réversible |
|--------|-----------|-------|-----------|
| `waf.block_ip` | edge admin API | ajoute l'IP à la blacklist dynamique, TTL | oui |
| `waf.unblock_ip` | edge admin API | libère l'IP | : |
| `waf.set_rate_limit` | edge admin API | limite rps par IP/route | oui |
| `auth.revoke_by_source` | api-auth admin | révoque tous les refresh tokens d'une IP source | non |
| `auth.revoke_token` | api-auth admin | révoque un token précis | non |
| `auth.lock_account` | api-auth admin | verrouille temporairement un compte ciblé | oui (TTL) |
| `auth.rotate_signing_key` | api-auth admin | nouvelle paire RS256, l'ancienne `compromised` → **invalide tous les JWT** | non |
| `docker.isolate` | docker-proxy | déconnecte un conteneur de `net-app` (quarantaine réseau) | oui |
| `docker.unisolate` | docker-proxy | reconnecte | : |
| `docker.restart` | docker-proxy | redémarre proprement | : |
| `docker.rollback` | docker-proxy | recrée le conteneur depuis l'image de référence (empreinte vérifiée) | : |
| `docker.scale` | docker-proxy | ajuste le nombre de réplicas | oui |
| `ledger.snapshot` | api-ledger admin | produit un instantané cohérent | : |
| `ledger.restore` | api-ledger admin | restaure depuis le dernier instantané sain | non |
| `ledger.reconcile` | api-ledger admin | recalcule les soldes depuis les jambes | oui |
| `ledger.freeze_account` | api-ledger admin | gèle un compte | oui |
| `vault.rotate_secret` | Vault | rotation d'un secret exposé | non |
| `ansible.run_playbook` | ansible | playbook de durcissement correctif | : |
| `notify.dashboard` | interne | publie un événement | : |
| `verify.recovery_suite` | interne | lance la vérification complète | : |
| `escalate.human` | interne | arrête l'automatisation, notifie | : |

### 4.4 Suite de vérification (cœur de l'exigence E6/E7)

| # | Contrôle | Méthode | Critère de succès |
|---|----------|---------|-------------------|
| V1 | `health` | `GET /healthz` + `/readyz` sur `edge`, `web`, `api-auth`, `api-payment`, `api-ledger` | 200 partout, < 5 s |
| V2 | `synthetic_tx` | transaction complète `auth → paiement → ledger` avec un compte de test dédié | `201 settled` et `settled_at` renseigné, < 3 s |
| V3 | `ledger_integrity` | les 4 requêtes de §1.3 | 0 ligne sur chacune |
| V4 | `containment` | rejoue une requête depuis l'IP source | `403` ou `429` |
| V5 | `config_drift` | compare l'empreinte de l'image en service à la référence (`ops.baseline_digests`) | identique |
| V6 | `auth_integrity` | aucun JWT émis par une clé `compromised` n'est accepté | `401` attendu |

**Décision** : `RECOVERED` si et seulement si V1..V6 passent. Sinon → `RECOVERING`
nouvelle tentative (max 2), puis `ESCALATED` + `escalate.human`. C'est ce qui rend
le « simple redémarrage » structurellement insuffisant : V2, V3, V4 et V5
échoueraient.

### 4.5 Guardrails

- **Liste blanche d'IP non bloquables** : `192.168.137.1` (PC Hôte), les IP des
  postes coachs, `net-mgmt`. Une tentative de blocage sur ces IP est refusée et
  journalisée.
- `max_actions_per_window` : 6 actions / 300 s (configurable par politique).
- **Coupe-circuit** : 3 échecs consécutifs d'exécution → arrêt de l'automatisation
  et escalade.
- **TTL obligatoire** sur toute action réversible (blocage : 900 s par défaut).
- `DRY_RUN=true` par défaut ; `DEMO_MODE=true` active l'exécution réelle : l'état
  est affiché en permanence sur le dashboard.
- **Audit intégral** : toute action (y compris refusée) est écrite dans
  `ops.actions` et poussée dans Loki avec le `trace_id`.

### 4.6 API du moteur

```
POST /api/ingest/alert        (HMAC) : Alertmanager
POST /api/ingest/falco        (HMAC) : Falcosidekick
POST /api/ingest/anomaly      (HMAC) : détecteur
GET  /api/incidents?state=&limit=
GET  /api/incidents/{id}      → incident + actions + vérifications + timeline
GET  /api/incidents/{id}/timeline
GET  /api/state               → {global_state, mttd_ms, mttr_ms, services[]}
GET  /api/services            → état des 18 conteneurs (via docker-proxy)
POST /api/actions/{action}    (rôle operator, hors automatisation : répétition manuelle)
POST /api/demo/run            (rôle operator : lance le scénario complet : confort de démo)
GET  /api/metrics-preview     → séries pour les graphiques du dashboard
GET  /healthz /readyz /metrics
```

---

## 5. Conception de l'edge (WAF & reverse proxy)

`nginx` + `ModSecurity v3` + **OWASP CRS 4.x**, construit depuis l'image
`owasp/modsecurity-crs` avec un gabarit de configuration maîtrisé.

### 5.1 Routage

| Chemin public | Backend | Remarque |
|---------------|---------|----------|
| `/` , `/assets`, `/pay`, `/ops`, `/login` | `web:8080` (SPA) | fallback SPA |
| `/api/auth/*` | `api-auth:8000/*` | limite 20 rps / IP |
| `/api/payments/*` | `api-payment:8000/*` | limite 50 rps / IP (durci dynamiquement) |
| `/api/ledger/*` | `api-ledger:8000/*` | rôle `service`/`auditor` requis |
| `/api/ops/*` | `remediation:8000/*` | rôle `operator` requis |
| `/api/assistant/*` | `assistant:8000/*` | limite 10 rpm |
| `/waf-admin/*` | local (endpoint interne) | réservé à `remediation` (réseau interne) |
| `/metrics` | local | **jamais** exposé à l'extérieur |

### 5.2 Règles ModSecurity

- Mode `DetectionOnly` **désactivé** en démonstration (`SecRuleEngine On`), CRS
  avec `paranoia level 1`, `anomaly scoring` en mode bloquant à partir de 5.
- Règles de rate-limit applicatives (`limit_req_zone`) par IP et par route.
- Blacklist dynamique : fichier `denylist.conf` inclus dans le serveur, rechargé
  par `nginx -s reload` déclenché par le moteur de remédiation (l'action
  `waf.block_ip` l'écrit puis recharge).
- En-têtes de sécurité : HSTS, CSP strict, `X-Content-Type-Options`,
  `Referrer-Policy`, `X-Frame-Options: DENY`.
- Injection de corrélation : `X-Request-ID` (réutilisé s'il est fourni et
  conforme), `X-Forwarded-For` maîtrisé.
- `audit_log` ModSecurity en JSON vers stdout → Loki (base de la feature
  `waf_block_ratio` et des preuves d'attaque).

### 5.3 TLS

Certificat auto-signé généré au premier démarrage (`scripts/gen-certs.sh`,
SAN `alphapay.local`, `192.168.137.1`), stocké dans `infra/certs/` (ignoré par Git).
HTTP redirige vers HTTPS. Le certificat étant interne, le client d'attaque et le
client légitime utilisent `--insecure` documenté, ou l'autorité locale importée.

---

## 6. Conception du frontend

### 6.1 Arborescence

```
frontend/
├── src/
│   ├── main.tsx  App.tsx  router.tsx
│   ├── lib/        api.ts (client typé), sse.ts (temps réel), format.ts
│   ├── design/     tokens.css, primitives (Button, Card, Badge, Sparkline…)
│   ├── features/
│   │   ├── auth/       LoginPage, useSession
│   │   ├── pay/        PayPage (montant, bénéficiaire, confirmation, historique)
│   │   └── ops/        OpsPage
│   │        ├── GlobalStateBanner.tsx
│   │        ├── ServiceGrid.tsx          (18 cartes : santé, RAM, CPU, version)
│   │        ├── MetricsPanel.tsx         (tx/s, latence p95, erreur, score ML)
│   │        ├── AnomalyPanel.tsx         (score + top-3 features explicatives)
│   │        ├── IncidentTimeline.tsx     (événements corrélés horodatés)
│   │        ├── RemediationPanel.tsx     (étapes du playbook, statut, durée)
│   │        ├── VerificationPanel.tsx    (V1..V6, pass/fail, preuves)
│   │        ├── MttrPanel.tsx            (MTTD, MTTR, historique d'incidents)
│   │        └── AssistantPanel.tsx       (chat RAG + citations)
│   └── types/  api.d.ts
├── tailwind.config.ts  vite.config.ts  index.html
└── Dockerfile  (build Vite → nginx alpine)
```

### 6.2 Temps réel

- **SSE** (`GET /api/ops/stream`) pour les événements, le score d'anomalie et les
  transitions d'état : léger, traversant WSL2 sans configuration.
- **Polling** 2 s en repli automatique si `EventSource` échoue, avec badge
  « mode dégradé » visible.
- Les 18 cartes de services proviennent de `/api/services` (docker-proxy) et
  incluent l'empreinte de version pour matérialiser le contrôle de dérive V5.

### 6.3 Narration visuelle du dashboard (ce que le jury doit comprendre en 10 s)

1. **Bandeau** plein largeur : état global + durée de l'incident + compteurs.
2. **Colonne gauche** : services (un rouge = l'incident se voit).
3. **Centre-haut** : 4 courbes : tx/s (baisse), latence p95 (pic), taux d'erreur
   (pic), score d'anomalie (franchissement du seuil, ligne pointillée).
4. **Centre-bas** : timeline verticale des événements, du premier signal à
   `recovery.completed`, avec l'origine de chaque signal (ML / Falco / WAF / alerte).
5. **Colonne droite** : étapes du playbook qui se cochent en direct, puis les 6
   contrôles de vérification (V1..V6) qui passent au vert.
6. **Bandeau bas** : MTTD / MTTR + bouton de relance du scénario + chat RAG.

### 6.4 Direction artistique

Thème sombre « salle d'opérations », une seule couleur d'accent, vert/ambre/rouge
réservés exclusivement à la sémantique d'état (pas de décoration colorée).
Typographie : une seule famille sans-serif, deux graisses ; chiffres tabulaires
obligatoires pour les métriques. Aucun dégradé superflu : la lisibilité prime -
un jury doit lire l'état à trois mètres. Maquettes Figma avant intégration.

---

## 7. Observabilité

| Élément | Contenu |
|---------|---------|
| `prometheus/rules/alphaplat.yml` | 9 règles : `AnomalyScoreHigh`, `HighErrorRate`, `LatencyP95High`, `ServiceDown`, `LedgerIntegrityFailed`, `RecoveryTooSlow`, `FalcoRuntimeAlert`, `WafBlockSpike`, `AuthFailureSpike` |
| `grafana/dashboards/01-supervision.json` | vue d'ensemble des 18 services |
| `grafana/dashboards/02-resilience.json` | MTTD/MTTR, score ML, timeline, historique d'incidents |
| `grafana/dashboards/03-soc.json` | événements Falco, décisions WAF, authentifications refusées |
| `grafana/dashboards/04-metier.json` | tx/s, montants, soldes, latence métier |
| Métriques custom | `remediation_actions_total`, `remediation_action_duration_seconds`, `remediation_incidents_total`, `remediation_mttr_seconds`, `remediation_mttd_seconds`, `detector_anomaly_score`, `detector_false_positive_total`, `ledger_integrity_ok`, `waf_blocked_requests_total` |
| Loki | tous les journaux JSON structurés + `audit_log` ModSecurity |
| Falco | détection runtime : `Terminal shell in container`, `Read sensitive file untrusted`, `Unexpected outbound connection`, `Write below monitored dir` |

---

## 8. Sécurité : conception

### 8.1 Durcissement des conteneurs

- Images distroless/slim, utilisateur non-root (`USER 10001`), système de fichiers
  racine en `read_only: true` + `tmpfs` pour les écritures.
- `cap_drop: [ALL]`, ajout minimal et justifié (Falco uniquement).
- `security_opt: [no-new-privileges:true]`, `restart: unless-stopped`.
- Limites `mem_limit`/`cpus` par service, `pids_limit`.
- Aucun port publié hormis `443` (edge) et `3000`/`9090` en profil `ops-ui`.
- Healthchecks stricts sur tous les services.

### 8.2 Secrets

| Niveau | Mécanisme |
|--------|-----------|
| Au repos dans le dépôt | `sops` + `age` : `secrets/*.enc.yaml` chiffrés, la clé `age` n'est **pas** versionnée |
| Au démarrage | Vault (mode dev, scellé au plus juste) seed depuis `secrets/*.enc.yaml` |
| En mémoire | injection par variables d'environnement, jamais par arguments de ligne de commande |
| Rotation | action `vault.rotate_secret` appelée par le moteur de remédiation après un incident |
| Interdits | `.env` réel, `.pem`, `id_rsa`, jetons : tous dans `.gitignore`, plus un hook `pre-commit` `gitleaks` |

### 8.3 Contrôle d'accès

- JWT RS256, durée 15 min, refresh en base révocable, `jti` journalisé.
- RBAC : `customer` (paiement), `service` (grand livre), `operator` (supervision et
  remédiation), `auditor` (lecture), `admin` (configuration).
- Rate-limiting à trois niveaux : nginx (`limit_req`), applicatif (par identité),
  dynamique (par IP, durci par la remédiation).
- Vérification d'idempotence obligatoire sur la création de paiement.

### 8.4 Red Team

- `redteam/attack.py` : CLI `argparse`, scénarios `A1|A2|A3|baseline|all`,
  `--target` obligatoire, **refus de démarrer** si la cible sort de
  `192.168.137.0/24` ou resolve vers une IP publique, `--confirm-authorized` requis.
- Marqueur d'horodatage : la première requête envoie un en-tête
  `X-RedTeam-Marker: <uuid>` capté par l'edge et transmis au moteur → permet de
  calculer un MTTD honnête (du premier octet, pas de la détection).
- Les scripts sont **bornés** : durée maximale, nombre de requêtes maximal, arrêt
  automatique, aucun déni de service persistant.

---

## 9. Plan de sprint (4 jours) et critères de sortie

| Jour | Objectif | Travaux | **Critère de sortie vérifiable** |
|------|----------|---------|----------------------------------|
| **J1** | Socle opérationnel | Compose + réseaux, edge/WAF, `api-auth`, `api-payment`, `api-ledger`, `postgres`, SPA `/pay`, observabilité minimale | Une transaction aboutit de bout en bout via `https://192.168.137.1/api/payments` ; les métriques des 3 services sont visibles dans Grafana |
| **J2** | Cybersécurité + IA | Durcissement, Vault/SOPS, Falco, détecteur ML entraîné et calibré, scripts `A1`/`A2` | L'attaque A1 fait franchir le seuil au score ML en **< 60 s** ; 0 faux positif sur 30 min de trafic nominal ; Falco remonte ≥ 1 événement sur A3 |
| **J3** | Résilience | Moteur de remédiation, politiques, playbooks, suite de vérification, dashboard `/ops` | **Reprise autonome prouvée 10 fois de suite sur A1 et A2** (V1..V6 vertes, MTTR < 180 s), aucun humain sollicité |
| **J4** | Consolidation & livrables | Scénario A3 complet, assistant RAG, gouvernance (EBIOS, PCA/PRA, NIS2/DORA), dossier, présentation, clip chrono | `Dossier.pdf` (≤ 8 pages), `Pres.pptx`, `VidChrono.mp4` (≤ 90 s, plan continu), `Code.zip` ; répétition générale < 12 min |
| **J5** | Jury local (vendredi) | Soutenance | Démonstration live + Q/R technique |

### Objectifs de service (SLO) mesurés

| Indicateur | Cible | Mesure |
|-----------|-------|--------|
| MTTD | < 60 s | détecteur (`attack_ts` → `detected_ts`) |
| MTTR | < 180 s | remédiation (`detected_ts` → `recovered_ts`) |
| Taux de reprise autonome | 100 % sur 10 exécutions | `ops.incidents` où `state='RECOVERED'` |
| Faux positifs | 0 sur 30 min nominal | `ml.features` sur trafic légitime |
| Intégrité comptable post-incident | 100 % | V3 |
| Transactions perdues | 0 | comparaison avant/après sur compte de test |

---

## 10. Arborescence cible du dépôt

```
resilience-alpha/
├─ docker-compose.yml  docker-compose.override.yml.example  .env.example
├─ Makefile  README.md  LICENSE  .gitignore  .sops.yaml
├─ docs/
│  ├─ ARCHITECTURE.md  DESIGN.md  glossaire.md
│  ├─ runbooks/      (A1, A2, A3, incident générique, rotation de secrets)
│  ├─ procedures/    (exploitation, sauvegarde, restauration, astreinte)
│  └─ governance/    (01-ebios-rm, 02-pca-pra, 03-nis2-dora, 04-arbitrages, 05-registre-risques)
├─ infra/
│  ├─ edge/          (nginx.conf, templates, crs config, denylist)
│  ├─ prometheus/    (prometheus.yml, rules/)
│  ├─ grafana/       (provisioning/, dashboards/)
│  ├─ loki/ promtail/ alertmanager/ falco/
│  ├─ policies/      (*.yaml)
│  ├─ playbooks/     (*.yaml)
│  ├─ ansible/       (inventaire, playbooks de déploiement et de durcissement)
│  └─ db/            (01-schema.sql, 02-seed.sql, 03-roles.sql)
├─ services/
│  ├─ api-auth/ api-payment/ api-ledger/ remediation/ detector/ assistant/
│  └─ common/        (lib partagée : logs JSON, auth, erreurs RFC 9457, HMAC)
├─ ml/               (features.py, train.py, evaluate.py, serve.py, autoencoder.py, artifacts/)
├─ frontend/
├─ redteam/          (attack.py, baseline_traffic.py, scenarios/, README.md)
├─ scripts/          (preflight.sh/.ps1, gen-certs.sh, seed-secrets.sh, demo.sh, verify.sh)
├─ tests/            (unit/, integration/, resilience/, e2e/)
└─ deliverables/     (Dossier.pdf, Pres.pptx, VidChrono.mp4, Code.zip)
```

---

*Document de conception : v1.0*
