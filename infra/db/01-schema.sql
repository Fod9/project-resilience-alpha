-- =============================================================================
--  PROJECT RESILIENCE-ALPHA : AlphaPay
--  01-schema.sql : création des schémas et des tables
-- =============================================================================
--  Transcription de `docs/DESIGN.md` sections 1.2 à 1.5.
--  Exécuté une seule fois, par le superutilisateur, à l'initialisation du
--  volume de données. Aucun rôle applicatif ne dispose du superutilisateur :
--  les droits sont accordés dans 02-roles.sh.
-- =============================================================================

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

-- -----------------------------------------------------------------------------
--  Schéma `auth` : identités, jetons, clés de signature, journal d'audit
-- -----------------------------------------------------------------------------
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

-- Paires RS256 : `auth.rotate_signing_key` marque l'ancienne `compromised`,
-- ce qui invalide immédiatement tous les JWT émis (scénario A2).
CREATE TABLE auth.signing_keys (
  kid         TEXT PRIMARY KEY,
  private_pem TEXT NOT NULL,          -- chiffré par Vault transit en production
  public_pem  TEXT NOT NULL,
  state       TEXT NOT NULL DEFAULT 'active'
                CHECK (state IN ('active','retired','compromised')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  retired_at  TIMESTAMPTZ
);

-- -----------------------------------------------------------------------------
--  Schéma `ledger` : comptes, transactions, jambes (partie double)
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
--  Schéma `ops` : incidents, journal d'événements, actions, vérifications
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS ops;

CREATE TABLE ops.incidents (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  reference     TEXT UNIQUE NOT NULL,            -- INC-2026-0001
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  state         TEXT NOT NULL CHECK (state IN
                  ('DETECTING','CONTAINING','ERADICATING','RECOVERING',
                   'VERIFYING','RECOVERED','FAILED','ESCALATED')),
  attack_ts     TIMESTAMPTZ,                     -- 1er octet de l'attaque (marqueur Red Team)
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
  id          BIGSERIAL PRIMARY KEY,
  ip          INET NOT NULL,
  reason      TEXT NOT NULL,
  incident_id UUID,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at  TIMESTAMPTZ,
  released_at TIMESTAMPTZ,
  active      BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE UNIQUE INDEX idx_block_active ON ops.blocklist(ip) WHERE active;

-- -----------------------------------------------------------------------------
--  Schémas `ml` (features, modèles) et `rag` (corpus documentaire)
-- -----------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS ml;

CREATE TABLE ml.features (
  id            BIGSERIAL PRIMARY KEY,
  window_start  TIMESTAMPTZ NOT NULL,
  window_end    TIMESTAMPTZ NOT NULL,
  vector        JSONB NOT NULL,               -- {feature: value}
  score         DOUBLE PRECISION,
  anomalous     BOOLEAN,
  top_features  JSONB,                        -- [{feature, value, z}]
  model_version TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_feat_time ON ml.features(window_start DESC);
CREATE INDEX idx_feat_anom ON ml.features(anomalous) WHERE anomalous;

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
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source      TEXT UNIQUE NOT NULL,      -- chemin relatif dans le dépôt
  title       TEXT NOT NULL,
  doc_type    TEXT NOT NULL,             -- architecture|runbook|procedure|pca_pra|api|glossaire
  sha256      TEXT NOT NULL,
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
