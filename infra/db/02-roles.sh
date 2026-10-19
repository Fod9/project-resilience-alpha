#!/bin/bash
# =============================================================================
#  PROJECT RESILIENCE-ALPHA — AlphaPay
#  02-roles.sh — rôles applicatifs et cloisonnement des privilèges
# =============================================================================
#  Un rôle par service, aucun superutilisateur en exécution. Les mots de passe
#  proviennent de l'environnement du conteneur et ne sont jamais écrits dans un
#  fichier : ils sont transmis à psql via des variables, ce qui évite toute
#  interpolation directe dans le texte SQL.
#
#  Ce script est le seul endroit du dépôt où l'ensemble des mots de passe de
#  rôles est visible simultanément. Il s'exécute une fois, à l'initialisation.
# =============================================================================

set -e

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$ALPHAPAY_DB_NAME" \
     -v db_name="$ALPHAPAY_DB_NAME" \
     -v auth_pw="$SVC_AUTH_PASSWORD" \
     -v payment_pw="$SVC_PAYMENT_PASSWORD" \
     -v ledger_pw="$SVC_LEDGER_PASSWORD" \
     -v detector_pw="$SVC_DETECTOR_PASSWORD" \
     -v remediation_pw="$SVC_REMEDIATION_PASSWORD" \
     -v rag_pw="$SVC_RAG_PASSWORD" \
     -v readonly_pw="$SVC_READONLY_PASSWORD" \
     -v monitoring_pw="$MONITORING_PASSWORD" <<'EOSQL'
-- ---------------------------------------------------------------------------
--  1. Retrait des droits par défaut sur le schéma public
-- ---------------------------------------------------------------------------
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db_name" TO postgres;

-- L'extension pgvector s'installe dans `public`. Un rôle ...[truncated]

-- ---------------------------------------------------------------------------
--  2. Création des rôles
-- ---------------------------------------------------------------------------
CREATE ROLE svc_auth        LOGIN PASSWORD :'auth_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 30;
CREATE ROLE svc_payment     LOGIN PASSWORD :'payment_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 40;
CREATE ROLE svc_ledger      LOGIN PASSWORD :'ledger_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 30;
CREATE ROLE svc_detector    LOGIN PASSWORD :'detector_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10;
CREATE ROLE svc_remediation LOGIN PASSWORD :'remediation_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;
CREATE ROLE svc_rag         LOGIN PASSWORD :'rag_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10;
-- svc_readonly : utilisé par l'assistant pour la lecture du corpus au moment
-- de la requête. Aucun droit d'écriture : une injection de prompt ne peut pas
-- modifier la base.
CREATE ROLE svc_readonly    LOGIN PASSWORD :'readonly_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20;
-- monitoring : provisionné pour l'exportateur PostgreSQL optionnel.
CREATE ROLE monitoring      LOGIN PASSWORD :'monitoring_pw'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 10;

GRANT CONNECT ON DATABASE :"db_name" TO
  svc_auth, svc_payment, svc_ledger, svc_detector,
  svc_remediation, svc_rag, svc_readonly, monitoring;

-- ---------------------------------------------------------------------------
--  3. Délais de garde : une requête ne peut pas immobiliser une connexion
-- ---------------------------------------------------------------------------
DO $$
DECLARE r TEXT;
BEGIN
  FOREACH r IN ARRAY ARRAY['svc_auth','svc_payment','svc_ledger','svc_detector',
                           'svc_remediation','svc_rag','svc_readonly','monitoring']
  LOOP
    EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', r, '10s');
    EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', r, '3s');
    EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', r, '15s');
  END LOOP;
END
$$;

-- ---------------------------------------------------------------------------
--  4. Privilèges — schéma `auth`
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA auth TO svc_auth, svc_remediation, monitoring, svc_readonly;
GRANT SELECT, INSERT, UPDATE ON auth.users, auth.refresh_tokens TO svc_auth;
GRANT SELECT, INSERT ON auth.signing_keys TO svc_auth;
GRANT UPDATE (state, retired_at) ON auth.signing_keys TO svc_auth;
GRANT USAGE, SELECT ON SEQUENCE auth.audit_log_id_seq TO svc_auth;
GRANT SELECT, INSERT ON auth.audit_log TO svc_auth;
GRANT SELECT ON ALL TABLES IN SCHEMA auth TO svc_remediation, monitoring, svc_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA auth
  GRANT SELECT ON TABLES TO svc_remediation, monitoring, svc_readonly;

-- ---------------------------------------------------------------------------
--  5. Privilèges — schéma `ledger`
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA ledger TO svc_ledger, svc_payment, svc_remediation, monitoring, svc_readonly;
GRANT ALL ON ALL TABLES IN SCHEMA ledger TO svc_ledger;
GRANT ALL ON ALL SEQUENCES IN SCHEMA ledger TO svc_ledger;
GRANT SELECT, INSERT, UPDATE ON ledger.transactions, ledger.entries TO svc_payment;
GRANT SELECT ON ledger.accounts TO svc_payment;
GRANT USAGE, SELECT ON SEQUENCE ledger.entries_id_seq TO svc_payment;
GRANT SELECT ON ALL TABLES IN SCHEMA ledger TO svc_remediation, monitoring, svc_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ledger
  GRANT SELECT ON TABLES TO svc_remediation, monitoring, svc_readonly;

-- ---------------------------------------------------------------------------
--  6. Privilèges — schéma `ops`
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA ops TO svc_remediation, svc_detector, monitoring, svc_readonly;
GRANT ALL ON ALL TABLES IN SCHEMA ops TO svc_remediation;
GRANT ALL ON ALL SEQUENCES IN SCHEMA ops TO svc_remediation;
GRANT SELECT ON ops.incident_events TO svc_detector;
GRANT SELECT ON ALL TABLES IN SCHEMA ops TO monitoring, svc_readonly;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ops
  GRANT ALL ON TABLES TO svc_remediation;

-- ---------------------------------------------------------------------------
--  7. Privilèges — schémas `ml` et `rag`
-- ---------------------------------------------------------------------------
GRANT USAGE ON SCHEMA ml TO svc_detector, svc_remediation, monitoring, svc_readonly;
GRANT SELECT, INSERT, UPDATE ON ml.features, ml.models TO svc_detector;
GRANT USAGE, SELECT ON SEQUENCE ml.features_id_seq TO svc_detector;
GRANT SELECT ON ALL TABLES IN SCHEMA ml TO svc_remediation, monitoring, svc_readonly;

GRANT USAGE ON SCHEMA rag TO svc_rag, svc_readonly, monitoring, svc_remediation;
GRANT SELECT, INSERT, UPDATE, DELETE ON rag.documents, rag.chunks TO svc_rag;
GRANT USAGE, SELECT ON SEQUENCE rag.chunks_id_seq TO svc_rag;
GRANT SELECT ON rag.documents, rag.chunks TO svc_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA rag TO monitoring, svc_remediation;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA ml
  GRANT SELECT ON TABLES TO svc_remediation, monitoring, svc_readonly;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA rag
  GRANT SELECT ON TABLES TO svc_readonly, monitoring, svc_remediation;
EOSQL

echo "[02-roles] roles applicatifs et privileges appliques"
