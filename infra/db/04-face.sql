-- =============================================================================
--  PROJECT RESILIENCE-ALPHA : AlphaPay
--  04-face.sql : gabarits faciaux et tentatives de vérification
-- =============================================================================
--  Un gabarit est la moyenne normalisée des descripteurs (128 dimensions,
--  modèle FaceNet exécuté dans le navigateur) des captures d'enrôlement d'un
--  compte. Aucune image n'est stockée, ni ici ni ailleurs : la base ne contient
--  que des vecteurs, et un vecteur ne permet pas de reconstruire un visage.
--
--  Exécuté une seule fois, par le superutilisateur, à l'initialisation du
--  volume. Le fichier est idempotent : le rejouer ne casse rien.
-- =============================================================================

CREATE TABLE IF NOT EXISTS auth.face_templates (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
  descriptor    vector(128) NOT NULL,
  capture_count INT NOT NULL DEFAULT 0 CHECK (capture_count >= 0),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index cosinus : la vérification est une recherche du plus proche voisin, et
-- c'est le même opérateur que la recherche documentaire du service assistant.
CREATE INDEX IF NOT EXISTS idx_face_templates_descriptor
  ON auth.face_templates USING hnsw (descriptor vector_cosine_ops);

-- Journal des tentatives faciales. Le verrouillage de compte est partagé avec
-- le mot de passe (auth.users.locked_until) : ce journal ajoute ce que le
-- verrouillage ne dit pas, la distance mesurée et la validité du défi actif.
CREATE TABLE IF NOT EXISTS auth.face_attempts (
  id           BIGSERIAL PRIMARY KEY,
  occurred_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id      UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  username     TEXT NOT NULL,
  outcome      TEXT NOT NULL CHECK (outcome IN ('success','failure','denied')),
  reason       TEXT,
  distance     DOUBLE PRECISION,
  threshold    DOUBLE PRECISION,
  challenge_ok BOOLEAN,
  source_ip    INET
);

CREATE INDEX IF NOT EXISTS idx_face_attempts_username
  ON auth.face_attempts (username, occurred_at DESC);

-- -----------------------------------------------------------------------------
--  Privilèges
-- -----------------------------------------------------------------------------
--  Le service d'authentification est le seul à écrire. La remédiation, la
--  supervision et le compte de lecture consultent sans pouvoir modifier.
--
--  Le type `vector` vit dans le schéma `public`, dont le bloc 1 a retiré les
--  droits par défaut. Le service d'authentification doit nommer ce type pour
--  écrire ou relire un gabarit : c'est le besoin déjà couvert pour le service de
--  recherche documentaire, accordé de la même façon. Sans ce droit, la requête
--  échoue sur « type "vector" does not exist », message qui désigne la
--  résolution du nom bien plus qu'un problème de privilège.
GRANT USAGE ON SCHEMA public TO svc_auth;

GRANT SELECT, INSERT, UPDATE, DELETE ON auth.face_templates TO svc_auth;
GRANT SELECT, INSERT ON auth.face_attempts TO svc_auth;
GRANT USAGE, SELECT ON SEQUENCE auth.face_attempts_id_seq TO svc_auth;
GRANT SELECT ON auth.face_templates, auth.face_attempts
  TO svc_remediation, monitoring, svc_readonly;
