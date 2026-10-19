-- =============================================================================
--  PROJECT RESILIENCE-ALPHA : AlphaPay
--  03-seed.sql : jeu de démonstration
-- =============================================================================
--  Données entièrement fictives. Aucune donnée réelle, aucune clé réelle.
--
--  Comptes créés (mot de passe communiqué dans le README, à changer) :
--    admin@alphapay.local       AlphaPay-Admin-2026!     rôle admin
--    operateur@alphapay.local   AlphaPay-Ops-2026!       rôle operator
--    client01..03@alphapay.local AlphaPay-Client-2026!   rôle customer
--
--  Les empreintes sont des argon2id (m=65536, t=3, p=2) calculées hors ligne.
--
--  Le grand livre est initialisé par une transaction de genèse équilibrée :
--  la somme des débits égale la somme des crédits, et la somme de toutes les
--  jambes vaut zéro. L'invariant comptable est donc vrai dès le départ, ce qui
--  permet à la suite de vérification de la remédiation de détecter toute
--  altération ultérieure.
-- =============================================================================

\set ON_ERROR_STOP on

BEGIN;

-- -----------------------------------------------------------------------------
--  Utilisateurs
-- -----------------------------------------------------------------------------
INSERT INTO auth.users (id, username, email, password_hash, role) VALUES
  ('00000000-0000-4000-9000-000000000001', 'admin',     'admin@alphapay.local',
   '$argon2id$v=19$m=65536,t=3,p=2$NwfXAKEp7liesYuXGFTj0g$NY7vrBEWxSM98559X2cUlRys6pi7KTH32Yori81nyE4',
   'admin'),
  ('00000000-0000-4000-9000-000000000002', 'operateur', 'operateur@alphapay.local',
   '$argon2id$v=19$m=65536,t=3,p=2$8MonXX1uLxrwDoe0PDJiLA$KymtPESgQ5+In9Y/b6FO4OhHSCR3fjMbsIsT9Z6hb6E',
   'operator'),
  ('00000000-0000-4000-9000-000000000101', 'client01',  'client01@alphapay.local',
   '$argon2id$v=19$m=65536,t=3,p=2$Al7KkpXli+0xa35VKZ9KAA$maAbCnQ6Y+5NQUfhVsX0isdzLTQBSdztMdL5rrOBsAc',
   'customer'),
  ('00000000-0000-4000-9000-000000000102', 'client02',  'client02@alphapay.local',
   '$argon2id$v=19$m=65536,t=3,p=2$Al7KkpXli+0xa35VKZ9KAA$maAbCnQ6Y+5NQUfhVsX0isdzLTQBSdztMdL5rrOBsAc',
   'customer'),
  ('00000000-0000-4000-9000-000000000103', 'client03',  'client03@alphapay.local',
   '$argon2id$v=19$m=65536,t=3,p=2$Al7KkpXli+0xa35VKZ9KAA$maAbCnQ6Y+5NQUfhVsX0isdzLTQBSdztMdL5rrOBsAc',
   'customer');

-- -----------------------------------------------------------------------------
--  Comptes du grand livre
-- -----------------------------------------------------------------------------
INSERT INTO ledger.accounts (id, owner_user_id, code, label, currency, balance_cents, status) VALUES
  ('00000000-0000-4000-8000-000000000001', NULL, 'SYS-SETTLEMENT', 'Compte de règlement système',
   'EUR', -455000, 'active'),
  ('00000000-0000-4000-8000-000000000002', NULL, 'MERCHANT-0001', 'Commerçant de démonstration',
   'EUR', 0, 'active'),
  ('00000000-0000-4000-8000-000000000101', '00000000-0000-4000-9000-000000000101',
   'CUST-000001', 'Compte client 01', 'EUR', 250000, 'active'),
  ('00000000-0000-4000-8000-000000000102', '00000000-0000-4000-9000-000000000102',
   'CUST-000002', 'Compte client 02', 'EUR', 120000, 'active'),
  ('00000000-0000-4000-8000-000000000103', '00000000-0000-4000-9000-000000000103',
   'CUST-000003', 'Compte client 03', 'EUR', 85000, 'active');

-- -----------------------------------------------------------------------------
--  Transaction de genèse : équilibrée
--      Débits   : 250000 + 120000 + 85000 = 455000
--      Crédits  : 455000 sur le compte de règlement
--      Somme de toutes les jambes = 0
-- -----------------------------------------------------------------------------
INSERT INTO ledger.transactions
  (id, idempotency_key, kind, status, amount_cents, currency, source_account, target_account, settled_at, metadata)
VALUES
  ('00000000-0000-4000-a000-000000000001', 'genesis-2026-0001', 'settlement', 'settled',
   455000, 'EUR',
   '00000000-0000-4000-8000-000000000001',
   '00000000-0000-4000-8000-000000000002',
   now(),
   '{"origin":"seed","description":"dotation initiale des comptes de demonstration"}'::jsonb);

INSERT INTO ledger.entries (transaction_id, account_id, direction, amount_cents) VALUES
  ('00000000-0000-4000-a000-000000000001', '00000000-0000-4000-8000-000000000101', 'D', 250000),
  ('00000000-0000-4000-a000-000000000001', '00000000-0000-4000-8000-000000000102', 'D', 120000),
  ('00000000-0000-4000-a000-000000000001', '00000000-0000-4000-8000-000000000103', 'D',  85000),
  ('00000000-0000-4000-a000-000000000001', '00000000-0000-4000-8000-000000000001', 'C', 455000);

-- -----------------------------------------------------------------------------
--  Journal d'audit : trace d'amorçage
-- -----------------------------------------------------------------------------
INSERT INTO auth.audit_log (actor_role, action, outcome, details) VALUES
  ('service', 'system.bootstrap', 'success',
   '{"step":"seed","note":"jeu de demonstration charge"}'::jsonb);

COMMIT;
