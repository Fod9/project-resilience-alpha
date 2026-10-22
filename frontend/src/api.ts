/**
 * Client d'API de l'interface AlphaPay.
 *
 * Toutes les requêtes passent par la bordure : l'interface ne connaît aucune
 * adresse interne, ce qui garantit que le WAF voit l'intégralité du trafic et
 * que la démonstration s'exécute sur le chemin réel d'un client.
 *
 * Aucune donnée n'est mise en cache : la salle d'opérations doit refléter
 * l'instant présent, une valeur vieille de quelques secondes n'a pas de sens
 * pendant un incident.
 */

import { ErreurApi, analyserErreur } from "./erreurs";
import type { PolitiqueFaciale } from "./face";
import { requeteAutorisee } from "./session";

export { ErreurApi };

const BASE = "";

async function requete<T>(chemin: string, init?: RequestInit): Promise<T> {
  const reponse = await fetch(`${BASE}${chemin}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
    cache: "no-store",
  });

  if (!reponse.ok) {
    throw await analyserErreur(reponse);
  }

  if (reponse.status === 204) {
    return undefined as T;
  }
  return (await reponse.json()) as T;
}

export const lire = <T>(chemin: string, entetes?: Record<string, string>): Promise<T> =>
  requete<T>(chemin, entetes ? { headers: entetes } : undefined);

export const ecrire = <T>(chemin: string, corps: unknown, entetes?: Record<string, string>) =>
  requete<T>(chemin, { method: "POST", body: JSON.stringify(corps), headers: entetes });

async function requeteAutoriseeJson<T>(chemin: string, init?: RequestInit): Promise<T> {
  const reponse = await requeteAutorisee(chemin, init);
  if (!reponse.ok) {
    throw await analyserErreur(reponse);
  }
  if (reponse.status === 204) {
    return undefined as T;
  }
  return (await reponse.json()) as T;
}

/**
 * Appels authentifiés par la session de l'opérateur connecté.
 *
 * Le jeton n'est jamais posé à la main ici : il vient de `session.ts`, qui le
 * renouvelle et le remplace lorsqu'il a été révoqué. C'est la seule façon
 * d'éviter qu'un écran continue de fonctionner avec un jeton que le moteur de
 * remédiation vient pourtant d'invalider.
 */
export const autorise = {
  lire: <T,>(chemin: string) => requeteAutoriseeJson<T>(chemin),
  ecrire: <T,>(chemin: string, corps: unknown, entetes?: Record<string, string>) =>
    requeteAutoriseeJson<T>(chemin, {
      method: "POST",
      body: JSON.stringify(corps),
      headers: entetes,
    }),
};

// =============================================================================
//  Types : miroir des contrats exposés par les services
// =============================================================================

export type EtatGlobal = "NOMINAL" | "INCIDENT" | "RECOVERED" | "FAILED";

export interface Incident {
  id: string;
  state: string;
  severity: string;
  title: string;
  opened_at: string;
  closed_at: string | null;
  source_ip: string | null;
  mttd_ms: number | null;
  mttr_ms: number | null;
  playbook_id: string | null;
}

export interface EtatSupervision {
  state: EtatGlobal;
  suspended: boolean;
  dry_run: boolean;
  consecutive_failures: number;
  actions_in_window: number;
  action_limit: number;
  incident: Incident | null;
  targets: { mttd_seconds: number; mttr_seconds: number };
  /** Contenu réellement chargé par le moteur : politiques, playbooks et
   *  actions autorisées. Affiché tel quel, jamais figé dans l'interface. */
  registry?: { policies: number; playbooks: number; allowed_actions: number };
}

export interface EvenementChronologie {
  occurred_at: string;
  incident_id: string | null;
  state: string | null;
  kind: string;
  severity: string | null;
  source: string;
  message: string | null;
  payload: Record<string, unknown>;
}

export interface DetailIncident {
  incident: Incident & { summary?: Record<string, unknown> };
  events: EvenementChronologie[];
  actions: Array<{
    step_id: string;
    action: string;
    /** Phase du playbook a laquelle appartient cette etape (CONTAINING,
     *  ERADICATING, RECOVERING, VERIFYING). Permet d'afficher jusqu'ou la
     *  reprise est allee, meme lorsque l'incident finit en FAILED. */
    phase?: string;
    status: string;
    duration_ms: number | null;
    result: Record<string, unknown> | null;
    error: string | null;
    started_at: string;
  }>;
  verifications: Array<{
    ran_at: string;
    passed: boolean;
    duration_ms: number;
    checks: Array<{ name: string; passed: boolean; duration_ms: number; evidence: Record<string, unknown> }>;
  }>;
}

export interface FenetreVariables {
  window_start: string;
  window_end: string;
  window_seconds: number;
  events_in_window: number;
  features: Record<string, number>;
  diagnostics?: {
    dominant_source_ip?: string;
    top_source_ips?: Array<{ value: string; count: number }>;
    top_paths?: Array<{ value: string; count: number }>;
    source_ips_distinctes?: number;
  };
}

export interface RapportDetection {
  detected_at: string;
  score: number;
  threshold: number;
  exceedance: number;
  anomalous: boolean;
  consecutive_windows: number;
  top_features: Array<{ feature: string; value: number; baseline_mean: number; z: number }>;
  suspected_target: string;
  suspected_source_ip: string;
  model_version: string | null;
  rules_used: boolean;
}

export interface DescriptionModele {
  loaded: boolean;
  version: string | null;
  algorithm: string;
  features: string[];
  threshold: number | null;
  threshold_quantile: number | null;
  trained_windows: number | null;
  nominal_detection_rate_pct: number | null;
  importances: Record<string, number> | null;
  consecutive_windows_required: number;
  anomaly_active: boolean;
  rules_used: boolean;
}

export interface Politique {
  id: string;
  title: string;
  severity: string;
  priority: number;
  conditions: string[];
  playbook: string;
  cooldown_seconds: number;
}

export interface Paiement {
  payment_id: string;
  status: string;
  amount_cents: number;
  currency: string;
  source_account: string;
  destination_account: string;
  reference: string;
  created_at: string;
  /** Vrai lorsque la transaction existait déjà : la demande a été rejouée sans
   *  créer de doublon, grâce à la clé d'idempotence. */
  idempotent_replay?: boolean;
}

export interface ReponseAssistant {
  answer: string;
  citations: Array<{ label: string; source: string; heading: string; similarity: number }>;
  model: string;
  elapsed_ms: number;
  refused: boolean;
}

// =============================================================================
//  Points d'entrée
// =============================================================================

export interface ServiceEtat {
  /** Nom du service, tel qu'il figure dans le rail. */
  nom: string;
  /** Nom du conteneur inspecte. */
  conteneur: string;
  /** Santé rapportée par le démon : lecture directe, jamais écrite en dur. */
  sante: "ok" | "degrade" | "indisponible" | "inconnu";
  detail: string;
}

export const api = {
  etat: () => autorise.lire<EtatSupervision>("/api/supervision/state"),
  services: () => autorise.lire<{ count: number; services: ServiceEtat[] }>("/api/supervision/services"),
  incidents: () => autorise.lire<{ incidents: Incident[] }>("/api/supervision/incidents?limit=20"),
  incident: (id: string) => autorise.lire<DetailIncident>(`/api/supervision/incidents/${id}`),
  chronologie: () =>
    autorise.lire<{ events: EvenementChronologie[] }>("/api/supervision/timeline?limit=200"),
  politiques: () => autorise.lire<{ policies: Politique[] }>("/api/supervision/policies"),
  fenetre: () => autorise.lire<FenetreVariables>("/api/telemetry/features/current"),
  detection: () => autorise.lire<RapportDetection>("/api/detector/score/current"),
  modele: () => autorise.lire<DescriptionModele>("/api/detector/model"),
  assistant: (question: string) =>
    autorise.ecrire<ReponseAssistant>(
      "/api/assistant/ask",
      { question },
      { "X-Client-Id": identifiantClient() },
    ),
  plafonds: () =>
    lire<{ min_cents: number; max_cents: number; daily_max_cents: number }>("/api/payments/limits"),
  payer: (corps: Record<string, unknown>) => autorise.ecrire<Paiement>("/api/payments", corps),
  historique: () =>
    autorise.lire<{ transactions: Array<Record<string, unknown>> }>("/api/payments?limit=25"),
  face: {
    /** Paramètres publics du contrôle facial : le seuil et le défi ne sont pas
     *  écrits dans l'interface, ils sont lus ici. */
    politique: () => lire<PolitiqueFaciale>("/api/auth/face/policy"),
    statut: (username: string) =>
      autorise.lire<StatutGabarit>(`/api/auth/face/status/${encodeURIComponent(username)}`),
    enroler: (username: string, descriptors: number[][]) =>
      autorise.ecrire<{ username: string; captures: number; updated_at: string }>(
        "/api/auth/face/enroll",
        { username, descriptors },
      ),
  },
  comptes: () => autorise.lire<{ accounts: Array<Record<string, unknown>> }>("/api/ledger/accounts"),
  integrite: () =>
    autorise.lire<{ balanced: boolean; imbalance_cents: number; accounts_checked: number }>(
      "/api/ledger/integrity",
    ),
};

/** Identifiant d'onglet : il ne sert qu'à répartir la limitation de débit de
 *  l'assistant entre les navigateurs du jury. */
function identifiantClient(): string {
  const cle = "alphapay-client-id";
  let valeur = sessionStorage.getItem(cle);
  if (valeur === null) {
    valeur = Math.random().toString(36).slice(2, 12);
    sessionStorage.setItem(cle, valeur);
  }
  return valeur;
}

/** Statut du gabarit facial d'un compte, tel que le renvoie le service. */
export interface StatutGabarit {
  username: string;
  enrolled: boolean;
  captures: number;
  updated_at: string | null;
  dimension: number;
  threshold: number;
  min_samples: number;
  challenge_min_turn_deg: number;
}
