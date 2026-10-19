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

const BASE = "";

export class ErreurApi extends Error {
  constructor(
    message: string,
    readonly statut: number,
    readonly code: string = "erreur",
  ) {
    super(message);
    this.name = "ErreurApi";
  }
}

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
    let detail = `HTTP ${reponse.status}`;
    let code = "erreur";
    try {
      const corps = await reponse.json();
      detail = corps.detail || corps.title || detail;
      code = corps.code || code;
    } catch {
      /* corps non JSON : on conserve le message d'état */
    }
    throw new ErreurApi(detail, reponse.status, code);
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

// =============================================================================
//  Types — miroir des contrats exposés par les services
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

export const api = {
  etat: () => lire<EtatSupervision>("/api/supervision/state"),
  incidents: () => lire<{ incidents: Incident[] }>("/api/supervision/incidents?limit=20"),
  incident: (id: string) => lire<DetailIncident>(`/api/supervision/incidents/${id}`),
  chronologie: () => lire<{ events: EvenementChronologie[] }>("/api/supervision/timeline?limit=200"),
  politiques: () => lire<{ policies: Politique[] }>("/api/supervision/policies"),
  fenetre: () => lire<FenetreVariables>("/api/telemetry/features/current"),
  detection: () => lire<RapportDetection>("/api/detector/score/current"),
  modele: () => lire<DescriptionModele>("/api/detector/model"),
  assistant: (question: string) =>
    ecrire<ReponseAssistant>("/api/assistant/ask", { question }, { "X-Client-Id": identifiantClient() }),
  plafonds: () =>
    lire<{ min_cents: number; max_cents: number; daily_max_cents: number }>("/api/payments/limits"),
  connexion: (username: string, password: string) =>
    ecrire<{ access_token: string; expires_in: number }>("/api/auth/token", { username, password }),
  payer: (corps: Record<string, unknown>) =>
    jetonDeSonde().then((valeur) =>
      ecrire<Paiement>("/api/payments", corps, { Authorization: `Bearer ${valeur}` }),
    ),
  historique: () =>
    jetonDeSonde().then((valeur) =>
      lire<{ transactions: Array<Record<string, unknown>> }>("/api/payments?limit=25", {
        Authorization: `Bearer ${valeur}`,
      }),
    ),
  comptes: () => lire<{ accounts: Array<Record<string, unknown>> }>("/api/ledger/accounts"),
  integrite: () =>
    lire<{ balanced: boolean; imbalance_cents: number; accounts_checked: number }>(
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

/**
 * Récupération d'un jeton de service pour la salle d'opérations.
 *
 * Le tableau de bord a besoin d'un jeton pour interroger les points d'entrée
 * authentifiés. En démonstration, il l'obtient avec le compte opérateur ; en
 * situation réelle, il utiliserait un jeton de service à durée de vie longue
 * délivré par le coffre.
 */
let jeton: string | null = null;
let expirationJeton = 0;

export async function jetonDeSonde(forcer = false): Promise<string> {
  if (!forcer && jeton !== null && Date.now() < expirationJeton) {
    return jeton;
  }
  const identifiants = identifiantsOperateur();
  const reponse = await api.connexion(identifiants.username, identifiants.password);
  jeton = reponse.access_token;
  expirationJeton = Date.now() + Math.max(30, reponse.expires_in - 60) * 1000;
  return jeton;
}

function identifiantsOperateur(): { username: string; password: string } {
  const parametres = new URLSearchParams(window.location.search);
  return {
    username: parametres.get("operateur") ?? "operateur",
    password: parametres.get("motdepasse") ?? "AlphaPay-Ops-2026!",
  };
}
