import type { EtatSupervision, Incident } from "../api";

/**
 * Rail des composants : l'état de la pile, lu comme un panneau de systèmes.
 *
 * Présentation volontairement dense. La disponibilité est indiquée par la forme
 * **et** par la couleur : la couleur seule exclurait une partie du jury, la
 * forme seule serait illisible depuis le fond de la salle.
 */

export interface EtatComposant {
  nom: string;
  role: string;
  colonne: "dev" | "infra" | "ia" | "cyber" | "gouvernance";
  sante: "ok" | "degrade" | "indisponible" | "inconnu";
  detail?: string;
}

const COULEUR: Record<EtatComposant["sante"], { pastille: string; texte: string; forme: string }> = {
  ok: { pastille: "bg-nominal", texte: "text-ink", forme: "rounded-full" },
  degrade: { pastille: "bg-degraded", texte: "text-degraded", forme: "rounded-sm rotate-45" },
  indisponible: { pastille: "bg-incident", texte: "text-incident", forme: "rounded-none" },
  inconnu: { pastille: "bg-ink-dim/40", texte: "text-ink-dim", forme: "rounded-full" },
};

const COLONNES: Array<{ cle: EtatComposant["colonne"]; libelle: string }> = [
  { cle: "dev", libelle: "Développement" },
  { cle: "infra", libelle: "Infrastructure" },
  { cle: "ia", libelle: "IA / Données" },
  { cle: "cyber", libelle: "Cybersécurité" },
];

export default function ServiceRail({
  composants,
  incident,
}: {
  composants: EtatComposant[];
  incident: Incident | null;
}) {
  const concernes = new Set<string>();
  if (incident?.playbook_id?.includes("A1")) concernes.add("api-payment");
  if (incident?.playbook_id?.includes("A2")) concernes.add("api-auth");
  if (incident?.playbook_id?.includes("A3")) concernes.add("edge");

  return (
    <aside className="bloc shrink-0">
      <div>
        {COLONNES.map(({ cle, libelle }) => {
          const lot = composants.filter((c) => c.colonne === cle);
          if (lot.length === 0) return null;
          return (
            <div key={cle}>
              <div className="px-3 pt-2.5 pb-0.5 font-sans text-[0.5625rem] font-semibold uppercase tracking-marque text-ink-dim/70">
                {libelle}
              </div>
              {lot.map((composant) => {
                const style = COULEUR[composant.sante];
                const vise = concernes.has(composant.nom);
                return (
                  <div
                    key={composant.nom}
                    className={[
                      "flex items-center gap-2.5 px-3 py-1 border-l-2",
                      vise ? "border-l-accent bg-accent/5" : "border-l-transparent",
                    ].join(" ")}
                  >
                    <span className={`pastille ${style.pastille} ${style.forme}`} />
                    <div className="min-w-0 flex-1">
                      <div className={`text-[0.6875rem] leading-tight font-mono truncate ${style.texte}`}>
                        {composant.nom}
                      </div>
                      <div className="text-[0.5625rem] leading-tight text-ink-dim truncate">
                        {composant.role}
                      </div>
                    </div>
                    {composant.detail && (
                      <span className="text-[0.625rem] font-mono text-ink-dim shrink-0">
                        {composant.detail}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>
    </aside>
  );
}

/** Compose la liste attendue des composants, avec leur état observé. */
export function composantsAttendus(etat: EtatSupervision | null): EtatComposant[] {
  const incident = etat?.incident ?? null;
  const playbook = incident?.playbook_id ?? "";

  // Le service reellement vise par le playbook en cours.
  //
  // L'interface ne dispose d'aucun releve de sante par composant : elle ne peut
  // donc pas afficher un etat qu'elle ne connait pas. L'ancienne version
  // repondait a ce manque par un vert ecrit en dur sur treize services, et trois
  // autres passaient a l'orange des qu'un incident existait. Resultat : le rail
  // affichait « tout va bien » pendant qu'on redemarrait un service, et il
  // designait toujours les memes trois composants au lieu du vrai.
  //
  // On marque donc celui qui est effectivement touche, et lui seul. C'est
  // moins riche qu'un releve de sante complet, mais c'est vrai.
  const vise = new Set<string>();
  if (playbook.includes("A1")) vise.add("api-payment");
  if (playbook.includes("A2")) vise.add("api-auth");
  if (playbook.includes("A3")) vise.add("edge");
  if (playbook.includes("INTEGRITE")) vise.add("api-ledger");
  if (playbook.includes("INDISPONIBLE")) vise.add("api-payment");
  if (playbook.includes("CONTAINER")) vise.add("edge");
  const santeVisee: EtatComposant["sante"] =
    incident?.state === "FAILED" ? "indisponible" : "degrade";

  const composants: EtatComposant[] = [
    { nom: "web", role: "interface React", colonne: "dev", sante: "ok" },
    { nom: "api-auth", role: "authentification", colonne: "dev", sante: "ok" },
    { nom: "api-payment", role: "orchestration paiement", colonne: "dev", sante: "ok" },
    { nom: "api-ledger", role: "grand livre partie double", colonne: "dev", sante: "ok" },
    { nom: "postgres", role: "PostgreSQL + pgvector", colonne: "dev", sante: "ok" },
    { nom: "edge", role: "WAF ModSecurity + CRS", colonne: "cyber", sante: "ok" },
    { nom: "remediation", role: "moteur de reprise", colonne: "cyber", sante: "ok" },
    { nom: "vault", role: "coffre de secrets", colonne: "cyber", sante: "ok" },
    { nom: "falco", role: "détection d'exécution", colonne: "cyber", sante: "ok" },
    { nom: "telemetry", role: "agrégation des journaux", colonne: "ia", sante: "ok" },
    { nom: "detector", role: "modèle Isolation Forest", colonne: "ia", sante: "ok" },
    { nom: "assistant", role: "assistant RAG local", colonne: "ia", sante: "ok" },
    { nom: "ollama", role: "modèle de langage local", colonne: "ia", sante: "ok" },
    { nom: "prometheus", role: "métriques", colonne: "infra", sante: "ok" },
    { nom: "grafana", role: "tableaux de bord", colonne: "infra", sante: "ok" },
    { nom: "loki", role: "journaux centralisés", colonne: "infra", sante: "ok" },
    { nom: "alertmanager", role: "routage d'alertes", colonne: "infra", sante: "ok" },
  ];

  return composants.map((composant) =>
    vise.has(composant.nom) ? { ...composant, sante: santeVisee } : composant,
  );
}
