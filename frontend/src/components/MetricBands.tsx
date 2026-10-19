import type { DetailIncident, FenetreVariables, RapportDetection } from "../api";

/**
 * Bandes de mesures et indication du seuil de détection.
 *
 * Le seuil est tracé sur la même échelle que le score : sans lui, le jury voit
 * une courbe monter sans pouvoir dire à partir de quand la plateforme a
 * effectivement conclu à une anomalie.
 */

function valeurFenetre(fenetre: FenetreVariables | null, nom: string): number {
  return fenetre?.features?.[nom] ?? 0;
}

export function BandesMesures({
  fenetre,
  detection,
}: {
  fenetre: FenetreVariables | null;
  detection: RapportDetection | null;
}) {
  const seuil = detection?.threshold ?? 0;
  const score = detection?.score ?? 0;
  const ratio = seuil > 0 ? Math.min(score / (seuil * 2), 1) : 0;
  const seuilRatio = seuil > 0 ? Math.min(seuil / (seuil * 2), 1) : 0.5;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
      <Bande
        titre="Score d'anomalie et seuil calibré"
        valeur={score.toFixed(4)}
        sous={`seuil ${seuil.toFixed(4)} · dépassement ×${(detection?.exceedance ?? 0).toFixed(2)}`}
        ratio={ratio}
        repere={seuilRatio}
        alerte={detection?.anomalous ?? false}
      />
      <Bande
        titre="Trafic observé"
        valeur={`${valeurFenetre(fenetre, "requests_per_second").toFixed(1)} req/s`}
        sous={`${fenetre?.events_in_window ?? 0} événements · ${valeurFenetre(fenetre, "unique_source_ips").toFixed(0)} adresses`}
        ratio={Math.min(valeurFenetre(fenetre, "requests_per_second") / 120, 1)}
      />
      <Bande
        titre="Latence p99 mesurée à la bordure"
        valeur={`${valeurFenetre(fenetre, "latency_p99_ms").toFixed(0)} ms`}
        sous={`p95 ${valeurFenetre(fenetre, "latency_p95_ms").toFixed(0)} ms`}
        ratio={Math.min(valeurFenetre(fenetre, "latency_p99_ms") / 3000, 1)}
      />
      <Bande
        titre="Signatures hostiles interceptées"
        valeur={`${(valeurFenetre(fenetre, "injection_token_ratio") * 100).toFixed(1)} %`}
        sous={`XSS ${(valeurFenetre(fenetre, "xss_token_ratio") * 100).toFixed(1)} % · blocages WAF ${(valeurFenetre(fenetre, "waf_block_ratio") * 100).toFixed(1)} %`}
        ratio={Math.min(valeurFenetre(fenetre, "injection_token_ratio") / 0.2, 1)}
      />
    </div>
  );
}

function Bande({
  titre,
  valeur,
  sous,
  ratio,
  repere,
  alerte,
}: {
  titre: string;
  valeur: string;
  sous: string;
  ratio: number;
  repere?: number;
  alerte?: boolean;
}) {
  const couleur = alerte ? "bg-incident" : "bg-brass";
  return (
    <div className="carte px-3 py-2.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="etiquette">{titre}</span>
        <span className={`tabular text-lg ${alerte ? "text-incident" : "text-ink"}`}>{valeur}</span>
      </div>
      <div className="relative mt-2 barre">
        <div
          className={`h-full ${couleur} rounded-full`}
          style={{ width: `${Math.max(ratio * 100, 0)}%` }}
        />
        {repere !== undefined && (
          <div
            className="absolute -top-0.5 bottom-[-2px] w-px bg-ink-dim"
            style={{ left: `${repere * 100}%` }}
            title="seuil de décision du modèle"
          />
        )}
      </div>
      <div className="mt-1.5 text-[0.625rem] font-mono text-ink-dim">{sous}</div>
    </div>
  );
}

/**
 * Panneau du playbook : la progression de la reprise, phase par phase.
 *
 * Les phases sont affichées dans l'ordre métier, pas dans l'ordre d'arrivée des
 * événements : le jury doit pouvoir lire où en est la reprise même si deux
 * actions ont été exécutées dans un ordre inattendu.
 */
const PHASES = ["CONTAINING", "ERADICATING", "RECOVERING", "VERIFYING"] as const;

export function PlaybookPanel({
  detail,
  erreur,
}: {
  detail: DetailIncident | null;
  erreur: string | null;
}) {
  const incident = detail?.incident;
  const actions = detail?.actions ?? [];
  const etat = incident?.state ?? "—";

  return (
    <section className="carte flex flex-col min-h-0">
      <div className="carte-entete shrink-0">
        <span className="etiquette">Playbook de reprise</span>
        <span className="text-xs font-mono text-ink-dim">{incident?.playbook_id ?? "en attente"}</span>
      </div>

      <div className="p-3 space-y-3 overflow-y-auto">
        <div className="flex items-center gap-2">
          {PHASES.map((phase) => {
            const faites = actions.some((a) => a.status === "ok");
            const atteinte = indexPhase(etat) >= indexPhase(phase);
            return (
              <div key={phase} className="flex-1">
                <div
                  className={[
                    "h-1 rounded-full",
                    atteinte ? "bg-nominal" : faites ? "bg-brass/40" : "bg-surface-2",
                  ].join(" ")}
                />
                <div
                  className={`mt-1 text-[0.5625rem] font-display uppercase tracking-marque ${
                    atteinte ? "text-nominal" : "text-ink-dim/60"
                  }`}
                >
                  {phase.slice(0, 5)}
                </div>
              </div>
            );
          })}
        </div>

        {actions.length === 0 && (
          <p className="text-xs text-ink-dim">
            {erreur ?? "Aucune action engagée. Le panneau se remplit dès la sélection d'une politique."}
          </p>
        )}

        <ol className="space-y-1.5">
          {actions.map((action) => {
            const reussi = action.status === "ok";
            return (
              <li key={`${action.step_id}-${action.started_at}`} className="flex items-start gap-2">
                <span
                  className={`mt-1 pastille ${reussi ? "bg-nominal rounded-full" : "bg-incident rounded-none"}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-mono text-ink truncate">{action.action}</span>
                    <span className="text-[0.625rem] font-mono text-ink-dim shrink-0">
                      {action.duration_ms ?? "—"} ms
                    </span>
                  </div>
                  <div className="text-[0.625rem] text-ink-dim truncate">
                    {action.error ?? etapeDescription(action.result)}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>

        {detail?.verifications?.length ? (
          <div className="border-t border-line pt-3">
            <div className="etiquette mb-2">Preuves de rétablissement</div>
            {detail.verifications.slice(-1).map((verification) => (
              <ul key={verification.ran_at} className="space-y-1">
                {verification.checks.map((controle) => (
                  <li key={controle.name} className="flex items-center gap-2 text-xs">
                    <span
                      className={`pastille ${
                        controle.passed ? "bg-nominal rounded-full" : "bg-incident rounded-none"
                      }`}
                    />
                    <span className="font-mono text-ink-dim">{controle.name}</span>
                    <span className="ml-auto font-mono text-[0.625rem] text-ink-dim">
                      {controle.duration_ms} ms
                    </span>
                  </li>
                ))}
              </ul>
            ))}
          </div>
        ) : null}
      </div>
    </section>
  );
}

function indexPhase(etat: string): number {
  const ordre = ["DETECTING", "CONTAINING", "ERADICATING", "RECOVERING", "VERIFYING", "RECOVERED"];
  const index = ordre.indexOf(etat);
  return index === -1 ? 0 : index;
}

function etapeDescription(resultat: Record<string, unknown> | null): string {
  if (!resultat) return "";
  const detail = resultat.detail;
  return typeof detail === "string" ? detail : "";
}
