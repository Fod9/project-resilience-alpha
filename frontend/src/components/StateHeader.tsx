import { useHorloge } from "../hooks";
import type { EtatGlobal, EtatSupervision } from "../api";

/**
 * Bandeau d'état : la signature du tableau de bord.
 *
 * Un seul mot, en très grand, plus le temps écoulé depuis l'ouverture de
 * l'incident. C'est ce qui doit être lisible à trois mètres, sans s'approcher
 * de l'écran : pendant une démonstration, le jury regarde la salle, pas un
 * tableau de bord.
 */

const LIBELLES: Record<EtatGlobal, string> = {
  NOMINAL: "Nominal",
  INCIDENT: "Incident",
  RECOVERED: "Rétabli",
  FAILED: "Échec",
};

const COULEURS: Record<EtatGlobal, { texte: string; fond: string; bord: string }> = {
  NOMINAL: { texte: "text-nominal", fond: "bg-nominal/10", bord: "border-nominal/40" },
  INCIDENT: { texte: "text-incident", fond: "bg-incident/10", bord: "border-incident/50" },
  RECOVERED: { texte: "text-brass", fond: "bg-brass/10", bord: "border-brass/40" },
  FAILED: { texte: "text-incident", fond: "bg-incident/10", bord: "border-incident/50" },
};

export default function StateHeader({
  etat,
  points,
}: {
  etat: EtatSupervision | null;
  points: number[];
}) {
  const maintenant = useHorloge(1000);
  const global: EtatGlobal = etat?.state ?? "NOMINAL";
  const couleurs = COULEURS[global];

  const ouvertA = etat?.incident?.opened_at ? Date.parse(etat.incident.opened_at) : null;
  const ecoule = ouvertA !== null ? Math.max(0, Math.floor((maintenant - ouvertA) / 1000)) : null;

  return (
    <section className={`border-b ${couleurs.bord} ${couleurs.fond}`}>
      <div className="flex flex-wrap items-end gap-x-8 gap-y-3 px-5 py-4">
        <div className="min-w-[16rem]">
          <div className="etiquette mb-1">État de la plateforme</div>
          <div className={`mot-etat ${couleurs.texte}`}>{LIBELLES[global]}</div>
        </div>

        <div className="flex gap-8">
          <Mesure
            libelle="Incident en cours depuis"
            valeur={ecoule === null ? "—" : formaterDuree(ecoule)}
            accent={global === "INCIDENT" ? couleurs.texte : undefined}
          />
          <Mesure
            libelle="Cible de détection"
            valeur={`${etat?.targets.mttd_seconds ?? "?"} s`}
          />
          <Mesure
            libelle="Cible de rétablissement"
            valeur={`${etat?.targets.mttr_seconds ?? "?"} s`}
          />
          <Mesure
            libelle="Actions sur la fenêtre"
            valeur={`${etat?.actions_in_window ?? 0} / ${etat?.action_limit ?? "?"}`}
          />
        </div>

        <div className="ml-auto min-w-[14rem]">
          <div className="etiquette mb-1 text-right">Score d'anomalie (30 dernières fenêtres)</div>
          <Bande points={points} />
        </div>
      </div>

      {etat?.incident && (
        <div className="px-5 pb-3 -mt-1">
          <div className="text-sm text-ink-dim">
            <span className="text-ink">{etat.incident.title}</span>
            {etat.incident.source_ip && (
              <span className="tabular ml-3 text-xs">
                origine {etat.incident.source_ip}
              </span>
            )}
            {etat.incident.playbook_id && (
              <span className="ml-3 text-xs font-mono text-ink-dim">
                {etat.incident.playbook_id}
              </span>
            )}
          </div>
        </div>
      )}

      {(etat?.suspended || etat?.dry_run) && (
        <div className="px-5 pb-3 flex gap-3 text-xs">
          {etat?.suspended && (
            <span className="border border-incident/50 text-incident px-2 py-0.5 rounded-sm">
              reprise automatique suspendue (coupe-circuit)
            </span>
          )}
          {etat?.dry_run && (
            <span className="border border-degraded/50 text-degraded px-2 py-0.5 rounded-sm">
              mode à blanc : les actions sont décrites mais non appliquées
            </span>
          )}
        </div>
      )}
    </section>
  );
}

function Mesure({
  libelle,
  valeur,
  accent,
}: {
  libelle: string;
  valeur: string;
  accent?: string;
}) {
  return (
    <div>
      <div className="etiquette mb-1">{libelle}</div>
      <div className={`tabular text-2xl ${accent ?? "text-ink"}`}>{valeur}</div>
    </div>
  );
}

function Bande({ points }: { points: number[] }) {
  if (points.length < 2) {
    return <div className="h-10 border border-line rounded-sm bg-surface" />;
  }
  const max = Math.max(...points, 1e-6);
  const largeur = 240;
  const hauteur = 40;
  const pas = largeur / (points.length - 1);
  const trace = points
    .map((valeur, index) => `${index * pas},${hauteur - (valeur / max) * (hauteur - 4) - 2}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${largeur} ${hauteur}`} className="w-full h-10" role="img"
         aria-label="Évolution du score d'anomalie">
      <polyline points={trace} fill="none" stroke="#D9A227" strokeWidth="1.5" />
    </svg>
  );
}

export function formaterDuree(secondes: number): string {
  const minutes = Math.floor(secondes / 60);
  const reste = secondes % 60;
  return `${String(minutes).padStart(2, "0")}:${String(reste).padStart(2, "0")}`;
}
