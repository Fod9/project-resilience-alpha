import { useEffect, useMemo, useState } from "react";
import { api, type DetailIncident, type FenetreVariables, type RapportDetection } from "../api";
import { useSonde } from "../hooks";
import AssistantPanel from "../components/AssistantPanel";
import { BandesMesures, PlaybookPanel } from "../components/MetricBands";
import RecorderStrip from "../components/RecorderStrip";
import ServiceRail, { composantsAttendus } from "../components/ServiceRail";
import StateHeader from "../components/StateHeader";

/**
 * Salle d'opérations.
 *
 * Organisation en lecture descendante : l'état global en haut, les composants à
 * gauche, les mesures au centre, la reprise à droite, la chronologie en bas.
 * Un jury qui entre dans la salle doit pouvoir répondre en trois secondes à la
 * question « le service est-il rétabli ? ».
 */
export default function Ops() {
  const etat = useSonde(api.etat, 3000);
  const fenetre = useSonde<FenetreVariables>(api.fenetre, 5000);
  const detection = useSonde<RapportDetection>(api.detection, 5000);
  const chronologie = useSonde(api.chronologie, 5000);

  const [detail, setDetail] = useState<DetailIncident | null>(null);

  useEffect(() => {
    const identifiant = etat.donnees?.incident?.id;
    if (!identifiant) return;
    let annule = false;
    api
      .incident(identifiant)
      .then((valeur) => {
        if (!annule) setDetail(valeur);
      })
      .catch(() => {
        /* l'incident peut être clos entre deux interrogations : on conserve
           le dernier détail connu plutôt que de vider le panneau. */
      });
    return () => {
      annule = true;
    };
  }, [etat.donnees?.incident?.id, etat.actualiseA]);

  const points = useMemo(
    () => (chronologie.donnees?.events ?? [])
      .filter((evenement) => evenement.kind === "state.changed" || evenement.source === "detector")
      .map((evenement) => Number((evenement.payload as { score?: number })?.score ?? 0))
      .filter((valeur) => valeur > 0)
      .slice(0, 30)
      .reverse(),
    [chronologie.donnees],
  );

  const scoreCourant = useMemo(
    () => points.length > 0 ? points : [detection.donnees?.score ?? 0],
    [points, detection.donnees],
  );

  const composants = composantsAttendus(etat.donnees);

  return (
    <div className="flex-1 flex flex-col min-h-0">
      <StateHeader etat={etat.donnees} points={scoreCourant} />

      <div className="flex-1 min-h-0 p-3 grid gap-3 grid-cols-1 xl:grid-cols-ops overflow-auto">
        <ServiceRail composants={composants} incident={etat.donnees?.incident ?? null} />

        <div className="flex flex-col gap-3 min-h-0">
          <BandesMesures fenetre={fenetre.donnees} detection={detection.donnees} />
          <Indicateurs
            detection={detection.donnees}
            fenetre={fenetre.donnees}
            erreurs={{
              etat: etat.erreur,
              fenetre: fenetre.erreur,
              detection: detection.erreur,
            }}
          />
          <RecorderStrip
            evenements={chronologie.donnees?.events ?? []}
            incident={etat.donnees?.incident ?? null}
          />
        </div>

        <div className="flex flex-col gap-3 min-h-0">
          <PlaybookPanel detail={detail} erreur={etat.erreur} />
          <AssistantPanel />
        </div>
      </div>
    </div>
  );
}

function Indicateurs({
  detection,
  fenetre,
  erreurs,
}: {
  detection: RapportDetection | null;
  fenetre: FenetreVariables | null;
  erreurs: { etat: string | null; fenetre: string | null; detection: string | null };
}) {
  const diagnostic = fenetre?.diagnostics;
  const actives = Object.entries(erreurs).filter(([, valeur]) => valeur !== null);

  return (
    <div className="carte px-3 py-2.5">
      <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
        <Item
          libelle="Modèle"
          valeur={detection?.model_version ?? "non chargé"}
          note={detection?.rules_used === false ? "aucune règle codée en dur" : undefined}
        />
        <Item
          libelle="Fenêtres consécutives"
          valeur={`${detection?.consecutive_windows ?? 0} / 2`}
          note="confirmation avant qualification"
        />
        <Item
          libelle="Origine dominante"
          valeur={diagnostic?.dominant_source_ip || "—"}
          note={`${diagnostic?.source_ips_distinctes ?? 0} adresses distinctes`}
        />
        <Item
          libelle="Variables les plus déviantes"
          valeur={(detection?.top_features ?? [])
            .slice(0, 2)
            .map((f) => `${f.feature} ×${f.z.toFixed(1)}σ`)
            .join(" · ") || "—"}
        />
        <Item
          libelle="Cible probable"
          valeur={detection?.suspected_target ?? "—"}
          note="indice de lecture, la décision vient de la politique"
        />
      </div>

      {actives.length > 0 && (
        <div className="mt-2 pt-2 border-t border-line text-[0.625rem] font-mono text-degraded">
          {actives.map(([nom, message]) => (
            <div key={nom}>
              {nom} : {message}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function Item({ libelle, valeur, note }: { libelle: string; valeur: string; note?: string }) {
  return (
    <div className="min-w-[9rem]">
      <div className="etiquette mb-0.5">{libelle}</div>
      <div className="text-xs font-mono text-ink">{valeur}</div>
      {note && <div className="text-[0.5625rem] text-ink-dim">{note}</div>}
    </div>
  );
}
