import { useEffect, useMemo, useState, type ReactNode } from "react";
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
 * Parti pris de mise en page : deux feuillets séparés par une gouttière, sous
 * une grille réglée, avec le filet de marge imprimé à gauche : la structure
 * d'un grand livre ouvert. Le feuillet de gauche porte le système, celui de
 * droite l'incident. Ce n'est pas une grille de cartes : un registre se lit
 * page par page, et le jury doit pouvoir suivre une seule histoire, celle de
 * la reprise.
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
    () =>
      (chronologie.donnees?.events ?? [])
        .filter((evenement) => evenement.kind === "state.changed" || evenement.source === "detector")
        .map((evenement) => Number((evenement.payload as { score?: number })?.score ?? 0))
        .filter((valeur) => valeur > 0)
        .slice(0, 30)
        .reverse(),
    [chronologie.donnees],
  );

  const scoreCourant = useMemo(
    () => (points.length > 0 ? points : [detection.donnees?.score ?? 0]),
    [points, detection.donnees],
  );

  const composants = composantsAttendus(etat.donnees);

  return (
    <main className="min-h-0 flex-1 grid grid-cols-1 grid-rows-[minmax(0,1fr)_auto] xl:grid-cols-ops bg-base">
      {/* --- Feuillet des services ------------------------------------------ */}
      <section className="flex min-h-0 flex-col gap-5 overflow-y-auto border-line bg-surface px-6 py-6 xl:border-l">
        <TitreFeuillet>Services</TitreFeuillet>
        <ServiceRail composants={composants} incident={etat.donnees?.incident ?? null} />
        <BandesMesures fenetre={fenetre.donnees} detection={detection.donnees} />
      </section>

      {/* --- Gouttière : la pliure du livre --------------------------------- */}
      <div className="hidden bg-base xl:block">
        <div className="mx-auto h-full w-px bg-line" />
      </div>

      {/* --- Feuillet des incidents ----------------------------------------- */}
      <section className="flex min-h-0 flex-col gap-5 overflow-y-auto border-line bg-surface px-6 py-6 xl:border-r">
        <TitreFeuillet>Incidents</TitreFeuillet>
        <div className="fiche px-6 py-6">
          <StateHeader etat={etat.donnees} points={scoreCourant} />
        </div>
        <PlaybookPanel detail={detail} erreur={etat.erreur} />
        <RecorderStrip
          incident={etat.donnees?.incident ?? null}
          evenements={chronologie.donnees?.events ?? []}
        />
        <AssistantPanel />
      </section>

      {/* --- Pied de page --------------------------------------------------- */}
      <footer className="col-span-1 border-t border-line py-3 xl:col-span-3">
        <p className="text-center font-mono text-[0.625rem] text-ink-dim">AlphaPay 2026©</p>
      </footer>
    </main>
  );
}

/**
 * Intitulé de feuillet : un libellé en petites capitales surmonté d'un filet
 * appuyé. C'est la règle imprimée qui ouvre une section dans un registre.
 */
function TitreFeuillet({ children }: { children: ReactNode }) {
  return (
    <div className="flex flex-col gap-2 border-b-2 border-line-fort pb-2">
      <span className="font-display text-[0.5625rem] uppercase tracking-marque text-ink-dim">
        {children}
      </span>
    </div>
  );
}
