import type { EvenementChronologie, Incident } from "../api";

/**
 * Bande-enregistreur : la chronologie de l'incident sur un axe horizontal.
 *
 * C'est l'élément qui encode la thèse du projet. Une liste verticale
 * d'événements obligerait à défiler pour comprendre l'enchaînement ; ici,
 * l'attaque, la détection, le confinement et le rétablissement sont situés les
 * uns par rapport aux autres, et les durées de détection et de reprise
 * apparaissent comme des longueurs réelles.
 */

const COULEUR_SOURCE: Record<string, string> = {
  // Thème clair : les marqueurs sont posés sur du papier, donc plus sourds que
  // sur un fond sombre. La source reste lisible par la teinte, jamais par
  // l'éclat.
  redteam: "#B4523F",
  detector: "#2E6B5A",
  alertmanager: "#96690C",
  falco: "#9C2B24",
  remediation: "#2F6B4F",
  operator: "#5C6670",
  edge: "#8A9284",
};

const JALONS_REMARQUABLES: Record<string, string> = {
  "incident.opened": "détection",
  "redteam.attack.started": "attaque",
  "action.executed": "action",
  "verification.completed": "vérification",
  "incident.recovered": "rétablissement",
  "incident.closed": "clôture",
  "state.changed": "phase",
  "circuit_breaker.opened": "coupe-circuit",
  "human.escalation": "escalade",
};

export default function RecorderStrip({
  evenements,
  incident,
}: {
  evenements: EvenementChronologie[];
  incident: Incident | null;
}) {
  const utiles = evenements.filter((e) => e.kind in JALONS_REMARQUABLES);
  if (incident === null && utiles.length === 0) {
    return (
      <section className="bloc gap-2">
        <div className="bloc-titre">
          <span className="etiquette">Bande-enregistreur</span>
          <span className="font-mono text-[0.625rem] text-ink-dim">aucun incident enregistré</span>
        </div>
        <div className="h-[132px] flex items-center justify-center text-sm text-ink-dim">
          La chronologie apparaîtra ici dès le premier signalement.
        </div>
      </section>
    );
  }

  const temps = utiles.map((e) => Date.parse(e.occurred_at)).filter((t) => !Number.isNaN(t));
  const ouvert = incident?.opened_at ? Date.parse(incident.opened_at) : Math.min(...temps);
  const ferme = incident?.closed_at ? Date.parse(incident.closed_at) : Date.now();
  const debut = Math.min(ouvert, ...temps, ferme) - 8000;
  const fin = Math.max(ferme, ...temps) + 4000;
  const etendue = Math.max(fin - debut, 1);

  const position = (t: number) => ((t - debut) / etendue) * 100;

  // Délai de détection : du début de la fenêtre anormale à la qualification.
  const mttdDebut = incident?.mttd_ms != null ? ouvert - incident.mttd_ms : null;
  const mttdFin = incident?.mttd_ms != null ? ouvert : null;
  // Temps de rétablissement : de l'ouverture de l'incident à sa clôture.
  const mttrFin = incident?.mttr_ms != null ? ouvert + incident.mttr_ms : null;

  return (
    <section className="bloc gap-2 shrink-0">
      <div className="bloc-titre">
        <span className="etiquette">Bande-enregistreur</span>
        <span className="font-mono text-[0.625rem] text-ink-dim tabular">
          {incident ? `incident ${incident.id.slice(0, 8)}` : "derniers événements"}
          {" · "}
          {utiles.length} jalons
        </span>
      </div>

      <div className="px-4 pt-6 pb-4">
        <div className="bande-enregistreur">
          {/* Axe */}
          <div className="absolute left-0 right-0 top-1/2 h-px bg-line" />

          {/* Durées mesurées, représentées à l'échelle */}
          {mttdDebut !== null && mttdFin !== null && (
            <Mesure
              gauche={position(mttdDebut)}
              largeur={position(mttdFin) - position(mttdDebut)}
              haut={54}
              couleur="#B4523F"
              libelle={`détection ${((incident?.mttd_ms ?? 0) / 1000).toFixed(1)} s`}
            />
          )}
          {mttrFin !== null && (
            <Mesure
              gauche={position(ouvert)}
              largeur={position(mttrFin) - position(ouvert)}
              haut={80}
              couleur="#2F6B4F"
              libelle={`reprise ${((incident?.mttr_ms ?? 0) / 1000).toFixed(1)} s`}
            />
          )}

          {/* Jalons */}
          {utiles.map((evenement, index) => {
            const t = Date.parse(evenement.occurred_at);
            if (Number.isNaN(t)) return null;
            const x = position(t);
            const couleur = COULEUR_SOURCE[evenement.source] ?? "#8A9284";
            const haut = index % 2 === 0 ? 76 : 92;
            return (
              <div key={`${evenement.occurred_at}-${index}`}>
                <div
                  className="jalon"
                  style={{ left: `${x}%`, backgroundColor: couleur, opacity: 0.75 }}
                />
                <div
                  className="jalon-etiq"
                  style={{
                    left: `${x}%`,
                    top: `${haut}px`,
                    transform: x > 78 ? "translateX(-100%)" : "translateX(2px)",
                  }}
                  title={evenement.message ?? evenement.kind}
                >
                  <span style={{ color: couleur }}>
                    {JALONS_REMARQUABLES[evenement.kind]}
                  </span>
                  <span className="text-ink-dim">
                    {" "}
                    {new Date(t).toLocaleTimeString("fr-FR")}
                  </span>
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex justify-between text-[0.625rem] font-mono text-ink-dim mt-1">
          <span>{new Date(debut).toLocaleTimeString("fr-FR")}</span>
          <span>maintenant</span>
        </div>
      </div>
    </section>
  );
}

function Mesure({
  gauche,
  largeur,
  haut,
  couleur,
  libelle,
}: {
  gauche: number;
  largeur: number;
  haut: number;
  couleur: string;
  libelle: string;
}) {
  const largeurSure = Math.max(largeur, 0.4);
  return (
    <div className="absolute" style={{ left: `${gauche}%`, top: `${haut}px` }}>
      <div
        className="h-2.5 rounded-sm"
        style={{ width: `${largeurSure}%`, backgroundColor: couleur, opacity: 0.35 }}
      />
      <div className="text-[0.625rem] font-mono mt-0.5" style={{ color: couleur }}>
        {libelle}
      </div>
    </div>
  );
}
