import { useEffect, useState, type ReactNode } from "react";
import Ops from "./pages/Ops";
import Pay from "./pages/Pay";

type Vue = "ops" | "pay";

/**
 * Coquille de l'application.
 *
 * Deux vues seulement, distinguées par le chemin : le parcours client (`/`) et
 * la salle d'opérations (`/ops`). Un routeur complet serait superflu ici, et
 * chaque dépendance en moins est une dépendance en moins à justifier devant le
 * jury.
 *
 * L'en-tête est celui d'un document, pas d'une application : le nom de la
 * plateforme à gauche, la navigation à droite, et un filet de pied qui sépare
 * l'en-tête du corps : exactement comme la bande d'un registre.
 */
export default function App() {
  const [vue, setVue] = useState<Vue>(() =>
    window.location.pathname.startsWith("/ops") ? "ops" : "pay",
  );

  useEffect(() => {
    const surNavigation = () =>
      setVue(window.location.pathname.startsWith("/ops") ? "ops" : "pay");
    window.addEventListener("popstate", surNavigation);
    return () => window.removeEventListener("popstate", surNavigation);
  }, []);

  const naviguer = (cible: Vue) => {
    const chemin = cible === "ops" ? "/ops" : "/";
    if (window.location.pathname !== chemin) {
      window.history.pushState({}, "", chemin);
    }
    setVue(cible);
  };

  return (
    <div className="flex h-full flex-col bg-base">
      <header className="shrink-0 border-b border-line-fort bg-base">
        <div className="flex items-center justify-between px-11 py-4">
          <div className="flex flex-col gap-0.5">
            <span className="font-display text-2xl font-extrabold uppercase tracking-[0.1em] text-ink">
              AlphaPay
            </span>
            <span className="font-sans text-[0.625rem] uppercase tracking-[0.16em] text-ink-dim">
              Project Resilience-Alpha · plateforme de paiement fictive
            </span>
          </div>

          <nav className="flex items-center gap-7">
            <LienNav actif={vue === "pay"} onClick={() => naviguer("pay")}>
              Paiement
            </LienNav>
            <LienNav actif={vue === "ops"} onClick={() => naviguer("ops")}>
              Tableau de bord
            </LienNav>
          </nav>
        </div>
      </header>

      {vue === "ops" ? <Ops /> : <Pay />}
    </div>
  );
}

/**
 * Entrée de navigation. L'onglet actif est souligné d'un filet vert-de-gris :
 * sur un fond papier, c'est le repère le plus sobre qui reste visible de loin.
 */
function LienNav({
  actif,
  onClick,
  children,
}: {
  actif: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="group flex flex-col items-center gap-1"
    >
      <span
        className={[
          "font-sans text-[0.6875rem] uppercase tracking-[0.14em] transition-colors",
          actif
            ? "font-semibold text-ink"
            : "font-medium text-ink-dim group-hover:text-ink",
        ].join(" ")}
      >
        {children}
      </span>
      <span
        className={[
          "h-0.5 w-full transition-colors",
          actif ? "bg-accent" : "bg-transparent group-hover:bg-line",
        ].join(" ")}
      />
    </button>
  );
}
