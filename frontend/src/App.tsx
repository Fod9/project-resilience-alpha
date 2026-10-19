import { useEffect, useState } from "react";
import Ops from "./pages/Ops";
import Pay from "./pages/Pay";

type Vue = "ops" | "pay";

/**
 * Coquille de l'application.
 *
 * Deux vues seulement, distinguées par le chemin : `/ops` pour la salle
 * d'opérations (supervision), tout le reste pour l'interface de paiement. Un
 * routeur complet serait superflu pour deux écrans, et chaque dépendance en
 * moins est une surface de défaillance en moins le jour de la démonstration.
 */
function vueCourante(): Vue {
  const chemin = window.location.pathname.replace(/\/+$/, "");
  return chemin.endsWith("/ops") ? "ops" : "pay";
}

export default function App() {
  const [vue, setVue] = useState<Vue>(vueCourante);

  useEffect(() => {
    const surNavigation = () => setVue(vueCourante());
    window.addEventListener("popstate", surNavigation);
    return () => window.removeEventListener("popstate", surNavigation);
  }, []);

  function naviguer(cible: Vue) {
    const chemin = cible === "ops" ? "/ops" : "/pay";
    window.history.pushState({}, "", chemin);
    setVue(cible);
  }

  return (
    <div className="min-h-full flex flex-col bg-base">
      <BarreDeNavigation vue={vue} onNaviguer={naviguer} />
      {vue === "ops" ? <Ops /> : <Pay />}
    </div>
  );
}

function BarreDeNavigation({ vue, onNaviguer }: { vue: Vue; onNaviguer: (cible: Vue) => void }) {
  return (
    <header className="flex items-center gap-6 px-5 h-11 border-b border-line bg-surface shrink-0">
      <span className="font-display font-bold tracking-marque text-sm uppercase text-brass">
        AlphaPay
      </span>
      <span className="text-xs text-ink-dim hidden md:inline">
        PROJECT RESILIENCE-ALPHA — plateforme fictive
      </span>
      <nav className="ml-auto flex items-center gap-1">
        <Onglet actif={vue === "pay"} libelle="Paiement" onClick={() => onNaviguer("pay")} />
        <Onglet actif={vue === "ops"} libelle="Salle d'opérations" onClick={() => onNaviguer("ops")} />
      </nav>
    </header>
  );
}

function Onglet({
  actif,
  libelle,
  onClick,
}: {
  actif: boolean;
  libelle: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "px-3 py-1.5 text-xs font-display uppercase tracking-marque rounded-sm border transition-colors",
        actif
          ? "border-brass text-brass bg-brass/10"
          : "border-transparent text-ink-dim hover:text-ink hover:border-line",
      ].join(" ")}
    >
      {libelle}
    </button>
  );
}
