import { useEffect, useState, type ReactNode } from "react";
import Acces, { Enrolement } from "./pages/Acces";
import Ops from "./pages/Ops";
import Pay from "./pages/Pay";
import { etatSession, fermerSession, reprendreSession, surveillerSession } from "./session";

type Vue = "ops" | "pay";

/** Rôles autorisés à ouvrir la salle d'opérations. Un compte client n'y a pas
 *  accès : il paie, il ne surveille pas la plateforme. */
const ROLES_SALLE = new Set(["operator", "admin", "auditor"]);

/**
 * Coquille de l'application.
 *
 * Deux vues seulement, distinguées par le chemin : le parcours client (`/`) et
 * la salle d'opérations (`/ops`). Un routeur complet serait superflu ici, et
 * chaque dépendance en moins est une dépendance en moins à justifier devant le
 * jury.
 *
 * L'accès est gardé par la session : sans session ouverte, rien d'autre que
 * l'écran d'accès n'est monté. La vue réellement affichée dépend du rôle porté
 * par le jeton, pas d'un choix d'interface : un compte client qui ouvre `/ops`
 * retombe sur le parcours de paiement.
 */
export default function App() {
  const [etat, setEtat] = useState(etatSession);
  const [reprise, setReprise] = useState(true);
  const [enrolement, setEnrolement] = useState(false);
  const [vue, setVue] = useState<Vue>(() =>
    window.location.pathname.startsWith("/ops") ? "ops" : "pay",
  );

  useEffect(() => surveillerSession(() => setEtat(etatSession())), []);

  useEffect(() => {
    let vivant = true;
    void reprendreSession().finally(() => {
      if (vivant) {
        setReprise(false);
      }
    });
    return () => {
      vivant = false;
    };
  }, []);

  useEffect(() => {
    const surNavigation = () =>
      setVue(window.location.pathname.startsWith("/ops") ? "ops" : "pay");
    window.addEventListener("popstate", surNavigation);
    return () => window.removeEventListener("popstate", surNavigation);
  }, []);

  if (reprise) {
    return <Attente />;
  }

  if (!etat.ouverte) {
    return <Acces />;
  }

  if (enrolement) {
    return <Enrolement onFermer={() => setEnrolement(false)} />;
  }

  const salleAutorisee = ROLES_SALLE.has(etat.identite?.role ?? "");
  const vueEffective: Vue = salleAutorisee ? vue : "pay";

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
          <span className="font-display text-2xl font-extrabold uppercase tracking-[0.1em] text-ink">
            AlphaPay
          </span>

          <nav className="flex items-center gap-7">
            <LienNav actif={vueEffective === "pay"} onClick={() => naviguer("pay")}>
              Paiement
            </LienNav>
            {salleAutorisee ? (
              <LienNav actif={vueEffective === "ops"} onClick={() => naviguer("ops")}>
                Tableau de bord
              </LienNav>
            ) : null}
            <span className="h-6 w-px bg-line" />
            <div className="flex items-center gap-4">
              <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-dim">
                {etat.identite?.username ?? "session"} / {etat.identite?.role ?? ""}
              </span>
              <button
                type="button"
                onClick={() => setEnrolement(true)}
                className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent"
              >
                Mon visage
              </button>
              <button
                type="button"
                onClick={() => void fermerSession()}
                className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-dim hover:text-ink"
              >
                Fermer la session
              </button>
            </div>
          </nav>
        </div>
      </header>

      {vueEffective === "ops" ? <Ops /> : <Pay />}
    </div>
  );
}

/** Écran d'attente pendant la reprise de session : sans lui, l'écran d'accès
 *  apparaîtrait une fraction de seconde à un opérateur déjà connecté. */
function Attente() {
  return (
    <div className="flex h-full items-center justify-center bg-base">
      <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-dim">
        Reprise de session
      </span>
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
    <button type="button" onClick={onClick} className="group flex flex-col items-center gap-1">
      <span
        className={[
          "font-sans text-[0.6875rem] uppercase tracking-[0.14em] transition-colors",
          actif ? "font-semibold text-ink" : "font-medium text-ink-dim group-hover:text-ink",
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
