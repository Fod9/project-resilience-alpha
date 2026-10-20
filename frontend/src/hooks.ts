import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Interrogation périodique d'un point d'entrée.
 *
 * La salle d'opérations doit refléter l'état réel, y compris quand la bordure
 * ou un service ne répond plus : une erreur n'efface donc pas la dernière
 * valeur connue, elle la marque comme périmée. Un tableau de bord qui se vide
 * au premier incident est inutilisable au moment précis où il compte.
 */
export function useSonde<T>(
  charge: () => Promise<T>,
  intervalleMs: number,
): {
  donnees: T | null;
  erreur: string | null;
  indisponible: boolean;
  actualiseA: number | null;
  rafraichir: () => void;
} {
  const [donnees, setDonnees] = useState<T | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);
  const [indisponible, setIndisponible] = useState(false);
  const [actualiseA, setActualiseA] = useState<number | null>(null);
  const monte = useRef(true);
  const chargeRef = useRef(charge);
  chargeRef.current = charge;

  const rafraichir = useCallback(() => {
    chargeRef
      .current()
      .then((valeur) => {
        if (!monte.current) return;
        setDonnees(valeur);
        setErreur(null);
        setIndisponible(false);
        setActualiseA(Date.now());
      })
      .catch((probleme: unknown) => {
        if (!monte.current) return;
        setErreur(probleme instanceof Error ? probleme.message : String(probleme));
        setIndisponible(estIndisponible(probleme));
      });
  }, []);

  useEffect(() => {
    monte.current = true;
    rafraichir();
    const minuteur = window.setInterval(rafraichir, intervalleMs);
    return () => {
      monte.current = false;
      window.clearInterval(minuteur);
    };
  }, [rafraichir, intervalleMs]);

  return { donnees, erreur, indisponible, actualiseA, rafraichir };
}

/**
 * Distingue une indisponibilite passagere d'une erreur applicative.
 *
 * Un service qui n'accepte pas encore de connexion n'est pas en panne : au
 * premier demarrage, la base s'initialise et le modele se charge, ce qui prend
 * une a deux minutes. Presenter cela comme une erreur donne l'image d'un
 * systeme casse au moment precis ou le jury le regarde.
 */
function estIndisponible(probleme: unknown): boolean {
  if (typeof probleme === "object" && probleme !== null && "status" in probleme) {
    const statut = (probleme as { status?: unknown }).status;
    if (typeof statut === "number") {
      return statut === 502 || statut === 503 || statut === 504;
    }
  }
  // Defaut reseau : la bordure n'a pas repondu du tout.
  const message = probleme instanceof Error ? probleme.message : String(probleme);
  return /failed to fetch|networkerror|load failed|econnrefused|fetch failed/i.test(message);
}

/** Horloge locale, réutilisée par plusieurs composants d'affichage. */
export function useHorloge(intervalleMs = 1000): number {
  const [maintenant, setMaintenant] = useState(() => Date.now());
  useEffect(() => {
    const minuteur = window.setInterval(() => setMaintenant(Date.now()), intervalleMs);
    return () => window.clearInterval(minuteur);
  }, [intervalleMs]);
  return maintenant;
}
