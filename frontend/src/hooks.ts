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
): { donnees: T | null; erreur: string | null; actualiseA: number | null; rafraichir: () => void } {
  const [donnees, setDonnees] = useState<T | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);
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
        setActualiseA(Date.now());
      })
      .catch((probleme: unknown) => {
        if (!monte.current) return;
        setErreur(probleme instanceof Error ? probleme.message : String(probleme));
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

  return { donnees, erreur, actualiseA, rafraichir };
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
