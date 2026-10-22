/**
 * Session opérateur : ouverture, renouvellement, fermeture.
 *
 * Le jeton d'accès vit en mémoire d'onglet uniquement : il n'est jamais écrit
 * dans le stockage du navigateur, donc il ne survit pas à un script malveillant
 * qui relirait le stockage. Seul le jeton de rafraîchissement est conservé,
 * sinon un simple rechargement de page interromprait un opérateur en pleine
 * manipulation.
 *
 * Le renouvellement est déclenché deux fois : à l'approche de l'expiration
 * annoncée par le serveur, et sur un refus 401. Le second cas est celui qui
 * compte : un jeton révoqué par la remédiation pendant un incident doit fermer
 * la session à la requête suivante, pas à la fin de sa durée de vie théorique.
 */
import { ErreurApi, analyserErreur } from "./erreurs";

const CLE_RAFRAICHISSEMENT = "alphapay-session-refresh";

export interface Identite {
  username: string;
  role: string;
}

export interface Jetons {
  access_token: string;
  refresh_token: string;
  token_type?: string;
  expires_in: number;
  kid?: string;
}

export interface EtatSession {
  ouverte: boolean;
  identite: Identite | null;
}

let jetonAcces: string | null = null;
let expiration = 0;
let rafraichissement: string | null = localStorage.getItem(CLE_RAFRAICHISSEMENT);
let identite: Identite | null = null;
let renouvellement: Promise<string> | null = null;

const abonnes = new Set<() => void>();

function prevenir(): void {
  for (const abonne of abonnes) {
    abonne();
  }
}

/** Abonnement aux changements de session, pour l'affichage React. */
export function surveillerSession(rappel: () => void): () => void {
  abonnes.add(rappel);
  return () => {
    abonnes.delete(rappel);
  };
}

export function etatSession(): EtatSession {
  return {
    ouverte: jetonAcces !== null || rafraichissement !== null,
    identite,
  };
}

export function jetonCourant(): string | null {
  return jetonAcces;
}

async function poster(chemin: string, corps: unknown): Promise<Response> {
  return fetch(chemin, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(corps),
    cache: "no-store",
  });
}

function memoriser(jetons: Jetons): void {
  jetonAcces = jetons.access_token;
  expiration = Date.now() + Math.max(30, jetons.expires_in - 60) * 1000;
  rafraichissement = jetons.refresh_token;
  localStorage.setItem(CLE_RAFRAICHISSEMENT, jetons.refresh_token);
}

function oublier(): void {
  jetonAcces = null;
  expiration = 0;
  identite = null;
  rafraichissement = null;
  localStorage.removeItem(CLE_RAFRAICHISSEMENT);
}

async function chargerIdentite(): Promise<void> {
  if (jetonAcces === null) {
    return;
  }
  const reponse = await fetch("/api/auth/users/me", {
    headers: { Authorization: `Bearer ${jetonAcces}`, Accept: "application/json" },
    cache: "no-store",
  });
  if (!reponse.ok) {
    return;
  }
  const profil = (await reponse.json()) as { username?: string; role?: string };
  identite = {
    username: profil.username ?? "",
    role: profil.role ?? "",
  };
}

async function renouveler(): Promise<string> {
  if (rafraichissement === null) {
    throw new ErreurApi("Session fermée.", 401, "session_closed");
  }
  const reponse = await poster("/api/auth/token/refresh", {
    refresh_token: rafraichissement,
  });
  if (!reponse.ok) {
    const erreur = await analyserErreur(reponse);
    oublier();
    prevenir();
    throw erreur;
  }
  memoriser((await reponse.json()) as Jetons);
  prevenir();
  return jetonAcces as string;
}

/** Jeton d'accès valide, renouvelé si nécessaire. Les appels concurrents
 *  partagent le même renouvellement : un jeton révoqué ne doit être remplacé
 *  qu'une fois, même si cinq requêtes partent en même temps. */
export async function jetonValide(): Promise<string> {
  if (jetonAcces !== null && Date.now() < expiration) {
    return jetonAcces;
  }
  if (renouvellement === null) {
    renouvellement = renouveler().finally(() => {
      renouvellement = null;
    });
  }
  return renouvellement;
}

/** Requête authentifiée, avec une seconde chance après renouvellement. */
export async function requeteAutorisee(
  chemin: string,
  init: RequestInit = {},
): Promise<Response> {
  const lancer = (jeton: string) =>
    fetch(chemin, {
      ...init,
      headers: {
        Accept: "application/json",
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(init.headers ?? {}),
        Authorization: `Bearer ${jeton}`,
      },
      cache: "no-store",
    });

  const reponse = await lancer(await jetonValide());
  if (reponse.status !== 401) {
    return reponse;
  }
  jetonAcces = null;
  return lancer(await renouveler());
}

/** Ouverture par mot de passe : c'est le moyen que la bordure journalise. */
export async function ouvrirParMotDePasse(
  username: string,
  password: string,
): Promise<void> {
  const reponse = await poster("/api/auth/token", { username, password });
  if (!reponse.ok) {
    throw await analyserErreur(reponse);
  }
  memoriser((await reponse.json()) as Jetons);
  await chargerIdentite();
  prevenir();
}

/** Ouverture par visage : le descripteur a été calculé dans le navigateur, le
 *  défi actif a été observé sur le flux caméra, et le serveur décide seul. */
export async function ouvrirParVisage(
  username: string,
  descripteur: number[],
  defi: { blink: boolean; turn_deg: number },
): Promise<void> {
  const reponse = await poster("/api/auth/face/verify", {
    username,
    descriptor: descripteur,
    challenge: defi,
  });
  if (!reponse.ok) {
    throw await analyserErreur(reponse);
  }
  memoriser((await reponse.json()) as Jetons);
  await chargerIdentite();
  prevenir();
}

export async function fermerSession(): Promise<void> {
  const jeton = rafraichissement;
  oublier();
  prevenir();
  if (jeton !== null) {
    try {
      await poster("/api/auth/token/revoke", { refresh_token: jeton });
    } catch {
      /* la session locale est déjà fermée : la révocation côté serveur est un
         confort, pas une condition */
    }
  }
}

/** Au démarrage : une session peut être reprise si un rafraîchissement subsiste. */
export async function reprendreSession(): Promise<boolean> {
  if (rafraichissement === null) {
    return false;
  }
  try {
    await jetonValide();
    await chargerIdentite();
    prevenir();
    return true;
  } catch {
    return false;
  }
}
