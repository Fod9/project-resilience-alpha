/**
 * Écran d'accès au tableau de bord, et enrôlement du gabarit facial.
 *
 * Deux moyens d'ouverture, un seul écran : le mot de passe et la reconnaissance
 * faciale. Le second ne remplace pas le premier, il l'évite quand la caméra est
 * là, et il retombe dessus dès qu'un gabarit manque.
 *
 * Aucun seuil, aucun nombre de tentatives, aucune durée de verrouillage n'est
 * écrit ici : tout vient de `GET /api/auth/face/policy`. Un état affiché qui ne
 * provient pas d'une lecture réelle finit toujours par mentir à l'écran pendant
 * une démonstration.
 */
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
  type RefObject,
} from "react";

import { api, ErreurApi } from "../api";
import {
  chargerModeles,
  expliquerRefusCamera,
  fermerCamera,
  mesurerDescripteur,
  ouvrirCamera,
  suivreDefi,
  type EtatDefi,
  type PolitiqueFaciale,
} from "../face";
import { etatSession, ouvrirParMotDePasse, ouvrirParVisage, surveillerSession } from "../session";

// =============================================================================
//  Outils d'état
// =============================================================================

/** Abonnement à la session : l'écran se retire dès qu'une session s'ouvre. */
function useSession() {
  const [etat, setEtat] = useState(etatSession);
  useEffect(() => surveillerSession(() => setEtat(etatSession())), []);
  return etat;
}

function usePolitiqueFaciale() {
  const [politique, setPolitique] = useState<PolitiqueFaciale | null>(null);
  const [souci, setSouci] = useState<string | null>(null);

  useEffect(() => {
    let vivant = true;
    api.face
      .politique()
      .then((valeur) => {
        if (vivant) {
          setPolitique(valeur);
        }
      })
      .catch((probleme: unknown) => {
        if (vivant) {
          setSouci(
            probleme instanceof Error
              ? `Paramètres du contrôle facial indisponibles : ${probleme.message}`
              : "Paramètres du contrôle facial indisponibles.",
          );
        }
      });
    return () => {
      vivant = false;
    };
  }, []);

  return { politique, souci };
}

/** Caméra et boucle d'observation, partagées par la connexion et l'enrôlement. */
function useCamera() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const fluxRef = useRef<MediaStream | null>(null);
  const arretRef = useRef<(() => void) | null>(null);
  const [fluxPret, setFluxPret] = useState(false);
  const [souci, setSouci] = useState<string | null>(null);
  const [modeles, setModeles] = useState<"attente" | "chargement" | "prets" | "echec">("attente");
  const [defi, setDefi] = useState<EtatDefi>({
    visage: false,
    clignement: false,
    rotationMax: 0,
    rotation: 0,
    ouverture: 0,
    seuilFermeture: 0,
    periodeMs: 0,
    mesures: 0,
  });

  const demarrer = useCallback(async () => {
    const video = videoRef.current;
    if (video === null || fluxRef.current !== null) {
      return;
    }
    setSouci(null);
    setModeles("chargement");
    try {
      await chargerModeles();
      setModeles("prets");
    } catch (probleme) {
      setModeles("echec");
      setSouci(
        `Chargement du modèle de reconnaissance impossible : ${
          probleme instanceof Error ? probleme.message : "cause inconnue"
        }`,
      );
      return;
    }
    try {
      fluxRef.current = await ouvrirCamera(video);
      setFluxPret(true);
      arretRef.current = suivreDefi(video, setDefi);
    } catch (probleme) {
      setSouci(expliquerRefusCamera(probleme));
    }
  }, []);

  const arreter = useCallback(() => {
    arretRef.current?.();
    arretRef.current = null;
    fermerCamera(fluxRef.current);
    fluxRef.current = null;
    setFluxPret(false);
  }, []);

  useEffect(
    () => () => {
      arretRef.current?.();
      fermerCamera(fluxRef.current);
    },
    [],
  );

  /**
   * Descripteur de l'image courante, calculé à la demande.
   *
   * Il n'est plus mesuré en continu : c'est précisément ce qui rendait la
   * surveillance trop lente pour voir un clignement, et ce qui produisait une
   * mesure inutile à chaque image.
   */
  const mesurer = useCallback(async (): Promise<number[] | null> => {
    const video = videoRef.current;
    if (video === null) {
      return null;
    }
    return mesurerDescripteur(video);
  }, []);

  return { videoRef, demarrer, arreter, fluxPret, souci, modeles, defi, mesurer };
}

// =============================================================================
//  Pièces d'interface
// =============================================================================

function Coquille({ etat, children }: { etat: string; children: ReactNode }) {
  return (
    <div className="flex h-full flex-col bg-base text-ink">
      <header className="shrink-0 border-b border-line-fort">
        <div className="flex items-center justify-between px-11 py-4">
          <span className="font-display text-2xl font-extrabold uppercase tracking-[0.1em]">
            AlphaPay
          </span>
          <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-dim">
            {etat}
          </span>
        </div>
      </header>

      <div className="grid flex-1 grid-cols-[minmax(0,1fr)_520px] gap-20 px-11 py-14">
        {children}
      </div>

      <footer className="shrink-0 border-t border-line px-11 py-5">
        <div className="flex justify-between font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
          <span>Jetons signés RS256 par api-auth</span>
          <span>Chaque tentative est inscrite au journal d'audit</span>
        </div>
      </footer>
    </div>
  );
}

function Panneau({ children }: { children: ReactNode }) {
  return <section className="h-fit border border-line bg-surface px-10 py-10">{children}</section>;
}

function Filet() {
  return <div className="h-px w-full bg-line" />;
}

function Onglets({
  onglet,
  onChange,
}: {
  onglet: "mdp" | "visage";
  onChange: (valeur: "mdp" | "visage") => void;
}) {
  const entrees: Array<{ cle: "mdp" | "visage"; libelle: string }> = [
    { cle: "mdp", libelle: "Mot de passe" },
    { cle: "visage", libelle: "Reconnaissance faciale" },
  ];
  return (
    <div className="flex items-end gap-7">
      {entrees.map((entree) => (
        <button
          key={entree.cle}
          type="button"
          onClick={() => onChange(entree.cle)}
          className="group flex flex-col gap-2"
        >
          <span
            className={[
              "font-mono text-[0.625rem] uppercase tracking-[0.14em]",
              onglet === entree.cle ? "text-accent" : "text-ink-dim group-hover:text-ink",
            ].join(" ")}
          >
            {entree.libelle}
          </span>
          <span
            className={[
              "h-0.5 w-full",
              onglet === entree.cle ? "bg-accent" : "bg-transparent",
            ].join(" ")}
          />
        </button>
      ))}
    </div>
  );
}

function Champ({
  libelle,
  valeur,
  onChange,
  type = "text",
  autoFocus = false,
}: {
  libelle: string;
  valeur: string;
  onChange: (valeur: string) => void;
  type?: string;
  autoFocus?: boolean;
}) {
  return (
    <label className="block">
      <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
        {libelle}
      </span>
      <input
        type={type}
        value={valeur}
        autoFocus={autoFocus}
        autoComplete={type === "password" ? "current-password" : "username"}
        onChange={(evenement) => onChange(evenement.target.value)}
        className="mt-2 w-full border border-line bg-base px-3.5 py-3 font-mono text-sm text-ink outline-none focus:border-accent"
      />
    </label>
  );
}

function Bouton({
  children,
  onClick,
  type = "submit",
  desactive = false,
  ton = "accent",
}: {
  children: ReactNode;
  onClick?: () => void;
  type?: "submit" | "button";
  desactive?: boolean;
  ton?: "accent" | "encre";
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={desactive}
      className={[
        "w-full px-5 py-3.5 font-sans text-[0.6875rem] font-semibold uppercase tracking-[0.18em] text-white",
        ton === "accent" ? "bg-accent hover:bg-accent-dim" : "bg-ink hover:bg-ink-dim",
        desactive ? "cursor-not-allowed opacity-40" : "",
      ].join(" ")}
    >
      {children}
    </button>
  );
}

function Etiquette({ children, ton = "neutre" }: { children: ReactNode; ton?: "neutre" | "incident" }) {
  return (
    <span
      className={[
        "inline-block border px-2.5 py-1 font-mono text-[0.625rem] uppercase tracking-[0.14em]",
        ton === "incident" ? "border-marge text-marge" : "border-line-fort text-ink-dim",
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function Ligne({ libelle, valeur }: { libelle: string; valeur: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line py-2.5 last:border-0">
      <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
        {libelle}
      </span>
      <span className="font-mono text-xs text-ink">{valeur}</span>
    </div>
  );
}

function Flux({
  videoRef,
  etatFlux,
  suit,
  pret,
}: {
  videoRef: RefObject<HTMLVideoElement>;
  etatFlux: string;
  suit: string;
  pret: boolean;
}) {
  return (
    <div className="relative h-[300px] w-full overflow-hidden bg-ink">
      <video
        ref={videoRef}
        muted
        autoPlay
        playsInline
        className={["h-full w-full object-cover", pret ? "opacity-100" : "opacity-0"].join(" ")}
      />
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-0 right-0 top-1/2 h-px bg-accent/60" />
        <div className="absolute bottom-0 top-0 left-1/2 w-px bg-accent/60" />
        <div className="absolute left-6 top-6 h-4 w-4 border-l border-t border-base/60" />
        <div className="absolute right-6 top-6 h-4 w-4 border-r border-t border-base/60" />
        <div className="absolute bottom-6 left-6 h-4 w-4 border-b border-l border-base/60" />
        <div className="absolute bottom-6 right-6 h-4 w-4 border-b border-r border-base/60" />
      </div>
      <span className="absolute left-4 top-4 font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-base/80">
        {etatFlux}
      </span>
      <span className="absolute bottom-3 left-1/2 -translate-x-1/2 font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-base/80">
        {suit}
      </span>
    </div>
  );
}

// =============================================================================
//  Écran d'accès
// =============================================================================

export default function Acces() {
  const [onglet, setOnglet] = useState<"mdp" | "visage">("mdp");
  const [identifiant, setIdentifiant] = useState("");
  const [motdepasse, setMotdepasse] = useState("");
  const [erreur, setErreur] = useState<ErreurApi | null>(null);
  const [enCours, setEnCours] = useState(false);
  const [horodatage, setHorodatage] = useState<string | null>(null);

  const { politique, souci: souciPolitique } = usePolitiqueFaciale();
  const camera = useCamera();

  useEffect(() => {
    if (onglet === "visage") {
      void camera.demarrer();
    } else {
      camera.arreter();
    }
  }, [onglet, camera.demarrer, camera.arreter]);

  const retenir = (probleme: unknown) => {
    setHorodatage(new Date().toISOString());
    setErreur(
      probleme instanceof ErreurApi
        ? probleme
        : new ErreurApi(probleme instanceof Error ? probleme.message : "Échec inattendu.", 0),
    );
  };

  const soumettreMotDePasse = async (evenement: FormEvent) => {
    evenement.preventDefault();
    setErreur(null);
    setEnCours(true);
    try {
      await ouvrirParMotDePasse(identifiant.trim(), motdepasse);
    } catch (probleme) {
      retenir(probleme);
    } finally {
      setEnCours(false);
    }
  };

  const seuilRotation = politique?.challenge_min_turn_deg ?? null;
  const defiComplet =
    camera.defi.clignement &&
    seuilRotation !== null &&
    camera.defi.rotationMax >= seuilRotation;

  const soumettreVisage = async (evenement: FormEvent) => {
    evenement.preventDefault();
    if (politique === null) {
      return;
    }
    setErreur(null);
    setEnCours(true);
    try {
      // Le descripteur est mesuré maintenant, sur l'image vivante : c'est le
      // geste que le défi vient d'autoriser, pas une mesure vieille de plusieurs
      // secondes conservée en mémoire pendant la surveillance.
      const descripteur = await camera.mesurer();
      if (descripteur === null) {
        retenir(
          new ErreurApi("Aucun visage détecté dans le cadre : rien à comparer.", 0, "face_missing"),
        );
        return;
      }
      await ouvrirParVisage(identifiant.trim(), descripteur, {
        blink: camera.defi.clignement,
        turn_deg: camera.defi.rotationMax,
      });
    } catch (probleme) {
      retenir(probleme);
    } finally {
      setEnCours(false);
    }
  };

  return (
    <Coquille
      etat={onglet === "visage" ? "Reconnaissance faciale" : "Salle d'opérations"}
    >
      <section className="flex flex-col gap-7">
        <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent">
          Accès
        </span>
        <h1 className="font-display text-[2.75rem] font-bold leading-[1.15]">
          Accès au tableau de bord
        </h1>
        <p className="max-w-[520px] font-sans text-[0.8125rem] leading-[1.6] text-ink-dim">
          Deux moyens d'ouverture, un seul contrôleur. Le mot de passe est vérifié
          par api-auth ; la reconnaissance faciale compare, côté serveur, le
          descripteur calculé dans ce navigateur au gabarit enregistré du compte.
          Aucune image ne quitte ce poste.
        </p>
        <ol className="flex flex-col gap-3 border-t border-line pt-6 font-mono text-[0.6875rem] uppercase tracking-[0.1em] text-ink-dim">
          <li>01 Jeton d'accès signé RS256, renouvelable</li>
          <li>
            02 Verrouillage du compte après{" "}
            {politique === null ? "un nombre configuré" : politique.max_failed_attempts} échecs
          </li>
          <li>03 Chaque tentative inscrite au journal d'audit</li>
        </ol>
        {souciPolitique !== null ? (
          <p className="max-w-[520px] border-l-2 border-marge pl-4 font-sans text-xs text-marge">
            {souciPolitique}
          </p>
        ) : null}
      </section>

      <Panneau>
        <div className="flex flex-col gap-7">
          <Onglets onglet={onglet} onChange={setOnglet} />
          <Filet />

          {onglet === "mdp" ? (
            <form className="flex flex-col gap-5" onSubmit={soumettreMotDePasse}>
              <Champ libelle="Identifiant" valeur={identifiant} onChange={setIdentifiant} autoFocus />
              <Champ
                libelle="Mot de passe"
                valeur={motdepasse}
                onChange={setMotdepasse}
                type="password"
              />
              <Bouton desactive={enCours || identifiant.trim().length === 0 || motdepasse.length === 0}>
                {enCours ? "Vérification" : "Ouvrir la session"}
              </Bouton>
            </form>
          ) : (
            <form className="flex flex-col gap-5" onSubmit={soumettreVisage}>
              <Champ
                libelle="Identifiant"
                valeur={identifiant}
                onChange={setIdentifiant}
                autoFocus
              />
              <Flux
                videoRef={camera.videoRef}
                pret={camera.fluxPret}
                etatFlux={
                  camera.modeles === "chargement"
                    ? "Chargement du modèle"
                    : camera.fluxPret
                      ? camera.defi.visage
                        ? "Visage détecté"
                        : "Recherche du visage"
                      : camera.modeles === "echec"
                        ? "Modèle indisponible"
                        : "Caméra en attente"
                }
                suit={
                  seuilRotation === null
                    ? "Paramètres indisponibles"
                    : camera.defi.clignement
                      ? camera.defi.rotationMax.toFixed(0) + " degrés sur " + seuilRotation.toFixed(0)
                      : "Défi : clignez des yeux, puis tournez la tête"
                }
              />

              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
                    Clignement
                  </span>
                  <Etiquette ton={camera.defi.clignement ? "neutre" : "incident"}>
                    {camera.defi.clignement ? "Acquis" : "Attendu"}
                  </Etiquette>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
                    Rotation de tête
                  </span>
                  <Etiquette
                    ton={
                      seuilRotation !== null && camera.defi.rotationMax >= seuilRotation
                        ? "neutre"
                        : "incident"
                    }
                  >
                    {seuilRotation === null
                      ? "Indisponible"
                      : camera.defi.rotationMax.toFixed(0) + " degrés sur " + seuilRotation.toFixed(0)}
                  </Etiquette>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
                    Ouverture des yeux
                  </span>
                  <Etiquette ton="neutre">
                    {camera.defi.visage
                      ? camera.defi.ouverture.toFixed(2) +
                        " sous " +
                        camera.defi.seuilFermeture.toFixed(2)
                      : "Aucune mesure"}
                  </Etiquette>
                </div>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-[0.5625rem] uppercase tracking-[0.14em] text-ink-dim">
                    Cadence de mesure
                  </span>
                  <Etiquette ton="neutre">
                    {camera.defi.mesures > 0
                      ? camera.defi.periodeMs.toFixed(0) + " ms par image"
                      : "En attente"}
                  </Etiquette>
                </div>
              </div>

              <Bouton
                desactive={
                  enCours ||
                  politique === null ||
                  !camera.fluxPret ||
                  !defiComplet ||
                  identifiant.trim().length === 0
                }
              >
                {enCours ? "Vérification" : "Vérifier"}
              </Bouton>

              <button
                type="button"
                onClick={() => setOnglet("mdp")}
                className="self-center font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent"
              >
                Revenir au mot de passe
              </button>
            </form>
          )}

          {camera.souci !== null && onglet === "visage" ? (
            <p className="border-l-2 border-marge pl-4 font-sans text-xs text-marge">
              {camera.souci}
            </p>
          ) : null}

          {erreur !== null ? (
            <div className="flex flex-col gap-3 border border-marge px-5 py-4">
              <Etiquette ton="incident">Accès refusé</Etiquette>
              <p className="font-sans text-[0.8125rem] leading-relaxed text-ink">{erreur.message}</p>
              <div className="flex flex-col">
                <Ligne libelle="Motif" valeur={erreur.code} />
                {erreur.nombre("attempts") !== null ? (
                  <Ligne
                    libelle="Tentatives"
                    valeur={`${erreur.nombre("attempts")} sur ${erreur.nombre("max_attempts") ?? "?"}`}
                  />
                ) : null}
                <Ligne libelle="Identifiant" valeur={identifiant.trim() || "non renseigné"} />
                <Ligne libelle="Horodatage" valeur={horodatage ?? "inconnu"} />
              </div>
              {erreur.code === "face_not_enrolled" ? (
                <p className="font-sans text-xs text-ink-dim">
                  Aucun gabarit pour ce compte : ouvrez une session par mot de passe, puis
                  enregistrez votre visage depuis l'en-tête.
                </p>
              ) : null}
              {erreur.statut === 423 ? (
                <p className="font-sans text-xs text-ink-dim">
                  Le verrouillage est partagé entre les deux moyens : cinq échecs par visage
                  comptent autant que cinq échecs par mot de passe.
                </p>
              ) : null}
            </div>
          ) : null}

          <p className="font-mono text-[0.5625rem] leading-relaxed uppercase tracking-[0.12em] text-ink-dim">
            {politique === null
              ? "Seuil de comparaison lu sur le service"
              : "Seuil cosinus " +
                politique.threshold.toFixed(2) +
                ", défi actif " +
                politique.challenge_min_turn_deg.toFixed(0) +
                " degrés, " +
                politique.min_samples +
                " captures d'enrôlement"}
          </p>
        </div>
      </Panneau>
    </Coquille>
  );
}

// =============================================================================
//  Enrôlement du gabarit
// =============================================================================

export function Enrolement({ onFermer }: { onFermer: () => void }) {
  const session = useSession();
  const { politique, souci: souciPolitique } = usePolitiqueFaciale();
  const camera = useCamera();
  const [captures, setCaptures] = useState<number[][]>([]);
  const [erreur, setErreur] = useState<ErreurApi | null>(null);
  const [enregistre, setEnregistre] = useState<{ captures: number } | null>(null);
  const [enCours, setEnCours] = useState(false);

  useEffect(() => {
    void camera.demarrer();
  }, [camera.demarrer]);

  const attendu = politique?.min_samples ?? 0;
  const identite = etatSession().identite;

  const capturer = async () => {
    const descripteur = await camera.mesurer();
    if (descripteur === null) {
      setErreur(
        new ErreurApi("Aucun visage détecté dans le cadre : capture refusée.", 0, "face_missing"),
      );
      return;
    }
    setErreur(null);
    setCaptures((precedentes) =>
      precedentes.length >= attendu && attendu > 0 ? precedentes : [...precedentes, descripteur],
    );
  };

  const enregistrer = async () => {
    if (identite === null || captures.length === 0) {
      return;
    }
    setEnCours(true);
    setErreur(null);
    try {
      const resultat = await api.face.enroler(identite.username, captures);
      setEnregistre({ captures: resultat.captures });
    } catch (probleme) {
      setErreur(
        probleme instanceof ErreurApi
          ? probleme
          : new ErreurApi(probleme instanceof Error ? probleme.message : "Échec inattendu.", 0),
      );
    } finally {
      setEnCours(false);
    }
  };

  if (!session.ouverte) {
    return (
      <Coquille etat="Enrôlement">
        <section className="flex flex-col gap-6">
          <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent">
            Gabarit facial
          </span>
          <h1 className="font-display text-[2.75rem] font-bold leading-[1.15]">Enrôlement</h1>
          <p className="max-w-[520px] font-sans text-[0.8125rem] leading-[1.6] text-ink-dim">
            L'enregistrement d'un gabarit exige une session ouverte : le service
            n'accepte un enrôlement que pour le compte authentifié qui le demande.
            Ouvrez d'abord une session par mot de passe.
          </p>
        </section>
        <Panneau>
          <Bouton type="button" onClick={onFermer}>
            Revenir à l'accès
          </Bouton>
        </Panneau>
      </Coquille>
    );
  }

  return (
    <Coquille etat="Enrôlement facial">
      <section className="flex flex-col gap-7">
        <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent">
          Gabarit facial
        </span>
        <h1 className="font-display text-[2.75rem] font-bold leading-[1.15]">
          Enrôlement de l'opérateur
        </h1>
        <p className="max-w-[520px] font-sans text-[0.8125rem] leading-[1.6] text-ink-dim">
          Les captures sont transformées en descripteurs dans ce navigateur, puis
          envoyées au service qui n'en conserve que la moyenne normalisée. Le
          visage lui-même n'est ni transmis ni stocké.
        </p>
        <ol className="flex flex-col gap-3 border-t border-line pt-6 font-mono text-[0.6875rem] uppercase tracking-[0.1em] text-ink-dim">
          <li>01 {attendu > 0 ? attendu : "un nombre"} captures, angles et lumières variés</li>
          <li>02 Compte authentifié : {identite?.username ?? "inconnu"}</li>
          <li>03 Gabarit remplacé à chaque nouvel enrôlement</li>
        </ol>
        {souciPolitique !== null ? (
          <p className="max-w-[520px] border-l-2 border-marge pl-4 font-sans text-xs text-marge">
            {souciPolitique}
          </p>
        ) : null}
      </section>

      <Panneau>
        <div className="flex flex-col gap-6">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[0.625rem] uppercase tracking-[0.14em] text-ink-dim">
              Captures
            </span>
            <Etiquette>
              {captures.length} sur {attendu > 0 ? attendu : "?"}
            </Etiquette>
          </div>

          <Flux
            videoRef={camera.videoRef}
            pret={camera.fluxPret}
            etatFlux={camera.fluxPret ? "Flux actif" : "Caméra en attente"}
            suit={camera.defi.visage ? "Visage détecté, cadrage stable" : "Placez le visage au centre"}
          />

          <div className="grid grid-cols-4 gap-3">
            {Array.from({ length: Math.max(attendu, captures.length, 4) }, (_, rang) => {
              const faite = rang < captures.length;
              return (
                <div
                  key={rang}
                  className={[
                    "flex h-[84px] flex-col justify-between border px-2.5 py-2",
                    faite ? "border-accent bg-line" : "border-line bg-base",
                  ].join(" ")}
                >
                  <span className="font-mono text-[0.5625rem] tracking-[0.12em] text-ink-dim">
                    {String(rang + 1).padStart(2, "0")}
                  </span>
                  <span
                    className={[
                      "font-mono text-[0.5625rem] uppercase tracking-[0.12em]",
                      faite ? "text-accent" : "text-ink-dim",
                    ].join(" ")}
                  >
                    {faite ? "acquise" : "vide"}
                  </span>
                </div>
              );
            })}
          </div>

          <div className="flex flex-col gap-2">
            <div className="flex items-center justify-between font-mono text-[0.5625rem] uppercase tracking-[0.12em] text-ink-dim">
              <span>Qualité de l'enrôlement</span>
              <span>
                {attendu > 0 ? Math.round((captures.length / attendu) * 100) : 0} pour cent
              </span>
            </div>
            <div className="h-1.5 w-full bg-line">
              <div
                className="h-full bg-accent"
                style={{
                  width: `${
                    attendu > 0 ? Math.min(100, (captures.length / attendu) * 100) : 0
                  }%`,
                }}
              />
            </div>
          </div>

          <Bouton
            type="button"
            onClick={() => void capturer()}
            ton="encre"
            desactive={!camera.fluxPret || (attendu > 0 && captures.length >= attendu)}
          >
            Capturer une vue
          </Bouton>

          <Bouton
            type="button"
            onClick={() => void enregistrer()}
            desactive={enCours || attendu === 0 || captures.length < attendu}
          >
            {enCours ? "Enregistrement" : "Enregistrer le gabarit"}
          </Bouton>

          <button
            type="button"
            onClick={onFermer}
            className="self-center font-mono text-[0.625rem] uppercase tracking-[0.14em] text-accent"
          >
            Fermer
          </button>

          {camera.souci !== null ? (
            <p className="border-l-2 border-marge pl-4 font-sans text-xs text-marge">
              {camera.souci}
            </p>
          ) : null}

          {enregistre !== null ? (
            <div className="border border-accent px-5 py-4 font-sans text-[0.8125rem] text-ink">
              Gabarit enregistré : {enregistre.captures} captures retenues. Vous pouvez fermer
              la session et vous reconnecter par reconnaissance faciale.
            </div>
          ) : null}

          {erreur !== null ? (
            <div className="border border-marge px-5 py-4">
              <p className="font-sans text-[0.8125rem] text-ink">{erreur.message}</p>
              <p className="mt-2 font-mono text-[0.5625rem] uppercase tracking-[0.12em] text-marge">
                {erreur.code}
              </p>
            </div>
          ) : null}
        </div>
      </Panneau>
    </Coquille>
  );
}
