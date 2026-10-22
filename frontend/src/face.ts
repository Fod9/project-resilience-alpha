/**
 * Reconnaissance faciale dans le navigateur.
 *
 * Le descripteur est calculé ici, sur le poste. Aucune image ne quitte le
 * navigateur : seuls les 128 nombres du descripteur partent vers le service, qui
 * les compare au gabarit du compte. Le flux vidéo ne traverse jamais le réseau,
 * et c'est vérifiable dans l'onglet réseau du navigateur.
 *
 * Deux boucles distinctes, et c'est délibéré :
 *   * la surveillance du défi ne demande que les points de repère du visage :
 *     elle tourne toutes les 60 ms, assez serré pour voir une paupière qui se
 *     ferme cent millisecondes ;
 *   * le calcul du descripteur mobilise le réseau de reconnaissance, dix fois
 *     plus lourd, et n'a lieu qu'au moment utile : une capture d'enrôlement, ou
 *     la vérification demandée par l'opérateur.
 * Les confondre, c'était mesurer une fois toutes les cinq cents millisecondes et
 * manquer tous les clignements.
 */
import * as faceapi from "@vladmandic/face-api";

export * from "./defi";

import { SuiviClignement, lacetEstime, ouvertureDesYeux, type PointRepere } from "./defi";

/** Paramètres publics du contrôle facial, lus depuis le service. */
export interface PolitiqueFaciale {
  dimension: number;
  threshold: number;
  min_samples: number;
  challenge_min_turn_deg: number;
  /** Gestes réclamés par le service : l'interface ne les suppose jamais. */
  require_blink: boolean;
  require_turn: boolean;
  max_failed_attempts: number;
  lockout_seconds: number;
  images_transmitted: boolean;
}

/** Mesure d'une image, sans descripteur : c'est le régime de la surveillance. */
export interface ObservationRapide {
  visage: boolean;
  ouverture: number;
  rotationDegres: number;
}

/** État du défi, publié à chaque mesure et affiché tel quel. */
export interface EtatDefi {
  visage: boolean;
  clignement: boolean;
  rotationMax: number;
  rotation: number;
  ouverture: number;
  seuilFermeture: number;
  periodeMs: number;
  mesures: number;
}

const OPTIONS_DETECTION = new faceapi.TinyFaceDetectorOptions({
  inputSize: 320,
  scoreThreshold: 0.35,
});

/** Cadence de la surveillance du défi. Un clignement dure une centaine de
 *  millisecondes : à 60 ms, on dispose de deux mesures pour le voir. */
export const PERIODE_DEFI_MS = 60;

export async function chargerModeles(dossier = "/models"): Promise<void> {
  await faceapi.nets.tinyFaceDetector.loadFromUri(dossier);
  await faceapi.nets.faceLandmark68Net.loadFromUri(dossier);
  await faceapi.nets.faceRecognitionNet.loadFromUri(dossier);
}

export async function ouvrirCamera(video: HTMLVideoElement): Promise<MediaStream> {
  const flux = await navigator.mediaDevices.getUserMedia({
    video: { width: { ideal: 640 }, height: { ideal: 480 }, facingMode: "user" },
    audio: false,
  });
  if (video.srcObject !== flux) {
    video.srcObject = flux;
  }
  // `play()` est interrompu lorsque la source change pendant la lecture : c'est
  // exactement ce qui se produit au passage de l'écran d'accès au tableau de
  // bord, ou d'un onglet à l'autre. L'interruption n'est pas une panne : le flux
  // reste attaché et l'attribut `autoplay` prend le relais. On ne laisse donc
  // pas une promesse rejetée remonter dans la console, ce qui ferait passer un
  // changement d'écran pour une erreur.
  try {
    await video.play();
  } catch (erreur) {
    if (!(erreur instanceof DOMException) || erreur.name !== "AbortError") {
      throw erreur;
    }
  }
  if (!video.isConnected) {
    // L'élément a été démonté pendant l'ouverture : on rend la caméra au poste.
    flux.getTracks().forEach((piste) => piste.stop());
  }
  return flux;
}

export function fermerCamera(flux: MediaStream | null): void {
  flux?.getTracks().forEach((piste) => piste.stop());
}

/**
 * Une image, sans descripteur : détecteur de visage et points de repère.
 * C'est le régime léger, celui qui peut tourner toutes les 60 ms.
 */
export async function observerRapide(video: HTMLVideoElement): Promise<ObservationRapide> {
  const resultat = await faceapi
    .detectSingleFace(video, OPTIONS_DETECTION)
    .withFaceLandmarks();
  if (!resultat) {
    return { visage: false, ouverture: 0, rotationDegres: 0 };
  }
  const points = resultat.landmarks.positions as unknown as PointRepere[];
  return {
    visage: true,
    ouverture: ouvertureDesYeux(points),
    rotationDegres: lacetEstime(points, resultat.detection.box),
  };
}

/**
 * Descripteur de l'image courante, à la demande.
 *
 * Mobilise le réseau de reconnaissance : quelques centaines de millisecondes.
 * On l'appelle donc au moment utile, jamais en continu.
 */
export async function mesurerDescripteur(video: HTMLVideoElement): Promise<number[] | null> {
  const resultat = await faceapi
    .detectSingleFace(video, OPTIONS_DETECTION)
    .withFaceLandmarks()
    .withFaceDescriptor();
  if (!resultat) {
    return null;
  }
  return Array.from(resultat.descriptor as Float32Array);
}

/**
 * Surveille le défi actif et publie chaque mesure.
 *
 * Retourne une fonction d'arrêt : la boucle doit être interrompue dès que
 * l'écran change, sinon elle continue de solliciter la caméra en arrière-plan.
 */
export function suivreDefi(
  video: HTMLVideoElement,
  surEtat: (etat: EtatDefi) => void,
  intervalleMs = PERIODE_DEFI_MS,
): () => void {
  const suivi = new SuiviClignement();
  let arrete = false;
  let rotationMax = 0;
  let mesures = 0;
  let derniere = performance.now();

  const tourner = async (): Promise<void> => {
    if (arrete) {
      return;
    }
    const debut = performance.now();
    try {
      const image = await observerRapide(video);
      if (image.visage) {
        suivi.mesurer(image.ouverture, debut);
        rotationMax = Math.max(rotationMax, Math.abs(image.rotationDegres));
      }
      mesures += 1;
      surEtat({
        visage: image.visage,
        clignement: suivi.estAcquis,
        rotationMax,
        rotation: image.visage ? image.rotationDegres : 0,
        ouverture: image.ouverture,
        seuilFermeture: suivi.seuilFermeture,
        periodeMs: mesures > 1 ? debut - derniere : 0,
        mesures,
      });
      derniere = debut;
    } catch {
      /* une image ratée ne doit pas interrompre la surveillance */
    }
    if (!arrete) {
      window.setTimeout(() => void tourner(), intervalleMs);
    }
  };

  void tourner();
  return () => {
    arrete = true;
  };
}

/** Message lisible pour un refus de caméra, sans jamais masquer la cause. */
export function expliquerRefusCamera(erreur: unknown): string {
  const nom = erreur instanceof Error ? erreur.name : "";
  if (nom === "NotAllowedError") {
    return "Accès à la caméra refusé par le navigateur. Autorisez la caméra pour ce site, puis réessayez.";
  }
  if (nom === "NotFoundError") {
    return "Aucune caméra détectée sur ce poste.";
  }
  if (nom === "NotReadableError") {
    return "La caméra est déjà utilisée par une autre application.";
  }
  if (typeof navigator === "undefined" || !navigator.mediaDevices) {
    return "Ce navigateur n'expose pas la caméra hors contexte sécurisé : la page doit être servie en HTTPS.";
  }
  return erreur instanceof Error ? erreur.message : "Caméra indisponible.";
}
