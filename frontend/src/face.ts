/**
 * Reconnaissance faciale dans le navigateur.
 *
 * Le descripteur est calculé ici, sur le poste. Aucune image ne quitte le
 * navigateur : seuls les 128 nombres du descripteur partent vers le service,
 * qui les compare au gabarit du compte. Le flux vidéo ne traverse jamais le
 * réseau, et c'est vérifiable dans l'onglet réseau du navigateur pendant la
 * démonstration.
 *
 * Le défi actif est observé de la même façon, sur les 68 points de repère du
 * visage : un clignement (fermeture puis réouverture des paupières) et une
 * rotation de tête. Sans lui, une photographie tenue devant la caméra produit
 * exactement le même descripteur qu'un visage vivant.
 */
import * as faceapi from "@vladmandic/face-api";

export interface PolitiqueFaciale {
  dimension: number;
  threshold: number;
  min_samples: number;
  challenge_min_turn_deg: number;
  max_failed_attempts: number;
  lockout_seconds: number;
  images_transmitted: boolean;
}

export interface Observation {
  visage: boolean;
  descripteur: number[] | null;
  yeuxOuverts: boolean;
  rotationDegres: number;
}

export interface EtatDefi {
  visage: boolean;
  clignement: boolean;
  rotationMax: number;
  rotation: number;
}

/** Seuil de fermeture des paupières sur le rapport d'ouverture de l'œil. */
const SEUIL_OEIL_FERME = 0.2;

/** Durée minimale de fermeture retenue comme un clignement, en millisecondes :
 *  en dessous, c'est du bruit de détection, pas une paupière. */
const DUREE_CLIGNEMENT_MS = 60;

const OPTIONS_DETECTION = new faceapi.TinyFaceDetectorOptions({
  inputSize: 320,
  scoreThreshold: 0.35,
});

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
  video.srcObject = flux;
  await video.play();
  return flux;
}

export function fermerCamera(flux: MediaStream | null): void {
  flux?.getTracks().forEach((piste) => piste.stop());
}

function ecart(a: faceapi.Point, b: faceapi.Point): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

/** Rapport d'ouverture de l'œil : petit quand la paupière est fermée. */
function ouvertureOeil(points: faceapi.Point[], index: number[]): number {
  const p = index.map((rang) => points[rang]);
  const hauteur = (ecart(p[1], p[5]) + ecart(p[2], p[4])) / 2;
  return hauteur / Math.max(1e-6, ecart(p[0], p[3]));
}

/**
 * Estimation du lacet à partir de la position du nez dans le cadre du visage.
 *
 * C'est une approximation, et elle est assumée : sans calibrage individuel, un
 * modèle de pose serait plus faux encore. Le seuil appliqué ne vient pas d'ici,
 * il vient du service : cette fonction fournit une mesure, pas une décision.
 */
function rotationEstimee(
  points: faceapi.Point[],
  cadre: { x: number; y: number; width: number; height: number },
): number {
  const nez = points[30];
  const centre = cadre.x + cadre.width / 2;
  const demi = Math.max(1e-6, cadre.width / 2);
  const rapport = (nez.x - centre) / demi;
  return Math.max(-90, Math.min(90, rapport * 45));
}

export async function observer(video: HTMLVideoElement): Promise<Observation> {
  const resultat = await faceapi
    .detectSingleFace(video, OPTIONS_DETECTION)
    .withFaceLandmarks()
    .withFaceDescriptor();

  if (!resultat) {
    return { visage: false, descripteur: null, yeuxOuverts: true, rotationDegres: 0 };
  }

  const points = resultat.landmarks.positions;
  const ouverture =
    (ouvertureOeil(points, [36, 37, 38, 39, 40, 41]) +
      ouvertureOeil(points, [42, 43, 44, 45, 46, 47])) /
    2;

  return {
    visage: true,
    descripteur: Array.from(resultat.descriptor as Float32Array),
    yeuxOuverts: ouverture > SEUIL_OEIL_FERME,
    rotationDegres: rotationEstimee(points, resultat.detection.box),
  };
}

/**
 * Suit le défi actif image par image et publie son état.
 *
 * Retourne une fonction d'arrêt : la boucle doit être interrompue dès que
 * l'écran change, sinon elle continue de solliciter la caméra en arrière-plan.
 */
export function suivreDefi(
  video: HTMLVideoElement,
  surEtat: (etat: EtatDefi) => void,
  surDescripteur: (descripteur: number[]) => void,
  intervalleMs = 120,
): () => void {
  let arrete = false;
  let clignement = false;
  let rotationMax = 0;
  let debutFermeture = 0;

  const tourner = async (): Promise<void> => {
    if (arrete) {
      return;
    }
    try {
      const image = await observer(video);
      if (image.visage && image.descripteur !== null) {
        surDescripteur(image.descripteur);
        if (!image.yeuxOuverts) {
          if (debutFermeture === 0) {
            debutFermeture = performance.now();
          }
        } else if (debutFermeture > 0) {
          if (performance.now() - debutFermeture >= DUREE_CLIGNEMENT_MS) {
            clignement = true;
          }
          debutFermeture = 0;
        }
        rotationMax = Math.max(rotationMax, Math.abs(image.rotationDegres));
        surEtat({
          visage: true,
          clignement,
          rotationMax,
          rotation: image.rotationDegres,
        });
      } else {
        surEtat({ visage: false, clignement, rotationMax, rotation: 0 });
      }
    } catch {
      /* une image ratée ne doit pas interrompre la boucle */
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
