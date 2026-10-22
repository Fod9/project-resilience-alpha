/**
 * Défi actif : mesures pures, sans caméra ni modèle.
 *
 * Ce module est isolé pour une raison précise : le clignement doit être
 * vérifiable. Détecter une paupière est un calcul sur des points, pas une
 * dépendance à un navigateur, et séparer les deux permet d'éprouver la règle sur
 * des séquences synthétiques aux vraies durées. Un clignement dure une centaine
 * de millisecondes : la règle doit être assez fine pour le voir, et assez
 * prudente pour ne pas prendre un cillement de bruit de mesure pour une paupière.
 *
 * Rien ici ne tranche une authentification : le service décide. Ces fonctions
 * produisent des mesures, affichées à l'écran, et l'état du défi.
 */

export interface PointRepere {
  x: number;
  y: number;
}

/** Points de repère des paupières (modèle à 68 points). */
export const OEIL_GAUCHE = [36, 37, 38, 39, 40, 41];
export const OEIL_DROIT = [42, 43, 44, 45, 46, 47];
export const BOUT_DU_NEZ = 30;

/** Sous ce rapport, l'œil est fermé quel que soit le visage : plancher absolu. */
export const OUVERTURE_PLANCHER = 0.15;

/** Part du maximum observé sous laquelle l'œil est considéré fermé. */
export const PART_DE_REFERENCE = 0.7;

/** Au-delà, une fermeture n'est plus un clignement mais un regard baissé. */
export const FERMETURE_MAXIMALE_MS = 1500;

/** Nombre de mesures conservées pour estimer l'ouverture de référence. */
const TAILLE_HISTORIQUE = 40;

function ecart(a: PointRepere, b: PointRepere): number {
  return Math.hypot(a.x - b.x, a.y - b.y);
}

/** Rapport d'ouverture d'un œil : environ 0,3 ouvert, sous 0,15 fermé. */
export function ouvertureOeil(points: PointRepere[], index: number[]): number {
  const p = index.map((rang) => points[rang]);
  const hauteur = (ecart(p[1], p[5]) + ecart(p[2], p[4])) / 2;
  return hauteur / Math.max(1e-6, ecart(p[0], p[3]));
}

export function ouvertureDesYeux(points: PointRepere[]): number {
  return (ouvertureOeil(points, OEIL_GAUCHE) + ouvertureOeil(points, OEIL_DROIT)) / 2;
}

/**
 * Lacet approximé par la position du nez dans le cadre du visage.
 *
 * Approximation assumée : sans calibrage individuel, un modèle de pose serait
 * plus faux encore. Le seuil ne vient pas d'ici, il vient du service.
 */
export function lacetEstime(
  points: PointRepere[],
  cadre: { x: number; y: number; width: number; height: number },
): number {
  const nez = points[BOUT_DU_NEZ];
  const centre = cadre.x + cadre.width / 2;
  const demi = Math.max(1e-6, cadre.width / 2);
  return Math.max(-90, Math.min(90, ((nez.x - centre) / demi) * 45));
}

/**
 * Suivi du clignement, mesure après mesure.
 *
 * La décision s'appuie sur une référence vivante : le maximum d'ouverture
 * observé récemment sur ce visage. Un seuil fixe se trompe d'un visage à
 * l'autre, et se trompe encore sur un porteur de lunettes. Un clignement est
 * donc une fermeture franche suivie d'une réouverture rapide. Une fermeture qui
 * dure n'en est pas un : c'est un regard baissé, et il ne compte pas.
 *
 * Une baisse isolée d'une seule mesure n'est retenue que si elle est franche,
 * sous le plancher absolu. Sinon c'est du bruit de détection de points, et le
 * prendre pour une paupière reviendrait à accepter une photographie.
 */
export class SuiviClignement {
  private readonly historique: number[] = [];
  private debutFermeture: number | null = null;
  private mesuresFermees = 0;
  private plusFermee = 1;
  private acquis = false;

  get estAcquis(): boolean {
    return this.acquis;
  }

  /** Référence courante d'ouverture, et seuil de fermeture qui en découle. */
  get seuilFermeture(): number {
    const ouverts = this.historique.filter((valeur) => valeur > OUVERTURE_PLANCHER);
    const reference = ouverts.length > 0 ? Math.max(...ouverts) : 0.3;
    return Math.max(OUVERTURE_PLANCHER, reference * PART_DE_REFERENCE);
  }

  /** Dernière ouverture mesurée, pour l'affichage. */
  get derniereOuverture(): number {
    return this.historique.length > 0 ? this.historique[this.historique.length - 1] : 0;
  }

  /** Enregistre une mesure ; retourne vrai si un clignement vient d'être vu. */
  mesurer(ouverture: number, instant: number): boolean {
    if (!Number.isFinite(ouverture) || ouverture <= 0) {
      return false;
    }
    this.historique.push(ouverture);
    if (this.historique.length > TAILLE_HISTORIQUE) {
      this.historique.shift();
    }
    const seuil = this.seuilFermeture;

    if (ouverture < seuil) {
      if (this.debutFermeture === null) {
        this.debutFermeture = instant;
        this.mesuresFermees = 0;
        this.plusFermee = ouverture;
      }
      this.mesuresFermees += 1;
      this.plusFermee = Math.min(this.plusFermee, ouverture);
      return false;
    }

    if (this.debutFermeture === null) {
      return false;
    }
    const duree = instant - this.debutFermeture;
    const franche = this.plusFermee <= OUVERTURE_PLANCHER;
    const tenue = this.mesuresFermees >= 2;
    this.debutFermeture = null;
    this.mesuresFermees = 0;
    this.plusFermee = 1;

    if (duree <= FERMETURE_MAXIMALE_MS && (tenue || franche)) {
      this.acquis = true;
      return true;
    }
    return false;
  }
}
