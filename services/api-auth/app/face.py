"""AlphaPay : gabarits faciaux, comparaison et validation du défi actif.

Ce module ne dépend ni de la base ni de la configuration : il ne manipule que
des nombres. Ce n'est pas un détail de rangement.

* La décision d'authentification faciale doit être vérifiable sans PostgreSQL ni
  service démarré : ce qui décide, ici, c'est la distance entre deux
  descripteurs, la validation du défi actif et le seuil retenu.
* Aucune image ne traverse ce module, et aucune ne traverse le service. Le
  navigateur calcule un descripteur de 128 nombres avec le modèle FaceNet
  (face-api.js, exécuté sur le poste) et n'envoie que ce vecteur. Le serveur ne
  voit jamais le visage, ne le stocke jamais et ne le journalise jamais.

Le gabarit conservé en base est la moyenne normalisée des descripteurs des
captures d'enrôlement : moyenner réduit le bruit de pose et d'éclairage, et la
normalisation rend la comparaison cosinus stable d'une capture à l'autre.
"""

from __future__ import annotations

import math

DIMENSION_DESCRIPTEUR = 128
"""Taille du descripteur produit par face-api.js (modèle `face_recognition`)."""

BORNE_DESCRIPTEUR = 1.0
"""Les descripteurs FaceNet sont bornés : chaque composante est dans [-1, 1]."""

DISTANCE_MAXIMALE = 2.0
"""Distance cosinus maximale (deux vecteurs opposés)."""


class DescripteurInvalide(ValueError):
    """Descripteur refusé avant toute comparaison, ou gabarit inexploitable."""


def valider_descripteur(valeurs: object) -> tuple[float, ...]:
    """Vérifie la forme d'un descripteur et le convertit en flottants.

    Les refus sont volontairement bavards : ils décrivent une capture mal formée,
    jamais un visage. Un descripteur refusé n'est ni comparé ni stocké.
    """
    if isinstance(valeurs, (str, bytes)) or not isinstance(valeurs, (list, tuple)):
        raise DescripteurInvalide("Le descripteur doit être une liste de nombres.")
    if len(valeurs) != DIMENSION_DESCRIPTEUR:
        raise DescripteurInvalide(
            f"Le descripteur doit contenir exactement {DIMENSION_DESCRIPTEUR} valeurs, "
            f"reçu {len(valeurs)}."
        )
    propre: list[float] = []
    for position, valeur in enumerate(valeurs):
        if isinstance(valeur, bool) or not isinstance(valeur, (int, float)):
            raise DescripteurInvalide(f"Valeur non numérique à la position {position}.")
        nombre = float(valeur)
        if not math.isfinite(nombre):
            raise DescripteurInvalide(f"Valeur non finie à la position {position}.")
        if abs(nombre) > BORNE_DESCRIPTEUR:
            raise DescripteurInvalide(f"Valeur hors bornes à la position {position}.")
        propre.append(nombre)
    return tuple(propre)


def norme(valeurs: tuple[float, ...] | list[float]) -> float:
    return math.sqrt(sum(valeur * valeur for valeur in valeurs))


def distance_cosinus(
    gauche: tuple[float, ...] | list[float],
    droite: tuple[float, ...] | list[float],
) -> float:
    """Distance cosinus dans [0, 2] : 0 pour deux vecteurs identiques en direction.

    Un vecteur nul n'a pas de direction : la comparaison n'a pas de sens et la
    réponse prudente est la distance maximale, donc le refus.
    """
    if len(gauche) != len(droite):
        raise DescripteurInvalide("Descripteurs de tailles différentes.")
    norme_gauche = norme(gauche)
    norme_droite = norme(droite)
    if norme_gauche == 0.0 or norme_droite == 0.0:
        return DISTANCE_MAXIMALE
    produit = sum(x * y for x, y in zip(gauche, droite))
    similarite = produit / (norme_gauche * norme_droite)
    return max(0.0, min(DISTANCE_MAXIMALE, 1.0 - similarite))


def distance_acceptee(distance: float, seuil: float) -> bool:
    """Le seuil est inclusif : distance inférieure ou égale au seuil est acceptée."""
    return distance <= seuil


def gabarit_moyen(captures: list[tuple[float, ...]] | list[list[float]]) -> list[float]:
    """Moyenne des captures, ramenée sur la sphère unité.

    Un gabarit non normalisé ferait dépendre la distance de la luminosité de la
    pièce plutôt que de l'identité.
    """
    if not captures:
        raise DescripteurInvalide("Aucune capture à moyenner.")
    dimension = len(captures[0])
    for rang, capture in enumerate(captures, start=1):
        if len(capture) != dimension:
            raise DescripteurInvalide(f"Capture {rang} de dimension inattendue.")
    nombre = len(captures)
    moyennes = [
        sum(float(capture[position]) for capture in captures) / nombre
        for position in range(dimension)
    ]
    longueur = norme(moyennes)
    if longueur == 0.0:
        raise DescripteurInvalide("Captures inexploitables : moyenne nulle.")
    return [valeur / longueur for valeur in moyennes]


def evaluer_defi(
    *,
    clignement: bool,
    rotation_degres: float,
    seuil_rotation_degres: float,
    exiger_clignement: bool = True,
    exiger_rotation: bool = True,
) -> tuple[bool, str]:
    """Défi actif, évalué selon les gestes que le service exige.

    Sans ce contrôle, une photo tenue devant la caméra produit exactement le
    même descripteur qu'un visage vivant et ouvrirait la session.

    Les gestes exigés sont un réglage du service, publié par `GET /face/policy` :
    l'interface affiche ce que le service réclame, et le service refuse ce qui
    manque. Un défi à géométrie variable reste un contrôle, à condition qu'il
    reste au moins un geste : l'absence totale est refusée au démarrage, voir la
    vérification de cohérence dans `main.py`.
    """
    if not exiger_clignement and not exiger_rotation:
        # Second verrou, volontairement redondant avec la vérification de
        # cohérence du service : une fonction de décision ne doit jamais pouvoir
        # valider un défi vide, même appelée directement.
        return False, "aucun geste exigé"
    if exiger_clignement and not clignement:
        return False, "clignement non observé"
    if exiger_rotation:
        if isinstance(rotation_degres, bool) or not isinstance(rotation_degres, (int, float)):
            return False, "rotation illisible"
        rotation = float(rotation_degres)
        if not math.isfinite(rotation):
            return False, "rotation illisible"
        if abs(rotation) < seuil_rotation_degres:
            return False, f"rotation insuffisante ({abs(rotation):.1f} degrés)"
    return True, "défi validé"
