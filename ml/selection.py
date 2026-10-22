#!/usr/bin/env python3
"""Choisit les variables du modele a partir des bandes mesurees.

Pourquoi une selection supervisee
---------------------------------
Un Isolation Forest rend un score unique, moyenne sur toutes les dimensions
qu'on lui donne. Quand une plateforme ne manifeste une attaque que sur deux
axes et que seize autres axes ne portent que du bruit de regime, ce score noie
le signal : mesure faite sur une pile reelle, les fenetres d'attaque etaient
notees 0,094 a 0,186 pendant que des fenetres nominales atteignaient 0,163, et
les deux variables qui separaient reellement (le taux d'erreur, de 0 a 0,90, et
le debit, de 0,28 a 117) portaient deux dix-huitiemes de la decision.

Le choix n'est pas fait a la main et ne peut pas l'etre : il depend de la
plateforme, de sa bordure et de son trafic. Il est donc *mesure*, sur les
fenetres nominales et les fenetres d'attaque observees, et il est publie avec
ses chiffres. Une variable est retenue si son minimum d'attaque depasse son
maximum nominal d'un facteur suffisant ; en dessous, les deux bandes se
touchent et l'ordre peut s'inverser a la fenetre suivante.

Aucune dependance hors bibliotheque standard : ce module est lu aussi bien
depuis un poste de developpement que depuis un conteneur.
"""

from __future__ import annotations

from typing import Any, Sequence

#: Ecart minimal entre maximum nominal et minimum d'attaque pour retenir une
#: variable. En dessous, deux valeurs voisines suffisent a inverser l'ordre des
#: bandes, et le seuil devient une coincidence.
RAPPORT_MINIMUM = 1.5

#: Nombre de variables retenues au plus. Au dela, le score se remet a moyenner
#: du bruit, ce qui est exactement le defaut qu'on corrige.
MAXIMUM_VARIABLES = 6


def separations(
    nominales: Sequence[Sequence[float]],
    attaques: Sequence[Sequence[float]],
    noms: Sequence[str],
    rapport_minimum: float = RAPPORT_MINIMUM,
) -> dict[str, dict[str, float]]:
    """Ecart mesure entre le maximum nominal et le minimum d'attaque, par variable.

    Renvoie, pour chaque variable retenue, son rapport et ses deux bornes. Une
    variable non retenue est absente, et son absence est aussi une information :
    elle ne distingue pas l'attaque du regime courant sur cette plateforme.
    """
    retenues: dict[str, dict[str, float]] = {}
    for rang, nom in enumerate(noms):
        if not nominales or not attaques:
            continue
        haut = max(float(ligne[rang]) for ligne in nominales)
        bas = min(float(ligne[rang]) for ligne in attaques)
        if haut <= 0.0 < bas:
            # Le nominal ne produit jamais cette variable : toute valeur non
            # nulle est deja un signe. C'est le cas du taux d'erreur sur une
            # plateforme saine.
            retenues[nom] = {
                "rapport": float("inf"),
                "nominal_max": haut,
                "attaque_min": bas,
            }
            continue
        if bas > haut > 0.0:
            rapport = bas / haut
            if rapport >= rapport_minimum:
                retenues[nom] = {
                    "rapport": rapport,
                    "nominal_max": haut,
                    "attaque_min": bas,
                }
    return retenues


def choisir(
    nominales: Sequence[Sequence[float]],
    attaques: Sequence[Sequence[float]],
    noms: Sequence[str],
    rapport_minimum: float = RAPPORT_MINIMUM,
    maximum: int = MAXIMUM_VARIABLES,
) -> tuple[list[str], dict[str, dict[str, float]]]:
    """Variables retenues, de la plus nette a la moins nette.

    Renvoie `(noms_retenus, tableau_des_separations)`. La liste peut etre vide :
    c'est alors que la plateforme ne separe pas ses propres attaques, et la
    calibration doit refuser de publier plutot que de fabriquer un seuil.
    """
    tableau = separations(nominales, attaques, noms, rapport_minimum)
    ordonnees = sorted(
        tableau.items(), key=lambda item: item[1]["rapport"], reverse=True
    )
    retenues = [nom for nom, _ in ordonnees[:maximum]]
    return retenues, tableau


def resume(tableau: dict[str, dict[str, float]]) -> str:
    """Tableau des separations, lisible sur une ligne par variable."""
    if not tableau:
        return "aucune variable ne separe les deux bandes mesurees"
    lignes = []
    for nom, mesures in sorted(
        tableau.items(), key=lambda item: item[1]["rapport"], reverse=True
    ):
        rapport = mesures["rapport"]
        texte = "infini" if rapport == float("inf") else "%.2f" % rapport
        lignes.append(
            "%s (nominal <= %.4f < attaque >= %.4f, rapport %s)"
            % (nom, mesures["nominal_max"], mesures["attaque_min"], texte)
        )
    return " ; ".join(lignes)


def projetter(
    lignes: Sequence[Sequence[float]], noms: Sequence[str], variables: Sequence[str]
) -> list[list[float]]:
    """Restreint des vecteurs complets aux variables retenues, dans leur ordre."""
    rangs = [list(noms).index(nom) for nom in variables]
    return [[float(ligne[rang]) for rang in rangs] for ligne in lignes]
