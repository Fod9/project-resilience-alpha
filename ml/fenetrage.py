#!/usr/bin/env python3
"""Ce qu'une fenetre de telemetrie peut apprendre a une calibration.

Une calibration nominale est un jeu d'entrainement comme un autre : il ne vaut
que par ce qu'il contient. Sur un poste qui a deja servi, l'historique de
telimetrie contient aussi bien le regime de repos que les fenetres d'une attaque
passee, la consultation du tableau de bord par l'operateur, et les premieres
fenetres de mise en route, dont les variables derivees de la memoire longue ne
veulent rien dire.

Melangees, ces fenetres ne decrivent plus « la normale » mais « tout ce que la
plateforme a fait ». Le modele apprend alors que l'attaque fait partie du
comportement ordinaire, le quantile haut du nominal grimpe au niveau des profils
d'attaque, et la calibration refuse de publier un seuil : c'est le recouvrement.
Le refus est correct, mais il arrive apres coup ; il vaut mieux ne pas nourrir la
calibration avec des fenetres qui ne sont pas nominales.

Ce module rassemble ce tri a un seul endroit, pour que les deux chemins de
calibration (`ml.recalibrer`, `ml.calibrer_sur_mesures`) ecartent exactement les
memes fenetres.

Aucun import hors bibliotheque standard : ce module est lu aussi bien depuis un
poste de developpement que depuis un conteneur.
"""

from __future__ import annotations

from typing import Any

#: Agents dont la presence dans une fenetre trahit le banc offensif. Le banc
#: s'annonce (`User-Agent: AlphaPay-RedTeam/1.0`) : c'est une commodite de
#: mesure, pas une defense. Une fenetre qui porte cette marque decrit une
#: agression, jamais une normale.
MARQUES_OFFENSIVES = ("redteam", "alphapay-redteam", "alpha-redteam")

#: Motif d'exclusion des fenetres d'agression. Nomme une fois : il est produit
#: par `fenetre_nominale` et recherche par `agressions_mesurees`, une divergence
#: entre les deux ferait silencieusement disparaitre la reference mesuree.
MOTIF_AGRESSION = "agression"


def fenetre_nominale(fenetre: dict[str, Any]) -> tuple[bool, str]:
    """Une fenetre decrit-elle un regime nominal exploitable ?

    Renvoie `(vrai, "")` si la fenetre est utilisable, sinon `(faux, motif)`.
    Le motif sert a publier ce qui a ete ecarte, pour qu'un refus ulterieur de la
    calibration ne soit pas attribue au modele alors qu'il vient du corpus.
    """
    if fenetre.get("warming_up"):
        # Les variables derivees de la reference longue sont incompletes : la
        # fenetre n'est pas fausse, elle n'est pas encore mesurable.
        return False, "mise-en-route"
    if not fenetre.get("features"):
        return False, "vecteur-absent"

    diagnostics = fenetre.get("diagnostics") or {}
    # Le compteur de reference est celui du trafic *metier*. Les requetes de
    # consultation (salle d'operations, sondes de telemetrie, /healthz) ne
    # participent pas au vecteur, et le generateur d'entrainement ne produit que
    # du metier : une fenetre qui ne contient que de la consultation n'apprend
    # rien sur le regime qu'on veut reconnaitre. La compter reviendrait a
    # elargir la bande apprise par ce que la plateforme se dit a elle-meme, donc
    # a faire monter le seuil sans rien proteger de plus.
    metier = diagnostics.get("edge_events_metier")
    if metier is None:
        # Telemetrie anterieure au compteur metier : repli sur le compteur
        # global, moins juste mais non silencieux.
        metier = fenetre.get("edge_events_in_window") or diagnostics.get("edge_events")
    if not int(metier or 0):
        # Projection nulle partout : decrit un poste qui ne recoit rien, pas un
        # regime nominal. L'inclure apprendrait que « rien » est ordinaire.
        return False, "sans-trafic"

    agents = [str(a).lower() for a in (diagnostics.get("agents_offensifs") or [])]
    if diagnostics.get("agent_offensif"):
        agents.append(str(diagnostics["agent_offensif"]).lower())
    agents.extend(
        str(a.get("value", "")).lower()
        for a in (diagnostics.get("top_agents") or [])
        if isinstance(a, dict)
    )
    if any(marque in agent for agent in agents for marque in MARQUES_OFFENSIVES):
        return False, MOTIF_AGRESSION

    if diagnostics.get("observation_seule"):
        # Le detecteur ne note jamais ces fenetres (routes de consultation sous
        # le plafond de debit). Les garder dans le corpus nominal elargit la
        # bande apprise sans rien proteger : le seuil monte, et une attaque
        # volumetrique qui emprunte les memes routes finit sous ce seuil.
        return False, "consultation"

    return True, ""


def trier(
    fenetres: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, int], dict[str, list[dict[str, Any]]]]:
    """Separe les fenetres exploitables des autres, en comptant les motifs.

    Renvoie `(nominales, ecartees_par_motif, fenetres_ecartees_par_motif)`. Le
    troisieme element n'est pas du decor : les fenetres ecartees pour cause
    d'agression sont la seule trace *mesuree* d'une attaque sur la plateforme, et
    une calibration qui n'a que des profils d'attaque theoriques se contente d'un
    seuil qui n'alerte sur rien de reel.
    """
    nominales: list[dict[str, Any]] = []
    ecartees: dict[str, int] = {}
    motifs: dict[str, list[dict[str, Any]]] = {}
    for fenetre in fenetres:
        garde, motif = fenetre_nominale(fenetre)
        if garde:
            nominales.append(fenetre)
        else:
            ecartees[motif] = ecartees.get(motif, 0) + 1
            motifs.setdefault(motif, []).append(fenetre)
    return nominales, ecartees, motifs


def resume_ecartees(ecartees: dict[str, int]) -> str:
    """Motifs d'exclusion, lisibles sur une ligne."""
    if not ecartees:
        return "aucune"
    return ", ".join(f"{motif} {nombre}" for motif, nombre in sorted(ecartees.items()))


def agressions_mesurees(motifs: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Fenetres portant la marque du banc offensif : agressions reellement mesurees.

    Elles sont ecartees du corpus nominal, mais elles ne sont pas perdues pour
    autant : ce sont les seules fenetres dont on sache, par mesure et non par
    hypothese, qu'elles decrivent une attaque. Un seuil reste sous leur score,
    ou il n'alertera jamais.
    """
    return list(motifs.get(MOTIF_AGRESSION, []))
