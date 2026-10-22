#!/usr/bin/env python3
"""Réajuste le détecteur sur le trafic réellement observé sur le poste.

Pourquoi ce script existe
-------------------------
Le modèle livré est calibré sur un trafic simulé, qui décrit une plateforme
normale mais pas *cette* plateforme-ci : le nombre d'adresses distinctes, la
latence ou la taille des requêtes dépendent du poste et de l'usage réel.

Un écart de profil se paie cher : si la normale apprise ne ressemble pas à la
normale observée, le détecteur signale une anomalie en permanence. Il devient
alors inutilisable, non parce qu'il est faux, mais parce qu'il est mal calibré.

Ce script supprime cet écart. Il lit l'historique des fenêtres réellement
observées auprès du service de télémétrie, réajuste le modèle sur ce profil, et
l'écrit dans le volume du détecteur. Au redémarrage, le détecteur le charge en
priorité sur le modèle embarqué.

    python -m ml.recalibrer http://telemetry:8000 /models
"""

from __future__ import annotations

import json
import sys
import urllib.request
from typing import Any

from common.features import FEATURE_NAMES
from ml import selection
from ml.fenetrage import agressions_mesurees, resume_ecartees, trier
from ml.profils_attaque import profils_du_modele

#: Marge minimale exigee entre le score nominal le plus haut et la plus faible
#: des attaques de reference. En dessous, la separation n'est pas exploitable et
#: la calibration doit echouer plutot que de publier un seuil inerte.
ECART_MINIMAL = 0.01


def ajuster_sur_mesures(
    vecteurs_mesures: list[dict[str, float]],
    *,
    source_libelle: str = "trafic-reel",
    n_estimateurs: int = 256,
    graine: int = 20261019,
    vecteurs_agression: list[dict[str, float]] | None = None,
) -> dict[str, Any]:
    """Réajuste le modèle sur des vecteurs réellement observés.

    `vecteurs_agression` : fenêtres d'agression déjà mesurées sur la plateforme,
    telles que `ml.fenetrage.agressions_mesurees` les restitue. Quand il y en a,
    elles font partie du banc d'essai du seuil au même titre que les profils
    théoriques, et c'est la plus faible d'entre elles qui contraint le seuil.

    Deux rôles, deux sources, et c'est tout l'enjeu :

    * le **modèle** est entraîné sur le générateur de trafic, qui décrit une
      plateforme en fonctionnement : débit variable, plusieurs adresses,
      latences étendues. C'est de cette variété que vient la capacité de
      distinguer, à condition que le générateur couvre aussi le régime de repos,
      qui est le plus fréquent sur un poste réel ;
    * le **seuil** est réglé sur les fenêtres réellement observées, ce qui
      garantit que le repos de *ce* poste reste en dessous.

    Entraîner le modèle directement sur les fenêtres réelles — ce que faisait la
    version précédente — revient à apprendre une distribution de variance nulle :
    un poste au repos produit des fenêtres quasi identiques, l'Isolation Forest
    renvoie alors le même score pour tout, et le détecteur ne distingue plus une
    attaque d'un système sain. Il ne détecte plus rien, sans jamais échouer.
    """
    import numpy as np

    from ml import train as soi

    if len(vecteurs_mesures) < 30:
        raise RuntimeError(
            f"historique réel insuffisant : {len(vecteurs_mesures)} fenêtres "
            "(il en faut au moins 30, soit environ cinq minutes de trafic)"
        )

    brut = np.asarray(
        [[float(v.get(nom, 0.0)) for nom in FEATURE_NAMES] for v in vecteurs_mesures],
        dtype=float,
    )

    # 1. Les variables du modele sont choisies sur les bandes MESUREES.
    #
    # Un Isolation Forest moyenne son score sur toutes les dimensions qu'on lui
    # donne. Mesure faite sur une pile reelle : les fenetres d'attaque etaient
    # notees 0,094 a 0,186 quand des fenetres nominales atteignaient 0,163,
    # alors que deux variables d'entree separaient parfaitement les deux bandes
    # (taux d'erreur de 0 a 0,90 ; debit de 0,28 a 117). Ces deux variables
    # portaient deux dix-huitiemes de la decision.
    #
    # Le jeu de variables n'est donc ni fige ni choisi a la main : il est
    # mesure, et il depend de la plateforme et de sa bordure. Aucune agression
    # mesuree, aucune selection possible, donc aucune publication : un modele
    # juge sur des profils theoriques n'a jamais alerte sur une attaque reelle.
    brut_attaque = np.asarray(
        [
            [float(v.get(nom, 0.0)) for nom in FEATURE_NAMES]
            for v in (vecteurs_agression or [])
        ],
        dtype=float,
    )
    if not len(brut_attaque):
        raise RuntimeError(
            "calibration refusee : aucune agression mesuree dans l'historique. "
            "Le modele doit etre choisi sur des faits, pas sur des profils "
            "theoriques. Rejouez une attaque, laissez la telemetrie "
            "l'enregistrer, puis relancez la calibration."
        )
    variables, tableau = selection.choisir(
        brut.tolist(), brut_attaque.tolist(), list(FEATURE_NAMES)
    )
    if not variables:
        raise RuntimeError(
            "calibration refusee : aucune variable ne separe les fenetres "
            "d'attaque des fenetres nominales mesurees. La plateforme ne separe "
            "pas ses propres attaques sur ces variables, publier un seuil "
            "n'alerterait sur rien. Ecart mesure : " + selection.resume(tableau)
        )

    # 2. Le corpus : generateur pour la densite, mesures pour les regimes reels,
    #    restreint aux variables retenues.
    #
    # Le generateur seul ne peut pas deviner la dispersion propre a un poste, et
    # les mesures seules donnent une distribution de variance trop faible pour
    # qu'un modele d'atypie ait un sens. Les deux ensemble : le generateur porte
    # la forme, les mesures portent les regimes.
    duree_simulee = max(4500.0, 30.0 * len(vecteurs_mesures))
    artefact = soi.entrainer(
        duree_simulee,
        n_estimateurs=n_estimateurs,
        graine=graine,
        vecteurs_supplementaires=brut.tolist(),
        variables=variables,
    )

    # 3. Le seuil est place entre les deux bandes MESUREES.
    #
    # Un seuil calibre « au-dessus du nominal » peut passer au-dessus du maximum
    # atteignable par le modele, et la comparaison `score >= seuil` devient
    # fausse en permanence : le dispositif n'alerte plus jamais tout en
    # paraissant arme. On exige donc que le seuil tombe entre le nominal mesure
    # et l'agression mesuree, sur le modele effectivement publie.
    modele = artefact["modele"]
    normaliseur = artefact["scaler"]
    rangs = [list(FEATURE_NAMES).index(nom) for nom in variables]
    scores = -modele.decision_function(normaliseur.transform(brut[:, rangs]))
    scores_attaque = -modele.decision_function(
        normaliseur.transform(brut_attaque[:, rangs])
    )

    score_max_nominal, tolerees = soi.quantile_haut_nominal(scores, soi.ALPHA_NOMINAL)
    score_min_attaque = float(np.min(scores_attaque))
    marge = score_min_attaque - score_max_nominal
    if marge <= ECART_MINIMAL:
        raise RuntimeError(
            "calibration refusee : le seuil ne separe plus le nominal de "
            f"l'attaque mesuree (nominal haut {score_max_nominal:.5f}, attaque "
            f"min {score_min_attaque:.5f}, marge {marge:.5f}). Un tel seuil "
            "n'alerterait jamais. Ecart par variable parmi : "
            + selection.resume(tableau)
        )

    # On place le seuil a un quart de la marge au-dessus du nominal : assez haut
    # pour ne pas confondre la pointe legitime avec une attaque, assez bas pour
    # que la plus faible des attaques mesurees le franchisse.
    seuil = score_max_nominal + max(ECART_MINIMAL, 0.25 * marge)
    artefact["seuil"] = seuil
    artefact["score_moyen"] = float(np.mean(scores))
    artefact["score_ecart_type"] = float(np.std(scores))
    artefact["score_min"] = float(np.min(scores))
    artefact["score_max"] = float(np.max(scores))
    # Traces de la verification de separabilite : sans elles, un seuil inerte
    # resterait indiscernable d'un seuil simplement prudent.
    artefact["score_max_nominal"] = score_max_nominal
    artefact["fenetres_tolerees_au_dessus"] = tolerees
    artefact["score_min_attaque"] = score_min_attaque
    artefact["marge_separabilite"] = marge
    artefact["variables"] = list(variables)
    artefact["separations_mesurees"] = {
        nom: mesures for nom, mesures in tableau.items()
    }
    artefact["profils_attaque"] = sorted(profils_du_modele())
    artefact["reference_attaque"] = "agressions-mesurees"
    artefact["n_fenetres_agression_mesurees"] = len(vecteurs_agression or [])
    artefact["taux_detection_nominal_pct"] = float(np.mean(scores > seuil)) * 100.0
    artefact["n_fenetres_reelles"] = len(vecteurs_mesures)
    # Les profils theoriques ne jugent plus le seuil : ils sont notes pour
    # memoire, afin qu'un ecart entre la theorie et la mesure reste visible.
    artefact["scores_profils_reference"] = {
        nom: float(
            -modele.decision_function(
                normaliseur.transform(
                    np.asarray(
                        [
                            [float(profil.get(v, 0.0)) for v in variables]
                            for profil in [profils_du_modele()[nom]]
                        ],
                        dtype=float,
                    )
                )
            )[0]
        )
        for nom in sorted(profils_du_modele())
    }

    artefact["version"] = f"isolation-forest-{source_libelle}"
    artefact["source_calibrage"] = source_libelle
    return artefact


def _lire_historique(
    base: str, limite: int
) -> tuple[list[dict[str, Any]], dict[str, int], int, list[dict[str, Any]]]:
    with urllib.request.urlopen(f"{base.rstrip('/')}/features/history?limit={limite}", timeout=30) as reponse:
        charge = json.loads(reponse.read().decode("utf-8"))
    fenetres = charge.get("windows") or []
    # Le tri est partage avec `ml.calibrer_sur_mesures` : les deux chemins de
    # calibration doivent ecarter exactement les memes fenetres. Quatre motifs
    # d'exclusion, et chacun a coute une calibration pour etre identifie :
    #   - fenetres de mise en route : variables derivees de la memoire longue
    #     encore incompletes ;
    #   - fenetres sans evenement de bordure : projection nulle partout, elles
    #     decrivent un poste qui ne recoit rien, pas un regime nominal ;
    #   - fenetres portant la marque du banc offensif : une agression apprise
    #     comme normale fait monter le seuil jusqu'aux profils d'attaque ;
    #   - fenetres composees des seules routes de consultation : le detecteur ne
    #     les note jamais, et les inclure ne fait qu'elargir la bande apprise.
    exploitables, ecartees, motifs = trier(fenetres)
    return exploitables, ecartees, len(fenetres), agressions_mesurees(motifs)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://telemetry:8000"
    sortie = sys.argv[2] if len(sys.argv) > 2 else "/models"

    fenetres, ecartees, lues, agressions = _lire_historique(base, limite=600)
    print(f"fenêtres lues : {lues}")
    print(f"fenêtres écartées : {resume_ecartees(ecartees)}")
    print(f"fenêtres réellement observées : {len(fenetres)}")
    print(f"agressions déjà mesurées : {len(agressions)} fenêtre(s) portant la marque du banc")
    if not fenetres:
        print(
            "aucune fenêtre exploitable : laissez la plateforme fonctionner "
            "quelques minutes avant de recalibrer."
        )
        return 1

    artefact = ajuster_sur_mesures(
        [f["features"] for f in fenetres],
        vecteurs_agression=[f["features"] for f in agressions],
    )
    from ml.train import ecrire_artefacts, resume

    print(resume(artefact))
    chemin_modele, chemin_meta = ecrire_artefacts(artefact, sortie)
    print(f"\nmodèle   : {chemin_modele}")
    print(f"métadonnées : {chemin_meta}")
    print(
        "\nRedémarrez le détecteur pour qu'il charge ce modèle :\n"
        "    docker compose restart detector"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
