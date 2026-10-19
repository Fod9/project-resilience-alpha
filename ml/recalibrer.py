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


def ajuster_sur_mesures(
    vecteurs_mesures: list[dict[str, float]],
    *,
    source_libelle: str = "trafic-reel",
    n_estimateurs: int = 256,
    graine: int = 20261019,
) -> dict[str, Any]:
    """Réajuste le modèle sur des vecteurs réellement observés.

    Le cœur d'ajustement n'est pas réécrit : on réutilise `ml.train.entrainer`
    en substituant sa source de données. Cela garantit que le modèle recalibré
    est produit par exactement le même code que le modèle embarqué — même
    normalisation, même seuil, mêmes explications.
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

    def _source_substituee(_duree_secondes: float = 0.0):  # noqa: ANN202
        moyennes = {nom: float(brut[:, i].mean()) for i, nom in enumerate(FEATURE_NAMES)}
        ecarts = {nom: float(brut[:, i].std() or 1.0) for i, nom in enumerate(FEATURE_NAMES)}
        return brut.tolist(), moyennes, ecarts

    origine = soi._vecteurs_nominaux
    soi._vecteurs_nominaux = _source_substituee
    try:
        artefact = soi.entrainer(0.0, n_estimateurs=n_estimateurs, graine=graine)
    finally:
        soi._vecteurs_nominaux = origine

    artefact["version"] = f"isolation-forest-{source_libelle}"
    artefact["source_calibrage"] = source_libelle
    return artefact


def _lire_historique(base: str, limite: int) -> list[dict[str, Any]]:
    with urllib.request.urlopen(f"{base.rstrip('/')}/features/history?limit={limite}", timeout=30) as reponse:
        charge = json.loads(reponse.read().decode("utf-8"))
    fenetres = charge.get("windows") or []
    # Les fenêtres de mise en route sont écartées : leurs variables dérivées de
    # la mémoire longue n'ont pas de sens, et les inclure corromprait la normale.
    return [f for f in fenetres if not f.get("warming_up") and f.get("features")]


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else "http://telemetry:8000"
    sortie = sys.argv[2] if len(sys.argv) > 2 else "/models"

    fenetres = _lire_historique(base, limite=600)
    print(f"fenêtres réellement observées : {len(fenetres)}")
    if not fenetres:
        print(
            "aucune fenêtre exploitable : laissez la plateforme fonctionner "
            "quelques minutes avant de recalibrer."
        )
        return 1

    artefact = ajuster_sur_mesures([f["features"] for f in fenetres])
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
