"""Entraînement et calibration du détecteur d'anomalies.

Algorithme retenu : *Isolation Forest* (`sklearn.ensemble.IsolationForest`).

Justification (attendue en soutenance)
--------------------------------------
* **Non supervisé.** Aucun jeu d'attaques étiqueté n'existe au démarrage, et le
  sujet interdit les règles codées en dur. On modélise donc la normale, puis on
  mesure l'écart.
* **Isolation par partitions aléatoires.** Une observation atypique est isolée
  en moins de coupures qu'une observation ordinaire : le score est directement
  une mesure d'atypie, sans hypothèse de distribution.
* **Coût.** Entraînement en quelques secondes sur un unique cœur, modèle
  sérialisé de quelques centaines de kilo-octets, aucune carte graphique. C'est
  compatible avec un poste hôte à 4 cœurs et 16 Go.
* **Grande dimension.** Reste performant avec 18 variables corrélées, là où une
  méthode par distance (k-NN, LOF) souffrirait de la malédiction de la
  dimension.

Calibration du seuil
--------------------
Le seuil n'est pas choisi à la main : il est fixé au quantile 99,8 des scores
observés sur le trafic nominal. On accepte donc *a priori* environ deux
détections par millier de fenêtres en régime normal, ce qui est mesurable et
défendable. Une confirmation sur plusieurs fenêtres consécutives (paramètre
`CONSECUTIVE_WINDOWS` du détecteur) élimine ensuite l'essentiel de ces
détections isolées.

La standardisation utilise la moyenne et l'écart-type du trafic nominal : sans
elle, les variables exprimées en octets domineraient celles exprimées en
ratios.
"""

from __future__ import annotations

import json
import math
import os
import statistics
from typing import Any

from common.features import FEATURE_NAMES, Agregateur, Reference, vecteur_vers_liste

from .synthetic import flux_normal

VERSION_MODELE = "isolation-forest-v1"
FENETRE_SECONDES = 60.0
PAS_SECONDES = 10.0
QUANTILE_SEUIL = 99.8


def _vecteurs_nominaux(
    duree_secondes: float = 5400.0,
    pas: float = PAS_SECONDES,
) -> tuple[list[list[float]], dict[str, float], dict[str, float]]:
    """Projette le trafic nominal simulé sur les fenêtres glissantes."""
    flux = flux_normal(duree_secondes=duree_secondes)
    reference = Reference()
    agregateur = Agregateur(window_seconds=FENETRE_SECONDES, reference=reference)

    vecteurs: list[list[float]] = []
    instant = 0.0
    index = 0
    while instant < duree_secondes:
        while index < len(flux) and flux[index].ts <= instant:
            agregateur.ajouter(flux[index])
            index += 1
        agregateur.purger(instant)
        if instant >= 15 * FENETRE_SECONDES:
            # Période de chauffe ignorée : la mémoire longue doit être garnie.
            vecteurs.append(vecteur_vers_liste(agregateur.vecteur()))
        agregateur.enrichir_reference()
        instant += pas

    moyennes = {
        nom: statistics.fmean(v[i] for v in vecteurs) for i, nom in enumerate(FEATURE_NAMES)
    }
    ecarts = {
        nom: (statistics.pstdev(v[i] for v in vecteurs) or 1.0)
        for i, nom in enumerate(FEATURE_NAMES)
    }
    return vecteurs, moyennes, ecarts


def entrainer(
    duree_secondes: float = 5400.0,
    *,
    n_estimateurs: int = 256,
    graine: int = 20261019,
) -> dict[str, Any]:
    """Ajuste le détecteur et renvoie l'artefact complet (sérialisable)."""
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError as erreur:  # pragma: no cover - dépendance de build
        raise RuntimeError(
            "scikit-learn et numpy sont requis pour entraîner le détecteur"
        ) from erreur

    vecteurs, moyennes, ecarts = _vecteurs_nominaux(duree_secondes)
    if len(vecteurs) < 50:
        raise RuntimeError(
            f"historique nominal insuffisant : {len(vecteurs)} fenêtres produites"
        )

    brut = np.asarray(vecteurs, dtype=float)
    normaliseur = StandardScaler()
    normalise = normaliseur.fit_transform(brut)

    modele = IsolationForest(
        n_estimators=n_estimateurs,
        max_samples="auto",
        contamination="auto",
        random_state=graine,
        n_jobs=1,
    )
    modele.fit(normalise)

    # `decision_function` est orienté « grand = normal ». On le retourne pour
    # obtenir un score d'atypie croissant, ce qui rend la lecture des courbes
    # intuitive et le seuil comparable d'une exécution à l'autre.
    scores = -modele.decision_function(normalise)
    seuil = float(np.percentile(scores, QUANTILE_SEUIL))

    importances = _importances_permutation(modele, normalise, np, graine)
    exces = float(np.mean(scores > seuil)) * 100.0

    return {
        "version": VERSION_MODELE,
        "feature_names": list(FEATURE_NAMES),
        "moyennes": moyennes,
        "ecarts": ecarts,
        "scaler_mean": [float(x) for x in normaliseur.mean_],
        "scaler_scale": [float(x) for x in normaliseur.scale_],
        "seuil": seuil,
        "n_fenetres": len(vecteurs),
        "n_estimateurs": n_estimateurs,
        "quantile_seuil": QUANTILE_SEUIL,
        "score_moyen": float(np.mean(scores)),
        "score_ecart_type": float(np.std(scores)),
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "taux_detection_nominal_pct": exces,
        "importances": importances,
        "duree_simulee_s": duree_secondes,
        "modele": modele,
        "scaler": normaliseur,
    }


def _importances_permutation(
    modele: Any, normalise: Any, np: Any, graine: int
) -> dict[str, float]:
    """Importance globale par permutation — explicabilité du modèle.

    L'erreur quadratique entre le score nominal et le score obtenu après
    permutation d'une variable mesure l'apport de cette variable. Aucune
    méthode propre à Isolation Forest n'existe, la permutation est donc la voie
    standard.
    """
    rng = np.random.default_rng(graine)
    reference = -modele.decision_function(normalise)
    importances: dict[str, float] = {}
    for index, nom in enumerate(FEATURE_NAMES):
        melange = normalise.copy()
        rng.shuffle(melange[:, index])
        altere = -modele.decision_function(melange)
        importances[nom] = float(np.mean((altere - reference) ** 2))
    total = sum(importances.values()) or 1.0
    return {nom: round(valeur / total, 6) for nom, valeur in importances.items()}


def ecrire_artefacts(artefact: dict[str, Any], dossier: str) -> tuple[str, str]:
    """Sérialise le modèle et ses métadonnées lisibles."""
    import joblib

    os.makedirs(dossier, exist_ok=True)
    chemin_modele = os.path.join(dossier, "model.joblib")
    chemin_meta = os.path.join(dossier, "model-meta.json")

    joblib.dump(
        {
            "version": artefact["version"],
            "feature_names": artefact["feature_names"],
            "modele": artefact["modele"],
            "scaler": artefact["scaler"],
            "seuil": artefact["seuil"],
            "moyennes": artefact["moyennes"],
            "ecarts": artefact["ecarts"],
        },
        chemin_modele,
        compress=3,
    )
    meta = {cle: valeur for cle, valeur in artefact.items() if cle not in {"modele", "scaler"}}
    with open(chemin_meta, "w", encoding="utf-8") as fichier:
        json.dump(meta, fichier, ensure_ascii=False, indent=2, sort_keys=True)
    return chemin_modele, chemin_meta


def resume(artefact: dict[str, Any]) -> str:
    top = sorted(artefact["importances"].items(), key=lambda item: item[1], reverse=True)[:6]
    lignes = [
        f"modèle            : {artefact['version']}",
        f"fenêtres apprises : {artefact['n_fenetres']}",
        f"seuil (q{artefact['quantile_seuil']}) : {artefact['seuil']:.5f}",
        f"score nominal     : moyenne {artefact['score_moyen']:.5f} "
        f"écart-type {artefact['score_ecart_type']:.5f}",
        f"dépassements nominaux : {artefact['taux_detection_nominal_pct']:.3f} % "
        "(attendu : proche du quantile choisi)",
        "variables les plus discriminantes :",
    ]
    lignes += [f"  - {nom:28s} {part * 100:5.1f} %" for nom, part in top]
    return "\n".join(lignes)


def main() -> int:
    racine = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    artefact = entrainer()
    chemins = ecrire_artefacts(artefact, os.path.join(racine, "ml", "artifacts"))
    print(resume(artefact))
    print(f"\nmodèle   : {chemins[0]}")
    print(f"métadonnées : {chemins[1]}")
    assert not math.isnan(artefact["seuil"]), "seuil non calculable"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
