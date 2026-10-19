"""Variante comparative : autoencodeur dense (PyTorch).

Cette variante ne se trouve **pas** sur le chemin critique de la démonstration.
Elle existe pour répondre à une question de jury : « pourquoi Isolation Forest
plutôt qu'un réseau de neurones ? ». Le script permet de mesurer les deux
approches sur le même trafic nominal.

Principe
--------
Un autoencodeur apprend à reconstruire le trafic nominal. Une observation
anormale se reconstruit mal : l'erreur de reconstruction sert de score
d'atypie. La logique est donc la même que pour Isolation Forest — modéliser la
normale, mesurer l'écart — mais le coût n'est pas comparable.

Comparaison honnête entre les deux approches
--------------------------------------------
* Coût d'entraînement : quelques secondes (Isolation Forest) contre quelques
  minutes (autoencodeur), sur le même unique cœur.
* Taille du modèle : quelques centaines de kilo-octets contre quelques
  mégaoctets.
* Dépendance : scikit-learn seul contre PyTorch, soit environ 900 Mo d'image en
  plus — rédhibitoire sur un poste à 16 Go partagé avec dix-huit conteneurs.
* Explicabilité : la permutation de variables s'applique aux deux, mais l'écart
  en écarts-types par variable reste plus immédiat à lire sur Isolation Forest.
* Performance : sur 18 variables corrélées et un régime nominal unimodal,
  l'écart de qualité de détection n'a pas justifié le surcoût.

Conclusion assumée : l'autoencodeur est fourni, exécutable et documenté, mais
n'est pas déployé.

Utilisation
-----------
    uv pip install torch
    PYTHONPATH=services python -m ml.autoencoder
"""

from __future__ import annotations

import json
import os
import statistics

from common.features import FEATURE_NAMES, Agregateur, Reference, vecteur_vers_liste

from .synthetic import flux_normal
from .train import FENETRE_SECONDES, PAS_SECONDES, QUANTILE_SEUIL, _vecteurs_nominaux


def entrainer_autoencodeur(
    duree_secondes: float = 5400.0,
    *,
    dimensions_latentes: int = 6,
    epoques: int = 60,
    graine: int = 20261019,
) -> dict:
    """Ajuste un autoencodeur dense sur le trafic nominal simulé."""
    try:
        import numpy as np
        import torch
        from torch import nn
    except ImportError as erreur:
        raise RuntimeError(
            "PyTorch est requis pour cette variante : uv pip install torch"
        ) from erreur

    torch.manual_seed(graine)
    vecteurs, moyennes, ecarts = _vecteurs_nominaux(duree_secondes)
    brut = np.asarray(vecteurs, dtype=float)
    moyenne = brut.mean(axis=0)
    ecart_type = brut.std(axis=0)
    ecart_type[ecart_type == 0.0] = 1.0
    normalise = (brut - moyenne) / ecart_type

    tenseur = torch.tensor(normalise, dtype=torch.float32)
    entree = len(FEATURE_NAMES)

    modele = nn.Sequential(
        nn.Linear(entree, 12),
        nn.ReLU(),
        nn.Linear(12, dimensions_latentes),
        nn.ReLU(),
        nn.Linear(dimensions_latentes, 12),
        nn.ReLU(),
        nn.Linear(12, entree),
    )
    optimiseur = torch.optim.Adam(modele.parameters(), lr=1e-2)
    perte = nn.MSELoss()

    for _ in range(epoques):
        optimiseur.zero_grad()
        reconstruction = modele(tenseur)
        cout = perte(reconstruction, tenseur)
        cout.backward()
        optimiseur.step()

    with torch.no_grad():
        erreurs = ((modele(tenseur) - tenseur) ** 2).mean(dim=1).numpy()

    seuil = float(np.percentile(erreurs, QUANTILE_SEUIL))
    return {
        "version": "autoencoder-v1",
        "feature_names": list(FEATURE_NAMES),
        "dimensions_latentes": dimensions_latentes,
        "epoques": epoques,
        "n_fenetres": len(vecteurs),
        "seuil": seuil,
        "erreur_moyenne": float(erreurs.mean()),
        "erreur_ecart_type": float(erreurs.std()),
        "taux_detection_nominal_pct": float((erreurs > seuil).mean()) * 100.0,
        "moyennes": moyennes,
        "ecarts": ecarts,
        "note": (
            "variante comparative, non déployée : voir la justification en tête "
            "de ml/autoencoder.py"
        ),
    }


def main() -> int:
    artefact = entrainer_autoencodeur()
    racine = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    chemin = os.path.join(racine, "ml", "artifacts", "autoencoder-meta.json")
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(artefact, fichier, ensure_ascii=False, indent=2, sort_keys=True)

    print(f"modèle            : {artefact['version']}")
    print(f"fenêtres apprises : {artefact['n_fenetres']}")
    print(f"seuil (q{QUANTILE_SEUIL}) : {artefact['seuil']:.5f}")
    print(f"erreur nominale   : moyenne {artefact['erreur_moyenne']:.5f} "
          f"écart-type {artefact['erreur_ecart_type']:.5f}")
    print(f"dépassements nominaux : {artefact['taux_detection_nominal_pct']:.3f} %")
    print(f"\nmétadonnées : {chemin}")
    assert artefact["seuil"] >= 0.0
    assert statistics.fmean(artefact["moyennes"].values()) != float("inf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
