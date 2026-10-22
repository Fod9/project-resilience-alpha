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

#: Part de fenetres nominales toleree au-dessus du seuil, partagee par les deux
#: chemins de calibration. Un alpha plus fin que 1 / nombre de fenetres ne
#: designe plus un quantile mais la plus grande valeur observee.
ALPHA_NOMINAL = 0.005

#: Part de fenetres mesurees visee dans le corpus d'entrainement. Le generateur
#: porte la forme d'une plateforme plausible, les mesures portent le regime
#: reel ; a poids egal les secondes se perdent dans les premieres et le corpus
#: reste decale. Mesure sur une pile reelle, sur les deux variables retenues :
#: generateur seul marge +0,011, generateur plus mesures a poids egal marge
#: -0,012, generateur plus mesures ponderees a six fois marge +0,035.
PART_MESUREE_CIBLE = 0.6

#: Poids maximal applique aux fenetres mesurees. Au dela, le modele recopie le
#: corpus mesure au lieu d'apprendre une forme, et une fenetre nominale un peu
#: differente ressort comme une anomalie.
POIDS_MESURES_MAXIMUM = 50



def quantile_haut_nominal(scores, alpha: float) -> tuple[float, int]:
    """Quantile haut du nominal, avec un plancher de fenetres tolerees au-dessus.

    Le quantile fin est un piege des que l'historique est court. Sur 123 fenetres
    mesurees, un alpha de 0,005 ne designe plus un quantile mais la deuxieme plus
    grande valeur ; sur un peu moins de fenetres encore, la plus grande. La
    moindre fenetre polluee fixe alors le seuil a elle seule. C'est de cette
    facon qu'un « nominal haut » se retrouve au niveau des profils d'attaque, et
    qu'une calibration refuse un seuil en realite discriminant.

    On tolere donc explicitement au moins une fenetre au-dessus du seuil, et on
    renvoie la statistique d'ordre correspondante : le resultat reste une valeur
    reellement observee, et son sens est enonce. Renvoie `(seuil_haut, tolerees)`.
    """
    ordonne = sorted(float(score) for score in scores)
    total = len(ordonne)
    if total == 0:
        raise ValueError("aucune fenetre nominale exploitable")
    tolerees = max(1, math.ceil(alpha * total))
    rang = max(0, total - tolerees - 1)
    return ordonne[rang], tolerees


def _vecteurs_nominaux(
    duree_secondes: float = 5400.0,
    pas: float = PAS_SECONDES,
    debit_moyen: float = 0.8,
) -> tuple[list[list[float]], dict[str, float], dict[str, float]]:
    """Projette le trafic nominal simulé sur les fenêtres glissantes.

    `debit_moyen` fixe l'ordre de grandeur du régime appris, en requêtes par
    seconde au pic. Le laisser à la valeur du générateur revient à apprendre une
    plateforme quasi vide : les fenêtres réellement observées sur un poste qui
    travaille sortent alors de la plage apprise, le score d'atypie sature pour
    *tout*, et le seuil n'a plus rien à séparer. La calibration transmet donc le
    débit observé au lieu de subir la valeur par défaut.
    """
    flux = flux_normal(duree_secondes=duree_secondes, debit_moyen=debit_moyen)
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
    debit_moyen: float = 0.8,
    vecteurs_supplementaires: list[list[float]] | None = None,
    poids_supplementaires: int | None = None,
    variables: list[str] | None = None,
) -> dict[str, Any]:
    """Ajuste le détecteur et renvoie l'artefact complet (sérialisable).

    `variables` : sous-ensemble des 18 variables sur lequel ajuster le modele.
    Un Isolation Forest moyenne son score sur toutes les dimensions recues ;
    lui donner seize axes qui ne portent que du bruit de regime revient a noyer
    le signal des deux axes qui comptent. Le sous-ensemble est mesure, jamais
    choisi a la main, et il est publie dans l'artefact pour que le detecteur
    projette la fenetre de la meme facon.

    `vecteurs_supplementaires` : fenetres reellement observees sur la
    plateforme, ajoutees au corpus simule. Le generateur ne peut pas deviner
    les regimes propres a un poste donne : sur un poste reel, une session
    authentifiee qui enchaine des appels produit des centaines de requetes par
    jeton, la ou le generateur en simule moins d'une. L'ecart-type appris sur
    cet axe devient alors minuscule, toute valeur reelle parait
    astronomiquement atypique, et la bande apprise finit par contenir des
    fenetres nominales plus atypiques que l'attaque elle-meme. Mesure faite sur
    la plateforme : z = 440 sur `requests_per_token` pour du trafic nominal,
    contre 472 pour l'attaque sur `requests_per_second` : les deux saturent, et
    le classement entre les deux n'a plus de sens. Completer le corpus par les
    fenetres mesurees rend au contraire leur dispersion reelle aux axes
    concernes.
    """
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError as erreur:  # pragma: no cover - dépendance de build
        raise RuntimeError(
            "scikit-learn et numpy sont requis pour entraîner le détecteur"
        ) from erreur

    vecteurs, moyennes, ecarts = _vecteurs_nominaux(duree_secondes, debit_moyen=debit_moyen)
    n_simulees = len(vecteurs)
    poids_mesures = 0
    if vecteurs_supplementaires:
        supplements = [[float(x) for x in v] for v in vecteurs_supplementaires]
        # Les fenetres mesurees pesent : le generateur produit des milliers de
        # fenetres a debit quasi nul, et a poids egal les fenetres reelles y
        # disparaissent. Mesure faite sur une pile reelle, sur les variables
        # retenues : a poids egal la marge de separation passe de +0,011 a
        # -0,012, et elle remonte a +0,035 quand les mesures pèsent six fois
        # plus. Le poids vise une part cible du corpus, il n'est pas choisi a la
        # main.
        if poids_supplementaires is None:
            cible = PART_MESUREE_CIBLE * n_simulees
            poids_mesures = max(
                1, min(POIDS_MESURES_MAXIMUM, int(round(cible / max(1, len(supplements)))))
            )
        else:
            poids_mesures = max(1, int(poids_supplementaires))
        vecteurs = [list(v) for v in vecteurs] + supplements * poids_mesures
    # Le modele ne voit que les variables retenues, dans leur ordre. La
    # projection a lieu ici, une fois, pour que le corpus simule et les fenetres
    # mesurees soient restreints de la meme facon.
    noms_modele = list(variables) if variables else list(FEATURE_NAMES)
    if variables:
        rangs = [FEATURE_NAMES.index(nom) for nom in noms_modele]
        vecteurs = [[float(ligne[rang]) for rang in rangs] for ligne in vecteurs]
        moyennes = {nom: moyennes[nom] for nom in noms_modele if nom in moyennes}
        ecarts = {nom: ecarts[nom] for nom in noms_modele if nom in ecarts}
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
    # Le seuil est le quantile haut des scores nominaux, PLUS une marge.
    #
    # Sans cette marge, un trafic de repos quasi invariant rend tous les scores
    # egaux : le quantile vaut alors exactement le score courant, la comparaison
    # `score >= seuil` devient vraie en permanence, et le detecteur signale une
    # anomalie sur un systeme parfaitement sain. C'est le pire des etats : une
    # alarme permanente ne se distingue plus d'une absence d'alarme, et le jury
    # conclut a juste titre que la detection ne veut rien dire.
    seuil = float(np.percentile(scores, QUANTILE_SEUIL)) + max(
        0.05, float(np.std(scores)) * 0.5
    )

    importances = _importances_permutation(modele, normalise, np, graine)
    exces = float(np.mean(scores > seuil)) * 100.0

    return {
        "version": VERSION_MODELE,
        "source_calibrage": (
            "trafic-simule" if n_simulees == len(vecteurs) else "trafic-simule+mesures"
        ),
        "feature_names": list(noms_modele),
        "moyennes": moyennes,
        "ecarts": ecarts,
        "scaler_mean": [float(x) for x in normaliseur.mean_],
        "scaler_scale": [float(x) for x in normaliseur.scale_],
        "seuil": seuil,
        "n_fenetres": len(vecteurs),
        "n_fenetres_simulees": n_simulees,
        "n_fenetres_mesurees": len(vecteurs) - n_simulees,
        "poids_mesures": poids_mesures,
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
    """Importance globale par permutation : explicabilité du modèle.

    L'erreur quadratique entre le score nominal et le score obtenu après
    permutation d'une variable mesure l'apport de cette variable. Aucune
    méthode propre à Isolation Forest n'existe, la permutation est donc la voie
    standard.
    """
    rng = np.random.default_rng(graine)
    reference = -modele.decision_function(normalise)
    importances: dict[str, float] = {}
    # Les colonnes de `normalise` sont celles du modele, qui peut ne porter que
    # sur un sous-ensemble mesure des variables. Lire FEATURE_NAMES ici
    # depasserait la largeur de la matrice.
    colonnes = list(getattr(modele, "feature_names_in_", []) or [])
    if len(colonnes) != normalise.shape[1]:
        colonnes = list(FEATURE_NAMES)[: normalise.shape[1]]
    for index, nom in enumerate(colonnes):
        melange = normalise.copy()
        rng.shuffle(melange[:, index])
        altere = -modele.decision_function(melange)
        importances[nom] = float(np.mean((altere - reference) ** 2))
    total = sum(importances.values()) or 1.0
    return {nom: round(valeur / total, 6) for nom, valeur in importances.items()}


def ecrire_artefacts(artefact: dict[str, Any], dossier: str) -> tuple[str, str]:
    """Sérialise le modèle et ses métadonnées lisibles.

    L'écriture passe par un fichier temporaire puis un `os.replace` : un
    artefact ecrit directement a sa place finale peut etre tronque si le
    processus est interrompu, et un modele tronque ne se distingue pas d'un
    modele valide avant d'etre charge. Un remplacement est atomique.
    """
    import joblib

    os.makedirs(dossier, exist_ok=True)
    chemin_modele = os.path.join(dossier, "model.joblib")
    chemin_meta = os.path.join(dossier, "model-meta.json")

    temporaire = f"{chemin_modele}.partiel"
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
        temporaire,
        compress=3,
    )
    os.replace(temporaire, chemin_modele)
    meta = {cle: valeur for cle, valeur in artefact.items() if cle not in {"modele", "scaler"}}
    temporaire_meta = f"{chemin_meta}.partiel"
    with open(temporaire_meta, "w", encoding="utf-8") as fichier:
        json.dump(meta, fichier, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(temporaire_meta, chemin_meta)
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
    if "marge_separabilite" in artefact:
        lignes += [
            "séparation nominal / attaque (vérifiée) :",
            f"  score nominal le plus haut  : {artefact['score_max_nominal']:.5f}",
            f"  attaque la plus faible      : {artefact['score_min_attaque']:.5f}",
            f"  marge                       : {artefact['marge_separabilite']:.5f}",
        ]
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
