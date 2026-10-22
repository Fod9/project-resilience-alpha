"""Tests du gabarit facial : validation, distance cosinus et défi actif.

Le module testé est chargé par son chemin, sans passer par le paquet `app` :
importer `app` déclenche `app/__init__.py`, donc `app.main`, qui exige une
configuration complète et une base joignable. Ces tests doivent tourner seuls,
sur un poste nu, parce que la décision d'authentification faciale est une
fonction de nombres et rien d'autre.
"""

from __future__ import annotations

import importlib.util
import math
import pathlib

import pytest

_CHEMIN = pathlib.Path(__file__).resolve().parents[1] / "app" / "face.py"
_SPEC = importlib.util.spec_from_file_location("face_sous_test", _CHEMIN)
assert _SPEC is not None and _SPEC.loader is not None
face = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(face)


def _descripteur(valeur: float = 0.5) -> list[float]:
    return [valeur] * face.DIMENSION_DESCRIPTEUR


# --- Validation du descripteur -----------------------------------------------


def test_descripteur_valide_accepte() -> None:
    resultat = face.valider_descripteur(_descripteur(0.25))
    assert len(resultat) == face.DIMENSION_DESCRIPTEUR
    assert resultat[0] == 0.25


def test_descripteur_trop_court_refuse() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur([0.1] * 127)


def test_descripteur_trop_long_refuse() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur([0.1] * 129)


def test_nan_refuse() -> None:
    valeurs = _descripteur()
    valeurs[7] = float("nan")
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur(valeurs)


def test_infini_refuse() -> None:
    valeurs = _descripteur()
    valeurs[7] = float("inf")
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur(valeurs)


def test_valeur_hors_bornes_refusee() -> None:
    valeurs = _descripteur()
    valeurs[42] = 1.4
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur(valeurs)


def test_valeur_non_numerique_refusee() -> None:
    valeurs = _descripteur()
    valeurs[3] = "0.2"  # type: ignore[assignment]
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur(valeurs)


def test_booleen_refuse() -> None:
    valeurs = _descripteur()
    valeurs[3] = True  # type: ignore[assignment]
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur(valeurs)


def test_chaine_de_caracteres_refusee() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.valider_descripteur("0.1,0.2")


# --- Distance cosinus --------------------------------------------------------


def test_distance_entre_vecteurs_identiques_est_nulle() -> None:
    vecteur = face.valider_descripteur(_descripteur(0.3))
    assert face.distance_cosinus(vecteur, vecteur) == pytest.approx(0.0, abs=1e-12)


def test_distance_entre_vecteurs_colineaires_est_nulle() -> None:
    """Un descripteur deux fois plus long décrit le même visage."""
    gauche = face.valider_descripteur(_descripteur(0.2))
    droite = face.valider_descripteur(_descripteur(0.6))
    assert face.distance_cosinus(gauche, droite) == pytest.approx(0.0, abs=1e-12)


def test_distance_entre_vecteurs_opposes_est_maximale() -> None:
    gauche = [1.0] + [0.0] * 127
    droite = [-1.0] + [0.0] * 127
    assert face.distance_cosinus(gauche, droite) == pytest.approx(2.0, abs=1e-12)


def test_distance_entre_vecteurs_orthogonaux_vaut_un() -> None:
    gauche = [1.0] + [0.0] * 127
    droite = [0.0, 1.0] + [0.0] * 126
    assert face.distance_cosinus(gauche, droite) == pytest.approx(1.0, abs=1e-12)


def test_vecteur_nul_donne_la_distance_maximale() -> None:
    nul = [0.0] * face.DIMENSION_DESCRIPTEUR
    assert face.distance_cosinus(nul, _descripteur()) == face.DISTANCE_MAXIMALE


def test_dimensions_differentes_refusees() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.distance_cosinus([0.1] * 128, [0.1] * 127)


# --- Seuil -------------------------------------------------------------------


def test_distance_juste_en_dessous_du_seuil_acceptee() -> None:
    seuil = 0.45
    assert face.distance_acceptee(seuil - 1e-9, seuil) is True


def test_distance_egale_au_seuil_acceptee() -> None:
    assert face.distance_acceptee(0.45, 0.45) is True


def test_distance_juste_au_dessus_du_seuil_refusee() -> None:
    seuil = 0.45
    assert face.distance_acceptee(seuil + 1e-9, seuil) is False


# --- Gabarit moyen -----------------------------------------------------------


def test_gabarit_moyen_est_normalise() -> None:
    captures = [
        face.valider_descripteur(_descripteur(0.1)),
        face.valider_descripteur(_descripteur(0.3)),
    ]
    gabarit = face.gabarit_moyen(captures)
    assert face.norme(gabarit) == pytest.approx(1.0, abs=1e-12)
    assert len(gabarit) == face.DIMENSION_DESCRIPTEUR


def test_gabarit_moyen_sans_capture_refuse() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.gabarit_moyen([])


def test_gabarit_moyen_captures_heterogenes_refuse() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.gabarit_moyen([_descripteur(), [0.1] * 64])


def test_gabarit_moyen_de_captures_nulles_refuse() -> None:
    with pytest.raises(face.DescripteurInvalide):
        face.gabarit_moyen([[0.0] * face.DIMENSION_DESCRIPTEUR])


# --- Défi actif --------------------------------------------------------------


def test_defi_valide_avec_clignement_et_rotation() -> None:
    valide, motif = face.evaluer_defi(clignement=True, rotation_degres=24.0, seuil_rotation_degres=20.0)
    assert valide is True
    assert motif == "défi validé"


def test_defi_rotation_negative_acceptee() -> None:
    valide, _ = face.evaluer_defi(clignement=True, rotation_degres=-31.5, seuil_rotation_degres=20.0)
    assert valide is True


def test_defi_sans_clignement_refuse() -> None:
    valide, motif = face.evaluer_defi(clignement=False, rotation_degres=30.0, seuil_rotation_degres=20.0)
    assert valide is False
    assert "clignement" in motif


def test_defi_rotation_insuffisante_refusee() -> None:
    valide, motif = face.evaluer_defi(clignement=True, rotation_degres=6.0, seuil_rotation_degres=20.0)
    assert valide is False
    assert "rotation insuffisante" in motif


def test_defi_rotation_non_numerique_refusee() -> None:
    valide, _ = face.evaluer_defi(
        clignement=True,
        rotation_degres=float("nan"),
        seuil_rotation_degres=20.0,
    )
    assert valide is False


def test_defi_rotation_booleenne_refusee() -> None:
    valide, _ = face.evaluer_defi(clignement=True, rotation_degres=True, seuil_rotation_degres=20.0)
    assert valide is False


def test_distance_dun_meme_visage_bruite_reste_sous_le_seuil() -> None:
    """Un bruit faible ne doit pas faire basculer un visage connu.

    C'est la propriété qui compte en exploitation : deux captures du même
    opérateur, à quelques centièmes près, doivent rester du même côté du seuil.
    """
    reference = face.gabarit_moyen([face.valider_descripteur(_descripteur(1.0))])
    bruite = [valeur + 0.05 * math.sin(position) for position, valeur in enumerate(reference)]
    assert face.distance_acceptee(face.distance_cosinus(reference, bruite), 0.45) is True
