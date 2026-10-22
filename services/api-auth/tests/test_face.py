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


# --- Gestes exigés par la configuration -------------------------------------


def test_clignement_seul_suffit_quand_la_rotation_n_est_pas_exigee():
    valide, motif = face.evaluer_defi(
        clignement=True,
        rotation_degres=0.0,
        seuil_rotation_degres=20.0,
        exiger_clignement=True,
        exiger_rotation=False,
    )
    assert valide is True, motif


def test_rotation_seule_suffit_quand_le_clignement_n_est_pas_exige():
    valide, motif = face.evaluer_defi(
        clignement=False,
        rotation_degres=25.0,
        seuil_rotation_degres=20.0,
        exiger_clignement=False,
        exiger_rotation=True,
    )
    assert valide is True, motif


def test_rotation_insuffisante_refusee_meme_sans_clignement_exige():
    valide, motif = face.evaluer_defi(
        clignement=False,
        rotation_degres=12.0,
        seuil_rotation_degres=20.0,
        exiger_clignement=False,
        exiger_rotation=True,
    )
    assert valide is False
    assert "rotation insuffisante" in motif


def test_rotation_negative_compte_en_valeur_absolue():
    valide, _ = face.evaluer_defi(
        clignement=False,
        rotation_degres=-24.0,
        seuil_rotation_degres=20.0,
        exiger_clignement=False,
        exiger_rotation=True,
    )
    assert valide is True


def test_defi_vide_refuse_meme_si_la_configuration_l_a_permis():
    valide, motif = face.evaluer_defi(
        clignement=True,
        rotation_degres=90.0,
        seuil_rotation_degres=20.0,
        exiger_clignement=False,
        exiger_rotation=False,
    )
    assert valide is False
    assert "aucun geste" in motif


# --- Calibration du seuil, sur les distances mesurees ------------------------
#
# Ces valeurs viennent de la mesure faite avec ce modele, sur 400 visages reels
# (jeu Olivetti, 40 personnes), descripteurs calcules par le reseau embarque sans
# alignement prealable, donc dans le cas le plus defavorable. Elles ne sont pas
# choisies pour faire passer le test : elles decrivent les deux populations que
# le seuil doit separer, et c'est le seuil qui doit tomber entre les deux.
INTRA_MEDIANE = 0.029      # deux photos de la meme personne
INTRA_CENTILE_95 = 0.067
INTER_MINIMUM = 0.042      # deux personnes differentes
INTER_CENTILE_1 = 0.073
INTER_MEDIANE = 0.132
INTER_MAXIMUM = 0.281
TAUX_EGALITE = 0.077


def test_seuil_par_defaut_plus_strict_que_le_taux_egalite():
    # Le point d'equilibre mesuré est 0,077 : le seuil livré doit etre plus
    # severe, parce qu'ouvrir une session d'administration n'est pas symetrique
    # d'un refus legitime.
    assert face.SEUIL_CALIBRE < TAUX_EGALITE


def test_visage_identique_accepte_aux_distances_mesurees():
    assert face.distance_acceptee(INTRA_MEDIANE, face.SEUIL_CALIBRE) is True
    assert face.distance_acceptee(INTRA_CENTILE_95, face.SEUIL_CALIBRE) is True


def test_visage_etranger_refuse_aux_distances_mesurees():
    assert face.distance_acceptee(INTER_CENTILE_1, face.SEUIL_CALIBRE) is False
    assert face.distance_acceptee(INTER_MEDIANE, face.SEUIL_CALIBRE) is False
    assert face.distance_acceptee(INTER_MAXIMUM, face.SEUIL_CALIBRE) is False


def test_paire_de_personnes_differentes_la_plus_proche_reste_acceptee():
    # Le recouvrement des deux populations est reel et mesure : la paire la plus
    # proche du jeu (0,042) se situe sous le seuil et serait acceptee. C'est le
    # prix d'un taux de refus legitimes tenable, et il est documente plutot que
    # masque. Exiger 0,042 pour tout refuser rejetterait plus d'un quart des
    # visages legitimes.
    assert face.distance_acceptee(INTER_MINIMUM, face.SEUIL_CALIBRE) is True


def test_ancien_seuil_acceptait_tous_les_visages_du_jeu():
    # 0,45 etait la valeur initiale, non mesuree. Elle depasse la distance
    # maximale observee entre deux personnes differentes : aucun visage du jeu
    # n'etait refuse, ce qui est exactement le defaut constate.
    assert 0.45 > INTER_MAXIMUM
    assert face.distance_acceptee(INTER_MAXIMUM, 0.45) is True


def test_equivalence_euclidienne_du_seuil():
    # Les descripteurs sortent normalises : euclidien = racine(2 x cosinus).
    assert face.euclidien_equivalent(face.SEUIL_CALIBRE) == pytest.approx(0.3742, abs=0.001)
    # A 0,45, la distance euclidienne equivalente depasse 0,9 : bien au-dela de
    # toute distance ou deux visages differents se distinguent encore.
    assert face.euclidien_equivalent(0.45) > 0.9
