#!/usr/bin/env python3
"""Calibre le detecteur sur des fenetres mesurees, seuil contraint des deux cotes.

Le defaut que ce script corrige
-------------------------------
Une calibration qui prend un simple quantile du score nominal ne dit rien de la
detection : le seuil peut se retrouver au-dessus de toutes les attaques. Le
dispositif a alors l'air arme, la salle d'operations affiche un score et un
seuil, et rien n'est jamais detecte. C'est le defaut constate deux fois de
suite, d'abord par des alertes permanentes, ensuite par une absence totale de
detection.

Deux changements de fond :

1. Le jeu d'entrainement est *mesure*. On apprend la normale sur les fenetres
   reellement observees sur la plateforme, dans plusieurs regimes : repos,
   trafic courant, consultation du tableau de bord. Le generateur simule ne sert
   qu'a amorcer, et seulement s'il y a trop peu de mesures : il est alors declare
   comme tel dans les metadonnees.
2. Le seuil est place sous contrainte explicite. Il doit etre au-dessus du
   quantile haut du nominal *et* sous le score du profil d'attaque le plus bas,
   avec une marge relative minimale. Si les deux bandes se recouvrent, le script
   refuse de publier un modele : un seuil non discriminant ne doit pas sortir
   d'ici sous l'apparence d'un modele calibre.

Usage :

    python ml/calibrer_sur_mesures.py http://telemetry:8000 --ecrire /models
    python ml/calibrer_sur_mesures.py http://127.0.0.1/api/telemetry --rapport
"""
import argparse
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RACINE, "services"))
sys.path.insert(0, RACINE)

from common.features import FEATURE_NAMES  # noqa: E402
from ml.profils_attaque import PROFILS, PROFILS_MODELE  # noqa: E402
from ml.train import VERSION_MODELE  # noqa: E402

#: Part de fenetres nominales toleree au-dessus du seuil.
ALPHA_NOMINAL = 0.005

#: Marge relative minimale exigee entre le seuil et le profil d'attaque le plus bas.
MARGE_RELATIVE_MINIMALE = 1.15

#: En dessous de ce nombre de fenetres mesurees distinctes, on amorce avec le generateur.
MINIMUM_MESURES = 30


def collecter(base, limite=300):
    """Fenetres reellement observees, dans l'ordre des variables du modele."""
    contexte = ssl.create_default_context()
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    requete = urllib.request.Request(
        f"{base.rstrip('/')}/features/history?limit={limite}",
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0 (calibration AlphaPay)"},
    )
    with urllib.request.urlopen(requete, timeout=30, context=contexte) as reponse:
        fenetres = json.loads(reponse.read().decode("utf-8", "replace")).get("windows") or []
    matrice = np.array(
        [[float((f.get("features") or {}).get(nom) or 0.0) for nom in FEATURE_NAMES] for f in fenetres],
        dtype=float,
    )
    distincts = len({tuple(ligne) for ligne in matrice.tolist()}) if len(matrice) else 0
    return matrice, distincts


def amorcage(nombre=450):
    from ml.train import _vecteurs_nominaux

    vecteurs, _, _ = _vecteurs_nominaux(5400.0, debit_moyen=0.8)
    return np.array(vecteurs[:nombre], dtype=float)


def ajuster(matrice):
    normaliseur = StandardScaler().fit(matrice)
    modele = IsolationForest(n_estimators=256, random_state=20261019, contamination="auto")
    modele.fit(normaliseur.transform(matrice))
    return modele, normaliseur


def noter(modele, normaliseur, vecteurs):
    return np.array([-modele.decision_function(normaliseur.transform([v]))[0] for v in vecteurs], dtype=float)


def placer_seuil(scores_nominaux, scores_attaques):
    """Place le seuil entre les deux bandes, ou refuse de publier un modele."""
    haut = float(np.quantile(scores_nominaux, 1.0 - ALPHA_NOMINAL))
    plus_basse = min(scores_attaques, key=lambda nom: scores_attaques[nom])
    bas = float(scores_attaques[plus_basse])
    rapport = {
        "score_nominal_haut": round(haut, 6),
        "score_attaque_bas": round(bas, 6),
        "attaque_la_plus_basse": plus_basse,
    }
    if bas <= haut:
        rapport["verdict"] = "recouvrement"
        rapport["message"] = (
            "les bandes nominale et d'attaque se recouvrent : aucun seuil ne peut "
            "separer les deux, il faut revoir le jeu d'entrainement"
        )
        return None, rapport
    seuil = float(np.sqrt(haut * bas))
    marge = bas / seuil if seuil else 0.0
    rapport.update(
        {
            "seuil": round(seuil, 6),
            "marge_relative": round(marge, 4),
            "marge_sur_nominal": round(seuil - haut, 6),
            "marge_sur_attaque": round(bas - seuil, 6),
        }
    )
    if marge < MARGE_RELATIVE_MINIMALE:
        rapport["verdict"] = "marge_insuffisante"
        rapport["message"] = f"marge relative {marge:.3f} inferieure a {MARGE_RELATIVE_MINIMALE}"
        return None, rapport
    rapport["verdict"] = "discriminant"
    return seuil, rapport


def principal() -> int:
    analyseur = argparse.ArgumentParser(description="Calibre le detecteur sur des mesures.")
    analyseur.add_argument("base", help="racine du service de telemetrie")
    analyseur.add_argument("--ecrire", default=None, help="dossier ou ecrire le modele")
    args = analyseur.parse_args()

    matrice, distincts = collecter(args.base)
    provenance = "mesures-plateforme"
    print(f"fenetres mesurees  : {len(matrice)} ({distincts} vecteurs distincts)")
    if distincts < MINIMUM_MESURES:
        simule = amorcage()
        print(f"amorcage           : {len(simule)} fenetres simulees ajoutees, provenance declaree")
        matrice = np.vstack([matrice, simule]) if len(matrice) else simule
        provenance = "mesures-plateforme+generateur-amorcage"

    modele, normaliseur = ajuster(matrice)
    scores_nominaux = noter(modele, normaliseur, matrice)
    scores_attaques = {
        nom: float(noter(modele, normaliseur, [[float(profil.get(n, 0.0)) for n in FEATURE_NAMES]])[0])
        for nom, profil in PROFILS.items()
    }
    seuil, rapport = placer_seuil(scores_nominaux, scores_attaques)

    print(f"bande nominale     : mediane {np.median(scores_nominaux):.4f}, maximum {scores_nominaux.max():.4f}")
    for nom, valeur in scores_attaques.items():
        role = "detection du modele" if nom in PROFILS_MODELE else "porte par une politique"
        print(f"  {nom:4s} score {valeur:7.4f}   ({role})")
    print(f"verdict            : {rapport['verdict']}")
    for cle in ("seuil", "score_nominal_haut", "score_attaque_bas", "marge_relative", "marge_sur_nominal", "marge_sur_attaque", "message"):
        if cle in rapport:
            print(f"  {cle:20s}: {rapport[cle]}")

    if seuil is None or not args.ecrire:
        if seuil is None:
            print("aucun modele ecrit : le seuil ne serait pas discriminant.")
            return 2
        print("modele non ecrit (ajouter --ecrire <dossier>).")
        return 0

    paquet = {
        "version": VERSION_MODELE,
        "source_calibrage": provenance,
        "feature_names": list(FEATURE_NAMES),
        "moyennes": {nom: float(normaliseur.mean_[rang]) for rang, nom in enumerate(FEATURE_NAMES)},
        "ecarts": {nom: float(normaliseur.scale_[rang]) for rang, nom in enumerate(FEATURE_NAMES)},
        "scaler": normaliseur,
        "scaler_mean": [float(x) for x in normaliseur.mean_],
        "scaler_scale": [float(x) for x in normaliseur.scale_],
        "seuil": seuil,
        "n_fenetres": int(len(matrice)),
    }
    meta = dict(rapport)
    meta.update(
        {
            "version": VERSION_MODELE,
            "seuil": seuil,
            "source_calibrage": provenance,
            "score_max_nominal": round(float(scores_nominaux.max()), 6),
            "score_max": round(float(scores_nominaux.max()), 6),
            "feature_names": list(FEATURE_NAMES),
            "n_fenetres": int(len(matrice)),
            "n_vecteurs_distincts": distincts,
            "calibre_le": datetime.now(timezone.utc).isoformat(),
        }
    )
    os.makedirs(args.ecrire, exist_ok=True)
    joblib.dump(paquet, os.path.join(args.ecrire, "model.joblib"))
    with open(os.path.join(args.ecrire, "model-meta.json"), "w", encoding="utf-8") as fichier:
        json.dump(meta, fichier, indent=2, ensure_ascii=False)
    print(f"ecrit              : {args.ecrire}")
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
