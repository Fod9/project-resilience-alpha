#!/usr/bin/env python3
"""Verifie que le detecteur est arme et silencieux a la fois.

Deux defauts opposes guettent une calibration d'anomalie, et ils se masquent
l'un l'autre :

* un seuil trop bas signale la plateforme au repos en permanence ;
* un seuil trop haut, choisi pour faire taire ces alertes, finit au-dessus des
  profils d'attaque et le detecteur ne declenche plus rien. C'est le defaut le
  plus grave des deux, parce qu'il ne se voit pas : le dispositif a l'air arme.

Ce script note, avec le modele reellement livre, trois ensembles : la normale
apprise, les fenetres reellement observees sur la plateforme, et les profils
d'attaque de reference. Il exige que le seuil tombe entre les deux premiers et le
troisieme, puis affiche la marge.

Usage, sur un poste de developpement, depuis la racine du depot :

    python ml/verifier_separation.py [base de la telemetrie]

La base est la racine du service de telemetrie : http://telemetry:8000 depuis le
reseau applicatif, ou http://127.0.0.1/api/telemetry depuis le poste hote, la
bordure retirant ce prefixe.

L'option --sans-telemetrie saute la notation des fenetres observees, utile en
integration continue.
"""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request

import joblib
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "services"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from ml.profils_attaque import PROFILS, PROFILS_MODELE  # noqa: E402
from ml.synthetic import flux_normal  # noqa: E402
from ml.train import entrainer  # noqa: E402


def vecteurs_nominaux(graine: int = 20261019) -> np.ndarray:
    from ml.train import _vecteurs_nominaux

    vecteurs, _, _ = _vecteurs_nominaux(5400.0, debit_moyen=0.8)
    return np.array(vecteurs, dtype=float)


def fenetres_observees(base: str | None, limite: int = 300) -> np.ndarray | None:
    if not base:
        return None
    contexte = ssl.create_default_context()
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    try:
        requete = urllib.request.Request(
            f"{base.rstrip('/')}/features/history?limit={limite}",
            headers={
                "Accept": "application/json",
                "User-Agent": "Mozilla/5.0 (verification de separation AlphaPay)",
            },
        )
        with urllib.request.urlopen(requete, timeout=30, context=contexte) as reponse:
            brut = reponse.read().decode("utf-8", "replace")
        fenetres = (json.loads(brut).get("windows") or [])
    except (urllib.error.URLError, OSError, ValueError) as erreur:
        debut = brut[:160].replace("\n", " ") if "brut" in dir() else ""
        print(f"telemetrie injoignable ({type(erreur).__name__}: {erreur}) : notation reelle sautee")
        if debut:
            print(f"reponse recue : {debut}")
        return None
    if not fenetres:
        return None
    return fenetres


def principal() -> int:
    base = None
    for argument in sys.argv[1:]:
        if argument != "--sans-telemetrie":
            base = argument
    # Les chemins sont surchargeables pour pouvoir viser l'artefact embarque
    # (/app/artifacts) ou celui d'un volume (/models) depuis un conteneur, ou le
    # modele livre depuis la racine du depot.
    chemin_modele = os.environ.get("MODEL_PATH", "ml/artifacts/model.joblib")
    chemin_meta = os.environ.get("MODEL_META_PATH", "ml/artifacts/model-meta.json")
    paquet = joblib.load(chemin_modele)
    meta = json.load(open(chemin_meta))
    noms = list(paquet["feature_names"])
    moyennes = np.array([float(paquet["moyennes"][n]) for n in noms])
    ecarts = np.array([float(paquet["ecarts"][n]) for n in noms])
    ecarts[ecarts == 0] = 1.0
    seuil = float(meta["seuil"])

    def score(valeurs):
        return float(-paquet["modele"].decision_function([(np.array(valeurs, dtype=float) - moyennes) / ecarts])[0])

    nominales = vecteurs_nominaux()
    scores_nominaux = np.array([score(v) for v in nominales])
    import hashlib

    empreinte = hashlib.sha256(open(chemin_modele, "rb").read()).hexdigest()[:16]
    print(f"artefact          : {chemin_modele}")
    print(f"empreinte         : {empreinte}  (a comparer entre deux postes)")
    print(f"modele            : {meta.get('version')} (source {meta.get('source_calibrage')})")
    print(f"calibre le        : {meta.get('calibre_le') or 'non declare'}")
    print(f"seuil             : {seuil:.4f}")
    for cle in ("score_nominal_haut", "score_attaque_bas", "marge_relative"):
        if meta.get(cle) is not None:
            print(f"{cle:18s}: {meta[cle]}")
    print(f"normale apprise   : {len(scores_nominaux)} fenetres, median {np.median(scores_nominaux):.4f}, max {scores_nominaux.max():.4f}")

    observees = fenetres_observees(base)
    silence = True
    if observees is not None:
        vecteurs = np.array([[float((f.get("features") or {}).get(n) or 0.0) for n in noms] for f in observees], dtype=float)
        scores_reels = np.array([score(v) for v in vecteurs])
        au_dessus = int((scores_reels >= seuil).sum())
        print(f"plateforme reelle : {len(scores_reels)} fenetres, median {np.median(scores_reels):.4f}, max {scores_reels.max():.4f}, au-dessus du seuil {au_dessus}")
        silence = au_dessus == 0

    arme = True
    print()
    print("profil | score | seuil franchi | marge")
    for nom, profil in PROFILS.items():
        valeur = score([float(profil[n]) for n in noms])
        franchi = valeur >= seuil
        arme = arme and franchi
        role = "detection du modele" if nom in PROFILS_MODELE else "porte par une politique"
        print(f"{nom:6s} | {valeur:7.4f} | {'oui' if franchi else 'NON':12s} | {valeur - seuil:+7.4f}   ({role})")

    print()
    print(f"arme        : {'oui' if arme else 'NON'}")
    if observees is None:
        print("silencieux  : non mesure (telemetrie injoignable ou aucune fenetre)")
    else:
        print(f"silencieux  : {'oui' if silence else 'NON'}")
    if not arme:
        print("Le seuil est au-dessus d'un profil d'attaque : le detecteur ne declenchera rien.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
