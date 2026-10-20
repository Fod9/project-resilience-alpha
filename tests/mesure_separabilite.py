"""Mesure la separabilite reelle entre le regime nominal observe et les profils d'attaque."""
import json
import urllib.request

import numpy as np

from common.features import FEATURE_NAMES
from ml import train as soi
from ml.profils_attaque import PROFILS

BASE = "http://telemetry:8000"


def principales(valeurs, combien=6):
    ordonnees = sorted(enumerate(valeurs), key=lambda item: -item[1])[:combien]
    return [(FEATURE_NAMES[i], round(float(v), 4)) for i, v in ordonnees]


with urllib.request.urlopen(f"{BASE}/features/history?limit=600", timeout=30) as reponse:
    fenetres = json.loads(reponse.read().decode()).get("windows") or []

utilisables = [
    f
    for f in fenetres
    if not f.get("warming_up")
    and f.get("features")
    and int((f.get("diagnostics") or {}).get("edge_events") or 0)
]
brut = [
    [float(v.get(nom, 0.0)) for nom in FEATURE_NAMES]
    for v in (f["features"] for f in utilisables)
]
debits = [ligne[0] for ligne in brut]
debit = max(0.8, float(np.percentile(debits, 90))) if debits else 0.8

artefact = soi.entrainer(
    max(4500.0, 30.0 * len(brut)),
    n_estimateurs=256,
    graine=20261019,
    debit_moyen=debit,
    supplementaires=brut,
)
modele = artefact["modele"]
normaliseur = artefact["scaler"]
scores_nominaux = -modele.decision_function(normaliseur.transform(brut))
scores_attaques = {
    nom: float(-modele.decision_function(normaliseur.transform([[float(profil.get(n, 0.0)) for n in FEATURE_NAMES]]))[0])
    for nom, profil in PROFILS.items()
}

print(f"fenetres nominales : {len(brut)}   debit retenu : {debit:.3f} req/s")
print(f"score nominal      : min {float(scores_nominaux.min()):.5f}  max {float(scores_nominaux.max()):.5f}")
for nom, score in sorted(scores_attaques.items()):
    print(f"score attaque {nom}   : {score:.5f}")
print(f"seuil annonce      : {float(artefact['seuil']):.5f}")
print("detail des 3 fenetres nominales les plus atypiques :")
for index in np.argsort(scores_nominaux)[-3:][::-1]:
    print(f"  score {float(scores_nominaux[index]):.5f} -> {principales(brut[index])}")
