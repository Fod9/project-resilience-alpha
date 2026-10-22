#!/usr/bin/env python3
"""Diagnostique la sensibilite du detecteur, sur la plateforme en service.

Pourquoi ce script existe
-------------------------
Un detecteur trop sensible n'est pas un detecteur faux : c'est un detecteur mal
cale. La cause est presque toujours la meme : le modele charge n'est pas celui
qui est livre. Le detecteur lit d'abord `/models/model.joblib` (volume
persistant, ecrit par un entrainement ou une recalibration passee), et ne
retombe sur l'artefact embarque que si ce volume est vide. Un modele entraine
sur du trafic simule y fixe un seuil nettement plus strict que le meme modele
recalibre sur du trafic reel, et la plateforme reelle passe alors au-dessus.

Ce script lit le modele reellement charge, annonce son seuil, puis note les
fenetres reellement observees avec ce seuil. C'est la seule mesure qui dise si
le detecteur va crier au loup sur une plateforme au repos.

Usage, sur la machine qui heberge la pile. La racine du conteneur du detecteur est
en lecture seule, donc `docker cp` y echoue : le script passe par l'entree
standard, ce qui fonctionne sans reconstruire l'image.

    docker exec -i alphaplat-detector sh -c 'cat > /tmp/diag.py' < tests/diagnostic_detecteur.py
    docker exec alphaplat-detector python /tmp/diag.py
"""
import json
import os
import sys
import urllib.request

import joblib
import numpy as np

VOLUME = "/models/model.joblib"
VOLUME_META = "/models/model-meta.json"
EMBARQUE = "/app/artifacts/model.joblib"
EMBARQUE_META = "/app/artifacts/model-meta.json"


def chemins():
    if os.path.exists(VOLUME):
        return VOLUME, VOLUME_META, "volume persistant"
    return EMBARQUE, EMBARQUE_META, "artefact embarque"


def fenetres(base, limite=300):
    with urllib.request.urlopen(f"{base.rstrip('/')}/features/history?limit={limite}", timeout=30) as reponse:
        return (json.load(reponse).get("windows") or [])


def principal() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("TELEMETRY_URL", "http://telemetry:8000")
    chemin, chemin_meta, provenance = chemins()
    paquet = joblib.load(chemin)
    meta = json.load(open(chemin_meta)) if os.path.exists(chemin_meta) else {}
    seuil = float(meta.get("seuil") or paquet.get("seuil") or 0.0)
    print(f"modele charge      : {chemin} ({provenance})")
    print(f"version du modele  : {paquet.get('version')}")
    print(f"version du calibrage: {meta.get('version')}")
    print(f"source de calibrage: {meta.get('source_calibrage')}")
    print(f"seuil              : {seuil:.4f}")
    if provenance == "volume persistant":
        print("               note : un modele du volume prime sur l'artefact embarque")

    observees = fenetres(base)
    if not observees:
        print("aucune fenetre observee : rien a noter")
        return 0
    noms = list(paquet["feature_names"])
    matrice = np.array(
        [[float((f.get("features") or {}).get(nom) or 0.0) for nom in noms] for f in observees],
        dtype=float,
    )
    moyennes = np.array([float(paquet["moyennes"][nom]) for nom in noms])
    ecarts = np.array([float(paquet["ecarts"][nom]) for nom in noms])
    ecarts[ecarts == 0] = 1.0
    scores = -paquet["modele"].decision_function((matrice - moyennes) / ecarts)
    au_dessus = scores >= seuil
    print()
    print(f"fenetres observees : {len(scores)}")
    print(f"score median       : {np.median(scores):.4f}, maximum {scores.max():.4f}")
    print(f"au-dessus du seuil : {int(au_dessus.sum())} / {len(scores)} ({au_dessus.mean()*100:.1f} %)")
    if au_dessus.any():
        ecarts_standardises = np.abs((matrice[au_dessus] - moyennes) / ecarts).mean(axis=0)
        ordre = np.argsort(ecarts_standardises)[::-1][:5]
        print("variables qui pesent le plus sur ces fenetres :")
        for rang in ordre:
            print(f"   {noms[rang]:<28s} ecart standardise moyen {ecarts_standardises[rang]:.2f}")
    print()
    if au_dessus.mean() > 0.2:
        print("conclusion : le seuil charge est trop strict pour cette plateforme.")
        print("Correction : retirer le modele du volume pour revenir a l'artefact livre,")
        print("puis redemarrer le detecteur.")
        print("   docker exec alphaplat-detector rm -f /models/model.joblib /models/model-meta.json")
        print("   docker restart alphaplat-detector")
    else:
        print("conclusion : le seuil charge laisse passer le trafic observe.")
    return 0


if __name__ == "__main__":
    raise SystemExit(principal())
