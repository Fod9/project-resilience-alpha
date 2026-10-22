#!/usr/bin/env python3
"""Mesure le seuil de comparaison faciale sur des visages reels.

Pourquoi ce script existe
-------------------------
Un seuil choisi a l'oeil ne veut rien dire dans un espace de descripteurs. La
premiere valeur livree, 0,45, acceptait 100 % des visages d'un jeu de test reel :
elle avait ete validee sur des vecteurs aleatoires, qui sont toujours tres
eloignes, alors que deux visages differents occupent une region voisine du meme
espace.

Ce script mesure la seule chose qui decide : la distribution des distances entre
deux photos d'une meme personne, et entre deux personnes differentes. Le seuil
se place ensuite entre les deux, en connaissance des taux de refus et
d'acceptation qu'il produit.

Prerequis (poste de developpement, pas l'image livree) :
    pip install scikit-learn pillow numpy playwright
    python -m playwright install chromium
Le jeu de visages (Olivetti, 400 images, 40 personnes) est telecharge au premier
lancement.

Usage :
    python tests/mesure_seuil_visage.py

Duree : deux a trois minutes, dont le calcul de 400 descripteurs par le modele.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(os.environ.get("DOSSIER_MESURE", "/opt/data/mesure-seuil-visage"))
SERVEUR = "http://127.0.0.1:8099"


def preparer() -> None:
    import numpy as np
    from PIL import Image
    from sklearn.datasets import fetch_olivetti_faces

    (RACINE / "images").mkdir(parents=True, exist_ok=True)
    (RACINE / "model").mkdir(parents=True, exist_ok=True)
    paquet = Path(__file__).resolve().parents[1] / "frontend/node_modules/@vladmandic/face-api"
    if not paquet.exists():
        raise SystemExit("dependance absente : lancer npm install dans frontend/")
    shutil.copy(paquet / "dist/face-api.esm.js", RACINE / "face-api.esm.js")
    for nom in sorted(os.listdir(paquet / "model")):
        if nom.startswith(("tiny_face_detector", "face_landmark_68_model", "face_recognition_model")):
            shutil.copy(paquet / "model" / nom, RACINE / "model" / nom)

    donnees = fetch_olivetti_faces(data_home=str(RACINE / "olivetti"), shuffle=False)
    for rang, (pixels, personne) in enumerate(zip(donnees.images, donnees.target)):
        image = Image.fromarray((pixels * 255).astype(np.uint8)).convert("RGB").resize((150, 150))
        image.save(RACINE / "images" / f"p{int(personne):02d}_{rang:03d}.png")
    noms = sorted(p.name for p in (RACINE / "images").glob("*.png"))
    (RACINE / "liste.json").write_text(json.dumps(noms), encoding="utf-8")
    print(f"jeu prepare : {len(noms)} visages")


AMORCE = """
async () => {
  const faceapi = await import('/face-api.esm.js');
  try { await faceapi.tf.setBackend('cpu'); } catch (e) { /* backend deja pret */ }
  await faceapi.tf.ready();
  await faceapi.nets.faceRecognitionNet.loadFromUri('/model');
  window.__faceapi = faceapi;
  return faceapi.tf.getBackend();
}
"""

UN_LOT = """
async (noms) => {
  const sortie = {};
  for (const nom of noms) {
    const image = new Image();
    image.src = '/images/' + nom;
    await image.decode();
    const descripteur = await window.__faceapi.nets.faceRecognitionNet.computeFaceDescriptor(image);
    sortie[nom] = Array.from(descripteur);
  }
  return sortie;
}
"""


def mesurer(lot: int = 40) -> dict:
    from playwright.sync_api import sync_playwright

    noms = json.loads((RACINE / "liste.json").read_text(encoding="utf-8"))
    descripteurs: dict[str, list[float]] = {}
    serveur = subprocess.Popen(
        [sys.executable, "-m", "http.server", "8099", "--bind", "127.0.0.1"],
        cwd=str(RACINE),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    try:
        with sync_playwright() as p:
            navigateur = p.chromium.launch(headless=True)
            page = navigateur.new_page()
            page.goto(SERVEUR, wait_until="load", timeout=30000)
            print("backend de calcul :", page.evaluate(AMORCE))
            for debut in range(0, len(noms), lot):
                descripteurs.update(page.evaluate(UN_LOT, noms[debut : debut + lot]))
                print(f"  descripteurs : {len(descripteurs)} / {len(noms)}")
            navigateur.close()
    finally:
        serveur.terminate()
    (RACINE / "descripteurs.json").write_text(json.dumps(descripteurs), encoding="utf-8")
    return descripteurs


def analyser(descripteurs: dict) -> dict:
    import itertools
    import random

    import numpy as np

    def distance(a, b):
        return float(1.0 - (a @ b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    personnes: dict[str, list] = {}
    for nom, vecteur in descripteurs.items():
        personnes.setdefault(nom.split("_")[0], []).append(np.array(vecteur, dtype=float))

    intra = [distance(a, b) for liste in personnes.values() for a, b in itertools.combinations(liste, 2)]
    tirage = random.Random(11)
    cles = list(personnes)
    inter = [
        distance(tirage.choice(personnes[g], ), tirage.choice(personnes[d]))
        for g, d in (tirage.sample(cles, 2) for _ in range(40000))
    ]
    intra_a, inter_a = np.array(intra), np.array(inter)

    print()
    print(f"intra-personne  : median {np.median(intra_a):.3f}, p95 {np.percentile(intra_a,95):.3f}, max {intra_a.max():.3f}")
    print(f"inter-personnes : min {inter_a.min():.3f}, p01 {np.percentile(inter_a,1):.3f}, median {np.median(inter_a):.3f}, max {inter_a.max():.3f}")
    print()
    print(" seuil | faux rejets | fausses acceptations")
    for seuil in np.arange(0.04, 0.21, 0.01):
        print(f" {seuil:5.2f} | {(intra_a > seuil).mean()*100:10.2f}% | {(inter_a <= seuil).mean()*100:18.2f}%")
    seuils = np.arange(0.02, 0.30, 0.001)
    ecarts = [abs((intra_a > s).mean() - (inter_a <= s).mean()) for s in seuils]
    egalite = float(seuils[int(np.argmin(ecarts))])
    print()
    print(f"taux d'egalite mesure : {egalite:.3f} (faux rejets {(intra_a > egalite).mean()*100:.1f} %, fausses acceptations {(inter_a <= egalite).mean()*100:.1f} %)")
    return {
        "intra_mediane": float(np.median(intra_a)),
        "intra_p95": float(np.percentile(intra_a, 95)),
        "inter_minimum": float(inter_a.min()),
        "inter_p01": float(np.percentile(inter_a, 1)),
        "inter_mediane": float(np.median(inter_a)),
        "inter_maximum": float(inter_a.max()),
        "taux_egalite": egalite,
    }


def principal() -> int:
    preparer()
    rapport = analyser(mesurer())
    print()
    print("rapport :", json.dumps(rapport, indent=2))
    print()
    print("Rappel : ces valeurs decrivent le modele embarque, sans alignement")
    print("prealable, donc dans le cas le plus defavorable. Le seuil livre est dans")
    print("services/api-auth/app/face.py, constante SEUIL_CALIBRE.")
    return 0


if __name__ == "__main__":
    sys.exit(principal())
