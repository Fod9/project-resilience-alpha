#!/usr/bin/env python3
"""Verifie le defi sans clignement, sur la pile reelle.

La rotation de tete est desormais le seul geste exige : ce script prouve qu'une
verification sans clignement est acceptee si la rotation est suffisante, et
refusee si elle ne l'est pas.
"""
import json
import math
import random
import ssl
import urllib.error
import urllib.request

BASE = "https://dind:443"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def appel(chemin, methode="GET", corps=None, jeton=None):
    donnees = json.dumps(corps).encode() if corps is not None else None
    requete = urllib.request.Request(BASE + chemin, data=donnees, method=methode)
    requete.add_header("Accept", "application/json")
    if donnees is not None:
        requete.add_header("Content-Type", "application/json")
    if jeton is not None:
        requete.add_header("Authorization", "Bearer " + jeton)
    try:
        with urllib.request.urlopen(requete, timeout=20, context=CTX) as reponse:
            return reponse.status, reponse.read().decode()
    except urllib.error.HTTPError as erreur:
        return erreur.code, erreur.read().decode()


def vecteur(graine):
    generateur = random.Random(graine)
    valeurs = [generateur.gauss(0, 1) for _ in range(128)]
    longueur = math.sqrt(sum(v * v for v in valeurs))
    return [v / longueur for v in valeurs]


def voisin(base, distance_visee, graine):
    """Construit un descripteur a une distance cosinus imposee de `base`.

    Le seuil se juge sur des distances mesurees, pas sur des vecteurs tires au
    hasard : 0,067 correspond au centile 95 de deux photos d'une meme personne,
    0,073 a la paire de personnes differentes la plus proche du jeu mesure.
    """
    aleatoire = random.Random(graine)
    norme = math.sqrt(sum(x * x for x in base))
    unitaire = [x / norme for x in base]
    reste = [aleatoire.gauss(0, 1) for _ in base]
    produit = sum(a * b for a, b in zip(reste, unitaire))
    reste = [a - produit * b for a, b in zip(reste, unitaire)]
    norme_reste = math.sqrt(sum(x * x for x in reste))
    reste = [x / norme_reste for x in reste]
    cosinus = 1.0 - distance_visee
    sinus = math.sqrt(max(0.0, 1.0 - cosinus * cosinus))
    return [cosinus * a + sinus * b for a, b in zip(unitaire, reste)]


def etape(titre, code, corps):
    court = corps if len(corps) < 200 else corps[:200] + "..."
    print("[" + titre + "] HTTP " + str(code))
    print("    " + court)


code, corps = appel("/api/auth/face/policy")
etape("politique faciale", code, corps)
politique = json.loads(corps)

code, corps = appel(
    "/api/auth/token",
    "POST",
    {"username": "operateur", "password": "AlphaPay-Ops-2026!"},
)
etape("connexion mot de passe", code, corps[:40])
jeton = json.loads(corps)["access_token"]

reference = vecteur(1)
code, corps = appel(
    "/api/auth/face/enroll",
    "POST",
    {"username": "operateur", "descriptors": [reference] * 8},
    jeton,
)
etape("enrolement de 8 captures", code, corps)

code, corps = appel(
    "/api/auth/face/verify",
    "POST",
    {
        "username": "operateur",
        "descriptor": reference,
        "challenge": {"blink": False, "turn_deg": 25.0},
    },
)
etape("sans clignement, rotation de 25 degres", code, corps[:150])
jeton_visage = json.loads(corps).get("access_token") if code == 200 else None

code, corps = appel(
    "/api/auth/face/verify",
    "POST",
    {
        "username": "operateur",
        "descriptor": reference,
        "challenge": {"blink": False, "turn_deg": 0.0},
    },
)
etape("sans clignement, rotation nulle", code, corps[:180])

code, corps = appel("/api/auth/face/verify", "POST", {
    "username": "operateur",
    "descriptor": voisin(reference, 0.067, 3),
    "challenge": {"blink": False, "turn_deg": 25.0},
})
etape("meme personne, centile 95 mesure (0,067)", code, corps[:140])

code, corps = appel("/api/auth/face/verify", "POST", {
    "username": "operateur",
    "descriptor": voisin(reference, 0.073, 5),
    "challenge": {"blink": False, "turn_deg": 25.0},
})
etape("personne differente la plus proche mesuree (0,073)", code, corps[:200])

if jeton_visage is not None:
    code, corps = appel("/api/auth/users/me", jeton=jeton_visage)
    etape("jeton obtenu sans clignement sur /users/me", code, corps[:110])

print()
print("clignement exige :", politique.get("require_blink"), "| rotation exigee :", politique.get("require_turn"))
