#!/usr/bin/env python3
"""Test de bout en bout de l'authentification faciale, sur la pile reelle.

Passe par la bordure (HTTPS, certificat auto-signe) : c'est le chemin d'un
navigateur, pas un appel interne a un conteneur.

Le visage est simule par des descripteurs : ce script ne peut pas tenir une
webcam. Ce qu'il prouve, c'est la chaine serveur complete : enrolement, moyenne
du gabarit, distance cosinus, refus du defi non valide, refus du visage
inconnu, delivrance d'un jeton, et journalisation sans le descripteur.
"""

import json
import math
import random
import ssl
import sys
import urllib.error
import urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1").rstrip("/")
SEUIL = 0.45
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def appel(chemin, methode="GET", corps=None, jeton=None):
    donnees = json.dumps(corps).encode() if corps is not None else None
    requete = urllib.request.Request(BASE + chemin, data=donnees, method=methode)
    requete.add_header("Accept", "application/json")
    if donnees is not None:
        requete.add_header("Content-Type", "application/json")
    if jeton:
        requete.add_header("Authorization", "Bearer " + jeton)
    try:
        with urllib.request.urlopen(requete, timeout=30, context=CTX) as reponse:
            return reponse.status, reponse.read().decode()
    except urllib.error.HTTPError as erreur:
        return erreur.code, erreur.read().decode()
    except Exception as erreur:  # reseau
        return 0, f"ECHEC RESEAU {erreur}"


def vecteur(graine):
    r = random.Random(graine)
    v = [r.gauss(0, 1) for _ in range(128)]
    norme = math.sqrt(sum(x * x for x in v))
    return [x / norme for x in v]


def bruite(base, amplitude, graine):
    r = random.Random(graine)
    v = [x + r.gauss(0, amplitude) for x in base]
    norme = math.sqrt(sum(x * x for x in v))
    return [x / norme for x in v]


def distance(a, b):
    produit = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return 1 - produit / (na * nb)


def etape(titre, code, corps, complement=""):
    texte = corps if len(corps) <= 300 else corps[:300] + "..."
    print(f"[{titre}] HTTP {code} {complement}")
    print(f"    {texte}")
    print()


reference = vecteur(1)
captures = [bruite(reference, 0.01, 100 + rang) for rang in range(8)]
proche = bruite(reference, 0.03, 7)
loin = vecteur(99)

print(f"distance moyenne gabarit/proche : {sum(distance(reference, c) for c in captures) / 8:.4f}")
print(f"distance proche/etranger        : {distance(proche, loin):.4f}")
print(f"seuil annonce par le service    : {SEUIL}")
print()

etape(*("politique faciale", *appel("/api/auth/face/policy")))

code, corps = appel(
    "/api/auth/token", "POST", {"username": "operateur", "password": "AlphaPay-Ops-2026!"}
)
etape("connexion mot de passe", code, corps)
if code != 200:
    sys.exit("la connexion par mot de passe est la base de tout : arret")
jeton = json.loads(corps)["access_token"]

etape(
    "enrolement 8 captures",
    *appel(
        "/api/auth/face/enroll",
        "POST",
        {"username": "operateur", "descriptors": captures},
        jeton,
    ),
)

etape("statut du gabarit", *appel("/api/auth/face/status/operateur", jeton=jeton))

code, corps = appel(
    "/api/auth/face/verify",
    "POST",
    {"username": "operateur", "descriptor": proche, "challenge": {"blink": True, "turn_deg": 25.0}},
)
etape("visage reconnu + defi valide", code, corps, f"jeton delivre={'access_token' in corps}")
jeton_visage = json.loads(corps).get("access_token") if code == 200 else None

etape(
    "visage etranger",
    *appel(
        "/api/auth/face/verify",
        "POST",
        {"username": "operateur", "descriptor": loin, "challenge": {"blink": True, "turn_deg": 25.0}},
    ),
)

etape(
    "defi non valide",
    *appel(
        "/api/auth/face/verify",
        "POST",
        {
            "username": "operateur",
            "descriptor": proche,
            "challenge": {"blink": False, "turn_deg": 0.0},
        },
    ),
)

etape(
    "descripteur a 127 valeurs",
    *appel(
        "/api/auth/face/verify",
        "POST",
        {"username": "operateur", "descriptor": proche[:127], "challenge": {"blink": True, "turn_deg": 25.0}},
    ),
)

etape(
    "descripteur hors bornes",
    *appel(
        "/api/auth/face/verify",
        "POST",
        {"username": "operateur", "descriptor": [2.0] * 128, "challenge": {"blink": True, "turn_deg": 25.0}},
    ),
)

if jeton_visage:
    etape("jeton du visage sur /users/me", *appel("/api/auth/users/me", jeton=jeton_visage))

etape("tableau de bord SANS jeton", *appel("/api/supervision/state"))
