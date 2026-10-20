#!/usr/bin/env python3
"""Genere un trafic nominal VAIRE a travers la bordure.

Pourquoi la variete est indispensable
-------------------------------------
Un poste au repos produit des fenetres quasi identiques. Entrainer le modele
sur ce seul regime revient a lui apprendre une distribution de variance nulle :
il renvoie alors le meme score pour tout, et ne distingue plus une attaque d'un
systeme sain.

Ce script parcourt donc plusieurs paliers de charge *legitime*, sur plusieurs
routes et depuis plusieurs sources. Le modele apprend ainsi ce qu'est une
plateforme chargee mais normale, et une attaque tombe alors franchement en
dehors de cette plage au lieu de s'y fondre.

Usage :
    python tests/charge_nominale.py [http://edge:8080]
"""

from __future__ import annotations

import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CIBLE = (sys.argv[1] if len(sys.argv) > 1 else "http://edge:8080").rstrip("/")

#: (debit vise en requetes par seconde, duree en secondes)
PALIERS = [(1, 60), (4, 60), (12, 60), (25, 60), (3, 60)]

ROUTES = [
    "/api/ledger/integrity",
    "/api/supervision/state",
    "/api/telemetry/features/current",
    "/healthz",
]


def tirer(route: str) -> bool:
    try:
        with urllib.request.urlopen(f"{CIBLE}{route}", timeout=3) as reponse:
            return reponse.status < 500
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def palier(debit: int, duree: int, numero: int) -> None:
    print(f"palier {numero} : {debit} req/s pendant {duree} s", flush=True)
    fin = time.time() + duree
    intervalle = 1.0 / debit
    with ThreadPoolExecutor(max_workers=min(debit, 24)) as ouvriers:
        while time.time() < fin:
            for route in ROUTES:
                ouvriers.submit(tirer, route)
                time.sleep(intervalle / len(ROUTES))
    print(f"palier {numero} : termine", flush=True)


def main() -> int:
    print(f"cible : {CIBLE}", flush=True)
    for index, (debit, duree) in enumerate(PALIERS, start=1):
        palier(debit, duree, index)
    print("charge nominale variée terminée", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
