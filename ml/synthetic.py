"""Simulation de trafic nominal : base de calibrage du détecteur.

Pourquoi simuler plutôt que collecter : au démarrage du sprint, on ne dispose
d'aucun historique réel étiqueté. Le détecteur est donc **non supervisé** : il
apprend la forme de la normale. Encore faut-il disposer d'un échantillon de
cette normale ; c'est le rôle de ce générateur.

Il ne s'agit pas d'un « jeu d'attaques » : ce module ne produit **que** du
trafic ordinaire, avec sa variabilité légitime (heures creuses et chargées,
pics d'activité, utilisateurs occasionnels, latence dépendante de la charge).
Aucune attaque simulée n'entre dans l'entraînement : c'est ce qui garantit que
le modèle mesure un écart à la normale au lieu de reconnaître des motifs
appris.

Le réalisme des corrélations importe plus que le volume : la latence doit
croître avec la charge, le nombre d'adresses distinctes doit varier avec
l'heure, la répartition des chemins doit rester concentrée.
"""

from __future__ import annotations

import math
import random

from common.features import Evenement

#: Utilisateurs légitimes du jeu de démonstration.
UTILISATEURS = ("admin", "operateur", "client01", "client02", "client03")

#: Chemins réellement servis, avec leur part approximative du trafic.
CHEMINS = (
    ("/api/payments", 0.34),
    ("/api/payments/", 0.10),
    ("/api/ledger/accounts", 0.14),
    ("/api/auth/token", 0.12),
    ("/api/supervision/timeline", 0.08),
    ("/api/detector/score/current", 0.06),
    ("/", 0.08),
    ("/api/payments/limits", 0.04),
    ("/api/ledger/integrity", 0.04),
)

#: Adresses clientes du réseau de démonstration (192.168.137.0/24).
ADRESSES = tuple(f"192.168.137.{dernier}" for dernier in range(30, 60))

_CODES = (200, 200, 200, 200, 200, 200, 200, 200, 200, 201, 400, 401, 404, 429)


def _choisir_chemin(rng: random.Random) -> str:
    tirage = rng.random()
    cumul = 0.0
    for chemin, poids in CHEMINS:
        cumul += poids
        if tirage <= cumul:
            return chemin
    return CHEMINS[0][0]


def _charge_de_l_heure(instant: float) -> float:
    """Profil d'activité sur 24 h : creux nocturne, pointe en journée."""
    heure = (instant % 86400.0) / 3600.0
    creux = 1.0 + 8.0 * math.exp(-((heure - 14.0) ** 2) / 18.0)
    nuit = 0.25 if 1.0 <= heure <= 6.0 else 1.0
    return creux * nuit


def _evenement_http(
    rng: random.Random, instant: float, charge: float, population: int = len(ADRESSES)
) -> Evenement:
    chemin = _choisir_chemin(rng)
    adresse = rng.choice(ADRESSES[: max(1, population)])
    statut = rng.choice(_CODES)
    # La latence suit la charge : plus il y a de trafic, plus le service ralentit.
    latence_s = max(0.004, rng.gauss(0.020 + 0.010 * charge, 0.008))
    entrant = max(120.0, rng.gauss(340.0 + 60.0 * charge, 55.0))
    sortant = max(140.0, rng.gauss(520.0 + 90.0 * charge, 80.0))
    if rng.random() < 0.006:
        # Incident technique ordinaire : latence longue, sans rapport avec une attaque.
        latence_s += rng.uniform(0.2, 0.9)
        statut = 504
    return Evenement(
        ts=instant,
        source="edge",
        kind="http.request",
        fields={
            "method": "POST" if rng.random() < 0.6 else "GET",
            "path": chemin,
            "route": chemin.split("/")[1] if "/" in chemin[1:] else "web",
            "status": statut,
            "duration_s": latence_s,
            "bytes_in": entrant,
            "bytes_out": sortant,
            "source_ip": adresse,
            "user_agent": "Mozilla/5.0 (banc d'essai AlphaPay)",
            "waf_blocked": 0,
            "redteam_marker": "",
        },
    )


def _evenement_service(
    rng: random.Random, instant: float, charge: float, population: int = len(ADRESSES)
) -> Evenement | None:
    if rng.random() > 0.45:
        return None
    identifiant = rng.choice(UTILISATEURS)
    return Evenement(
        ts=instant,
        source="service",
        kind="http.request",
        fields={
            "identity": identifiant,
            "route": "/payments",
            "status": 201 if rng.random() < 0.85 else 400,
            "source_ip": rng.choice(ADRESSES[: max(1, population)]),
            "duration_ms": max(3.0, rng.gauss(25.0 + 15.0 * charge, 9.0)),
        },
    )


def _evenement_auth(
    rng: random.Random, instant: float, population: int = len(ADRESSES)
) -> Evenement:
    utilisateur = rng.choice(UTILISATEURS)
    # Taux d'échec ordinaire : mot de passe oublié, jeton expiré.
    echec = rng.random() < 0.09
    return Evenement(
        ts=instant,
        source="service",
        kind="auth.attempt",
        fields={
            "identity": utilisateur,
            "outcome": "failure" if echec else "success",
            "source_ip": rng.choice(ADRESSES[: max(1, population)]),
            "role": "customer" if utilisateur.startswith("client") else "operator",
        },
    )


def flux_normal(
    duree_secondes: float = 5400.0,
    debit_moyen: float = 0.8,
    graine: int = 20261019,
    pas: float = 0.25,
) -> list[Evenement]:
    """Produit un flux d'événements nominaux couvrant `duree_secondes`.

    `debit_moyen` est exprimé en requêtes par seconde en heure de pointe.
    """
    rng = random.Random(graine)
    evenements: list[Evenement] = []
    instant = 0.0
    budget = 0.0
    while instant < duree_secondes:
        charge = _charge_de_l_heure(instant) * rng.uniform(0.85, 1.15)
        # Population d'adresses et activite d'authentification suivent la charge :
        # une plateforme peu sollicitee n'a qu'un client et n'authentifie presque
        # personne. Les tirer a taux fixe par pas de temps garantissait des
        # dizaines d'adresses et d'identites par fenetre, meme au repos : le
        # regime de repos reel, un seul client et aucune authentification, sortait
        # alors de la normale apprise et etait declare anormal en permanence.
        debit_instantane = max(0.0, debit_moyen * charge)
        population = 1 if debit_instantane < 1.0 else min(len(ADRESSES), int(debit_instantane))
        budget += max(0.0, debit_moyen * charge * pas)
        while budget >= 1.0:
            budget -= 1.0
            evenements.append(_evenement_http(rng, instant, charge, population))
            if rng.random() < 0.25:
                service = _evenement_service(rng, instant, charge, population)
                if service is not None:
                    evenements.append(service)
            if rng.random() < 0.06:
                evenements.append(_evenement_auth(rng, instant, population))
        instant += pas
    return evenements
