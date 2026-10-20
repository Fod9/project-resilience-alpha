#!/usr/bin/env python3
"""Profils d'attaque de référence, partagés par la calibration et les tests.

Ces trois vecteurs décrivent les scénarios A1 (rafale volumétrique), A2
(bourrage d'identités) et A3 (injection et exfiltration). Ils servent à deux
choses, avec exactement les mêmes valeurs :

* `tests/scenario.sh` et le banc offensif les poussent vers le moteur, en
  jouant le rôle du détecteur, pour rejouer un signalement ;
* la recalibration s'en sert pour *vérifier* que le seuil retenu sépare
  réellement une attaque du régime nominal.

Ce second usage est le point important. Un seuil que l'attaque ne franchit pas
est un seuil qui ne détecte rien, tout en donnant l'apparence d'un dispositif
armé : il doit faire échouer la calibration au lieu d'être publié.

Aucun import ici : ce module doit rester lisible par un script lancé depuis le
poste comme par un conteneur, sans chemin d'import particulier.
"""

from __future__ import annotations

#: Chaque profil est un vecteur complet des 18 variables observées.
PROFILS: dict[str, dict[str, float]] = {
    "A1": {
        "requests_per_second": 142.0, "error_ratio": 0.62, "latency_p95_ms": 1840.0,
        "latency_p99_ms": 4120.0, "unique_source_ips": 6.0, "source_ip_entropy": 0.41,
        "auth_failure_ratio": 0.12, "auth_attempts_per_identity": 2.0,
        "unique_identities": 8.0, "injection_token_ratio": 0.0, "xss_token_ratio": 0.0,
        "avg_payload_bytes": 412.0, "payload_bytes_stddev": 96.0,
        "endpoint_entropy": 0.36, "requests_per_token": 3.0,
        "outgoing_bytes_ratio": 1.4, "new_source_ip_ratio": 0.0, "waf_block_ratio": 0.04,
    },
    "A2": {
        "requests_per_second": 34.0, "error_ratio": 0.48, "latency_p95_ms": 320.0,
        "latency_p99_ms": 610.0, "unique_source_ips": 3.0, "source_ip_entropy": 0.22,
        "auth_failure_ratio": 0.88, "auth_attempts_per_identity": 42.0,
        "unique_identities": 63.0, "injection_token_ratio": 0.0, "xss_token_ratio": 0.0,
        "avg_payload_bytes": 208.0, "payload_bytes_stddev": 24.0,
        "endpoint_entropy": 0.18, "requests_per_token": 0.4,
        "outgoing_bytes_ratio": 1.1, "new_source_ip_ratio": 0.02, "waf_block_ratio": 0.02,
    },
    "A3": {
        "requests_per_second": 19.0, "error_ratio": 0.71, "latency_p95_ms": 480.0,
        "latency_p99_ms": 900.0, "unique_source_ips": 2.0, "source_ip_entropy": 0.15,
        "auth_failure_ratio": 0.05, "auth_attempts_per_identity": 1.0,
        "unique_identities": 2.0, "injection_token_ratio": 0.34, "xss_token_ratio": 0.11,
        "avg_payload_bytes": 1180.0, "payload_bytes_stddev": 340.0,
        "endpoint_entropy": 0.44, "requests_per_token": 6.0,
        "outgoing_bytes_ratio": 11.5, "new_source_ip_ratio": 0.0, "waf_block_ratio": 0.46,
    },
}

#: Cible applicative suggérée pour chaque scénario, utilisée par les
#: signalements rejoués.
CIBLES: dict[str, str] = {
    "A1": "api-payment",
    "A2": "api-auth",
    "A3": "api-payment",
}

#: Profils dont la detection incombe au score d'atypie du modele. Les autres
#: scenarios sont portes par les conditions de leur politique : le bourrage
#: d'identites par `auth_failure_ratio` et `auth_attempts_per_identity`,
#: l'injection par `injection_token_ratio` et `waf_block_ratio`. Exiger du modele
#: qu'il les isole reviendrait a lui demander de reproduire des regles ecrites
#: ailleurs, et rendrait toute calibration impossible sans rien proteger de plus.
PROFILS_MODELE: tuple[str, ...] = ("A1",)


def profils_du_modele() -> dict[str, dict[str, float]]:
    """Profils d'attaque que le score d'atypie doit savoir repousser."""
    return {nom: PROFILS[nom] for nom in PROFILS_MODELE if nom in PROFILS}
