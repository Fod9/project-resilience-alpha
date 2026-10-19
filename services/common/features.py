"""Vecteur des 18 variables observées — contrat partagé.

Ce module est utilisé à deux endroits, ce qui garantit qu'ils parlent
exactement le même langage :

* le service `telemetry`, qui agrège en continu la télémétrie réelle ;
* l'entraînement `ml/train.py`, qui agrège un trafic nominal simulé pour
  calibrer le détecteur.

Si les deux divergeaient, le modèle apprendrait une distribution qui n'a rien à
voir avec celle observée en production : l'écart serait silencieux et fatal.
D'où la mise en commun.

Aucune règle de décision ne se trouve ici : ces grandeurs sont des
**observations**. La qualification « normal / anormal » est produite par le
modèle non supervisé, uniquement.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field

#: Ordre canonique du vecteur. Ne pas réordonner sans réentraîner le modèle.
FEATURE_NAMES: tuple[str, ...] = (
    "requests_per_second",
    "error_ratio",
    "latency_p95_ms",
    "latency_p99_ms",
    "unique_source_ips",
    "source_ip_entropy",
    "auth_failure_ratio",
    "auth_attempts_per_identity",
    "unique_identities",
    "injection_token_ratio",
    "xss_token_ratio",
    "avg_payload_bytes",
    "payload_bytes_stddev",
    "endpoint_entropy",
    "requests_per_token",
    "outgoing_bytes_ratio",
    "new_source_ip_ratio",
    "waf_block_ratio",
)

#: Familles de règles OWASP CRS considérées comme des signatures d'injection
#: (SQL, inclusion de fichier, traversée de répertoire, injection de commande).
FAMILLES_INJECTION = (
    "attack-sqli",
    "attack-lfi",
    "attack-rfi",
    "attack-path-traversal",
    "attack-command-injection",
)

FAMILLES_XSS = ("attack-xss",)


@dataclass(slots=True)
class Evenement:
    """Événement normalisé, quelle que soit sa provenance."""

    ts: float
    source: str  # edge | service | modsec
    kind: str  # http.request | auth.attempt | modsec.transaction
    fields: dict = field(default_factory=dict)


def _entropie_normalisee(compteurs: dict[str, int]) -> float:
    """Entropie de Shannon ramenée dans [0, 1]."""
    total = sum(compteurs.values())
    if total <= 0 or len(compteurs) <= 1:
        return 0.0
    h = 0.0
    for valeur in compteurs.values():
        if valeur <= 0:
            continue
        p = valeur / total
        h -= p * math.log(p)
    return h / math.log(len(compteurs))


def _percentile(valeurs: list[float], quantile: float) -> float:
    if not valeurs:
        return 0.0
    ordonnees = sorted(valeurs)
    if len(ordonnees) == 1:
        return float(ordonnees[0])
    position = quantile * (len(ordonnees) - 1)
    bas = int(math.floor(position))
    haut = min(bas + 1, len(ordonnees) - 1)
    fraction = position - bas
    return float(ordonnees[bas] + (ordonnees[haut] - ordonnees[bas]) * fraction)


@dataclass
class Reference:
    """Mémoire longue des comportements déjà observés.

    Elle sert à deux variables dont le sens est « par rapport à d'habitude » :
    la part d'adresses jamais vues et l'écart de volume sortant. Sans elle, ces
    deux variables seraient constantes et n'apporteraient rien au modèle.
    """

    alpha: float = 0.05
    ips_connues: set[str] = field(default_factory=set)
    moyenne_sortante: float = 0.0
    observations: int = 0

    def observer(self, adresses: set[str], moyenne_sortante: float) -> None:
        self.ips_connues.update(adresses)
        self.observations += 1
        if self.observations == 1:
            self.moyenne_sortante = moyenne_sortante
        else:
            self.moyenne_sortante = (
                (1.0 - self.alpha) * self.moyenne_sortante + self.alpha * moyenne_sortante
            )

    def part_nouvelles_adresses(self, adresses: set[str]) -> float:
        if not adresses:
            return 0.0
        inconnues = sum(1 for a in adresses if a not in self.ips_connues)
        return inconnues / len(adresses)

    def ratio_sortant(self, moyenne_sortante: float) -> float:
        if self.moyenne_sortante <= 0.0:
            return 1.0
        return moyenne_sortante / self.moyenne_sortante

    @property
    def prete(self) -> bool:
        """Vrai lorsque la référence compte assez de fenêtres pour être fiable.

        Au démarrage, la référence est vide : la part d'adresses jamais vues
        vaut mécaniquement 100 % et le ratio de volume sortant vaut exactement 1,
        ce qui produit des anomalies fantômes à chaque redémarrage. Le détecteur
        ignore donc les fenêtres tant que cette propriété est fausse.
        """
        return self.observations >= 3


class Agregateur:
    """Fenêtre glissante d'événements, projetée sur les 18 variables."""

    def __init__(self, window_seconds: float = 60.0, reference: Reference | None = None) -> None:
        self.window_seconds = float(window_seconds)
        self.reference = reference or Reference()
        self._evenements: list[Evenement] = []

    # -- alimentation ------------------------------------------------------

    def ajouter(self, evenement: Evenement) -> None:
        self._evenements.append(evenement)

    def purger(self, maintenant: float) -> None:
        limite = maintenant - self.window_seconds
        if not self._evenements:
            return
        # Les événements arrivent globalement dans l'ordre : on coupe par
        # dichotomie plutôt que de filtrer la liste entière à chaque cycle.
        premier = 0
        for index, evenement in enumerate(self._evenements):
            if evenement.ts >= limite:
                premier = index
                break
        else:
            premier = len(self._evenements)
        if premier:
            del self._evenements[:premier]

    def __len__(self) -> int:
        return len(self._evenements)

    # -- projection --------------------------------------------------------

    def vecteur(self) -> dict[str, float]:
        requetes_edge = [e for e in self._evenements if e.source == "edge"]
        requetes_service = [e for e in self._evenements if e.source == "service"]
        tentatives = [e for e in self._evenements if e.kind == "auth.attempt"]
        transactions_waf = [e for e in self._evenements if e.source == "modsec"]

        # --- trafic vu par la bordure
        nb_edge = len(requetes_edge)
        statuts = [int(e.fields.get("status") or 0) for e in requetes_edge]
        erreurs = sum(1 for s in statuts if s >= 400)
        latences = [float(e.fields.get("duration_s") or 0.0) * 1000.0 for e in requetes_edge]
        adresses = {str(e.fields.get("source_ip") or "") for e in requetes_edge}
        adresses.discard("")
        compteur_ips: dict[str, int] = {}
        for e in requetes_edge:
            ip = str(e.fields.get("source_ip") or "")
            if ip:
                compteur_ips[ip] = compteur_ips.get(ip, 0) + 1
        entrantes = [float(e.fields.get("bytes_in") or 0.0) for e in requetes_edge]
        sortantes = [float(e.fields.get("bytes_out") or 0.0) for e in requetes_edge]
        compteur_chemins: dict[str, int] = {}
        for e in requetes_edge:
            chemin = str(e.fields.get("path") or "")
            if chemin:
                compteur_chemins[chemin] = compteur_chemins.get(chemin, 0) + 1
        blocages = sum(1 for e in requetes_edge if int(e.fields.get("waf_blocked") or 0) == 1)

        # --- authentification
        echecs = sum(1 for e in tentatives if e.fields.get("outcome") != "success")
        identites = {str(e.fields.get("identity") or "") for e in tentatives}
        identites.discard("")

        # --- décisions du WAF (journal d'audit ModSecurity)
        regles_injection = 0
        regles_xss = 0
        for e in transactions_waf:
            familles = set(e.fields.get("familles") or [])
            if familles & set(FAMILLES_INJECTION):
                regles_injection += 1
            if familles & set(FAMILLES_XSS):
                regles_xss += 1

        # --- identités authentifiées sur les services applicatifs
        identites_service: dict[str, int] = {}
        for e in requetes_service:
            identifiant = str(e.fields.get("identity") or "")
            if identifiant:
                identites_service[identifiant] = identites_service.get(identifiant, 0) + 1

        moyenne_sortante = statistics.fmean(sortantes) if sortantes else 0.0
        moyenne_entrante = statistics.fmean(entrantes) if entrantes else 0.0

        vecteur = {
            "requests_per_second": nb_edge / self.window_seconds if nb_edge else 0.0,
            "error_ratio": erreurs / nb_edge if nb_edge else 0.0,
            "latency_p95_ms": _percentile(latences, 0.95),
            "latency_p99_ms": _percentile(latences, 0.99),
            "unique_source_ips": float(len(adresses)),
            "source_ip_entropy": _entropie_normalisee(compteur_ips),
            "auth_failure_ratio": echecs / len(tentatives) if tentatives else 0.0,
            "auth_attempts_per_identity": len(tentatives) / len(identites) if identites else 0.0,
            "unique_identities": float(len(identites)),
            "injection_token_ratio": regles_injection / nb_edge if nb_edge else 0.0,
            "xss_token_ratio": regles_xss / nb_edge if nb_edge else 0.0,
            "avg_payload_bytes": moyenne_entrante,
            "payload_bytes_stddev": statistics.pstdev(entrantes) if len(entrantes) > 1 else 0.0,
            "endpoint_entropy": _entropie_normalisee(compteur_chemins),
            "requests_per_token": (
                len(requetes_service) / len(identites_service) if identites_service else 0.0
            ),
            "outgoing_bytes_ratio": self.reference.ratio_sortant(moyenne_sortante),
            "new_source_ip_ratio": self.reference.part_nouvelles_adresses(adresses),
            "waf_block_ratio": blocages / nb_edge if nb_edge else 0.0,
        }
        return vecteur

    def diagnostics(self) -> dict[str, object]:
        """Informations de localisation, hors vecteur de variables.

        Elles ne participent **pas** à la décision du modèle : elles servent à
        désigner la cible probable du confinement (adresse d'origine dominante)
        et à guider la lecture de l'opérateur dans la salle d'opérations.
        """
        def _principaux(compteur: dict[str, int], combien: int = 5) -> list[dict[str, object]]:
            return [
                {"value": cle, "count": valeur}
                for cle, valeur in sorted(compteur.items(), key=lambda i: -i[1])[:combien]
            ]

        ip_compteur: dict[str, int] = {}
        chemin_compteur: dict[str, int] = {}
        identite_compteur: dict[str, int] = {}
        for evenement in self._evenements:
            if evenement.source == "edge":
                ip = str(evenement.fields.get("source_ip") or "")
                if ip:
                    ip_compteur[ip] = ip_compteur.get(ip, 0) + 1
                chemin = str(evenement.fields.get("path") or "")
                if chemin:
                    chemin_compteur[chemin] = chemin_compteur.get(chemin, 0) + 1
            elif evenement.kind == "auth.attempt":
                identifiant = str(evenement.fields.get("identity") or "")
                if identifiant:
                    identite_compteur[identifiant] = identite_compteur.get(identifiant, 0) + 1

        principaux = _principaux(ip_compteur)
        return {
            "top_source_ips": principaux,
            "dominant_source_ip": principaux[0]["value"] if principaux else "",
            "source_ips_distinctes": len(ip_compteur),
            "top_paths": _principaux(chemin_compteur),
            "top_identities": _principaux(identite_compteur),
        }

    def enrichir_reference(self) -> None:
        """Met à jour la mémoire longue avec la fenêtre courante.

        À appeler **après** `vecteur()` : sinon la fenêtre courante se
        comparerait à elle-même et les deux variables concernées seraient
        toujours nulles.
        """
        adresses = {
            str(e.fields.get("source_ip") or "")
            for e in self._evenements
            if e.source == "edge"
        }
        adresses.discard("")
        sortantes = [
            float(e.fields.get("bytes_out") or 0.0)
            for e in self._evenements
            if e.source == "edge"
        ]
        self.reference.observer(adresses, statistics.fmean(sortantes) if sortantes else 0.0)


def vecteur_vers_liste(vecteur: dict[str, float]) -> list[float]:
    """Projette le vecteur sur l'ordre canonique attendu par le modèle."""
    return [float(vecteur.get(nom, 0.0)) for nom in FEATURE_NAMES]
