"""Moteur de politiques et de playbooks.

Séparation des responsabilités
------------------------------
* Une **politique** répond à la question « ce que je viens d'observer
  correspond-il à une situation connue nécessitant une réaction ? ». Elle
  contient des conditions déclaratives et l'identifiant du playbook à engager.
* Un **playbook** répond à la question « comment je réagis ? ». C'est une suite
  ordonnée d'actions élémentaires, chacune rattachée à une phase de la reprise.

Ni l'une ni l'autre n'est codée en dur : tout est déclaratif, chargé au
démarrage depuis `infra/policies/` et `infra/playbooks/`. Modifier une règle de
réaction ne demande donc ni recompilation, ni redéploiement du moteur.

Ce que ces fichiers ne font pas : décider qu'il y a attaque. Ils ne
s'appliquent qu'à une anomalie **déjà qualifiée** par le détecteur, ou à une
alerte d'exploitation explicite. La qualification reste du ressort du modèle.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

LOGGER = logging.getLogger("remediation.policies")

#: Phases de la reprise, dans l'ordre. L'état de l'incident suit cette
#: progression : c'est ce que la salle d'opérations affiche.
PHASES: tuple[str, ...] = (
    "DETECTING",
    "CONTAINING",
    "ERADICATING",
    "RECOVERING",
    "VERIFYING",
)

_MOTIF = re.compile(r"\$\{([^}]+)\}")


class ErreurDeConfiguration(RuntimeError):
    """Un fichier de politique ou de playbook est inexploitable."""


# =============================================================================
#  Modèles
# =============================================================================


@dataclass(frozen=True)
class Condition:
    signal: str  # feature | event | tag
    name: str
    op: str
    value: Any = None

    def extraire(self, sac: dict[str, Any]) -> Any:
        if self.signal == "feature":
            return sac.get(f"feature.{self.name}")
        if self.signal == "event":
            return sac.get(self.name)
        if self.signal == "tag":
            return self.name in (sac.get("tags") or [])
        return None

    def evaluee(self, sac: dict[str, Any]) -> bool:
        present = self.extraire(sac)
        if self.op == "present":
            return present is not None and present != "" and present is not False
        if self.op == "absent":
            return present is None or present == "" or present is False
        if present is None:
            return False
        try:
            if self.op == ">=":
                return float(present) >= float(self.value)
            if self.op == ">":
                return float(present) > float(self.value)
            if self.op == "<=":
                return float(present) <= float(self.value)
            if self.op == "<":
                return float(present) < float(self.value)
            if self.op == "==":
                return str(present) == str(self.value)
            if self.op == "!=":
                return str(present) != str(self.value)
            if self.op == "contains":
                return str(self.value) in str(present)
            if self.op == "one_of":
                return str(present) in [str(v) for v in (self.value or [])]
        except (TypeError, ValueError):
            return False
        raise ErreurDeConfiguration(f"opérateur inconnu : {self.op}")

    def description(self) -> str:
        if self.op in {"present", "absent"}:
            return f"{self.signal}.{self.name} {self.op}"
        return f"{self.signal}.{self.name} {self.op} {self.value}"


@dataclass(frozen=True)
class Politique:
    id: str
    title: str
    severity: str
    priority: int
    sources: tuple[str, ...]
    match: str
    conditions: tuple[Condition, ...]
    playbook: str
    cooldown_seconds: int = 300
    enabled: bool = True

    def correspond(self, sac: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        if self.sources and str(sac.get("source", "")) not in self.sources:
            return False
        resultats = [c.evaluee(sac) for c in self.conditions]
        if not resultats:
            return False
        return all(resultats) if self.match == "all" else any(resultats)

    def explication(self) -> list[str]:
        return [c.description() for c in self.conditions]


@dataclass(frozen=True)
class Etape:
    id: str
    action: str
    phase: str
    description: str
    params: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float = 20.0
    on_failure: str = "abort"  # abort | continue | continue_anyway
    critical: bool = False

    def rendre(self, contexte: dict[str, Any]) -> dict[str, Any]:
        return {cle: _rendre_valeur(valeur, contexte) for cle, valeur in self.params.items()}


@dataclass(frozen=True)
class Playbook:
    id: str
    title: str
    description: str
    steps: tuple[Etape, ...]
    verification_required: bool = True

    @property
    def phases(self) -> list[str]:
        vues: list[str] = []
        for etape in self.steps:
            if etape.phase not in vues:
                vues.append(etape.phase)
        return vues


def _rendre_valeur(valeur: Any, contexte: dict[str, Any]) -> Any:
    if isinstance(valeur, str):
        return _MOTIF.sub(lambda m: str(_resoudre(m.group(1), contexte)), valeur)
    if isinstance(valeur, dict):
        return {cle: _rendre_valeur(v, contexte) for cle, v in valeur.items()}
    if isinstance(valeur, list):
        return [_rendre_valeur(v, contexte) for v in valeur]
    return valeur


def _resoudre(chemin: str, contexte: dict[str, Any]) -> Any:
    courant: Any = contexte
    for morceau in chemin.split("."):
        if isinstance(courant, dict):
            courant = courant.get(morceau)
        else:
            return ""
        if courant is None:
            return ""
    return courant


# =============================================================================
#  Chargement
# =============================================================================


def _lire_yaml(chemin: str) -> dict[str, Any]:
    try:
        with open(chemin, encoding="utf-8") as fichier:
            contenu = yaml.safe_load(fichier)
    except (OSError, yaml.YAMLError) as exc:
        raise ErreurDeConfiguration(f"{chemin} illisible : {exc}") from exc
    if not isinstance(contenu, dict):
        raise ErreurDeConfiguration(f"{chemin} : la racine doit être un objet YAML")
    return contenu


def charger_politiques(dossier: str) -> list[Politique]:
    politiques: list[Politique] = []
    if not os.path.isdir(dossier):
        raise ErreurDeConfiguration(f"dossier de politiques introuvable : {dossier}")
    for nom in sorted(os.listdir(dossier)):
        if not nom.endswith((".yaml", ".yml")):
            continue
        document = _lire_yaml(os.path.join(dossier, nom))
        for brut in document.get("policies") or []:
            politiques.append(_construire_politique(brut, nom))
    if not politiques:
        raise ErreurDeConfiguration(f"aucune politique exploitable dans {dossier}")
    politiques.sort(key=lambda p: (-p.priority, p.id))
    LOGGER.info("politiques chargees : %d", len(politiques))
    return politiques


def _construire_politique(brut: dict[str, Any], origine: str) -> Politique:
    conditions = []
    for item in brut.get("conditions") or []:
        signal = str(item.get("signal", "event"))
        if signal not in {"feature", "event", "tag"}:
            raise ErreurDeConfiguration(f"{origine} : signal inconnu {signal!r}")
        conditions.append(
            Condition(
                signal=signal,
                name=str(item.get("name", "")),
                op=str(item.get("op", "present")),
                value=item.get("value"),
            )
        )
    if not conditions:
        raise ErreurDeConfiguration(f"{origine} : politique sans condition")
    correspondance = str(brut.get("match", "any"))
    if correspondance not in {"any", "all"}:
        raise ErreurDeConfiguration(f"{origine} : `match` doit valoir any ou all")
    return Politique(
        id=str(brut["id"]),
        title=str(brut.get("title", brut["id"])),
        severity=str(brut.get("severity", "warning")),
        priority=int(brut.get("priority", 50)),
        sources=tuple(str(s) for s in (brut.get("sources") or [])),
        match=correspondance,
        conditions=tuple(conditions),
        playbook=str(brut["playbook"]),
        cooldown_seconds=int(brut.get("cooldown_seconds", 300)),
        enabled=bool(brut.get("enabled", True)),
    )


def charger_playbooks(dossier: str) -> dict[str, Playbook]:
    playbooks: dict[str, Playbook] = {}
    if not os.path.isdir(dossier):
        raise ErreurDeConfiguration(f"dossier de playbooks introuvable : {dossier}")
    for nom in sorted(os.listdir(dossier)):
        if not nom.endswith((".yaml", ".yml")):
            continue
        document = _lire_yaml(os.path.join(dossier, nom))
        for brut in document.get("playbooks") or []:
            playbook = _construire_playbook(brut, nom)
            playbooks[playbook.id] = playbook
    if not playbooks:
        raise ErreurDeConfiguration(f"aucun playbook exploitable dans {dossier}")
    LOGGER.info("playbooks charges : %d", len(playbooks))
    return playbooks


def _construire_playbook(brut: dict[str, Any], origine: str) -> Playbook:
    etapes = []
    for index, item in enumerate(brut.get("steps") or [], start=1):
        phase = str(item.get("phase", "RECOVERING")).upper()
        if phase not in PHASES:
            raise ErreurDeConfiguration(f"{origine} : phase inconnue {phase!r}")
        action = str(item["action"])
        if action not in ACTIONS_AUTORISEES:
            raise ErreurDeConfiguration(
                f"{origine} : action {action!r} absente de la liste blanche"
            )
        sur_echec = str(item.get("on_failure", "abort"))
        if sur_echec not in {"abort", "continue", "continue_anyway"}:
            raise ErreurDeConfiguration(f"{origine} : on_failure inconnu {sur_echec!r}")
        etapes.append(
            Etape(
                id=str(item.get("id", f"etape-{index}")),
                action=action,
                phase=phase,
                description=str(item.get("description", action)),
                params=dict(item.get("params") or {}),
                timeout_seconds=float(item.get("timeout_seconds", 20.0)),
                on_failure=sur_echec,
                critical=bool(item.get("critical", False)),
            )
        )
    if not etapes:
        raise ErreurDeConfiguration(f"{origine} : playbook sans étape")
    return Playbook(
        id=str(brut["id"]),
        title=str(brut.get("title", brut["id"])),
        description=str(brut.get("description", "")),
        steps=tuple(etapes),
        verification_required=bool(brut.get("verification_required", True)),
    )


#: Liste blanche des actions. Une action absente d'ici ne peut pas être
#: exécutée, même si un playbook la référence : la configuration est rejetée au
#: chargement, avant tout incident.
ACTIONS_AUTORISEES: frozenset[str] = frozenset(
    {
        "edge.block_ip",
        "edge.unblock_ip",
        "edge.status",
        "auth.revoke_by_source",
        "auth.lock_account",
        "auth.rotate_signing_key",
        "docker.isolate",
        "docker.unisolate",
        "docker.restart",
        "docker.rollback",
        "docker.wait_healthy",
        "ledger.snapshot",
        "ledger.restore",
        "ledger.reconcile",
        "ledger.freeze_account",
        "vault.rotate_secret",
        "payments.probe",
        "verify.recovery_suite",
        "notify.operator",
        "escalate.human",
    }
)


# =============================================================================
#  Sélection
# =============================================================================


def selectionner(
    politiques: list[Politique],
    sac: dict[str, Any],
    dernieres_activations: dict[str, float],
    maintenant: float,
) -> Politique | None:
    """Renvoie la politique applicable la plus prioritaire, hors délai de repos.

    Le délai de repos (`cooldown_seconds`) évite qu'une même situation, encore
    présente dans la fenêtre d'observation, ne redéclenche un playbook toutes
    les dix secondes. Sans lui, le moteur se battrait contre lui-même.
    """
    for politique in politiques:
        if not politique.correspond(sac):
            continue
        # Une politique jamais activée est toujours éligible : le délai de repos
        # ne s'applique qu'après une activation réelle.
        derniere = dernieres_activations.get(politique.id, float("-inf"))
        if maintenant - derniere < politique.cooldown_seconds:
            continue
        return politique
    return None
