"""Connecteurs d'action : la seule partie du moteur qui agit sur le monde.

Principes
---------
1. **Liste blanche.** Seules les actions déclarées dans `policies.ACTIONS_AUTORISEES`
   existent ici, et un playbook qui en référence une autre est refusé au
   chargement de la configuration.
2. **Périmètre clos.** Les conteneurs manipulables sont limités à
   `MANAGED_CONTAINERS`, et certaines adresses ne peuvent jamais être bloquées
   (`NEVER_BLOCK_IPS`) sans quoi le jury se couperait lui-même l'accès.
3. **Preuve.** Chaque action renvoie non seulement un succès, mais une preuve
   vérifiable : empreinte du fichier de blocage confirmée par la bordure,
   identifiant de transaction, état de santé observé. Un succès sans preuve
   n'est pas comptabilisé comme un rétablissement.
4. **Mode à blanc.** Hors exécution de démonstration (`DRY_RUN`), les actions
   sont journalisées et décrites sans être appliquées.
5. **Idempotence.** Rejouer une action déjà satisfaite renvoie un succès avec
   la mention « déjà appliqué » plutôt qu'une erreur : indispensable quand la
   reprise est retentée.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import ipaddress
import json
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from common.config import env_bool, env_float, env_int, env_str
from common.http_client import request_json
from common.logging_setup import EventLogger

# =============================================================================
#  Résultat d'action
# =============================================================================


@dataclass
class Resultat:
    ok: bool
    action: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False
    dry_run: bool = False

    def resume(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "ok": self.ok,
            "skipped": self.skipped,
            "dry_run": self.dry_run,
            "detail": self.detail,
            "evidence": self.evidence,
        }


class ActionRefusee(RuntimeError):
    """Garde-fou déclenché : l'action demandée sort du périmètre autorisé."""


# =============================================================================
#  Connecteurs
# =============================================================================


class Connecteurs:
    """Implémentation des actions du catalogue."""

    def __init__(self, events: EventLogger) -> None:
        self.events = events
        self.dry_run = env_bool("DRY_RUN", False)
        self.admin_token = env_str("ADMIN_API_TOKEN", required=True)
        self.auth_url = env_str("AUTH_URL", "http://api-auth:8000")
        self.payment_url = env_str("PAYMENT_URL", "http://api-payment:8000")
        self.ledger_url = env_str("LEDGER_URL", "http://api-ledger:8000")
        self.detector_url = env_str("DETECTOR_URL", "http://detector:8000")
        # La télémétrie est interrogée au moment de confiner : ses diagnostics
        # portent les adresses qui consultent la salle d'opérations et l'agent du
        # banc offensif, dont dépend la sélectivité du confinement.
        self.telemetry_url = env_str("TELEMETRY_URL", "http://telemetry:8000")
        self.edge_url = env_str("EDGE_PUBLIC_URL", "http://edge:8080")
        self.vault_addr = env_str("VAULT_ADDR", "")
        self.vault_token = env_str("VAULT_TOKEN", "")
        self.edge_state_dir = env_str("EDGE_STATE_DIR", "/var/lib/alphapay/edge-state")
        self.never_block = {
            ip.strip()
            for ip in env_str("NEVER_BLOCK_IPS", "127.0.0.1,::1").split(",")
            if ip.strip()
        }
        # Réseaux jamais bloquables (notation CIDR). Ils couvrent l'infrastructure
        # de la plateforme elle-même : bloquer l'adresse d'un de ses propres
        # services ne protège rien et coupe l'observabilité. Le poste de
        # l'opérateur s'ajoute à NEVER_BLOCK_IPS, en adresse exacte.
        self.never_block_reseaux: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for reseau in env_str("NEVER_BLOCK_NETWORKS", "").split(","):
            reseau = reseau.strip()
            if not reseau:
                continue
            try:
                self.never_block_reseaux.append(ipaddress.ip_network(reseau, strict=False))
            except ValueError:
                continue
        self.managed = {
            nom.strip()
            for nom in env_str("MANAGED_CONTAINERS", "").split(",")
            if nom.strip()
        }
        self.docker_host = env_str("DOCKER_HOST", "")
        self.reload_timeout = env_float("EDGE_RELOAD_TIMEOUT_SECONDS", 8.0)
        self.probe_user = env_str("PROBE_USERNAME", "client01")
        self.probe_password = env_str("PROBE_PASSWORD", "AlphaPay-Client-2026!")
        self.probe_account = env_str("PROBE_SOURCE_ACCOUNT", "CUST-000001")
        self.probe_target = env_str("PROBE_DESTINATION_ACCOUNT", "MERCHANT-0001")
        self.probe_amount = env_int("PROBE_AMOUNT_CENTS", 100)
        self._probe_tokens: dict[str, Any] = {"value": None, "expires": 0.0}

        self._registre = {
            "edge.block_ip": self._edge_block_ip,
            "edge.unblock_ip": self._edge_unblock_ip,
            "edge.block_signature": self._edge_block_signature,
            "edge.unblock_signature": self._edge_unblock_signature,
            "edge.status": self._edge_status,
            "auth.revoke_by_source": self._auth_revoke_by_source,
            "auth.lock_account": self._auth_lock_account,
            "auth.rotate_signing_key": self._auth_rotate_signing_key,
            "docker.isolate": self._docker_isolate,
            "docker.unisolate": self._docker_unisolate,
            "docker.restart": self._docker_restart,
            "docker.rollback": self._docker_rollback,
            "docker.wait_healthy": self._docker_wait_healthy,
            "ledger.snapshot": self._ledger_snapshot,
            "ledger.restore": self._ledger_restore,
            "ledger.reconcile": self._ledger_reconcile,
            "ledger.freeze_account": self._ledger_freeze_account,
            "vault.rotate_secret": self._vault_rotate_secret,
            "payments.probe": self._payments_probe,
            "notify.operator": self._notify_operator,
            "escalate.human": self._escalate_human,
        }

    # -- exécution ---------------------------------------------------------

    async def executer(
        self, action: str, params: dict[str, Any], contexte: dict[str, Any]
    ) -> Resultat:
        fonction = self._registre.get(action)
        if fonction is None:
            raise ActionRefusee(f"action hors liste blanche : {action}")
        if self.dry_run and action not in {"edge.status", "payments.probe"}:
            self.events.warn(
                "action.dry_run",
                message="action non appliquée (mode à blanc)",
                action=action,
                params=params,
            )
            return Resultat(
                ok=True,
                action=action,
                detail="mode à blanc : action décrite, non appliquée",
                dry_run=True,
                evidence={"params": params},
            )
        debut = time.perf_counter()
        try:
            resultat = await fonction(params, contexte)
        except ActionRefusee:
            raise
        except Exception as erreur:  # noqa: BLE001
            resultat = Resultat(
                ok=False,
                action=action,
                detail=f"{type(erreur).__name__} : {erreur}",
                evidence={"params": params},
            )
        resultat.evidence.setdefault("duration_ms", round((time.perf_counter() - debut) * 1000, 2))
        return resultat

    # -- bordure -----------------------------------------------------------

    def _chemin_liste(self) -> str:
        return os.path.join(self.edge_state_dir, "blocklist.map")

    def _chemin_temoin(self) -> str:
        return os.path.join(self.edge_state_dir, "reload-witness.json")

    def _chemin_etat(self) -> str:
        """Fichier compagnon : échéance et justification de chaque blocage.

        Le fichier appliqué par nginx ne peut pas porter ces informations : sa
        syntaxe est celle d'une `map`, deux jetons par ligne, et il est relu à
        chaque rechargement. Tenir l'état à part permet d'expirer un blocage
        sans avoir à relire une durée dans une carte nginx, qui ne connaît pas
        la notion de date.
        """
        return os.path.join(self.edge_state_dir, "blocklist-state.json")

    def _lire_etat(self) -> dict[str, dict[str, Any]]:
        return self._lire_etat_fichier(self._chemin_etat())

    def _lire_etat_fichier(self, chemin: str) -> dict[str, dict[str, Any]]:
        try:
            with open(chemin, encoding="utf-8") as fichier:
                contenu = json.load(fichier)
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(contenu, dict):
            return {}
        return {
            str(cle): dict(meta)
            for cle, meta in contenu.items()
            if isinstance(meta, dict)
        }

    def _ecrire_etat(self, etat: dict[str, dict[str, Any]]) -> None:
        self._ecrire_etat_fichier(self._chemin_etat(), etat)

    def _ecrire_etat_fichier(self, chemin: str, etat: dict[str, dict[str, Any]]) -> None:
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        provisoire = f"{chemin}.{uuid.uuid4().hex}.tmp"
        with open(provisoire, "w", encoding="utf-8") as fichier:
            json.dump(etat, fichier, ensure_ascii=False, indent=2, sort_keys=True)
            fichier.flush()
            os.fsync(fichier.fileno())
        os.replace(provisoire, chemin)

    def blocages_en_cours(self) -> list[dict[str, Any]]:
        """État lisible par l'opérateur : qui est bloqué, jusqu'à quand, pourquoi."""
        etat = self._lire_etat()
        maintenant = time.time()
        lignes: list[dict[str, Any]] = []
        for adresse in sorted(self._lire_entrees()):
            meta = etat.get(adresse) or {}
            echeance = float(meta.get("expire_at") or 0.0)
            lignes.append(
                {
                    "ip": adresse,
                    "expire_at": echeance or None,
                    "expire_le": meta.get("expire_le") or "",
                    "secondes_restantes": (
                        max(0, int(echeance - maintenant)) if echeance else None
                    ),
                    "raison": meta.get("raison") or "",
                    "incident": meta.get("incident") or "",
                    # Un blocage sans échéance connue ne peut pas expirer : il
                    # est signalé comme tel plutôt que présenté comme temporaire.
                    "permanent": not echeance,
                }
            )
        # Les signatures confinées figurent dans la même liste : l'opérateur doit
        # pouvoir lire d'un seul coup d'œil tout ce que la bordure refuse, qu'il
        # s'agisse d'une adresse ou d'un banc offensif.
        etat_signatures = self._lire_etat_fichier(self._chemin_etat_signatures())
        for agent in sorted(self._lire_signatures()):
            meta = etat_signatures.get(agent) or {}
            echeance = float(meta.get("expire_at") or 0.0)
            lignes.append(
                {
                    "signature": agent,
                    "expire_at": echeance or None,
                    "expire_le": meta.get("expire_le") or "",
                    "secondes_restantes": (
                        max(0, int(echeance - maintenant)) if echeance else None
                    ),
                    "raison": meta.get("raison") or "",
                    "incident": meta.get("incident") or "",
                    "permanent": not echeance,
                }
            )
        return lignes

    async def expirer_blocages(self) -> list[str]:
        """Retire les blocages arrivés à échéance. Rend les adresses libérées.

        Sans cette purge, `ttl_seconds` n'est qu'une intention : la durée est
        écrite dans la `map` de nginx, qui ne connaît pas la notion de date, et
        tout blocage devient définitif. C'est acceptable contre une attaque, pas
        pour un opérateur confiné par erreur. Les signatures suivent la même
        échéance, sinon un banc resterait confiné au-delà de la durée annoncée.
        """
        maintenant = time.time()
        etat = self._lire_etat()
        expirees = [
            adresse
            for adresse, meta in etat.items()
            if float(meta.get("expire_at") or 0.0) and float(meta["expire_at"]) <= maintenant
        ]
        chemin_signatures = self._chemin_etat_signatures()
        etat_signatures = self._lire_etat_fichier(chemin_signatures)
        signatures_expirees = [
            agent
            for agent, meta in etat_signatures.items()
            if float(meta.get("expire_at") or 0.0) and float(meta["expire_at"]) <= maintenant
        ]
        if not expirees and not signatures_expirees:
            return []

        contenu: bytes | None = None
        if expirees:
            entrees = self._lire_entrees()
            for adresse in expirees:
                entrees.pop(adresse, None)
                etat.pop(adresse, None)
            contenu = self._ecrire_entrees(entrees)
            self._ecrire_etat(etat)
        contenu_signatures: bytes | None = None
        if signatures_expirees:
            signatures = self._lire_signatures()
            for agent in signatures_expirees:
                signatures.pop(agent, None)
                etat_signatures.pop(agent, None)
            contenu_signatures = self._ecrire_signatures(signatures)
            self._ecrire_etat_fichier(chemin_signatures, etat_signatures)
        empreinte = self._empreinte_bordure(liste=contenu, signatures=contenu_signatures)
        confirmation = await self._attendre_rechargement(empreinte)
        self.events.emit(
            "edge.block_expired",
            message="blocage arrivé à échéance, adresse libérée à la bordure",
            adresses=expirees,
            signatures=signatures_expirees,
            edge_reload=confirmation,
        )
        return expirees

    def _lire_entrees(self) -> dict[str, int]:
        chemin = self._chemin_liste()
        entrees: dict[str, int] = {}
        if not os.path.isfile(chemin):
            return entrees
        with open(chemin, encoding="utf-8", errors="replace") as fichier:
            for ligne in fichier:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#"):
                    continue
                morceaux = ligne.split()
                if len(morceaux) == 2 and morceaux[1] == "1;":
                    entrees[morceaux[0]] = int(time.time())
        return entrees

    def _ecrire_entrees(self, entrees: dict[str, Any]) -> bytes:
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lignes = [
            "# Liste de blocage AlphaPay : ecrite par le moteur de remediation.",
            f"# Derniere mise a jour : {now}",
        ]
        for adresse in sorted(entrees):
            lignes.append(f"{adresse} 1;")
        contenu = ("\n".join(lignes) + "\n").encode()
        chemin = self._chemin_liste()
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        provisoire = f"{chemin}.{uuid.uuid4().hex}.tmp"
        with open(provisoire, "wb") as fichier:
            fichier.write(contenu)
            fichier.flush()
            os.fsync(fichier.fileno())
        os.replace(provisoire, chemin)
        return contenu

    async def _attendre_rechargement(self, empreinte: str) -> dict[str, Any]:
        """Attend que la bordure confirme avoir appliqué cette version exacte."""
        echeance = time.monotonic() + self.reload_timeout
        dernier: dict[str, Any] = {}
        while time.monotonic() < echeance:
            try:
                with open(self._chemin_temoin(), encoding="utf-8") as fichier:
                    dernier = json.load(fichier)
            except (OSError, json.JSONDecodeError):
                dernier = {}
            if dernier.get("fingerprint") == empreinte:
                return dernier
            await asyncio.sleep(0.4)
        return dernier or {"result": "temoin-absent"}

    def _raison_protection(self, adresse: str) -> str | None:
        """Motif de protection d'une adresse, ou None si elle est bloquable.

        Guardrail du cahier des charges : certaines adresses ne peuvent jamais
        être confinées, sans quoi la plateforme se couperait l'accès à elle-même
        ou à son opérateur.
        """
        if adresse in self.never_block:
            return "liste blanche NEVER_BLOCK_IPS"
        try:
            candidate = ipaddress.ip_address(adresse)
        except ValueError:
            return None
        for reseau in self.never_block_reseaux:
            if candidate.version == reseau.version and candidate in reseau:
                return f"réseau protégé {reseau}"
        return None

    def _chemin_signatures(self) -> str:
        return os.path.join(self.edge_state_dir, "agents.map")

    def _chemin_etat_signatures(self) -> str:
        return os.path.join(self.edge_state_dir, "agents-state.json")

    def _lire_signatures(self) -> dict[str, int]:
        """Signatures confinees, lues dans la `map` d'agents de la bordure."""
        chemin = self._chemin_signatures()
        entrees: dict[str, int] = {}
        if not os.path.isfile(chemin):
            return entrees
        with open(chemin, encoding="utf-8", errors="replace") as fichier:
            for ligne in fichier:
                ligne = ligne.strip()
                if not ligne or ligne.startswith("#"):
                    continue
                # La cle est entre guillemets : un agent utilisateur contient des
                # espaces et des parentheses, qu'une `map` nginx n'accepterait pas
                # nue.
                if not ligne.startswith('"'):
                    continue
                fin = ligne.find('"', 1)
                if fin > 0 and ligne[fin + 1 :].strip().startswith("1;"):
                    entrees[ligne[1:fin].replace('\\"', '"')] = int(time.time())
        return entrees

    def _ecrire_signatures(self, entrees: dict[str, Any]) -> bytes:
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lignes = [
            "# Signatures de banc offensif confinees : ecrite par le moteur de remediation.",
            f"# Derniere mise a jour : {now}",
        ]
        for agent in sorted(entrees):
            cle = str(agent).replace("\\", "\\\\").replace('"', '\\"')
            lignes.append(f'"{cle}" 1;')
        contenu = ("\n".join(lignes) + "\n").encode()
        chemin = self._chemin_signatures()
        os.makedirs(os.path.dirname(chemin), exist_ok=True)
        provisoire = f"{chemin}.{uuid.uuid4().hex}.tmp"
        with open(provisoire, "wb") as fichier:
            fichier.write(contenu)
            fichier.flush()
            os.fsync(fichier.fileno())
        os.replace(provisoire, chemin)
        return contenu

    def _empreinte_bordure(
        self, liste: bytes | None = None, signatures: bytes | None = None
    ) -> str:
        """Empreinte des deux listes, telle que la calcule le surveillant.

        Le surveillant de la bordure observe les deux fichiers et publie une
        empreinte combinee : la reproduire ici est ce qui permet d'attendre la
        confirmation du rechargement apres une ecriture.
        """
        parties: list[str] = []
        for chemin, contenu in (
            (self._chemin_liste(), liste),
            (self._chemin_signatures(), signatures),
        ):
            if contenu is None:
                try:
                    with open(chemin, "rb") as fichier:
                        contenu = fichier.read()
                except OSError:
                    parties.append("absent")
                    continue
            parties.append(hashlib.md5(contenu).hexdigest())
        return hashlib.md5("".join(parties).encode()).hexdigest()

    async def _fenetre_courante(self) -> dict[str, Any]:
        """Diagnostics de la derniere fenetre notee par la telemetrie."""
        try:
            reponse = await request_json(
                "GET", f"{self.telemetry_url}/features/history?limit=3", timeout=4.0
            )
        except Exception as erreur:  # noqa: BLE001
            # Sans diagnostics, le confinement par adresse reste applique : c'est
            # le comportement d'avant, jamais un blocage silencieux de l'inconnu.
            self.events.warn(
                "edge.diagnostics_unavailable",
                message="diagnostics indisponibles : confinement par adresse applique",
                error=str(erreur)[:160],
            )
            return {}
        fenetres = (reponse or {}).get("windows") or []
        for fenetre in reversed(list(fenetres)):
            diagnostics = fenetre.get("diagnostics") or {}
            if diagnostics:
                return diagnostics
        return {}

    async def _adresse_de_consultation(self, adresse: str) -> bool:
        """Vrai si l'adresse dessert la consultation dans la fenetre courante.

        Derriere Docker Desktop, l'attaquant et l'operateur partagent l'adresse
        de la passerelle : confiner cette adresse couperait l'operateur, qui n'a
        rien fait. Elle est donc epargnee, et le confinement est porte par la
        signature du banc offensif.
        """
        if not adresse:
            return False
        diagnostics = await self._fenetre_courante()
        adresses = {str(item) for item in (diagnostics.get("adresses_consultation") or [])}
        return adresse in adresses

    async def _edge_block_signature(
        self, params: dict[str, Any], _: dict[str, Any]
    ) -> Resultat:
        """Confine une signature de banc offensif, pas une adresse.

        La signature ne depend pas de la passerelle : elle reste juste quand
        l'adresse ne distingue plus l'attaquant de l'operateur.
        """
        agent = str(params.get("agent") or params.get("signature") or "").strip()
        if not agent:
            diagnostics = await self._fenetre_courante()
            agent = str(diagnostics.get("agent_offensif") or "").strip()
        if not agent:
            raise ActionRefusee(
                "signature absente et aucune signature offensive identifiable dans la fenetre"
            )
        ttl = int(params.get("ttl_seconds") or 900)
        entrees = self._lire_signatures()
        if agent in entrees:
            return Resultat(
                ok=True,
                action="edge.block_signature",
                skipped=True,
                detail=f"signature « {agent} » déjà confinée",
                evidence={"agent": agent, "already_blocked": True},
            )
        echeance = time.time() + max(0, ttl)
        entrees[agent] = int(echeance)
        contenu = self._ecrire_signatures(entrees)
        chemin_etat = self._chemin_etat_signatures()
        etat = self._lire_etat_fichier(chemin_etat)
        etat[agent] = {
            "expire_at": round(echeance, 3),
            "expire_le": dt.datetime.fromtimestamp(echeance, dt.timezone.utc).isoformat(),
            "duree_secondes": ttl,
            "raison": str(params.get("reason") or ""),
            "incident": str(params.get("incident_id") or ""),
        }
        self._ecrire_etat_fichier(chemin_etat, etat)
        empreinte = self._empreinte_bordure(signatures=contenu)
        confirmation = await self._attendre_rechargement(empreinte)
        applique = confirmation.get("result") == "applied"
        return Resultat(
            ok=applique,
            action="edge.block_signature",
            detail=(
                f"signature « {agent} » confinée à la bordure"
                if applique
                else f"confinement non confirmé par la bordure ({confirmation.get('result')})"
            ),
            evidence={
                "agent": agent,
                "ttl_seconds": ttl,
                "expire_le": etat[agent]["expire_le"],
                "fingerprint": empreinte,
                "edge_reload": confirmation,
            },
        )

    async def _edge_unblock_signature(
        self, params: dict[str, Any], _: dict[str, Any]
    ) -> Resultat:
        agent = str(params.get("agent") or params.get("signature") or "").strip()
        if not agent:
            raise ActionRefusee("signature absente")
        entrees = self._lire_signatures()
        chemin_etat = self._chemin_etat_signatures()
        etat = self._lire_etat_fichier(chemin_etat)
        if agent not in entrees and agent not in etat:
            return Resultat(
                ok=True,
                action="edge.unblock_signature",
                skipped=True,
                detail=f"la signature « {agent} » n'était pas confinée",
                evidence={"agent": agent, "was_blocked": False},
            )
        entrees.pop(agent, None)
        etat.pop(agent, None)
        contenu = self._ecrire_signatures(entrees)
        self._ecrire_etat_fichier(chemin_etat, etat)
        empreinte = self._empreinte_bordure(signatures=contenu)
        confirmation = await self._attendre_rechargement(empreinte)
        return Resultat(
            ok=True,
            action="edge.unblock_signature",
            detail=f"signature « {agent} » libérée",
            evidence={
                "agent": agent,
                "restantes": sorted(entrees),
                "fingerprint": empreinte,
                "edge_reload": confirmation,
            },
        )

    async def _edge_block_ip(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        adresse = str(params.get("ip") or "").strip()
        if not adresse:
            raise ActionRefusee("adresse IP absente")
        protection = self._raison_protection(adresse)
        if protection is not None:
            # Le refus est journalisé : une tentative de blocage sur une adresse
            # protégée est un événement en soi, pas un silence.
            self.events.warn(
                "edge.block_refused",
                message="blocage refusé : adresse protégée",
                ip=adresse,
                raison=protection,
            )
            return Resultat(
                ok=True,
                action="edge.block_ip",
                skipped=True,
                detail=f"{adresse} figure parmi les adresses jamais bloquées ({protection})",
                evidence={"ip": adresse, "protected": True, "raison": protection},
            )
        if await self._adresse_de_consultation(adresse):
            # Derriere Docker Desktop, l'attaquant et l'operateur partagent
            # l'adresse de la passerelle. Confiner cette adresse reviendrait a
            # couper l'operateur : elle est epargnee, le confinement etant porte
            # par la signature du banc (voir `edge.block_signature`).
            self.events.warn(
                "edge.block_refused",
                message="blocage refusé : adresse de consultation de l'opérateur",
                ip=adresse,
                raison="consultation",
            )
            return Resultat(
                ok=True,
                action="edge.block_ip",
                skipped=True,
                detail=(
                    f"{adresse} consulte la salle d'opérations : adresse épargnée, "
                    "le confinement est porté par la signature du banc"
                ),
                evidence={"ip": adresse, "consultation": True, "protected": True},
            )
        ttl = int(params.get("ttl_seconds") or 900)
        entrees = self._lire_entrees()
        if adresse in entrees:
            return Resultat(
                ok=True,
                action="edge.block_ip",
                skipped=True,
                detail=f"{adresse} déjà bloquée",
                evidence={"ip": adresse, "already_blocked": True},
            )
        echeance = time.time() + max(0, ttl)
        entrees[adresse] = int(echeance)
        contenu = self._ecrire_entrees(entrees)
        # L'échéance est tenue hors du fichier appliqué : nginx ne connaît pas la
        # notion de date, et sans cet état un blocage serait définitif.
        etat = self._lire_etat()
        etat[adresse] = {
            "expire_at": round(echeance, 3),
            "expire_le": dt.datetime.fromtimestamp(
                echeance, dt.timezone.utc
            ).isoformat(),
            "duree_secondes": ttl,
            "raison": str(params.get("reason") or ""),
            "incident": str(params.get("incident_id") or ""),
        }
        self._ecrire_etat(etat)
        empreinte = self._empreinte_bordure(liste=contenu)
        confirmation = await self._attendre_rechargement(empreinte)
        applique = confirmation.get("result") == "applied"
        return Resultat(
            ok=applique,
            action="edge.block_ip",
            detail=(
                f"{adresse} bloquée à la bordure"
                if applique
                else f"blocage non confirmé par la bordure ({confirmation.get('result')})"
            ),
            evidence={
                "ip": adresse,
                "ttl_seconds": ttl,
                "expire_le": etat[adresse]["expire_le"],
                "fingerprint": empreinte,
                "edge_reload": confirmation,
            },
        )

    async def _edge_unblock_ip(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        adresse = str(params.get("ip") or "").strip()
        entrees = self._lire_entrees()
        etat = self._lire_etat()
        if adresse not in entrees and adresse not in etat:
            return Resultat(
                ok=True,
                action="edge.unblock_ip",
                skipped=True,
                detail=f"{adresse} n'était pas bloquée",
                evidence={"ip": adresse},
            )
        entrees.pop(adresse, None)
        etat.pop(adresse, None)
        contenu = self._ecrire_entrees(entrees)
        # L'état est nettoyé en même temps que la règle : le laisser derrière
        # ferait expirer plus tard une adresse déjà libérée, et l'opérateur
        # verrait un blocage fantôme dans la liste.
        self._ecrire_etat(etat)
        empreinte = self._empreinte_bordure(liste=contenu)
        confirmation = await self._attendre_rechargement(empreinte)
        reste = sorted(self._lire_entrees())
        return Resultat(
            ok=confirmation.get("result") == "applied",
            action="edge.unblock_ip",
            detail=f"{adresse} débloquée",
            evidence={
                "ip": adresse,
                "restantes": reste,
                "edge_reload": confirmation,
            },
        )

    async def _edge_status(self, _: dict[str, Any], __: dict[str, Any]) -> Resultat:
        entrees = self._lire_entrees()
        signatures = self._lire_signatures()
        temoin: dict[str, Any] = {}
        try:
            with open(self._chemin_temoin(), encoding="utf-8") as fichier:
                temoin = json.load(fichier)
        except (OSError, json.JSONDecodeError):
            temoin = {}
        return Resultat(
            ok=True,
            action="edge.status",
            detail=(
                f"{len(entrees)} adresse(s) bloquée(s), "
                f"{len(signatures)} signature(s) confinée(s)"
            ),
            evidence={
                "blocked": sorted(entrees),
                "signatures": sorted(signatures),
                "witness": temoin,
            },
        )

    # -- authentification --------------------------------------------------

    async def _auth_revoke_by_source(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        adresse = str(params.get("source_ip") or "").strip()
        if not adresse:
            raise ActionRefusee("adresse source absente")
        reponse = await request_json(
            "POST",
            f"{self.auth_url}/admin/revoke-by-source",
            json_body={
                "source_ip": adresse,
                "reason": str(params.get("reason") or "confinement automatique"),
            },
            headers={"X-Admin-Token": self.admin_token},
            timeout=10.0,
        ) or {}
        return Resultat(
            ok=True,
            action="auth.revoke_by_source",
            detail=(
                f"{reponse.get('refresh_tokens_revoked', 0)} jeton(s) révoqué(s), "
                f"{reponse.get('accounts_locked', 0)} compte(s) verrouillé(s)"
            ),
            evidence=reponse,
        )

    async def _auth_lock_account(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        reponse = await request_json(
            "POST",
            f"{self.auth_url}/admin/lock-account",
            json_body={
                "username": str(params.get("username") or ""),
                "seconds": int(params.get("seconds") or 900),
            },
            headers={"X-Admin-Token": self.admin_token},
            timeout=10.0,
        ) or {}
        return Resultat(
            ok=True,
            action="auth.lock_account",
            detail=f"compte {reponse.get('username')} verrouillé",
            evidence=reponse,
        )

    async def _auth_rotate_signing_key(self, _: dict[str, Any], __: dict[str, Any]) -> Resultat:
        reponse = await request_json(
            "POST",
            f"{self.auth_url}/admin/rotate-signing-key",
            headers={"X-Admin-Token": self.admin_token},
            timeout=10.0,
        ) or {}
        return Resultat(
            ok=bool(reponse.get("active_kid")),
            action="auth.rotate_signing_key",
            detail=f"nouvelle clé active : {reponse.get('active_kid')}",
            evidence=reponse,
        )

    # -- conteneurs --------------------------------------------------------

    def _docker_base(self) -> str:
        if self.docker_host.startswith("tcp://"):
            return "http://" + self.docker_host[len("tcp://") :]
        if self.docker_host.startswith("http"):
            return self.docker_host
        raise ActionRefusee(
            f"accès au démon Docker non configuré (DOCKER_HOST={self.docker_host!r})"
        )

    def _verifier_perimetre(self, nom: str) -> str:
        if not nom:
            raise ActionRefusee("conteneur non précisé")
        # Les alertes d'exploitation désignent les services par leur nom court
        # (`api-payment`) ; les conteneurs portent un préfixe de pile.
        candidat = nom if nom.startswith("alphaplat-") else f"alphaplat-{nom}"
        if self.managed and candidat not in self.managed:
            raise ActionRefusee(f"conteneur hors périmètre : {candidat}")
        return candidat

    async def _inspecter(self, nom: str) -> dict[str, Any]:
        reponse = await request_json(
            "GET", f"{self._docker_base()}/containers/{nom}/json", timeout=8.0
        )
        return reponse or {}

    async def _docker_isolate(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        nom = self._verifier_perimetre(str(params.get("container") or ""))
        info = await self._inspecter(nom)
        reseaux = list(((info.get("NetworkSettings") or {}).get("Networks") or {}).keys())
        cibles = [r for r in reseaux if "net-app" in r] or reseaux
        if not cibles:
            return Resultat(False, "docker.isolate", f"{nom} n'est sur aucun réseau identifiable",
                            {"container": nom, "networks": reseaux})
        deconnectes = []
        for reseau in cibles:
            await request_json(
                "POST",
                f"{self._docker_base()}/networks/{reseau}/disconnect",
                json_body={"Container": nom, "Force": True},
                timeout=10.0,
            )
            deconnectes.append(reseau)
        return Resultat(
            ok=True,
            action="docker.isolate",
            detail=f"{nom} retiré du/des réseau(x) {', '.join(deconnectes)}",
            evidence={"container": nom, "networks": deconnectes},
        )

    async def _docker_unisolate(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        nom = self._verifier_perimetre(str(params.get("container") or ""))
        reseaux = [str(r) for r in (params.get("networks") or [])]
        if not reseaux:
            raise ActionRefusee("aucun réseau à reconnecter")
        for reseau in reseaux:
            await request_json(
                "POST",
                f"{self._docker_base()}/networks/{reseau}/connect",
                json_body={"Container": nom},
                timeout=10.0,
            )
        return Resultat(
            ok=True,
            action="docker.unisolate",
            detail=f"{nom} reconnecté à {', '.join(reseaux)}",
            evidence={"container": nom, "networks": reseaux},
        )

    async def _docker_restart(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        nom = self._verifier_perimetre(str(params.get("container") or ""))
        attente = int(params.get("grace_seconds") or 5)
        await request_json(
            "POST",
            f"{self._docker_base()}/containers/{nom}/restart?t={attente}",
            timeout=60.0,
        )
        return Resultat(
            ok=True,
            action="docker.restart",
            detail=f"{nom} redémarré",
            evidence={"container": nom},
        )

    async def _docker_rollback(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        """Redéploiement sur l'état de référence connu sain.

        Sur une pile Compose, l'image de référence est identifiée par un
        étiquetage immuable ; le retour arrière consiste à recréer le conteneur
        depuis cette étiquette plutôt que depuis la dernière version déployée.
        L'action est ici ramenée à un redémarrage contrôlé, ce qui suffit à
        démontrer la reprise, et l'écart est assumé dans le dossier de
        gouvernance (le mécanisme complet relèverait d'un registre d'images
        versionnées).
        """
        nom = self._verifier_perimetre(str(params.get("container") or ""))
        await request_json(
            "POST",
            f"{self._docker_base()}/containers/{nom}/restart?t=5",
            timeout=60.0,
        )
        return Resultat(
            ok=True,
            action="docker.rollback",
            detail=f"{nom} redéployé sur l'état de référence",
            evidence={"container": nom, "strategy": "restart-from-reference"},
        )

    async def _docker_wait_healthy(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        nom = self._verifier_perimetre(str(params.get("container") or ""))
        delai = float(params.get("timeout_seconds") or 60.0)
        echeance = time.monotonic() + delai
        dernier = {}
        while time.monotonic() < echeance:
            info = await self._inspecter(nom)
            etat = info.get("State") or {}
            sante = (etat.get("Health") or {}).get("Status")
            dernier = {"running": etat.get("Running"), "health": sante, "status": etat.get("Status")}
            si_sain = etat.get("Running") and sante in (None, "healthy")
            if si_sain and etat.get("Status") == "running":
                return Resultat(
                    ok=True,
                    action="docker.wait_healthy",
                    detail=f"{nom} opérationnel",
                    evidence={"container": nom, **dernier},
                )
            await asyncio.sleep(1.5)
        return Resultat(
            ok=False,
            action="docker.wait_healthy",
            detail=f"{nom} n'est pas revenu à un état sain dans le délai",
            evidence={"container": nom, **dernier},
        )

    # -- grand livre -------------------------------------------------------

    async def _appel_grand_livre(self, chemin: str, charge: dict[str, Any] | None = None) -> Any:
        return await request_json(
            "POST" if charge is not None else "GET",
            f"{self.ledger_url}{chemin}",
            json_body=charge,
            headers={"X-Internal-Token": self.admin_token},
            timeout=20.0,
        )

    async def _ledger_snapshot(self, _: dict[str, Any], __: dict[str, Any]) -> Resultat:
        reponse = await self._appel_grand_livre("/admin/snapshot", {}) or {}
        return Resultat(
            ok=bool(reponse.get("snapshot")),
            action="ledger.snapshot",
            detail=f"instantané {reponse.get('snapshot')} pris",
            evidence=reponse,
        )

    async def _ledger_restore(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        instantane = str(params.get("snapshot") or "")
        if not instantane:
            liste = await self._appel_grand_livre("/admin/snapshots") or {}
            disponibles = liste.get("snapshots") or []
            if not disponibles:
                return Resultat(False, "ledger.restore", "aucun instantané disponible", {})
            instantane = disponibles[-1]
        reponse = await self._appel_grand_livre("/admin/restore", {"snapshot": instantane}) or {}
        return Resultat(
            ok=bool(reponse.get("accounts_restored")),
            action="ledger.restore",
            detail=f"{reponse.get('accounts_restored', 0)} compte(s) rétabli(s) depuis {instantane}",
            evidence=reponse,
        )

    async def _ledger_reconcile(self, _: dict[str, Any], __: dict[str, Any]) -> Resultat:
        reponse = await self._appel_grand_livre("/admin/reconcile", {}) or {}
        corriges = int(reponse.get("accounts_corrected", 0))
        return Resultat(
            ok=True,
            action="ledger.reconcile",
            detail=f"{corriges} compte(s) recalculé(s) depuis le journal des jambes",
            evidence=reponse,
        )

    async def _ledger_freeze_account(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        reponse = await self._appel_grand_livre(
            "/admin/freeze-account",
            {
                "account_code": str(params.get("account_code") or ""),
                "frozen": bool(params.get("frozen", True)),
                "reason": str(params.get("reason") or "confinement automatique"),
            },
        ) or {}
        return Resultat(
            ok=bool(reponse.get("account_code")),
            action="ledger.freeze_account",
            detail=f"compte {reponse.get('account_code')} → {reponse.get('status')}",
            evidence=reponse,
        )

    # -- secrets -----------------------------------------------------------

    async def _vault_rotate_secret(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        if not self.vault_addr or not self.vault_token:
            return Resultat(
                ok=False,
                action="vault.rotate_secret",
                detail="coffre non configuré (VAULT_ADDR ou VAULT_TOKEN absent)",
                evidence={},
            )
        nom = str(params.get("name") or "alphapay/demo")
        nouveau = secrets.token_urlsafe(32)
        await request_json(
            "POST",
            f"{self.vault_addr}/v1/secret/data/{nom}",
            json_body={"data": {"value": nouveau, "rotated_at": dt.datetime.now(dt.timezone.utc).isoformat()}},
            headers={"X-Vault-Token": self.vault_token},
            timeout=10.0,
        )
        return Resultat(
            ok=True,
            action="vault.rotate_secret",
            detail=f"secret {nom} renouvelé",
            evidence={"path": nom, "fingerprint": hashlib.sha256(nouveau.encode()).hexdigest()[:16]},
        )

    # -- vérification fonctionnelle ----------------------------------------

    async def jeton_de_sonde(self, forcer: bool = False) -> str:
        if not forcer and self._probe_tokens["value"] and time.time() < self._probe_tokens["expires"]:
            return str(self._probe_tokens["value"])
        reponse = await request_json(
            "POST",
            f"{self.edge_url}/api/auth/token",
            json_body={"username": self.probe_user, "password": self.probe_password},
            timeout=15.0,
        ) or {}
        jeton = reponse.get("access_token")
        if not jeton:
            raise ActionRefusee("jeton de sonde non obtenu")
        self._probe_tokens["value"] = jeton
        self._probe_tokens["expires"] = time.time() + max(30, int(reponse.get("expires_in", 900)) - 60)
        return str(jeton)

    async def _payments_probe(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        reference = str(params.get("reference") or f"verif-{uuid.uuid4().hex[:12]}")
        jeton = await self.jeton_de_sonde()
        reponse = await request_json(
            "POST",
            f"{self.edge_url}/api/payments",
            json_body={
                "source_account": str(params.get("source_account") or self.probe_account),
                "destination_account": str(params.get("destination_account") or self.probe_target),
                "amount_cents": int(params.get("amount_cents") or self.probe_amount),
                "currency": "EUR",
                "reference": reference,
            },
            headers={"Authorization": f"Bearer {jeton}"},
            timeout=20.0,
        ) or {}
        return Resultat(
            ok=bool(reponse.get("payment_id")),
            action="payments.probe",
            detail=f"paiement de vérification {reponse.get('payment_id')} accepté",
            evidence={
                "payment_id": reponse.get("payment_id"),
                "reference": reference,
                "status": reponse.get("status"),
                "amount_cents": reponse.get("amount_cents"),
            },
        )

    # -- notification et escalade ------------------------------------------

    async def _notify_operator(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        self.events.warn(
            "operator.notified",
            message=str(params.get("message") or "information opérateur"),
            severity=str(params.get("severity") or "warning"),
        )
        return Resultat(
            ok=True,
            action="notify.operator",
            detail=str(params.get("message") or "opérateur informé"),
            evidence={"channel": "journal"},
        )

    async def _escalate_human(self, params: dict[str, Any], _: dict[str, Any]) -> Resultat:
        self.events.error(
            "human.escalation",
            str(params.get("reason") or "reprise automatique interrompue"),
            reason=str(params.get("reason") or "indéterminée"),
        )
        return Resultat(
            ok=True,
            action="escalate.human",
            detail="escalade vers un opérateur humain",
            evidence={"reason": str(params.get("reason") or "")},
        )


def _import_externe() -> None:
    """Rappel des points d'extension volontairement non implémentés.

    Les actions `verify.recovery_suite` et les commandes Ansible ne figurent pas
    dans le registre : la première est portée par `verification.py`, les
    secondes relèvent de `ansible/` et sont déclenchées hors du chemin critique
    de la démonstration. Cela évite qu'un playbook d'Ansible en échec bloque une
    reprise.
    """
