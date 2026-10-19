"""AlphaPay : tenue de compte en partie double.

Invariant central
-----------------
Pour toute transaction réglée, la somme des débits égale la somme des crédits.
Chaque compte porte en outre `balance_cents`, qui doit toujours rester égal à
`SUM(débits) - SUM(crédits)` des jambes le concernant. Deux fonctions exposent
ces vérifications :

* `/integrity` recalcule l'invariant comptable sur l'ensemble du journal ;
* `/admin/reconcile` recalcule les soldes à partir des jambes et corrige les
  écarts.

C'est ce second point qui distingue une vraie reprise d'un simple redémarrage :
un conteneur qui redémarre peut retrouver son état, pas réparer un solde
incohérent. La suite de vérification du moteur de remédiation appelle
`/integrity` et refuse de déclarer la reprise tant qu'un écart subsiste.

Les instantanés (`/admin/snapshot`) permettent en outre de revenir à un état
antérieur connu sain si l'écart est trop important pour être réconcilié.
"""

from __future__ import annotations

import datetime as dt
import glob
import json
import os
import uuid
from typing import Any

from fastapi import Header
from pydantic import BaseModel, Field

from common.app import build_app
from common.config import env_str
from common.db import connection, execute, fetch_all, fetch_one
from common.errors import AppError, bad_request, conflict, forbidden, not_found
from common.metrics import LEDGER_IMBALANCE_CENTS, LEDGER_TRANSACTIONS_TOTAL
from common.security import constant_time_equals
from common.tracing import current_trace_id, set_route_label

VERSION = "1.0.0"

ctx = build_app(
    service_name="api-ledger",
    version=VERSION,
    title="AlphaPay : Grand livre",
    description=(
        "Soldes, transactions en partie double, contrôle d'intégrité, "
        "instantanés et réconciliation."
    ),
    with_database=True,
)
app = ctx.app
events = ctx.events

ADMIN_TOKEN = env_str("ADMIN_API_TOKEN", required=True)
SNAPSHOT_DIR = env_str("SNAPSHOT_DIR", "/var/lib/alphapay/snapshots")
MAX_TRANSACTION_CENTS = 100_000_00


# =============================================================================
#  Schémas
# =============================================================================


class EntreeDemandee(BaseModel):
    account_code: str = Field(min_length=3, max_length=64)
    direction: str = Field(pattern="^[DC]$")
    amount_cents: int = Field(gt=0)


class TransactionDemandee(BaseModel):
    idempotency_key: str = Field(min_length=8, max_length=120)
    kind: str = Field(default="transfer", pattern="^(transfer|settlement|fee|adjustment)$")
    entries: list[EntreeDemandee] = Field(min_length=2, max_length=8)
    currency: str = Field(default="EUR", min_length=3, max_length=3)
    source_ip: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class FreezeRequest(BaseModel):
    account_code: str = Field(min_length=3, max_length=64)
    frozen: bool = True
    reason: str = Field(default="confinement automatique", max_length=200)


class RestoreRequest(BaseModel):
    snapshot: str = Field(min_length=3, max_length=200)


# =============================================================================
#  Utilitaires
# =============================================================================


def _exiger_amont(jeton: str | None) -> None:
    """Contrôle d'accès interne : le grand livre n'est pas exposé publiquement."""
    if not jeton or not constant_time_equals(jeton, ADMIN_TOKEN):
        raise forbidden("Appel interne non autorisé.")


async def _comptes_par_code(codes: list[str]) -> dict[str, dict[str, Any]]:
    lignes = await fetch_all(
        "SELECT id, code, status, balance_cents, currency FROM ledger.accounts "
        "WHERE code = ANY(%s)",
        (codes,),
    )
    return {ligne["code"]: ligne for ligne in lignes}


# =============================================================================
#  Lecture
# =============================================================================


@app.get("/accounts", tags=["grand livre"])
async def lister_comptes(limit: int = 50) -> dict[str, Any]:
    set_route_label("/accounts")
    lignes = await fetch_all(
        "SELECT code, label, currency, balance_cents, status FROM ledger.accounts "
        "ORDER BY code LIMIT %s",
        (min(max(limit, 1), 200),),
    )
    return {"accounts": [dict(ligne) for ligne in lignes]}


@app.get("/accounts/{code}", tags=["grand livre"])
async def lire_compte(code: str) -> dict[str, Any]:
    set_route_label("/accounts")
    ligne = await fetch_one(
        "SELECT code, label, currency, balance_cents, status, owner_user_id "
        "FROM ledger.accounts WHERE code = %s",
        (code,),
    )
    if ligne is None:
        raise not_found(f"Compte {code} inconnu.")
    return dict(ligne)


@app.get("/transactions", tags=["grand livre"])
async def lister_transactions(limit: int = 20) -> dict[str, Any]:
    set_route_label("/transactions")
    lignes = await fetch_all(
        "SELECT id, kind, status, amount_cents, currency, source_ip, created_at, "
        "settled_at, metadata "
        "FROM ledger.transactions ORDER BY created_at DESC LIMIT %s",
        (min(max(limit, 1), 200),),
    )
    return {"transactions": [dict(ligne) for ligne in lignes]}


@app.get("/transactions/{identifiant}", tags=["grand livre"])
async def lire_transaction(identifiant: str) -> dict[str, Any]:
    set_route_label("/transactions")
    entete = await fetch_one(
        "SELECT id, kind, status, amount_cents, currency, source_ip, trace_id, "
        "created_at, settled_at, metadata "
        "FROM ledger.transactions WHERE id = %s",
        (identifiant,),
    )
    if entete is None:
        raise not_found("Transaction inconnue.")
    jambes = await fetch_all(
        "SELECT a.code, e.direction, e.amount_cents FROM ledger.entries e "
        "JOIN ledger.accounts a ON a.id = e.account_id "
        "WHERE e.transaction_id = %s ORDER BY e.id",
        (identifiant,),
    )
    resultat = dict(entete)
    resultat["entries"] = [dict(jambe) for jambe in jambes]
    return resultat


@app.get("/integrity", tags=["contrôle"])
async def integrite() -> dict[str, Any]:
    """Contrôle d'intégrité comptable : appelé par la suite de vérification."""
    set_route_label("/integrity")

    desequilibre = await fetch_one(
        "SELECT COALESCE(SUM(CASE WHEN direction = 'D' THEN amount_cents "
        "ELSE -amount_cents END), 0) AS ecart FROM ledger.entries"
    )
    ecart_global = int(desequilibre["ecart"]) if desequilibre else 0

    incoherents = await fetch_all(
        "SELECT a.code, a.balance_cents, "
        "COALESCE(SUM(CASE WHEN e.direction = 'D' THEN e.amount_cents "
        "ELSE -e.amount_cents END), 0) AS attendu "
        "FROM ledger.accounts a LEFT JOIN ledger.entries e ON e.account_id = a.id "
        "GROUP BY a.code, a.balance_cents "
        "HAVING a.balance_cents <> COALESCE(SUM(CASE WHEN e.direction = 'D' "
        "THEN e.amount_cents ELSE -e.amount_cents END), 0)"
    )

    orphelines = await fetch_one(
        "SELECT COUNT(*) AS n FROM ledger.transactions t "
        "WHERE t.status = 'settled' AND NOT EXISTS "
        "(SELECT 1 FROM ledger.entries e WHERE e.transaction_id = t.id)"
    )

    comptes = await fetch_one("SELECT COUNT(*) AS n FROM ledger.accounts")

    LEDGER_IMBALANCE_CENTS.labels(service="api-ledger").set(abs(ecart_global))
    equilibre = ecart_global == 0 and not incoherents and int(orphelines["n"]) == 0
    return {
        "balanced": equilibre,
        "imbalance_cents": ecart_global,
        "accounts_checked": int(comptes["n"]) if comptes else 0,
        "inconsistent_accounts": [dict(ligne) for ligne in incoherents],
        "settled_transactions_without_entries": int(orphelines["n"]) if orphelines else 0,
    }


# =============================================================================
#  Écriture
# =============================================================================


@app.post("/transactions", status_code=201, tags=["grand livre"])
async def creer_transaction(
    demande: TransactionDemandee,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Enregistre une transaction équilibrée, ou renvoie celle déjà connue.

    L'idempotence est portée par (devise, somme des débits) : utile lorsque la
    bordure rejoue une requête après un délai d'attente.
    """
    set_route_label("/transactions")
    _exiger_amont(x_internal_token)

    debits = sum(e.amount_cents for e in demande.entries if e.direction == "D")
    credits = sum(e.amount_cents for e in demande.entries if e.direction == "C")
    if debits != credits:
        raise bad_request(
            "desequilibre",
            "Transaction déséquilibrée",
            f"Total débits {debits} ≠ total crédits {credits}.",
        )
    if debits > MAX_TRANSACTION_CENTS:
        raise bad_request(
            "montant_hors_limite",
            "Montant hors limite",
            f"Le montant dépasse le plafond de {MAX_TRANSACTION_CENTS} centimes.",
        )
    if len({e.account_code for e in demande.entries}) < 2:
        raise bad_request(
            "comptes_insuffisants",
            "Comptes insuffisants",
            "Une transaction en partie double mobilise au moins deux comptes.",
        )

    existante = await fetch_one(
        "SELECT id, status FROM ledger.transactions WHERE idempotency_key = %s",
        (demande.idempotency_key,),
    )
    if existante is not None:
        return {
            "id": str(existante["id"]),
            "status": existante["status"],
            "idempotent_replay": True,
        }

    codes = [e.account_code for e in demande.entries]
    comptes = await _comptes_par_code(codes)
    manquants = [code for code in codes if code not in comptes]
    if manquants:
        raise not_found(f"Comptes inconnus : {', '.join(sorted(set(manquants)))}")
    geles = [code for code in codes if comptes[code]["status"] != "active"]
    if geles:
        raise AppError(
            409,
            "compte_non_actif",
            "Compte non disponible",
            f"Comptes inactifs : {', '.join(sorted(set(geles)))}.",
        )

    identifiant = uuid.uuid4()
    try:
        async with connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO ledger.transactions "
                    "(id, idempotency_key, kind, status, amount_cents, currency, "
                    " source_ip, trace_id, settled_at, metadata) "
                    "VALUES (%s, %s, %s, 'settled', %s, %s, "
                    "        NULLIF(%s, '')::inet, NULLIF(%s, '')::uuid, now(), %s::jsonb)",
                    (
                        identifiant,
                        demande.idempotency_key,
                        demande.kind,
                        debits,
                        demande.currency,
                        demande.source_ip or "",
                        current_trace_id(),
                        json.dumps(demande.metadata),
                    ),
                )
                for entree in demande.entries:
                    compte = comptes[entree.account_code]
                    await cur.execute(
                        "INSERT INTO ledger.entries "
                        "(transaction_id, account_id, direction, amount_cents) "
                        "VALUES (%s, %s, %s, %s)",
                        (identifiant, compte["id"], entree.direction, entree.amount_cents),
                    )
                    delta = entree.amount_cents if entree.direction == "D" else -entree.amount_cents
                    await cur.execute(
                        "UPDATE ledger.accounts SET balance_cents = balance_cents + %s "
                        "WHERE id = %s",
                        (delta, compte["id"]),
                    )
    except Exception as exc:  # noqa: BLE001 : reprise en cas de doublon concurrent
        if "idempotency_key" in str(exc):
            raise conflict(
                "rejeu_concurrent",
                "Transaction déjà enregistrée",
                "Une transaction portant la même clé d'idempotence existe déjà.",
            ) from exc
        raise

    LEDGER_TRANSACTIONS_TOTAL.labels(service="api-ledger", status="settled").inc()
    events.emit(
        "ledger.transaction",
        transaction_id=str(identifiant),
        kind=demande.kind,
        status="settled",
        amount_cents=debits,
        currency=demande.currency,
        accounts=sorted(set(codes)),
        source_ip=demande.source_ip or "",
    )
    return {
        "id": str(identifiant),
        "status": "settled",
        "amount_cents": debits,
        "currency": demande.currency,
        "idempotent_replay": False,
    }


# =============================================================================
#  Administration et reprise
# =============================================================================


@app.post("/admin/freeze-account", tags=["administration"])
async def geler_compte(
    demande: FreezeRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, Any]:
    set_route_label("/admin/freeze-account")
    _exiger_amont(x_internal_token)
    etat = "frozen" if demande.frozen else "active"
    resultat = await execute(
        "UPDATE ledger.accounts SET status = %s WHERE code = %s",
        (etat, demande.account_code),
    )
    if resultat == 0:
        raise not_found(f"Compte {demande.account_code} inconnu.")
    events.warn(
        "ledger.account.status_changed",
        message="état de compte modifié",
        account=demande.account_code,
        status=etat,
        reason=demande.reason,
    )
    return {"account_code": demande.account_code, "status": etat}


@app.post("/admin/reconcile", tags=["administration"])
async def reconcilier(x_internal_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Recalcule les soldes à partir des jambes et corrige les écarts."""
    set_route_label("/admin/reconcile")
    _exiger_amont(x_internal_token)
    async with connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "WITH attendu AS ("
                "  SELECT a.id, COALESCE(SUM(CASE WHEN e.direction = 'D' "
                "  THEN e.amount_cents ELSE -e.amount_cents END), 0) AS solde "
                "  FROM ledger.accounts a LEFT JOIN ledger.entries e ON e.account_id = a.id "
                "  GROUP BY a.id) "
                "UPDATE ledger.accounts a SET balance_cents = attendu.solde "
                "FROM attendu WHERE attendu.id = a.id AND a.balance_cents <> attendu.solde"
            )
            corriges = cur.rowcount or 0
    if corriges:
        events.warn(
            "ledger.reconciled",
            message="soldes recalculés depuis le journal des jambes",
            accounts_corrected=corriges,
        )
    else:
        events.emit("ledger.reconciled", accounts_corrected=0)
    return {"accounts_corrected": corriges}


@app.post("/admin/snapshot", tags=["administration"])
async def instantane(x_internal_token: str | None = Header(default=None)) -> dict[str, Any]:
    set_route_label("/admin/snapshot")
    _exiger_amont(x_internal_token)
    comptes = await fetch_all(
        "SELECT code, label, currency, balance_cents, status FROM ledger.accounts ORDER BY code"
    )
    controle = await fetch_one(
        "SELECT COALESCE(SUM(CASE WHEN direction = 'D' THEN amount_cents "
        "ELSE -amount_cents END), 0) AS ecart FROM ledger.entries"
    )
    horodatage = dt.datetime.now(dt.timezone.utc)
    nom = f"ledger-{horodatage.strftime('%Y%m%dT%H%M%SZ')}.json"
    os.makedirs(SNAPSHOT_DIR, exist_ok=True)
    chemin = os.path.join(SNAPSHOT_DIR, nom)
    charge = {
        "taken_at": horodatage.isoformat(),
        "imbalance_cents": int(controle["ecart"]) if controle else 0,
        "accounts": [dict(ligne) for ligne in comptes],
    }
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(charge, fichier, ensure_ascii=False, indent=2)
    events.emit(
        "ledger.snapshot.created",
        snapshot=nom,
        accounts=len(comptes),
        imbalance_cents=charge["imbalance_cents"],
    )
    return {"snapshot": nom, "accounts": len(comptes)}


@app.get("/admin/snapshots", tags=["administration"])
async def lister_instantanes(x_internal_token: str | None = Header(default=None)) -> dict[str, Any]:
    _exiger_amont(x_internal_token)
    fichiers = sorted(glob.glob(os.path.join(SNAPSHOT_DIR, "ledger-*.json")))
    return {"snapshots": [os.path.basename(f) for f in fichiers[-50:]]}


@app.post("/admin/restore", tags=["administration"])
async def restaurer(
    demande: RestoreRequest,
    x_internal_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Rétablit les soldes depuis un instantané contrôlé."""
    set_route_label("/admin/restore")
    _exiger_amont(x_internal_token)
    nom = os.path.basename(demande.snapshot)
    chemin = os.path.join(SNAPSHOT_DIR, nom)
    if not os.path.isfile(chemin):
        raise not_found(f"Instantané {nom} introuvable.")
    with open(chemin, encoding="utf-8") as fichier:
        charge = json.load(fichier)
    if int(charge.get("imbalance_cents", 0)) != 0:
        raise bad_request(
            "instantane_desequilibre",
            "Instantané inutilisable",
            "L'instantané retenu présente lui-même un déséquilibre comptable.",
        )
    restaures = 0
    async with connection() as conn:
        async with conn.cursor() as cur:
            for compte in charge.get("accounts", []):
                await cur.execute(
                    "UPDATE ledger.accounts SET balance_cents = %s, status = %s "
                    "WHERE code = %s",
                    (compte["balance_cents"], compte["status"], compte["code"]),
                )
                restaures += cur.rowcount or 0
    events.warn(
        "ledger.snapshot.restored",
        message="soldes rétablis depuis un instantané",
        snapshot=nom,
        accounts_restored=restaures,
    )
    return {"snapshot": nom, "accounts_restored": restaures}
