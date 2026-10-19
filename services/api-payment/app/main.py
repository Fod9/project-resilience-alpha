"""AlphaPay — orchestration des paiements.

Le service ne tient pas de registre propre : il applique les règles métier
(autorisation, propriété du compte débité, plafonds, vélocité), puis délègue
l'écriture comptable au grand livre. C'est ce dernier qui porte l'invariant de
partie double.

Une transaction n'existe donc qu'à un seul endroit, ce qui évite toute
divergence entre deux registres après une reprise.
"""

from __future__ import annotations

import datetime as dt
import time
from typing import Any

import jwt
from fastapi import Header, Query
from pydantic import BaseModel, Field

from common.app import build_app
from common.config import env_int, env_str
from common.errors import AppError, bad_request, forbidden, not_found, unauthorized
from common.http_client import UpstreamError, request_json
from common.tracing import current_client_ip, current_trace_id, set_identity, set_route_label

VERSION = "1.0.0"

ctx = build_app(
    service_name="api-payment",
    version=VERSION,
    title="AlphaPay — Paiements",
    description="Création et consultation des paiements, contrôle des plafonds et de la vélocité.",
)
app = ctx.app
events = ctx.events

LEDGER_URL = env_str("LEDGER_URL", "http://api-ledger:8000", required=True)
JWKS_URL = env_str("AUTH_JWKS_URL", "http://api-auth:8000/.well-known/jwks.json", required=True)
INTERNAL_TOKEN = env_str("ADMIN_API_TOKEN", required=True)
MIN_CENTS = env_int("PAYMENT_MIN_CENTS", 100)
MAX_CENTS = env_int("PAYMENT_MAX_CENTS", 500_000)
DAILY_MAX_CENTS = env_int("PAYMENT_DAILY_MAX_CENTS", 2_000_000)
VELOCITY_WINDOW_SECONDS = env_int("PAYMENT_VELOCITY_WINDOW_SECONDS", 60)
VELOCITY_MAX = env_int("PAYMENT_VELOCITY_MAX", 20)
JWKS_CACHE_SECONDS = env_int("JWKS_CACHE_SECONDS", 10)


# =============================================================================
#  Schémas
# =============================================================================


class PaiementDemande(BaseModel):
    source_account: str = Field(min_length=3, max_length=64)
    destination_account: str = Field(min_length=3, max_length=64)
    amount_cents: int = Field(gt=0)
    currency: str = Field(default="EUR", min_length=3, max_length=3)
    reference: str = Field(min_length=4, max_length=120)


class PaiementReponse(BaseModel):
    payment_id: str
    status: str
    amount_cents: int
    currency: str
    source_account: str
    destination_account: str
    reference: str
    created_at: str
    idempotent_replay: bool


# =============================================================================
#  Vérification des jetons
# =============================================================================

_jwks: dict[str, Any] = {"keys": None, "fetched_at": 0.0}


async def _cles_publiques(forcer: bool = False) -> dict[str, Any]:
    maintenant = time.monotonic()
    if not forcer and _jwks["keys"] is not None and maintenant - _jwks["fetched_at"] < JWKS_CACHE_SECONDS:
        return _jwks["keys"]
    reponse = await request_json("GET", JWKS_URL, timeout=5.0)
    if not isinstance(reponse, dict) or "keys" not in reponse:
        raise AppError(
            503,
            "jwks_indisponible",
            "Clés de signature indisponibles",
            "Le service d'authentification n'a pas fourni de jeu de clés exploitable.",
        )
    _jwks["keys"] = reponse
    _jwks["fetched_at"] = maintenant
    return reponse


async def _verifier_jeton(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise unauthorized("En-tête Authorization absent ou mal formé.")
    jeton = authorization[7:].strip()
    try:
        entete = jwt.get_unverified_header(jeton)
    except jwt.InvalidTokenError as exc:
        raise unauthorized("Jeton illisible.") from exc

    kid = entete.get("kid")
    for tentative in (1, 2):
        jeu = await _cles_publiques(forcer=(tentative == 2))
        cle = next((k for k in jeu.get("keys", []) if k.get("kid") == kid), None)
        if cle is None and tentative == 1:
            # Clé inconnue : elle a peut-être été renouvelée, on rafraîchit.
            continue
        if cle is None:
            raise unauthorized("Clé de signature inconnue : jeton émis avant rotation.")
        try:
            return jwt.decode(
                jeton,
                key=jwt.PyJWK.from_dict(cle).key,
                algorithms=[cle.get("alg", "RS256")],
                issuer="alphapay-auth",
                options={"require": ["exp", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise unauthorized("Jeton expiré.") from exc
        except jwt.InvalidTokenError as exc:
            raise unauthorized("Signature de jeton invalide.") from exc
    raise unauthorized("Jeton non vérifiable.")


def _identite(revendications: dict[str, Any]) -> str:
    return revendications.get("username") or revendications.get("sub", "")


# =============================================================================
#  Accès au grand livre
# =============================================================================


async def _appeler_grand_livre(methode: str, chemin: str, *, charge: dict[str, Any] | None = None,
                               timeout: float = 8.0) -> Any:
    """Appelle le grand livre en distinguant refus métier et indisponibilité.

    Un refus métier (solde, compte gelé, transaction déséquilibrée) est renvoyé
    tel quel : c'est une réponse légitime du domaine. Seul un défaut de
    disponibilité devient une erreur d'infrastructure, que la sonde de reprise
    interprétera comme un service non rétabli.
    """
    try:
        return await request_json(
            methode,
            f"{LEDGER_URL}{chemin}",
            json_body=charge,
            headers={"X-Internal-Token": INTERNAL_TOKEN},
            timeout=timeout,
        )
    except UpstreamError as exc:
        statut = exc.status if 400 <= exc.status < 500 else 502
        raise AppError(
            statut,
            exc.code,
            exc.payload.get("title") or "Refus du grand livre",
            exc.detail,
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise AppError(
            502,
            "grand_livre_indisponible",
            "Grand livre indisponible",
            "Le service de tenue de compte n'a pas répondu dans le délai imparti.",
        ) from exc


def _libelle_compte(code: str) -> str:
    return f"Compte {code}"


async def _verifier_propriete(code: str, revendications: dict[str, Any]) -> None:
    if revendications.get("role") in {"operator", "admin"}:
        return
    compte = await _appeler_grand_livre("GET", f"/accounts/{code}")
    proprietaire = compte.get("owner_user_id")
    if proprietaire and str(proprietaire) != str(revendications.get("sub")):
        raise forbidden(
            f"Le compte {code} n'appartient pas à l'identité authentifiée."
        )


async def _verifier_velocite(identite: str) -> None:
    """Limite le nombre de paiements d'une même identité sur une fenêtre courte."""
    historique = await _appeler_grand_livre("GET", "/transactions?limit=200")
    maintenant = dt.datetime.now(dt.timezone.utc)
    recents = 0
    for transaction in historique.get("transactions", []):
        metadonnees = transaction.get("metadata") or {}
        if metadonnees.get("identity") != identite:
            continue
        horodatage = transaction.get("created_at")
        if not horodatage:
            continue
        quand = dt.datetime.fromisoformat(str(horodatage).replace("Z", "+00:00"))
        if (maintenant - quand).total_seconds() < VELOCITY_WINDOW_SECONDS:
            recents += 1
    if recents >= VELOCITY_MAX:
        raise AppError(
            429,
            "velocite_excessive",
            "Trop de transactions",
            f"Plus de {VELOCITY_MAX} transactions en {VELOCITY_WINDOW_SECONDS} s.",
        )


async def _total_journalier(identite: str) -> int:
    historique = await _appeler_grand_livre("GET", "/transactions?limit=200")
    maintenant = dt.datetime.now(dt.timezone.utc)
    total = 0
    for transaction in historique.get("transactions", []):
        metadonnees = transaction.get("metadata") or {}
        if metadonnees.get("identity") != identite:
            continue
        horodatage = transaction.get("created_at")
        if not horodatage:
            continue
        quand = dt.datetime.fromisoformat(str(horodatage).replace("Z", "+00:00"))
        if quand.date() == maintenant.date():
            total += int(transaction.get("amount_cents", 0))
    return total


# =============================================================================
#  Routes
# =============================================================================


@app.post("/payments", response_model=PaiementReponse, status_code=201, tags=["paiements"])
async def creer_paiement(
    demande: PaiementDemande,
    authorization: str | None = Header(default=None),
) -> PaiementReponse:
    set_route_label("/payments")
    revendications = await _verifier_jeton(authorization)
    identite = _identite(revendications)
    set_identity(identite)

    if demande.source_account == demande.destination_account:
        raise bad_request(
            "comptes_identiques",
            "Comptes identiques",
            "Le compte émetteur et le compte destinataire doivent différer.",
        )
    if demande.amount_cents < MIN_CENTS:
        raise bad_request(
            "montant_trop_faible",
            "Montant trop faible",
            f"Le montant minimum est de {MIN_CENTS} centimes.",
        )
    if demande.amount_cents > MAX_CENTS:
        raise bad_request(
            "montant_trop_eleve",
            "Montant trop élevé",
            f"Le montant maximum par paiement est de {MAX_CENTS} centimes.",
        )

    await _verifier_propriete(demande.source_account, revendications)
    await _verifier_velocite(identite)
    deja = await _total_journalier(identite)
    if deja + demande.amount_cents > DAILY_MAX_CENTS:
        raise AppError(
            429,
            "plafond_journalier",
            "Plafond journalier atteint",
            f"Cumul autorisé : {DAILY_MAX_CENTS} centimes par jour.",
        )

    cle_idempotence = f"{identite}:{demande.reference}"
    resultat = await _appeler_grand_livre(
        "POST",
        "/transactions",
        charge={
            "idempotency_key": cle_idempotence,
            "kind": "transfer",
            "currency": demande.currency,
            "source_ip": current_client_ip(),
            "metadata": {
                "identity": identite,
                "reference": demande.reference,
                "trace_id": current_trace_id(),
                "channel": "web",
            },
            "entries": [
                {"account_code": demande.source_account, "direction": "C",
                 "amount_cents": demande.amount_cents},
                {"account_code": demande.destination_account, "direction": "D",
                 "amount_cents": demande.amount_cents},
            ],
        },
    )

    if not resultat.get("idempotent_replay"):
        events.emit(
            "payment.created",
            payment_id=resultat["id"],
            identity=identite,
            amount_cents=demande.amount_cents,
            currency=demande.currency,
            source_account=demande.source_account,
            destination_account=demande.destination_account,
            source_ip=current_client_ip(),
        )
    return PaiementReponse(
        payment_id=str(resultat["id"]),
        status=resultat.get("status", "settled"),
        amount_cents=demande.amount_cents,
        currency=demande.currency,
        source_account=demande.source_account,
        destination_account=demande.destination_account,
        reference=demande.reference,
        created_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        idempotent_replay=bool(resultat.get("idempotent_replay")),
    )


@app.get("/payments", tags=["paiements"])
async def lister_paiements(
    authorization: str | None = Header(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    set_route_label("/payments")
    revendications = await _verifier_jeton(authorization)
    set_identity(_identite(revendications))
    return await _appeler_grand_livre("GET", f"/transactions?limit={limit}")


@app.get("/payments/{identifiant}", tags=["paiements"])
async def lire_paiement(
    identifiant: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    set_route_label("/payments")
    revendications = await _verifier_jeton(authorization)
    set_identity(_identite(revendications))
    resultat = await _appeler_grand_livre("GET", f"/transactions/{identifiant}")
    if resultat is None:
        raise not_found("Paiement inconnu.")
    return resultat


@app.get("/limits", tags=["paiements"])
async def plafonds() -> dict[str, Any]:
    """Plafonds appliqués — publiés pour que l'interface les affiche."""
    set_route_label("/limits")
    return {
        "min_cents": MIN_CENTS,
        "max_cents": MAX_CENTS,
        "daily_max_cents": DAILY_MAX_CENTS,
        "velocity_window_seconds": VELOCITY_WINDOW_SECONDS,
        "velocity_max": VELOCITY_MAX,
    }


@app.get("/ready/ledger", include_in_schema=False)
async def disponibilite_grand_livre() -> dict[str, Any]:
    """Sonde de bout en bout utilisée par la suite de vérification."""
    await _appeler_grand_livre("GET", "/integrity", timeout=5.0)
    return {"ledger_reachable": True, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat()}


def _coherence() -> None:
    if MIN_CENTS >= MAX_CENTS:
        raise AppError(
            500,
            "config_invalide",
            "Configuration incohérente",
            "PAYMENT_MIN_CENTS doit être inférieur à PAYMENT_MAX_CENTS.",
        )


_coherence()
