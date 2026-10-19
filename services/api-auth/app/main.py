"""AlphaPay : authentification, jetons d'accès et cycle de vie des clés.

Responsabilités
---------------
* délivrer des jetons JWT signés RS256 (`/token`) ;
* gérer leur rafraîchissement et leur révocation ;
* publier les clés publiques (`/.well-known/jwks.json`) consommées par les
  autres services ;
* exposer une surface d'administration restreinte que le moteur de remédiation
  peut piloter : révocation par adresse source, verrouillage de compte, rotation
  de la clé de signature.

Choix de conception
-------------------
La paire de clés est générée au premier démarrage et conservée dans
`auth.signing_keys`. Aucun fichier de clé n'existe sur l'hôte : la rotation,
qui invalide instantanément tous les jetons en circulation, se réduit donc à une
écriture en base - ce qui est précisément l'action attendue lorsque la clé de
signature est soupçonnée compromise.

Les jetons d'accès ne sont pas stockés (durée de vie courte). La fenêtre
résiduelle après une révocation est donc bornée par `JWT_ACCESS_TTL_SECONDS`,
et la réponse immédiate est la rotation de clé. Cette limite est assumée et
documentée dans le dossier de gouvernance.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import uuid
from typing import Any

import jwt
import jwt.algorithms
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Header, Request
from pydantic import BaseModel, Field

from common.app import build_app
from common.config import env_int, env_str
from common.db import execute, fetch_all, fetch_one
from common.errors import AppError, bad_request, forbidden, not_found, unauthorized
from common.metrics import AUTH_ATTEMPTS_TOTAL, TOKENS_REVOKED_TOTAL
from common.security import constant_time_equals, hash_token
from common.tracing import current_client_ip, set_identity, set_route_label

VERSION = "1.0.0"
ISSUER = "alphapay-auth"
ALGORITHM = "RS256"

ctx = build_app(
    service_name="api-auth",
    version=VERSION,
    title="AlphaPay : Authentification",
    description=(
        "Authentification des clients et des opérateurs, émission et révocation "
        "des jetons, publication des clés de signature."
    ),
    with_database=True,
)
app = ctx.app
events = ctx.events

ACCESS_TTL = env_int("JWT_ACCESS_TTL_SECONDS", 900)
REFRESH_TTL = env_int("JWT_REFRESH_TTL_SECONDS", 604800)
MAX_FAILED = env_int("AUTH_MAX_FAILED_ATTEMPTS", 5)
LOCKOUT_SECONDS = env_int("AUTH_LOCKOUT_SECONDS", 300)
ADMIN_TOKEN = env_str("ADMIN_API_TOKEN", required=True)

_HASHER = PasswordHasher(
    time_cost=env_int("ARGON2_TIME_COST", 3),
    memory_cost=env_int("ARGON2_MEMORY_COST", 65536),
    parallelism=env_int("ARGON2_PARALLELISM", 2),
)


# =============================================================================
#  Schémas
# =============================================================================


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int
    kid: str


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=16)


class RevokeRequest(BaseModel):
    refresh_token: str = Field(min_length=16)


class IntrospectRequest(BaseModel):
    token: str


class RevokeBySourceRequest(BaseModel):
    source_ip: str = Field(min_length=3, max_length=64)
    reason: str = Field(default="confinement automatique", max_length=200)


class LockAccountRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    seconds: int = Field(default=LOCKOUT_SECONDS, ge=1, le=86400)
    reason: str = Field(default="confinement automatique", max_length=200)


# =============================================================================
#  Clés de signature
# =============================================================================


async def _generer_paire() -> tuple[str, str]:
    cle = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privee = cle.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    publique = cle.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return privee, publique


async def cle_active() -> dict[str, Any]:
    ligne = await fetch_one(
        "SELECT kid, private_pem, public_pem FROM auth.signing_keys "
        "WHERE state = 'active' ORDER BY created_at DESC LIMIT 1"
    )
    if ligne is not None:
        return ligne
    privee, publique = await _generer_paire()
    kid = f"k-{uuid.uuid4().hex[:12]}"
    await execute(
        "INSERT INTO auth.signing_keys (kid, private_pem, public_pem, state) "
        "VALUES (%s, %s, %s, 'active') ON CONFLICT (kid) DO NOTHING",
        (kid, privee, publique),
    )
    events.emit("auth.signing_key.created", kid=kid, algo=ALGORITHM)
    ligne = await fetch_one(
        "SELECT kid, private_pem, public_pem FROM auth.signing_keys WHERE kid = %s",
        (kid,),
    )
    assert ligne is not None
    return ligne


async def rotation_cle() -> str:
    """Crée une nouvelle clé active et marque l'ancienne comme compromise."""
    actuelle = await cle_active()
    nouveau_kid = f"k-{uuid.uuid4().hex[:12]}"
    privee, publique = await _generer_paire()
    async with _transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE auth.signing_keys SET state = 'compromised', "
                "retired_at = now() WHERE state = 'active' AND kid = %s",
                (actuelle["kid"],),
            )
            await cur.execute(
                "INSERT INTO auth.signing_keys (kid, private_pem, public_pem, state) "
                "VALUES (%s, %s, %s, 'active')",
                (nouveau_kid, privee, publique),
            )
    events.warn(
        "auth.signing_key.rotated",
        message="clé de signature remplacée : tous les jetons antérieurs sont invalides",
        ancien_kid=actuelle["kid"],
        nouveau_kid=nouveau_kid,
    )
    return nouveau_kid


def _transaction():  # type: ignore[no-untyped-def]
    from common.db import connection

    return connection()


# =============================================================================
#  Utilitaires
# =============================================================================


def _maintenant() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _exiger_admin(jeton: str | None) -> None:
    if not jeton or not constant_time_equals(jeton, ADMIN_TOKEN):
        raise forbidden("Jeton d'administration invalide ou absent.")


async def _auditer(
    *,
    action: str,
    outcome: str,
    actor_id: str | None = None,
    actor_role: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    await execute(
        "INSERT INTO auth.audit_log "
        "(actor_id, actor_role, source_ip, action, outcome, details) "
        "VALUES (%s, %s, NULLIF(%s, '')::inet, %s, %s, %s::jsonb)",
        (
            actor_id,
            actor_role,
            current_client_ip(),
            action,
            outcome,
            json.dumps(details) if details is not None else None,
        ),
    )


def _emettre_jetons(utilisateur: dict[str, Any], kid: str, privee: str) -> tuple[str, str, int]:
    maintenant = _maintenant()
    identifiant = str(uuid.uuid4())
    jti_acces = uuid.uuid4().hex
    charge = {
        "iss": ISSUER,
        "sub": str(utilisateur["id"]),
        "username": utilisateur["username"],
        "role": utilisateur["role"],
        "jti": jti_acces,
        "iat": int(maintenant.timestamp()),
        "exp": int((maintenant + dt.timedelta(seconds=ACCESS_TTL)).timestamp()),
    }
    acces = jwt.encode(charge, privee, algorithm=ALGORITHM, headers={"kid": kid})
    refresh = f"rt_{secrets.token_urlsafe(40)}"
    return acces, refresh, int((maintenant + dt.timedelta(seconds=REFRESH_TTL)).timestamp())


# =============================================================================
#  Routes publiques
# =============================================================================


@app.post("/token", response_model=TokenPair, tags=["authentification"])
async def obtenir_jeton(charge: LoginRequest, request: Request) -> TokenPair:
    set_route_label("/token")
    ligne = await fetch_one(
        "SELECT id, username, password_hash, role, locked_until "
        "FROM auth.users WHERE username = %s",
        (charge.username,),
    )
    source = current_client_ip()

    def refus(motif: str) -> AppError:
        AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="failure").inc()
        events.warn(
            "auth.attempt",
            message="authentification refusée",
            identity=charge.username,
            outcome="failure",
            reason=motif,
            source_ip=source,
        )
        return unauthorized("Identifiants invalides.")

    if ligne is None:
        # Comparaison à vide pour ne pas révéler l'existence du compte par le
        # temps de réponse.
        try:
            _HASHER.verify(
                "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$"
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                charge.password,
            )
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            pass
        raise refus("compte inconnu")

    verrou = ligne.get("locked_until")
    if verrou is not None and verrou > _maintenant():
        AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="locked").inc()
        events.warn(
            "auth.attempt",
            message="compte verrouillé",
            identity=charge.username,
            outcome="locked",
            source_ip=source,
        )
        raise AppError(
            423,
            "account_locked",
            "Compte temporairement verrouillé.",
            f"Nouvelle tentative possible après {verrou.isoformat()}.",
        )

    try:
        _HASHER.verify(ligne["password_hash"], charge.password)
        besoin_rehash = _HASHER.check_needs_rehash(ligne["password_hash"])
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        await execute(
            "UPDATE auth.users SET failed_attempts = failed_attempts + 1, "
            "locked_until = CASE WHEN failed_attempts + 1 >= %s "
            "THEN now() + make_interval(secs => %s) ELSE locked_until END, "
            "updated_at = now() WHERE id = %s",
            (MAX_FAILED, LOCKOUT_SECONDS, ligne["id"]),
        )
        await _auditer(
            action="auth.login",
            outcome="failure",
            actor_id=str(ligne["id"]),
            actor_role=ligne["role"],
            details={"reason": "mot de passe invalide"},
        )
        raise refus("mot de passe invalide")

    if besoin_rehash:
        await execute(
            "UPDATE auth.users SET password_hash = %s, updated_at = now() WHERE id = %s",
            (_HASHER.hash(charge.password), ligne["id"]),
        )

    cle = await cle_active()
    acces, refresh, expiration = _emettre_jetons(ligne, cle["kid"], cle["private_pem"])

    await execute(
        "INSERT INTO auth.refresh_tokens (user_id, token_hash, source_ip, expires_at) "
        "VALUES (%s, %s, NULLIF(%s, '')::inet, to_timestamp(%s))",
        (ligne["id"], hash_token(refresh), source, expiration),
    )
    await execute(
        "UPDATE auth.users SET failed_attempts = 0, locked_until = NULL, "
        "updated_at = now() WHERE id = %s",
        (ligne["id"],),
    )
    await _auditer(
        action="auth.login",
        outcome="success",
        actor_id=str(ligne["id"]),
        actor_role=ligne["role"],
        details={"kid": cle["kid"]},
    )
    AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="success").inc()
    events.emit(
        "auth.attempt",
        identity=charge.username,
        outcome="success",
        role=ligne["role"],
        source_ip=source,
    )
    return TokenPair(
        access_token=acces,
        refresh_token=refresh,
        expires_in=ACCESS_TTL,
        kid=cle["kid"],
    )


@app.post("/token/refresh", response_model=TokenPair, tags=["authentification"])
async def rafraichir(charge: RefreshRequest) -> TokenPair:
    set_route_label("/token/refresh")
    empreinte = hash_token(charge.refresh_token)
    ligne = await fetch_one(
        "SELECT r.id AS jeton_id, r.expires_at, r.revoked_at, u.id, u.username, u.role "
        "FROM auth.refresh_tokens r JOIN auth.users u ON u.id = r.user_id "
        "WHERE r.token_hash = %s",
        (empreinte,),
    )
    if ligne is None or ligne["revoked_at"] is not None:
        raise unauthorized("Jeton de rafraîchissement inconnu ou révoqué.")
    if ligne["expires_at"] <= _maintenant():
        raise unauthorized("Jeton de rafraîchissement expiré.")

    cle = await cle_active()
    acces, refresh, expiration = _emettre_jetons(ligne, cle["kid"], cle["private_pem"])

    # Rotation systématique : l'ancien jeton de rafraîchissement est consommé.
    await execute(
        "UPDATE auth.refresh_tokens SET revoked_at = now(), revoked_reason = 'rotated' "
        "WHERE id = %s",
        (ligne["jeton_id"],),
    )
    await execute(
        "INSERT INTO auth.refresh_tokens (user_id, token_hash, source_ip, expires_at) "
        "VALUES (%s, %s, NULLIF(%s, '')::inet, to_timestamp(%s))",
        (ligne["id"], hash_token(refresh), current_client_ip(), expiration),
    )
    return TokenPair(
        access_token=acces,
        refresh_token=refresh,
        expires_in=ACCESS_TTL,
        kid=cle["kid"],
    )


@app.post("/token/revoke", tags=["authentification"])
async def revoquer(charge: RevokeRequest) -> dict[str, Any]:
    set_route_label("/token/revoke")
    resultat = await execute(
        "UPDATE auth.refresh_tokens SET revoked_at = now(), revoked_reason = 'explicit' "
        "WHERE token_hash = %s AND revoked_at IS NULL",
        (hash_token(charge.refresh_token),),
    )
    if resultat == 0:
        raise not_found("Jeton de rafraîchissement inconnu ou déjà révoqué.")
    TOKENS_REVOKED_TOTAL.labels(service="api-auth", reason="explicit").inc()
    return {"revoked": resultat}


@app.post("/introspect", tags=["authentification"])
async def introspecter(charge: IntrospectRequest) -> dict[str, Any]:
    set_route_label("/introspect")
    cle = await cle_active()
    try:
        revendications = jwt.decode(
            charge.token,
            cle["public_pem"],
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "sub"]},
        )
    except jwt.ExpiredSignatureError:
        return {"active": False, "reason": "expired"}
    except jwt.InvalidTokenError:
        return {"active": False, "reason": "invalid"}
    return {
        "active": True,
        "sub": revendications.get("sub"),
        "username": revendications.get("username"),
        "role": revendications.get("role"),
        "exp": revendications.get("exp"),
    }


@app.get("/.well-known/jwks.json", tags=["authentification"])
async def jwks() -> dict[str, Any]:
    """Clés publiques actives. Seule la clé active est publiée."""
    lignes = await fetch_all(
        "SELECT kid, public_pem FROM auth.signing_keys WHERE state = 'active' "
        "ORDER BY created_at DESC"
    )
    cles = []
    for ligne in lignes:
        cle_publique = serialization.load_pem_public_key(ligne["public_pem"].encode())
        if not isinstance(cle_publique, RSAPublicKey):
            continue
        dictionnaire = jwt.algorithms.RSAAlgorithm.to_jwk(cle_publique, as_dict=True)
        dictionnaire["kid"] = ligne["kid"]
        dictionnaire["use"] = "sig"
        dictionnaire["alg"] = ALGORITHM
        cles.append(dictionnaire)
    return {"keys": cles}


@app.get("/jwks.json", include_in_schema=False)
async def jwks_alias() -> dict[str, Any]:
    return await jwks()


@app.get("/users/me", tags=["utilisateurs"])
async def profil(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    set_route_label("/users/me")
    if not authorization or not authorization.lower().startswith("bearer "):
        raise unauthorized("En-tête Authorization absent ou mal formé.")
    cle = await cle_active()
    try:
        revendications = jwt.decode(
            authorization[7:],
            cle["public_pem"],
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "sub"]},
        )
    except jwt.InvalidTokenError as exc:
        raise unauthorized("Jeton invalide.") from exc
    set_identity(revendications.get("username") or revendications.get("sub", ""))
    ligne = await fetch_one(
        "SELECT id, username, email, role, created_at FROM auth.users WHERE id = %s",
        (revendications["sub"],),
    )
    if ligne is None:
        raise not_found("Utilisateur inconnu.")
    return dict(ligne)


# =============================================================================
#  Routes d'administration (moteur de remédiation)
# =============================================================================


@app.post("/admin/revoke-by-source", tags=["administration"])
async def revoquer_par_source(
    charge: RevokeBySourceRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Révoque tous les jetons de rafraîchissement émis depuis une adresse.

    Complète le blocage au niveau de la bordure : même si l'attaquant change
    d'empreinte applicative, ses jetons ne sont plus renouvelables.
    """
    set_route_label("/admin/revoke-by-source")
    _exiger_admin(x_admin_token)

    lignes = await fetch_all(
        "SELECT id, user_id FROM auth.refresh_tokens "
        "WHERE source_ip = NULLIF(%s, '')::inet AND revoked_at IS NULL",
        (charge.source_ip,),
    )
    jetons_revoques = 0
    comptes_verrouilles = 0
    async with _transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE auth.refresh_tokens SET revoked_at = now(), "
                "revoked_reason = %s WHERE source_ip = NULLIF(%s, '')::inet "
                "AND revoked_at IS NULL",
                (charge.reason, charge.source_ip),
            )
            jetons_revoques = cur.rowcount or 0
            identifiants = sorted({str(ligne["user_id"]) for ligne in lignes})
            if identifiants:
                await cur.execute(
                    "UPDATE auth.users SET locked_until = now() + make_interval(secs => %s), "
                    "updated_at = now() WHERE id = ANY(%s::uuid[])",
                    (LOCKOUT_SECONDS, identifiants),
                )
                comptes_verrouilles = cur.rowcount or 0

    TOKENS_REVOKED_TOTAL.labels(service="api-auth", reason="source_ip").inc()
    await _auditer(
        action="auth.revoke_by_source",
        outcome="success",
        actor_role="remediation",
        details={
            "source_ip": charge.source_ip,
            "tokens_revoked": jetons_revoques,
            "accounts_locked": comptes_verrouilles,
        },
    )
    events.warn(
        "auth.tokens.revoked",
        message="jetons révoqués par adresse source",
        source_ip=charge.source_ip,
        tokens_revoked=jetons_revoques,
        accounts_locked=comptes_verrouilles,
    )
    return {
        "source_ip": charge.source_ip,
        "refresh_tokens_revoked": jetons_revoques,
        "accounts_locked": comptes_verrouilles,
        "access_token_ttl_seconds": ACCESS_TTL,
    }


@app.post("/admin/lock-account", tags=["administration"])
async def verrouiller(
    charge: LockAccountRequest,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    set_route_label("/admin/lock-account")
    _exiger_admin(x_admin_token)
    resultat = await execute(
        "UPDATE auth.users SET locked_until = now() + make_interval(secs => %s), "
        "updated_at = now() WHERE username = %s",
        (charge.seconds, charge.username),
    )
    if resultat == 0:
        raise not_found("Compte inconnu.")
    await _auditer(
        action="auth.lock_account",
        outcome="success",
        actor_role="remediation",
        details={"username": charge.username, "seconds": charge.seconds},
    )
    events.warn(
        "auth.account.locked",
        message="compte verrouillé",
        identity=charge.username,
        duration_seconds=charge.seconds,
        reason=charge.reason,
    )
    return {"username": charge.username, "locked_seconds": charge.seconds}


@app.post("/admin/rotate-signing-key", tags=["administration"])
async def tourner_cle(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    """Remplace la clé de signature ; tous les jetons émis deviennent invalides."""
    set_route_label("/admin/rotate-signing-key")
    _exiger_admin(x_admin_token)
    nouveau_kid = await rotation_cle()
    await _auditer(
        action="auth.rotate_signing_key",
        outcome="success",
        actor_role="remediation",
        details={"new_kid": nouveau_kid},
    )
    return {"active_kid": nouveau_kid, "previous_keys_status": "compromised"}


@app.get("/admin/keys", tags=["administration"])
async def lister_cles(x_admin_token: str | None = Header(default=None)) -> dict[str, Any]:
    _exiger_admin(x_admin_token)
    lignes = await fetch_all(
        "SELECT kid, state, created_at, retired_at FROM auth.signing_keys "
        "ORDER BY created_at DESC"
    )
    return {"keys": [dict(ligne) for ligne in lignes], "algo": ALGORITHM}


@app.get("/users/{username}/exists", include_in_schema=False)
async def compte_existe(username: str) -> dict[str, Any]:
    """Sonde de disponibilité utilisée par la remédiation (existence d'un compte)."""
    ligne = await fetch_one("SELECT 1 AS present FROM auth.users WHERE username = %s", (username,))
    if ligne is None:
        raise not_found("Compte inconnu.")
    return {"present": True}


def _verifier_coherence() -> None:
    if ACCESS_TTL <= 0 or REFRESH_TTL <= 0:
        raise bad_request(
            "config_invalide",
            "Configuration invalide",
            "Les durées de vie de jeton doivent être strictement positives.",
        )


_verifier_coherence()
