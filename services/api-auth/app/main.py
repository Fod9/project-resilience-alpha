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
from typing import Any, Sequence

import jwt
import jwt.algorithms
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from fastapi import Header, Request
from psycopg import errors as psycopg_errors
from pydantic import BaseModel, Field

from common.app import build_app
from common.config import env_bool, env_float, env_int, env_str
from common.db import execute, fetch_all, fetch_one
from common.errors import AppError, bad_request, forbidden, not_found, unauthorized
from common.metrics import AUTH_ATTEMPTS_TOTAL, TOKENS_REVOKED_TOTAL
from common.security import constant_time_equals, hash_token
from common.tracing import current_client_ip, set_identity, set_route_label

from .face import (
    DIMENSION_DESCRIPTEUR,
    SEUIL_CALIBRE,
    DescripteurInvalide,
    distance_acceptee,
    distance_cosinus,
    evaluer_defi,
    gabarit_moyen,
    valider_descripteur,
)

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

#: Roles d'exploitation, jamais verrouilles par une revocation pilotee par
#: l'adresse source. Leur session est ce que la plateforme doit preserver
#: pendant un incident, et l'adresse source ne designe personne derriere une
#: passerelle de publication de ports.
ROLES_EXPLOITATION = ("operator", "auditor", "admin")
ADMIN_TOKEN = env_str("ADMIN_API_TOKEN", required=True)

# Authentification faciale. Le seuil porte sur une distance cosinus : il est
# inclusif, et le durcir augmente mécaniquement les refus de visages légitimes.
# La valeur par défaut n'est pas choisie : elle est mesurée sur 400 visages
# réels, voir SEUIL_CALIBRE dans face.py, qui documente la distribution des
# distances entre deux photos d'une même personne et entre deux personnes.
FACE_MATCH_THRESHOLD = env_float("FACE_MATCH_THRESHOLD", SEUIL_CALIBRE)
FACE_ENROLL_MIN_SAMPLES = env_int("FACE_ENROLL_MIN_SAMPLES", 8)
FACE_CHALLENGE_MIN_TURN_DEG = env_float("FACE_CHALLENGE_MIN_TURN_DEG", 20.0)
# Gestes exigés par le défi actif. Le geste retenu est la rotation de tête : une
# photo immobile tenue devant la caméra ne la produit pas, puisque la mesure
# regarde la position du nez dans le cadre du visage, pas la position du cadre.
# Le clignement reste disponible (FACE_REQUIRE_BLINK=true) pour qui veut le
# cumuler, mais il est fragile en pratique : une paupière se mesure sur des
# durées plus courtes que la cadence de détection. Au moins un geste doit rester
# exigé : sans geste, le défi ne distingue plus un visage vivant d'une photo.
FACE_REQUIRE_BLINK = env_bool("FACE_REQUIRE_BLINK", False)
FACE_REQUIRE_TURN = env_bool("FACE_REQUIRE_TURN", True)

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


class FaceEnrollRequest(BaseModel):
    """Enrôlement : les captures brutes, moyennées et normalisées par le service.

    Le client n'annonce pas un nombre de captures, il en fournit : le minimum
    exigé est vérifié sur la longueur réelle de la liste, pas sur une valeur
    déclarée.
    """

    username: str = Field(min_length=3, max_length=120)
    descriptors: list[list[float]] = Field(min_length=1, max_length=64)


class FaceChallenge(BaseModel):
    blink: bool = False
    turn_deg: float = Field(default=0.0, ge=-180.0, le=180.0)


class FaceVerifyRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    descriptor: list[float] = Field(min_length=1, max_length=512)
    challenge: FaceChallenge = Field(default_factory=FaceChallenge)


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


async def _revendications(authorization: str | None) -> dict[str, Any]:
    """Revendications du jeton d'accès présenté dans l'en-tête `Authorization`."""
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
    return revendications


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
    revendications = await _revendications(authorization)
    set_identity(revendications.get("username") or revendications.get("sub", ""))
    ligne = await fetch_one(
        "SELECT id, username, email, role, created_at FROM auth.users WHERE id = %s",
        (revendications["sub"],),
    )
    if ligne is None:
        raise not_found("Utilisateur inconnu.")
    return dict(ligne)


# =============================================================================
#  Authentification faciale
# =============================================================================
#
# Le descripteur est calculé dans le navigateur : le service ne reçoit jamais
# d'image, seulement 128 nombres. Il n'en conserve que le gabarit moyen du
# compte, et aucune valeur de descripteur n'apparaît dans une réponse, un
# message d'erreur, un journal ou un audit.


def _schema_facial_absent() -> AppError:
    """Erreur diagnosable quand la migration faciale n'a pas été appliquée.

    `infra/db/04-face.sql` n'est joué qu'à l'initialisation d'un volume vide.
    Sur une base créée avant son ajout, l'insertion échoue : sans cette
    traduction, l'exploitant ne reçoit qu'une erreur interne et n'a aucun moyen
    de savoir quoi faire.
    """
    return AppError(
        503,
        "face_schema_absent",
        "Table des gabarits absente",
        "La table auth.face_templates n'existe pas sur cette base. Appliquez "
        "infra/db/04-face.sql sur la base en service, ou recréez le volume "
        "(docker compose down -v puis up).",
    )


async def _gabarit_ecrire(requete: str, parametres: tuple[Any, ...]) -> int:
    try:
        return await execute(requete, parametres)
    except psycopg_errors.UndefinedTable as erreur:
        raise _schema_facial_absent() from erreur


async def _gabarit_lire(requete: str, parametres: tuple[Any, ...]) -> Any:
    try:
        return await fetch_one(requete, parametres)
    except psycopg_errors.UndefinedTable as erreur:
        raise _schema_facial_absent() from erreur


def _gestes_exiges() -> list[str]:
    """Gestes réclamés par la configuration, tels qu'ils sont journalisés."""
    gestes: list[str] = []
    if FACE_REQUIRE_BLINK:
        gestes.append("clignement")
    if FACE_REQUIRE_TURN:
        gestes.append("rotation")
    return gestes


def _litteral_vecteur(gabarit: Sequence[float]) -> str:
    """Forme textuelle acceptée par le type `vector` de PostgreSQL."""
    return json.dumps([round(float(valeur), 8) for valeur in gabarit])


def _descripteur_depuis_base(valeur: Any) -> tuple[float, ...]:
    """Relit un gabarit quel que soit le type rendu par le pilote."""
    if isinstance(valeur, str):
        contenu = valeur.strip()
        contenu = contenu[1:-1] if contenu.startswith("[") else contenu
        return tuple(float(item) for item in contenu.split(",") if item)
    if isinstance(valeur, (list, tuple)):
        return tuple(float(item) for item in valeur)
    raise DescripteurInvalide("Gabarit illisible en base.")


async def _journaliser_tentative_faciale(
    *,
    user_id: Any,
    username: str,
    outcome: str,
    reason: str,
    distance: float | None = None,
    challenge_ok: bool | None = None,
) -> None:
    await _gabarit_ecrire(
        "INSERT INTO auth.face_attempts "
        "(user_id, username, outcome, reason, distance, threshold, challenge_ok, source_ip) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, NULLIF(%s, '')::inet)",
        (
            user_id,
            username,
            outcome,
            reason,
            distance,
            FACE_MATCH_THRESHOLD,
            challenge_ok,
            current_client_ip(),
        ),
    )


async def _compter_echec(ligne: dict[str, Any]) -> dict[str, Any]:
    """Incrémente le compteur d'échecs du compte, comme le ferait un mot de passe.

    Le verrouillage est partagé entre les deux moyens d'authentification : cinq
    échecs par visage comptent autant que cinq échecs par mot de passe, ce qui
    interdit de transformer le visage en canal moins surveillé.
    """
    await execute(
        "UPDATE auth.users SET failed_attempts = failed_attempts + 1, "
        "locked_until = CASE WHEN failed_attempts + 1 >= %s "
        "THEN now() + make_interval(secs => %s) ELSE locked_until END, "
        "updated_at = now() WHERE id = %s",
        (MAX_FAILED, LOCKOUT_SECONDS, ligne["id"]),
    )
    compteur = await fetch_one(
        "SELECT failed_attempts, locked_until FROM auth.users WHERE id = %s",
        (ligne["id"],),
    )
    return dict(compteur) if compteur is not None else {"failed_attempts": 0, "locked_until": None}


def _refus_facial(
    *,
    code: str,
    titre: str,
    detail: str,
    username: str,
    motif: str,
    method: str = "face",
    **extra: Any,
) -> AppError:
    AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="failure").inc()
    events.warn(
        "auth.attempt",
        message="authentification faciale refusée",
        identity=username,
        outcome="failure",
        reason=motif,
        method=method,
        source_ip=current_client_ip(),
    )
    return AppError(401 if code != "face_not_enrolled" else 404, code, titre, detail, **extra)


@app.get("/face/policy", tags=["authentification"])
async def politique_faciale() -> dict[str, Any]:
    """Paramètres publics du contrôle facial, lus par l'interface.

    L'interface n'écrit aucun seuil en dur : elle lit ici la dimension du
    descripteur, le seuil de distance et l'amplitude attendue par le défi.
    """
    set_route_label("/face/policy")
    return {
        "dimension": DIMENSION_DESCRIPTEUR,
        "threshold": FACE_MATCH_THRESHOLD,
        "min_samples": FACE_ENROLL_MIN_SAMPLES,
        "challenge_min_turn_deg": FACE_CHALLENGE_MIN_TURN_DEG,
        "require_blink": FACE_REQUIRE_BLINK,
        "require_turn": FACE_REQUIRE_TURN,
        "max_failed_attempts": MAX_FAILED,
        "lockout_seconds": LOCKOUT_SECONDS,
        "images_transmitted": False,
    }


@app.post("/face/enroll", tags=["authentification"])
async def enrolement_visage(
    charge: FaceEnrollRequest,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Enregistre le gabarit d'un compte à partir de ses captures d'enrôlement."""
    set_route_label("/face/enroll")
    revendications = await _revendications(authorization)
    est_admin = revendications.get("role") == "admin"
    if charge.username != revendications.get("username") and not est_admin:
        raise forbidden("Un gabarit ne peut être enregistré que pour son propre compte.")

    ligne = await fetch_one(
        "SELECT id, username, role FROM auth.users WHERE username = %s",
        (charge.username,),
    )
    if ligne is None:
        raise not_found("Utilisateur inconnu.")

    captures: list[tuple[float, ...]] = []
    for rang, brut in enumerate(charge.descriptors, start=1):
        try:
            captures.append(valider_descripteur(brut))
        except DescripteurInvalide as exc:
            raise bad_request(
                "face_descriptor_invalid",
                "Descripteur facial invalide",
                f"Capture {rang} refusée : {exc}",
            ) from exc

    if len(captures) < FACE_ENROLL_MIN_SAMPLES:
        raise bad_request(
            "face_enrollment_incomplete",
            "Enrôlement incomplet",
            f"{len(captures)} capture(s) fournie(s), "
            f"{FACE_ENROLL_MIN_SAMPLES} attendues au minimum.",
        )

    try:
        gabarit = gabarit_moyen(captures)
    except DescripteurInvalide as exc:
        raise bad_request(
            "face_descriptor_invalid",
            "Descripteur facial invalide",
            str(exc),
        ) from exc

    await _gabarit_ecrire(
        "INSERT INTO auth.face_templates (user_id, descriptor, capture_count) "
        "VALUES (%s, %s::vector, %s) "
        "ON CONFLICT (user_id) DO UPDATE SET descriptor = EXCLUDED.descriptor, "
        "capture_count = EXCLUDED.capture_count, updated_at = now()",
        (ligne["id"], _litteral_vecteur(gabarit), len(captures)),
    )
    await _auditer(
        action="auth.face.enroll",
        outcome="success",
        actor_id=str(ligne["id"]),
        actor_role=ligne["role"],
        details={"username": ligne["username"], "captures": len(captures)},
    )
    events.emit(
        "auth.face.enrolled",
        identity=ligne["username"],
        captures=len(captures),
        sequential=len(captures) != len(charge.descriptors),
    )
    return {
        "username": ligne["username"],
        "enrolled": True,
        "captures": len(captures),
        "dimension": DIMENSION_DESCRIPTEUR,
        "threshold": FACE_MATCH_THRESHOLD,
    }


@app.post("/face/verify", response_model=TokenPair, tags=["authentification"])
async def verifier_visage(charge: FaceVerifyRequest) -> TokenPair:
    """Compare un descripteur au gabarit du compte et ouvre la session.

    Les refus sont volontairement indiscernables d'un compte à l'autre : ni la
    distance mesurée, ni la présence d'un gabarit ne sont renvoyées en clair, ce
    qui empêche de s'en servir comme oracle de réglage.
    """
    set_route_label("/face/verify")
    ligne = await fetch_one(
        "SELECT id, username, role, locked_until FROM auth.users WHERE username = %s",
        (charge.username,),
    )
    if ligne is None:
        raise _refus_facial(
            code="face_rejected",
            titre="Authentification faciale refusée",
            detail="Visage non reconnu.",
            username=charge.username,
            motif="compte inconnu",
        )

    verrou = ligne.get("locked_until")
    if verrou is not None and verrou > _maintenant():
        AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="locked").inc()
        events.warn(
            "auth.attempt",
            message="compte verrouillé",
            identity=charge.username,
            outcome="locked",
            method="face",
            source_ip=current_client_ip(),
        )
        raise AppError(
            423,
            "account_locked",
            "Compte temporairement verrouillé.",
            f"Nouvelle tentative possible après {verrou.isoformat()}.",
        )

    try:
        presente = valider_descripteur(charge.descriptor)
    except DescripteurInvalide as exc:
        raise bad_request(
            "face_descriptor_invalid",
            "Descripteur facial invalide",
            str(exc),
        ) from exc

    defi_valide, motif_defi = evaluer_defi(
        clignement=charge.challenge.blink,
        rotation_degres=charge.challenge.turn_deg,
        seuil_rotation_degres=FACE_CHALLENGE_MIN_TURN_DEG,
        exiger_clignement=FACE_REQUIRE_BLINK,
        exiger_rotation=FACE_REQUIRE_TURN,
    )

    gabarit = await _gabarit_lire(
        "SELECT descriptor::text AS descriptor FROM auth.face_templates WHERE user_id = %s",
        (ligne["id"],),
    )
    if gabarit is None:
        await _journaliser_tentative_faciale(
            user_id=ligne["id"],
            username=ligne["username"],
            outcome="denied",
            reason="aucun gabarit enregistré",
            challenge_ok=defi_valide,
        )
        await _auditer(
            action="auth.face.verify",
            outcome="denied",
            actor_id=str(ligne["id"]),
            actor_role=ligne["role"],
            details={"reason": "aucun gabarit", "method": "face"},
        )
        raise AppError(
            404,
            "face_not_enrolled",
            "Aucun gabarit facial",
            "Aucun gabarit n'est enregistré pour ce compte.",
        )

    reference = _descripteur_depuis_base(gabarit["descriptor"])
    if len(reference) != DIMENSION_DESCRIPTEUR:
        raise AppError(
            500,
            "face_template_corrupt",
            "Gabarit inexploitable",
            "Le gabarit enregistré n'a pas la dimension attendue.",
        )

    distance = distance_cosinus(reference, presente)

    # Le défi est évalué avant la comparaison : une photo tenue devant la caméra
    # produit un descripteur valide, et c'est le défi qui la distingue d'un
    # visage vivant.
    accepte = defi_valide and distance_acceptee(distance, FACE_MATCH_THRESHOLD)
    if not accepte:
        motif = motif_defi if not defi_valide else "distance au-dessus du seuil"
        compteur = await _compter_echec(ligne)
        await _journaliser_tentative_faciale(
            user_id=ligne["id"],
            username=ligne["username"],
            outcome="failure",
            reason=motif,
            distance=distance,
            challenge_ok=defi_valide,
        )
        await _auditer(
            action="auth.face.verify",
            outcome="failure",
            actor_id=str(ligne["id"]),
            actor_role=ligne["role"],
            details={
                "method": "face",
                "reason": motif,
                "distance": round(distance, 6),
                "threshold": FACE_MATCH_THRESHOLD,
                "challenge_ok": defi_valide,
                "gestes_exiges": _gestes_exiges(),
            },
        )
        tentatives = int(compteur.get("failed_attempts") or 0)
        verrou_pose = compteur.get("locked_until")
        if verrou_pose is not None and verrou_pose > _maintenant():
            detail = f"Compte verrouillé après {tentatives} échec(s)."
        elif not defi_valide:
            # Le seuil du défi est public (voir /face/policy) : le nommer aide
            # l'opérateur à se placer, et n'apprend rien à un attaquant. En
            # revanche la distance au gabarit, elle, n'est jamais renvoyée.
            detail = f"Défi actif non validé : {motif_defi}."
        else:
            detail = "Visage non reconnu."
        return_code = "face_challenge_failed" if not defi_valide else "face_rejected"
        titre = "Défi actif non validé" if not defi_valide else "Authentification faciale refusée"
        raise _refus_facial(
            code=return_code,
            titre=titre,
            detail=detail,
            username=charge.username,
            motif=motif,
            attempts=tentatives,
            max_attempts=MAX_FAILED,
        )

    cle = await cle_active()
    acces, refresh, expiration = _emettre_jetons(ligne, cle["kid"], cle["private_pem"])
    await execute(
        "INSERT INTO auth.refresh_tokens (user_id, token_hash, source_ip, expires_at) "
        "VALUES (%s, %s, NULLIF(%s, '')::inet, to_timestamp(%s))",
        (ligne["id"], hash_token(refresh), current_client_ip(), expiration),
    )
    await execute(
        "UPDATE auth.users SET failed_attempts = 0, locked_until = NULL, "
        "updated_at = now() WHERE id = %s",
        (ligne["id"],),
    )
    await _journaliser_tentative_faciale(
        user_id=ligne["id"],
        username=ligne["username"],
        outcome="success",
        reason="visage reconnu",
        distance=distance,
        challenge_ok=True,
    )
    await _auditer(
        action="auth.face.verify",
        outcome="success",
        actor_id=str(ligne["id"]),
        actor_role=ligne["role"],
        details={
            "method": "face",
            "distance": round(distance, 6),
            "threshold": FACE_MATCH_THRESHOLD,
            "kid": cle["kid"],
        },
    )
    AUTH_ATTEMPTS_TOTAL.labels(service="api-auth", outcome="success").inc()
    events.emit(
        "auth.attempt",
        identity=ligne["username"],
        outcome="success",
        role=ligne["role"],
        method="face",
        distance=round(distance, 6),
        source_ip=current_client_ip(),
    )
    return TokenPair(
        access_token=acces,
        refresh_token=refresh,
        expires_in=ACCESS_TTL,
        kid=cle["kid"],
    )


@app.get("/face/status/{username}", tags=["authentification"])
async def statut_gabarit(
    username: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """Indique si un gabarit existe, sans jamais exposer le descripteur."""
    set_route_label("/face/status")
    revendications = await _revendications(authorization)
    if revendications.get("username") != username and revendications.get("role") != "admin":
        raise forbidden("Le statut d'un gabarit se consulte pour son propre compte.")

    ligne = await _gabarit_lire(
        "SELECT t.capture_count, t.created_at, t.updated_at "
        "FROM auth.face_templates t JOIN auth.users u ON u.id = t.user_id "
        "WHERE u.username = %s",
        (username,),
    )
    commun: dict[str, Any] = {
        "username": username,
        "dimension": DIMENSION_DESCRIPTEUR,
        "threshold": FACE_MATCH_THRESHOLD,
        "min_samples": FACE_ENROLL_MIN_SAMPLES,
        "challenge_min_turn_deg": FACE_CHALLENGE_MIN_TURN_DEG,
    }
    if ligne is None:
        return {**commun, "enrolled": False, "captures": 0, "updated_at": None}
    return {
        **commun,
        "enrolled": True,
        "captures": ligne["capture_count"],
        "updated_at": ligne["updated_at"].isoformat(),
    }


@app.delete("/face/template/{username}", tags=["administration"])
async def supprimer_gabarit(
    username: str,
    x_admin_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """Retire un gabarit : l'accès au tableau de bord redevient mot de passe seul."""
    set_route_label("/face/template")
    _exiger_admin(x_admin_token)
    resultat = await _gabarit_ecrire(
        "DELETE FROM auth.face_templates t USING auth.users u "
        "WHERE u.id = t.user_id AND u.username = %s",
        (username,),
    )
    if resultat == 0:
        raise not_found("Aucun gabarit enregistré pour ce compte.")
    await _auditer(
        action="auth.face.template_deleted",
        outcome="success",
        actor_role="remediation",
        details={"username": username, "templates_deleted": resultat},
    )
    events.warn(
        "auth.face.template_deleted",
        message="gabarit facial supprimé",
        identity=username,
    )
    return {"username": username, "deleted": resultat}


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
        "SELECT t.id, t.user_id, u.role FROM auth.refresh_tokens t "
        "JOIN auth.users u ON u.id = t.user_id "
        "WHERE t.source_ip = NULLIF(%s, '')::inet AND t.revoked_at IS NULL",
        (charge.source_ip,),
    )
    jetons_revoques = 0
    comptes_verrouilles = 0
    comptes_epargnes: list[str] = []
    async with _transaction() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE auth.refresh_tokens SET revoked_at = now(), "
                "revoked_reason = %s WHERE source_ip = NULLIF(%s, '')::inet "
                "AND revoked_at IS NULL",
                (charge.reason, charge.source_ip),
            )
            jetons_revoques = cur.rowcount or 0
            # Les comptes d'exploitation sont epargnes par le verrouillage.
            #
            # Cette action est pilotee par une *adresse*, et derriere Docker
            # Desktop tous les clients d'un meme poste partagent celle de la
            # passerelle : l'adresse n'identifie plus personne. Verrouiller un
            # compte operator, auditor ou admin sur ce critere revient a couper
            # l'operateur qui surveille l'incident, sans rien retirer a
            # l'attaquant. La revocation des jetons reste appliquee, elle.
            verrouillables = sorted(
                {
                    str(ligne["user_id"])
                    for ligne in lignes
                    if str(ligne["role"]) not in ROLES_EXPLOITATION
                }
            )
            comptes_epargnes = sorted(
                {
                    str(ligne["user_id"])
                    for ligne in lignes
                    if str(ligne["role"]) in ROLES_EXPLOITATION
                }
            )
            if verrouillables:
                await cur.execute(
                    "UPDATE auth.users SET locked_until = now() + make_interval(secs => %s), "
                    "updated_at = now() WHERE id = ANY(%s::uuid[])",
                    (LOCKOUT_SECONDS, verrouillables),
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
            "accounts_spared": len(comptes_epargnes),
        },
    )
    events.warn(
        "auth.tokens.revoked",
        message="jetons révoqués par adresse source",
        source_ip=charge.source_ip,
        tokens_revoked=jetons_revoques,
        accounts_locked=comptes_verrouilles,
        accounts_spared=len(comptes_epargnes),
    )
    return {
        "source_ip": charge.source_ip,
        "refresh_tokens_revoked": jetons_revoques,
        "accounts_locked": comptes_verrouilles,
        "accounts_spared": len(comptes_epargnes),
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
    if not 0.0 < FACE_MATCH_THRESHOLD < 2.0:
        raise bad_request(
            "config_invalide",
            "Configuration invalide",
            "Le seuil facial doit être strictement compris entre 0 et 2.",
        )
    if FACE_ENROLL_MIN_SAMPLES < 1:
        raise bad_request(
            "config_invalide",
            "Configuration invalide",
            "Le nombre minimal de captures d'enrôlement doit être au moins 1.",
        )
    if FACE_CHALLENGE_MIN_TURN_DEG <= 0:
        raise bad_request(
            "config_invalide",
            "Configuration invalide",
            "La rotation minimale du défi actif doit être strictement positive.",
        )
    if not FACE_REQUIRE_BLINK and not FACE_REQUIRE_TURN:
        raise bad_request(
            "config_invalide",
            "Configuration invalide",
            "Le défi actif doit exiger au moins un geste, clignement ou rotation : "
            "sans geste, il ne distingue plus un visage vivant d'une photographie.",
        )


_verifier_coherence()
