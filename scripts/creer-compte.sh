#!/usr/bin/env bash
# =============================================================================
#  creer-compte.sh : creation d'un compte nominatif sur une pile en service
# =============================================================================
#  Usage :
#      bash scripts/creer-compte.sh <identifiant> [role]
#
#  Role par defaut : operator, le seul utile pour ouvrir le tableau de bord. Les
#  roles acceptes sont ceux du schema : customer, service, operator, auditor,
#  admin.
#
#  Le mot de passe est demande deux fois et jamais passe en argument : un mot de
#  passe en argument finit dans l'historique du shell et dans la liste des
#  processus. Il n'est jamais ecrit sur le disque : il est hache en argon2id par
#  le service d'authentification, et seul le hache part en base.
#
#  Pourquoi ce script existe : le premier demarrage ne pose que les comptes de
#  demonstration d'infra/db/03-seed.sql. Un compte nominatif ne se met pas dans
#  ce jeu de donnees, qui est versionne : il faudrait y ecrire un mot de passe
#  en clair dans Git.
# =============================================================================
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RACINE"

CONTENEUR_AUTH="${CONTENEUR_AUTH:-alphaplat-api-auth}"
CONTENEUR_DB="${CONTENEUR_DB:-alphaplat-postgres}"
BASE="${POSTGRES_DB:-alphapay}"

IDENTIFIANT="${1:-}"
ROLE="${2:-operator}"

if [ -z "$IDENTIFIANT" ]; then
    echo "Usage : bash scripts/creer-compte.sh <identifiant> [role]" >&2
    exit 2
fi

case "$ROLE" in
    customer|service|operator|auditor|admin) ;;
    *)
        echo "Role inconnu : $ROLE" >&2
        echo "Roles acceptes : customer, service, operator, auditor, admin" >&2
        exit 2
        ;;
esac

if [[ ! "$IDENTIFIANT" =~ ^[A-Za-z0-9._-]{3,64}$ ]]; then
    echo "Identifiant invalide : lettres, chiffres, point, tiret et souligne, de 3 a 64 caracteres." >&2
    exit 2
fi

printf 'Mot de passe pour %s : ' "$IDENTIFIANT"
read -rs MOT_DE_PASSE
printf '\nConfirmation : '
read -rs CONFIRMATION
printf '\n'

if [ "$MOT_DE_PASSE" != "$CONFIRMATION" ]; then
    echo "Les deux saisies different." >&2
    exit 1
fi

if [ "${#MOT_DE_PASSE}" -lt 12 ]; then
    echo "Mot de passe trop court : douze caracteres au minimum." >&2
    exit 1
fi

HACHE="$(docker exec "$CONTENEUR_AUTH" python -c "
import sys
from argon2 import PasswordHasher
print(PasswordHasher().hash(sys.argv[1]))
" "$MOT_DE_PASSE")"

docker exec -i "$CONTENEUR_DB" psql -U postgres -d "$BASE" -q \
    -v identifiant="$IDENTIFIANT" \
    -v role="$ROLE" \
    -v hache="$HACHE" <<'SQL'
INSERT INTO auth.users (username, email, password_hash, role)
VALUES (:'identifiant', :'identifiant' || '@alphapay.local', :'hache', :'role')
ON CONFLICT (username) DO UPDATE
   SET password_hash   = EXCLUDED.password_hash,
       role            = EXCLUDED.role,
       failed_attempts = 0,
       locked_until    = NULL,
       is_active       = TRUE,
       updated_at      = now();

SELECT username, role, is_active, locked_until FROM auth.users
 WHERE username = :'identifiant';
SQL

echo
echo "Compte $IDENTIFIANT pret, role $ROLE."
echo "Gabarit facial : ouvrez le tableau de bord, connectez-vous par mot de passe,"
echo "puis bouton Mon visage, huit captures, Enregistrer le gabarit."
echo "Le descripteur est calcule dans le navigateur : aucune photo n'est envoyee."
