#!/usr/bin/env bash
# =============================================================================
#  preflight.sh : contrôles de pré-vol de la pile AlphaPay
# =============================================================================
#  À exécuter sur le poste hôte (Windows + WSL2 ou Linux) AVANT tout démarrage.
#  Vérifie les prérequis matériels et logiciels du sujet, puis la cohérence de
#  la configuration.
#
#  Usage :
#      bash scripts/preflight.sh
#
#  Code de sortie : 0 si tous les contrôles bloquants passent, 1 sinon.
# =============================================================================
set -uo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BLOQUANTS=0
AVERTISSEMENTS=0

ok()    { printf '  [ OK ]   %s\n' "$1"; }
echec() { printf '  [ECHEC]  %s\n' "$1"; BLOQUANTS=$((BLOQUANTS + 1)); }
avert() { printf '  [AVERT]  %s\n' "$1"; AVERTISSEMENTS=$((AVERTISSEMENTS + 1)); }

echo "=== 1. Outils ==="
if command -v docker >/dev/null 2>&1; then
    ok "docker présent ($(docker --version 2>/dev/null | head -1))"
else
    echec "docker introuvable : installer Docker Desktop puis activer l'intégration WSL2"
fi

if docker compose version >/dev/null 2>&1; then
    ok "docker compose v2 présent ($(docker compose version --short 2>/dev/null))"
else
    echec "docker compose v2 indisponible"
fi

if docker info >/dev/null 2>&1; then
    ok "démon Docker joignable"
else
    echec "démon Docker injoignable : démarrer Docker Desktop"
fi

echo "=== 2. Ressources du poste hôte ==="
if command -v nproc >/dev/null 2>&1; then
    COEURS="$(nproc)"
    if [ "$COEURS" -ge 4 ]; then ok "cœurs : $COEURS (minimum 4)"; else echec "cœurs : $COEURS (minimum 4)"; fi
fi

if [ -r /proc/meminfo ]; then
    MEM_GO=$(( $(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024 ))
    if [ "$MEM_GO" -ge 12 ]; then
        ok "mémoire : ${MEM_GO} Go accessibles au conteneur (minimum conseillé 12)"
    else
        echec "mémoire : ${MEM_GO} Go : relever la limite WSL2 dans %UserProfile%\\.wslconfig (memory=12GB)"
    fi
fi

DISPONIBLE_GO=$(( $(df -Pk "$RACINE" | awk 'NR==2 {print $4}') / 1024 / 1024 ))
if [ "$DISPONIBLE_GO" -ge 30 ]; then
    ok "espace disque : ${DISPONIBLE_GO} Go libres (minimum 30)"
else
    echec "espace disque : ${DISPONIBLE_GO} Go libres (minimum 30)"
fi

echo "=== 3. Ports ==="
for port in 80 443 3000 9090; do
    if command -v ss >/dev/null 2>&1; then
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
            if [ "$port" = "80" ] || [ "$port" = "443" ]; then
                avert "port $port déjà occupé : arrêter le service qui l'utilise ou changer EDGE_HTTP_PORT/EDGE_HTTPS_PORT"
            else
                avert "port $port déjà occupé : changer GRAFANA_PORT/PROMETHEUS_PORT"
            fi
        else
            ok "port $port libre"
        fi
    fi
done

echo "=== 4. Configuration ==="
if [ -f "$RACINE/.env" ]; then
    ok ".env présent"
    for cle in POSTGRES_PASSWORD HMAC_SECRET ADMIN_API_TOKEN VAULT_DEV_ROOT_TOKEN \
               GRAFANA_ADMIN_PASSWORD PROBE_PASSWORD; do
        if grep -qE "^${cle}=.+" "$RACINE/.env"; then
            ok "  $cle renseigné"
        else
            echec "  $cle vide dans .env"
        fi
    done
else
    echec ".env absent : exécuter « bash scripts/seed-secrets.sh »"
fi

echo "=== 5. Cohérence de la pile ==="
if docker compose -f "$RACINE/docker-compose.yml" config --quiet >/dev/null 2>&1; then
    ok "docker-compose.yml valide"
else
    echec "docker-compose.yml invalide ou variables manquantes"
fi

if [ -f "$RACINE/ml/artifacts/model.joblib" ]; then
    ok "modèle du détecteur présent (sinon il sera entraîné au démarrage)"
else
    avert "modèle du détecteur absent : entraînement automatique au premier démarrage (~30 s)"
fi

echo
echo "======================================================"
printf 'contrôles bloquants en échec : %d   avertissements : %d\n' "$BLOQUANTS" "$AVERTISSEMENTS"
echo "======================================================"
if [ "$BLOQUANTS" -eq 0 ]; then
    echo "Prêt : « docker compose up -d --build »"
    exit 0
fi
echo "Corriger les points bloquants avant de démarrer."
exit 1
