# =============================================================================
#  AlphaPay : Interface web
# =============================================================================
#  Construction en deux étapes : la chaîne Node ne sert qu'à produire les
#  fichiers statiques et n'est pas présente dans l'image finale. L'image livrée
#  ne contient qu'un serveur statique et les fichiers compilés.
#
#  Le contexte de construction est la racine du dépôt (voir docker-compose.yml),
#  afin que la commande soit reproductible depuis n'importe quel répertoire.
# =============================================================================

FROM node:22-alpine AS construction

WORKDIR /app

# Les dépendances sont installées dans une couche séparée : tant que
# package.json ne change pas, cette couche reste en cache.
COPY frontend/package.json /app/package.json
RUN npm install --no-audit --no-fund

COPY frontend/tsconfig.json /app/tsconfig.json
COPY frontend/vite.config.ts /app/vite.config.ts
COPY frontend/tailwind.config.js /app/tailwind.config.js
COPY frontend/postcss.config.js /app/postcss.config.js
COPY frontend/index.html /app/index.html
COPY frontend/scripts /app/scripts
COPY frontend/src /app/src

# `npm run build` exécute d'abord la vérification de types : une erreur de
# typage fait échouer la construction de l'image, jamais la démonstration.
RUN npm run build


FROM nginx:1.27-alpine AS livraison

LABEL org.opencontainers.image.title="AlphaPay : Interface web"
LABEL org.opencontainers.image.description="Interface de paiement et salle d'operations"

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=construction /app/dist /usr/share/nginx/html

# Le serveur statique tourne sous l'utilisateur `nginx` de l'image : aucun
# privilège particulier n'est nécessaire pour écouter sur 8080.
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=10s \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
