# =============================================================================
#  AlphaPay : Bordure : WAF applicatif (ModSecurity v3 + OWASP CRS) + reverse proxy
# =============================================================================
#  L'image de base fournit :
#    * nginx compilé avec ngx_http_modsecurity_module ;
#    * ModSecurity v3 et le Core Rule Set OWASP dans /opt/owasp-crs ;
#    * une mécanique de modèles (/etc/nginx/templates) appliquée par envsubst ;
#    * un certificat auto-signé généré au démarrage (/etc/nginx/ssl).
#
#  Nous remplaçons la configuration de site par la nôtre, qui aiguille vers les
#  sept services applicatifs et produit un journal d'accès JSON, et nous
#  ajoutons des règles ModSecurity propres à AlphaPay.
# =============================================================================
FROM owasp/modsecurity-crs:nginx-alpine

LABEL org.opencontainers.image.title="AlphaPay : Bordure WAF"
LABEL org.opencontainers.image.description="WAF applicatif ModSecurity + OWASP CRS, reverse proxy et journalisation JSON"

# L'image s'exécute sous l'utilisateur `nginx` ; les étapes de construction qui
# écrivent dans /etc/nginx exigent temporairement les droits root.
USER root

# La configuration par défaut de l'image ne connaît qu'un seul amont, et
# déclare le WAF au niveau serveur : ces modèles sont retirés au profit des
# nôtres, qui déclarent le WAF au niveau `http` (couverture totale, y compris
# les requêtes rejetées avant tout amont).
RUN rm -f /etc/nginx/templates/conf.d/default.conf.template \
          /etc/nginx/templates/conf.d/logging.conf.template \
          /etc/nginx/templates/conf.d/modsecurity.conf.template

# Le `default.conf` livre par l'image de base reste present dans `conf.d` et son
# `server_name localhost` prend la main des qu'un client vise `localhost` : la
# bordure sert alors la page d'accueil nginx et repond 404 sur `/api/...`, alors
# que `127.0.0.1` atteint normalement l'application. On le neutralise en le
# rendant non selectionnable, plutot qu'en le supprimant : les scripts d'entree
# de l'image le modifient par `sed` et echoueraient sur un fichier absent.
RUN sed -i 's/server_name  localhost;/server_name  __desactive__;/' \
          /etc/nginx/conf.d/default.conf \
 && grep -q '__desactive__' /etc/nginx/conf.d/default.conf

COPY templates/conf.d/alphaplat.conf.template \
     /etc/nginx/templates/conf.d/alphaplat.conf.template

COPY templates/includes/alphapay_locations.conf.template \
     /etc/nginx/templates/includes/alphapay_locations.conf.template
COPY templates/includes/alphapay_proxy_entetes.conf.template \
     /etc/nginx/templates/includes/alphapay_proxy_entetes.conf.template
COPY templates/includes/alphapay_proxy.conf.template \
     /etc/nginx/templates/includes/alphapay_proxy.conf.template

COPY templates/modsecurity.d/modsecurity-override.conf.template \
     /etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template

# Le répertoire de la liste de blocage est un volume nommé (partagé avec le
# moteur de remédiation). nginx tolère un répertoire vide grâce à l'inclusion
# par motif : aucun fichier factice n'est nécessaire.
RUN mkdir -p /etc/nginx/dynamic /usr/local/share/alphapay

# Le répertoire de la liste de blocage est créé ici avec ses droits définitifs.
# Docker recopie en effet la propriété et le mode du répertoire de l'image dans
# un volume nommé vide lors du premier montage : un répertoire root:root 0755
# annulerait le `chown` réalisé par le service `init-perms`, et la bordure ne
# pourrait plus publier son témoin de rechargement.
RUN chown 101:10001 /etc/nginx/dynamic \
 && chmod 0770 /etc/nginx/dynamic

COPY entrypoint/99-blocklist-watcher.sh /docker-entrypoint.d/99-blocklist-watcher.sh
# Les fins de ligne sont normalisees ici, et pas seulement dans le depot : un
# contexte de construction prepare depuis Windows peut livrer ces scripts en
# CRLF, et l'interpreteur cherche alors un fichier dont le nom se termine par un
# retour chariot. Le lancement echoue alors en « not found » et le rechargement
# automatique de la bordure ne fonctionne plus.
RUN sed -i 's/\r$//' /docker-entrypoint.d/99-blocklist-watcher.sh \
 && chmod 0755 /docker-entrypoint.d/99-blocklist-watcher.sh

COPY entrypoint/blocklist-watcher.sh /usr/local/share/alphapay/blocklist-watcher.sh
RUN sed -i 's/\r$//' /usr/local/share/alphapay/blocklist-watcher.sh \
 && chmod 0755 /usr/local/share/alphapay/blocklist-watcher.sh

# Meme raison pour les modeles de configuration nginx : un retour chariot en fin
# de ligne dans la carte de blocage ou dans le format de journal produirait une
# configuration valide en apparence mais fausse a l'usage.
RUN find /etc/nginx/templates -type f -exec sed -i 's/\r$//' {} +

# Retour à l'utilisateur non privilégié de l'image : nginx n'a besoin ni de
# root ni de capacités particulières pour écouter sur 8080 et 8443.
USER nginx

EXPOSE 8080 8443
