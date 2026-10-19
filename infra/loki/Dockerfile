# AlphaPay : Loki
FROM grafana/loki:3.1.1

COPY loki-config.yaml /etc/loki/loki-config.yaml

# Le contenu doit rester lisible au démarrage ; l'utilisateur d'exécution est
# celui de l'image officielle, que l'on ne surcharge pas.
USER root
RUN chmod 0644 /etc/loki/loki-config.yaml

EXPOSE 3100
