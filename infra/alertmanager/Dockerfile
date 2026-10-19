# AlphaPay — Alertmanager
FROM prom/alertmanager:v0.27.0

COPY alertmanager.yml /etc/alertmanager/alertmanager.yml.tmpl

# Le fichier conservé dans l'image est un modèle : le secret partagé y figure
# sous la forme d'un marqueur, remplacé au démarrage du conteneur. Aucune image
# ne contient donc de secret.
USER root
RUN chmod 0644 /etc/alertmanager/alertmanager.yml.tmpl

USER 65534
EXPOSE 9093
