# AlphaPay — Grafana
FROM grafana/grafana:11.2.0

# Sources de données et tableaux de bord sont provisionnés au démarrage : un
# tableau de bord qu'il faut importer à la main est un tableau de bord qui
# manquera le jour de la soutenance.
COPY provisioning /etc/grafana/provisioning

# Les tableaux de bord sont placés sous /etc, et non sous /var/lib/grafana :
# ce dernier est recouvert par le volume persistant de Grafana, qui figerait
# leur contenu à la première initialisation du volume. Une correction du JSON
# n'aurait alors jamais atteint le conteneur.
COPY dashboards /etc/grafana/dashboards

USER root
RUN chmod -R a+r /etc/grafana/provisioning /etc/grafana/dashboards

USER 472
EXPOSE 3000
