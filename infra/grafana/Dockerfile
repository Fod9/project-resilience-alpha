# AlphaPay — Grafana
FROM grafana/grafana:11.2.0

# Sources de données et tableaux de bord sont provisionnés au démarrage : un
# tableau de bord qui doit être importé à la main est un tableau de bord qui
# manquera le jour de la soutenance.
COPY provisioning /etc/grafana/provisioning
COPY dashboards   /var/lib/grafana/dashboards

USER root
RUN chmod -R a+r /etc/grafana/provisioning /var/lib/grafana/dashboards

USER 472
EXPOSE 3000
