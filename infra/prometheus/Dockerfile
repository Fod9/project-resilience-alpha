# AlphaPay : Prometheus
FROM prom/prometheus:v2.54.1

# La configuration est embarquée dans l'image plutôt que montée depuis l'hôte :
# l'image est alors autoportante et reproductible, et la pile démarre à
# l'identique quel que soit le système hôte (Linux, WSL2, démon Docker distant).
COPY prometheus.yml /etc/prometheus/prometheus.yml
COPY alerts.yml     /etc/prometheus/alerts.yml

# Le contenu doit rester lisible par l'utilisateur `nobody` (uid 65534) sous
# lequel l'image officielle s'exécute.
USER root
RUN chmod 0644 /etc/prometheus/prometheus.yml /etc/prometheus/alerts.yml

USER 65534
EXPOSE 9090
