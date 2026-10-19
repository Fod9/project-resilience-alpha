# AlphaPay : Promtail
FROM grafana/promtail:3.1.1

COPY promtail-config.yaml /etc/promtail/promtail-config.yaml

USER root
RUN chmod 0644 /etc/promtail/promtail-config.yaml

EXPOSE 9080
