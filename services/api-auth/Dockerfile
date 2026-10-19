# api-auth — AlphaPay
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Les dépendances sont copiées seules pour que la couche pip reste en cache
# tant que seuls les sources changent.
COPY services/common/requirements.txt /tmp/req-common.txt
COPY services/api-auth/requirements.txt    /tmp/req-service.txt
RUN pip install --no-cache-dir -r /tmp/req-common.txt -r /tmp/req-service.txt \
 && rm -f /tmp/req-common.txt /tmp/req-service.txt

COPY services/common     /app/common
COPY services/api-auth/app  /app/app

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && chown -R 10001:10001 /app

USER 10001
EXPOSE 8000

# Le journal d'accès d'uvicorn est désactivé : les services produisent leurs
# propres événements `http.request` sous forme JSON, exploités par la
# télémétrie et par Loki.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-level", "warning"]
