FROM python:3.12-slim

LABEL org.opencontainers.image.title="AlphaPay : amont factice (banc d'essai)"

WORKDIR /app
COPY server.py /app/server.py

USER 10001:10001
ENTRYPOINT ["python", "/app/server.py"]
