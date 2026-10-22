# detector : AlphaPay
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
COPY services/detector/requirements.txt    /tmp/req-service.txt
RUN pip install --no-cache-dir -r /tmp/req-common.txt -r /tmp/req-service.txt \
 && rm -f /tmp/req-common.txt /tmp/req-service.txt

COPY services/common     /app/common
COPY services/detector/app  /app/app

# Le détecteur embarque aussi la fabrique de trafic nominal et l'entraînement :
# si aucun modèle pré-entraîné n'est présent, il l'entraîne lui-même au premier
# démarrage. Cela évite de dépendre d'une étape de construction préalable, au
# prix d'une trentaine de secondes d'initialisation, signalée dans les journaux.
COPY ml/__init__.py       /app/ml/__init__.py
COPY ml/synthetic.py      /app/ml/synthetic.py
COPY ml/train.py          /app/ml/train.py
COPY ml/fenetrage.py      /app/ml/fenetrage.py
COPY ml/selection.py      /app/ml/selection.py
COPY ml/recalibrer.py     /app/ml/recalibrer.py
COPY ml/profils_attaque.py /app/ml/profils_attaque.py
# La calibration sur mesures et sa verification sont embarquees : elles doivent
# pouvoir tourner sur la plateforme elle-meme, depuis le conteneur, sans dépendre
# d'une installation Python sur le poste hôte.
COPY ml/calibrer_sur_mesures.py /app/ml/calibrer_sur_mesures.py
COPY ml/verifier_separation.py  /app/ml/verifier_separation.py
COPY ml/verifier_modele_en_place.py /app/ml/verifier_modele_en_place.py
COPY ml/artifacts         /app/artifacts

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir -p /app/artifacts \
 && chown -R 10001:10001 /app

USER 10001
EXPOSE 8000

# Le journal d'accès d'uvicorn est désactivé : les services produisent leurs
# propres événements `http.request` sous forme JSON, exploités par la
# télémétrie et par Loki.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-level", "warning"]
