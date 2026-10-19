# =============================================================================
#  AlphaPay : banc offensif
# =============================================================================
#  Sur le poste hôte du sujet, le banc offensif s'exécute directement depuis le
#  poste attaquant : `python3 alpha_redteam.py --scenario A1 ...`.
#
#  Cette image sert à deux usages complémentaires :
#
#    * rejouer un scénario depuis l'intérieur de la pile, lorsque l'attaque doit
#      provenir d'une adresse distincte de celle du poste de test : cas d'un
#      démon Docker isolé ;
#    * disposer d'un attaquant reproductible, dont l'environnement ne dépend pas
#      de ce qui est installé sur la machine de l'opérateur.
#
#  Elle ne contient que la bibliothèque standard : aucune dépendance à installer.
# =============================================================================

FROM python:3.12-slim

LABEL org.opencontainers.image.title="AlphaPay : banc offensif"
LABEL org.opencontainers.image.description="Scenarios offensifs A1, A2 et A3 du workshop"

WORKDIR /app
COPY alpha_redteam.py /app/alpha_redteam.py

RUN groupadd --gid 10001 attaquant \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin attaquant \
 && chown -R 10001:10001 /app

USER 10001

ENTRYPOINT ["python", "/app/alpha_redteam.py"]
CMD ["--aide"]
