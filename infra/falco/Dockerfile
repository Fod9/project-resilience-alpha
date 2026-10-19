# AlphaPay — Falco (détection d'exécution)
FROM falcosecurity/falco:0.38.2

# Configuration et règles embarquées : l'image est autoportante, ce qui évite
# tout montage de fichiers hôte et garantit que la politique de détection
# appliquée est exactement celle versionnée dans ce dépôt.
COPY falco.yaml /etc/falco/falco.yaml
COPY rules.d   /etc/falco/rules.d

USER root
RUN chmod 0644 /etc/falco/falco.yaml \
 && chmod -R a+r /etc/falco/rules.d

# L'image officielle exécute Falco en root : l'accès aux appels système
# l'exige, et le conteneur tourne de toute façon en mode privilégié.
