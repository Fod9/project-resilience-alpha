# Gouvernance et exploitation — PROJECT RESILIENCE-ALPHA

Plateforme de paiement fictive AlphaPay, réalisée dans le cadre du
workshop national EPSI BAC+5 « PROJECT RESILIENCE-ALPHA : cyber-résilience
et reprise autonome ». Sprint d'ingénierie de quatre jours, soutenance
devant jury le vendredi.

Document de référence pour la gouvernance, la continuité d'activité et
l'exploitation du dispositif. Les faits techniques proviennent des
documents du dépôt (`README.md`, `ARCHITECTURE.md`, `DESIGN.md`) et des
fichiers `infra/policies/` et `infra/playbooks/`. Les procédures d'exploitation
sont détaillées dans `RUNBOOKS.md` et `runbooks/PLAYBOOKS.md`.

---

## 1. Contexte et périmètre

### 1.1 Système étudié

AlphaPay est une **plateforme de paiement fictive** : aucune donnée réelle,
aucun client réel, aucun fonds réel. Les comptes, soldes et transactions
sont générés par initialisation. La valeur métier simulée est traitée comme
si elle était réelle : le grand livre est tenu comptablement de bout en
bout (journal des jambes, soldes recalculables) et son intégrité est
protégée comme un bien à part entière.

Le périmètre d'étude comprend la bordure (reverse proxy nginx, WAF
ModSecurity v3 + OWASP CRS 4), les trois services applicatifs
(authentification, paiement, grand livre) et le front de démonstration,
la pile de détection (détecteur d'anomalies, supervision Prometheus,
détection runtime Falco, Alertmanager), le moteur de remédiation autonome
et ses connecteurs (proxy d'administration Docker, coffre de secrets), la
salle d'opérations (Grafana, Loki, dashboards) et la base PostgreSQL
unique, avec un rôle par service au moindre privilège.

La pile compte **23 conteneurs** sur **5 réseaux Docker cloisonnés**
(`net-edge`, `net-app`, `net-data`, `net-obs`, `net-mgmt`), dont **trois
strictement internes** (`net-data`, `net-obs`, `net-mgmt`). Seuls la bordure
(port 443) et, en profil de démonstration, les accès Grafana/Prometheus
(3000, 9090) sont exposés au poste hôte.

### 1.2 Valeurs métier

| Valeur | Définition | Priorité |
|--------|------------|----------|
| VM1 — Intégrité des opérations | Un paiement enregistré est complet, cohérent, conforme au double effet ; le grand livre n'est jamais incohérent. | 1 |
| VM2 — Confidentialité des identités et données | Identifiants, jetons, clés et données de compte ne sont pas exposés à des tiers non autorisés. | 1 |
| VM3 — Disponibilité du paiement | Le client peut authentifier une session et solder un paiement dans un délai raisonnable. | 2 |

VM1 et VM2 priment sur VM3 : en cas de conflit, le système préfère refuser
une transaction à en exécuter une dont l'intégrité ou la légitimité n'est
pas établie.

### 1.3 Contraintes

1. **Durée limitée à quatre jours** : le dispositif est dimensionné pour
   être démontrable et non exploité en production ; chaque choix est arbitré
   à l'aune de « ce qui peut être construit, prouvé et défendu en quatre
   jours ».
2. **Exigence de reprise autonome** : détecter, se remédier sans
   intervention humaine, prouver le rétablissement (MTTD < 60 s, MTTR <
   180 s). Chaque action du moteur est vérifiée par une suite de contrôles ;
   la main est rendue à l'humain seulement si les preuves de
   rétablissement ne sont pas réunies.

---

## 2. Analyse de risques — EBIOS Risk Manager

Démarche EBIOS RM en deux temps : socle (valeurs métier, biens supports,
événements redoutés, sources de risque, scénarios stratégiques) puis volet
opérationnel (scénarios d'incident, matrice de risques, mesures).

### 2.1 Socle

**Biens supports des valeurs métier**

| Bien | Valeurs |
|------|---------|
| Grand livre et journal des jambes (PostgreSQL) | VM1 |
| Clé de signature RS256 | VM1, VM2 |
| Jetons d'accès et de rafraîchissement | VM2 |
| Comptes clients et soldes | VM1, VM2 |
| Bordure (edge + WAF) | VM2, VM3 |
| Moteur de remédiation et connecteurs | VM1, VM2, VM3 (délégation) |
| Chaîne de supervision (Prometheus, Alertmanager) | VM3 |
| Stockage des secrets (Vault, dépôts chiffrés sops+age) | VM2 |

**Événements redoutés** — ER1 indisponibilité du paiement (volume hostile saturant la capacité) ; ER2 indépendance d'identité compromise (identifiants brouillés, jetons ou clé usurpés) ; ER3 compromission d'intégrité des données (injection, écriture non autorisée, exfiltration) ; ER4 altération du grand livre (solde incohérent) ; ER5 perte d'observation (attaque ou panne sans détection).

**Sources de risque** — SR1 attaquant externe automatisé (scripts contre la bordure exposée, A1/A2/A3) ; SR2 défaut applicatif (fuite, blocage, déséquilibre comptable) ; SR3 compromission d'un conteneur interne (charge utile détectée par Falco) ; SR4 défaillance de la chaîne de détection ; SR5 erreur du dispositif de remédiation (blocage d'une adresse légitime) ; SR6 faiblesse d'hygiène (durcissement incomplet, secret mal distribué, dérive de configuration).

**Scénarios stratégiques** — SS1 saturation et déni de service (SR1 -> ER1) ; SS2 usurpation d'identité de masse (SR1 -> ER2) ; SS3 compromission applicative (SR1/SR3 -> ER3) ; SS4 dégradation silencieuse (SR2 -> ER4) ; SS5 aveuglement (SR4 -> ER5) ; SS6 dérive de sécurité (SR6 -> ER2/ER3).

### 2.2 Scénarios opérationnels

| Réf. | Scénario | Scénario stratégique | Déroulement |
|------|----------|----------------------|-------------|
| A1 | Rafale volumétrique (déni de service) | SS1 | Volumétrie très au-dessus de la pointe légitime, forte proportion d'erreurs, latence en pic. |
| A2 | Bourrage d'identités / rotation de clé de signature | SS2 | Échecs d'authentification massifs depuis une même origine, essai sur de nombreuses identités distinctes. |
| A3 | Injection applicative et tentative d'exfiltration | SS3 | Charges utiles hostiles bloquées par le WAF, volume sortant anormal. |
| O1 | Service applicatif indisponible | SS4 | Conteneur hors ligne ; redémarrage contrôlé puis preuve fonctionnelle. |
| O2 | Invariant comptable rompu | SS4 | Déséquilibre du grand livre ; instantané puis recalcul depuis le journal des jambes. |
| O3 | Exécution suspecte dans un conteneur | SS3 | Shell ou écriture binaire détectée par Falco ; quarantaine réseau. |

### 2.3 Matrice de risques

Probabilité (P) et gravité (G) sur l'échelle 1 à 4 ; niveau = P x G. Les
niveaux 6 et plus exigent une mesure de réduction ; 8 et plus, une mesure
prioritaire. Les limites résiduelles subsistantes sont portées à la section 8.

| Réf. | Risque | P | G | Niveau | Mesure(s) associée(s) |
|------|--------|---|---|--------|------------------------|
| R1 | Rafale volumétrique (A1) | 3 | 3 | 9 | WAF et rate-limit bordure ; détecteur d'anomalie ; POL-A1-RAFALE / PB-A1 ; redondance par alertes Prometheus |
| R2 | Bourrage d'identifiants (A2) | 3 | 3 | 9 | Surveillance des échecs d'authentification ; rotation de clé (invalide tous les jetons) ; verrouillage temporaire des comptes |
| R3 | Injection / exfiltration (A3) | 2 | 4 | 8 | WAF CRS 4 bloquant ; gel du compte exposé ; réconciliation comptable ; détection runtime Falco |
| R4 | Compromission de la clé de signature | 2 | 4 | 8 | Rotation automatique ; jetons signés par une clé compromise rejetés |
| R5 | Déséquilibre du grand livre (O2) | 2 | 4 | 8 | Journal d'audit en ajout seul garanti par les privilèges SQL ; recalcul depuis le journal des jambes |
| R6 | Perte de disponibilité (O1) | 3 | 2 | 6 | Alertes de disponibilité ; redémarrage contrôlé avec suite de vérification complète |
| R7 | Exécution malveillante en conteneur (O3) | 2 | 4 | 8 | Conteneurs durcis (read-only, no-new-privileges, sans privilèges) ; quarantaine réseau par Falco |
| R8 | Défaillance du détecteur (SS5) | 2 | 3 | 6 | Deuxième chemin de détection par seuils d'exploitation, indépendant du modèle |
| R9 | Erreur du dispositif de remédiation (SR5) | 2 | 3 | 6 | Couvre-feu, liste blanche d'adresses, TTL obligatoires, mode simulé par défaut, coupe-circuit |
| R10 | Exfiltration de secrets | 2 | 3 | 6 | Secrets chiffrés (sops+age), Vault, interdiction des secrets versionnés, rotation post-incident |

### 2.4 Vue de synthèse des scénarios d'attaque

| Scénario | Objectif de l'attaquant | Signature détectée | Réponse | Confinement |
|----------|-------------------------|--------------------|---------|-------------|
| A1 | Indisponibilité | Trafic très supérieur à la pointe légitime, erreurs élevées, latence en pic | Blocage de l'adresse source, révocation des jetons émis depuis elle, redémarrage du service de paiement, preuve de bout en bout | Oui (bordure) |
| A2 | Usurpation d'identité | Échecs d'authentification massifs, nombreuses identités distinctes depuis une origine | Blocage de l'adresse source, révocation des jetons, rotation de la clé de signature, instantané du grand livre, redémarrage du service d'authentification | Oui (bordure) + invalidation des jetons |
| A3 | Vol ou altération de données | Charges d'injection bloquées par le WAF, volume sortant anormal | Blocage de l'adresse source, instantané du grand livre, gel du compte exposé, réconciliation comptable, preuve de bout en bout | Oui (bordure) + gel comptable |

Le moteur opère sur des signalements déjà qualifiés : les politiques sont
évaluées sur des seuils volontairement placés au-dessus de la plage de
trafic nominal mesurée à l'entraînement, afin qu'un pic d'activité légitime
ne déclenche pas de remédiation.

---

## 3. Mesures de sécurité en place

Organisation par couche, en distinguant prévention, détection, réaction.

### 3.1 Bordure

| Type | Mesure |
|------|--------|
| Prévention | WAF ModSecurity v3 + OWASP CRS 4, paranoïa 1, mode bloquant, seuil d'anomalie entrant de 5 ; les charges d'injection et XSS sont rejetées avant les services. |
| Prévention | Limites de débit par adresse IP et par route (authentification, paiement, assistant), durcissables dynamiquement par la remédiation. |
| Prévention | En-têtes de sécurité (HSTS, CSP strict, X-Frame-Options : DENY, etc.) ; certificat TLS interne auto-signé, HTTP redirigé vers HTTPS (limité, section 8). |
| Réaction | Liste de blocage dynamique : fichier relu par la bordure à chaque changement ; un témoin de rechargement horodaté (empreinte de la liste, résultat) est publié et vérifié par le moteur — une règle n'est active que si le rechargement a abouti. |

### 3.2 Couche applicative

| Type | Mesure |
|------|--------|
| Prévention | Jetons RS256 de courte durée (15 minutes), jetons de rafraîchissement révocables et journalisés, verrouillage temporaire des comptes. |
| Prévention | Cinq rôles (client, service, opérateur, auditeur, administrateur) ; chaque API n'accepte que les rôles nécessaires. |
| Prévention | Idempotence obligatoire à la création d'un paiement : une même demande produit au plus un effet. |
| Prévention | Moindre privilège côté données : un rôle PostgreSQL par service ; le journal d'audit de l'authentification est en ajout seul, garanti par l'absence de droits de mise à jour et de suppression sur la table d'audit. |
| Prévention | Conteneurs durcis : images minimales, utilisateur non privilégié, système de fichiers racine en lecture seule, abandon de tous les privilèges, no-new-privileges, limites mémoire/CPU/processus, aucun port publié hors bordure et profils de démonstration. |
| Détection | Compteurs métier exposés (requêtes, erreurs, authentifications, jetons révoqués, déséquilibre comptable), collectés par supervision. |
| Réaction | Gel des comptes exposés : action réversible ; un solde n'est jamais écrit par le dispositif. |

### 3.3 Couche de détection

| Type | Mesure |
|------|--------|
| Détection | Modèle d'anomalie non supervisé (forêt d'isolation) : 18 variables, fenêtre glissante de 60 s, seuil calibré au 99,8e centile du trafic nominal simulé. Le signalement qualifié identifie l'adresse d'origine pressentie, ce qui rend le confinement possible. |
| Détection | Règles d'alerte Prometheus formant le deuxième chemin, indépendant du modèle : neuf règles (anomalie, injection, exfiltration, service indisponible, taux d'erreurs, latence, déséquilibre comptable, événement runtime, WAF, authentification). Ces alertes ne transportent pas d'adresse d'origine : elles remettent en état et vérifient, sans confinement. |
| Détection | Supervision runtime (Falco) : shell dans un conteneur, écriture dans un binaire système, connexion sortante inattendue — comportements à malveillance intrinsèque que le modèle statistique ne qualifie pas. |
| Prévention de la défaillance | Redondance des chemins : les priorités du chemin « modèle » sont supérieures, car il est le plus complet (il sait quelle adresse bloquer). |

### 3.4 Couche de réaction (moteur de remédiation)

| Type | Mesure |
|------|--------|
| Réaction | Dix politiques déclaratives (`infra/policies/`) associant un signalement qualifié à un scénario connu et à un playbook ; sept playbooks (`infra/playbooks/`) dont chaque étape est rattachée à une phase (confinement, éradication, remise en état, vérification) visible dans la salle d'opérations. |
| Prévention de l'erreur | Couvre-feu : 6 actions automatiques maximum par fenêtre de 300 secondes. |
| Prévention | Liste blanche d'adresses non bloquables (poste hôte, postes d'encadrement, réseau d'administration) : le blocage en est refusé et journalisé. |
| Prévention | Délai d'expiration obligatoire sur toute action réversible (900 s par défaut pour un blocage) : un blocage ne devient pas pérenne sans renouvellement. |
| Prévention | Mode simulé (DRY_RUN) actif par défaut ; le mode réel (DEMO_MODE) est affiché en permanence dans la salle d'opérations. |
| Réaction | Coupe-circuit : trois échecs consécutifs d'exécution arrêtent l'automatisation et escaladent vers un opérateur. |
| Réaction | Suite de vérification de six preuves : santé des services ; transaction synthétique de bout en bout ; intégrité comptable (quatre requêtes de contrôle) ; confinement effectif (rejeu depuis l'adresse source refusé) ; absence de dérive d'image (empreinte vérifiée contre la référence) ; intégrité de l'authentification (aucun jeton signé par une clé compromise n'est accepté). Le rétablissement n'est déclaré que si les six preuves passent ; un simple redémarrage ne peut donc pas masquer un échec. |
| Prévention (audit) | Toute action, y compris refusée, est consignée dans le journal opérationnel et poussée dans le journal centralisé avec l'identifiant de suivi. |

### 3.5 Administration et secrets

| Type | Mesure |
|------|--------|
| Prévention | Secrets du dépôt chiffrés (sops + age, clé privée non versionnée) ; coffre de secrets alimenté au démarrage depuis ces dépôts ; injection par variables d'environnement, jamais en arguments de ligne de commande. |
| Prévention | Fichiers d'environnement réels, certificats, jetons : exclus du dépôt et contrôlés par un contrôle à la préversion. |
| Réaction | Rotation des secrets exposés après incident. |
| Limitation | Le coffre fonctionne en mode développement (arbitrage A4, section 7). |

### 3.6 Observation

| Type | Mesure |
|------|--------|
| Détection | Collecte centralisée : journaux des services, journal de bordure du WAF, journal des rechargements, avec champs structurés. |
| Détection | Quatre tableaux de bord : vue d'ensemble, détection et reprise, sécurité (événements runtime, décisions WAF, authentifications refusées), métier. |
| Réaction (information) | Salle d'opérations en temps réel avec repli automatique : état global, étapes du playbook, preuves, lisibles en permanence. |

---

## 4. PCA et PRA

### 4.1 Scénarios de sinistre retenus

Les trois scénarios d'attaque (A1, A2, A3), la défaillance d'un service
applicatif (O1), la rupture de l'invariant comptable (O2), l'exécution
suspecte dans un conteneur (O3), et la défaillance de chaque maillon de la
chaîne de détection — le deuxième chemin doit alors suffire.

### 4.2 Objectifs de reprise par composant

| Composant | RTO | RPO | Justification |
|-----------|-----|-----|---------------|
| Bordure (edge + WAF) | 180 s | Néant | Premier maillon ; le blocage est un fichier relu, sans état durable. |
| Authentification | 180 s | Néant | État dans la base ; la rotation de clé rend les jetons caducs, les clients reconnectent. |
| Paiement | 180 s | Néant | Idempotence : une transaction non soldée est reprenable, sans double effet. |
| Grand livre (PostgreSQL) | 180 s | Néant | Journal d'audit en ajout seul, volume dédié ; les soldes sont recalculables à tout instant. |
| Détecteur d'anomalies | 300 s (dégradé) | Néant | Pendant l'absence du modèle, le chemin Prometheus assure la détection ; le modèle est réentraînable au démarrage si l'artefact est absent. |
| Chaîne de supervision | 300 s (dégradé) | Néant | Pendant son absence, le chemin modèle assure la détection. |
| Moteur de remédiation | 300 s | Néant | Politiques et playbooks sont des fichiers déclaratifs ; il retrouve son état depuis la base. |
| Salle d'opérations (Grafana, Loki) | 24 h (non bloquant) | 24 h | L'exploitation s'appuie sur l'API et les journaux, pas sur le tableau de bord. |

### 4.3 Stratégies de continuité et de reprise

1. **Continuité d'observation d'abord.** Les deux chemins de détection sont
   indépendants : la perte de l'un ne neutralise pas la boucle.
2. **Donnée avant disponibilité.** En cas de doute sur l'intégrité
   comptable, on photographie l'état fautif avant toute écriture, puis on
   recalcule les soldes depuis le journal des jambes ; on ne corrige jamais
   un solde à la main.
3. **Confinement avant remise en service.** Redémarrer sans couper la
   source reviendrait à réadmettre l'attaque ; l'ordre des phases est
   imposé par la structure des playbooks.
4. **Reprise prouvée, pas supposée.** Seul le passage des six preuves
   autorise l'état « rétabli » ; à défaut, deux reprises au plus, puis la
   main est rendue à un opérateur avec l'ensemble du diagnostic.
5. **Retour sans perte.** Les états persistants (base, journaux,
   instantanés, modèle, certificats) vivent sur des volumes dédiés : les
   conteneurs sont remplaçables, les données se restaurent (`RUNBOOKS.md`).
6. **Gouvernance de l'automatisation.** Le dispositif réparateur est lui-même
   borné (couvre-feu, liste blanche, TTL obligatoires, mode simulé par
   défaut, coupe-circuit) : c'est la condition de l'acceptabilité de la
   reprise autonome.

### 4.4 Procédure de retour à la normale

1. Clôture : l'état global redevient « nominal » après la suite de
   vérification ; la salle d'opérations conserve la trace complète
   (signalement, actions, preuves, MTTD/MTTR).
2. Blocage de bordure : la règle expire d'elle-même à son échéance (900 s
   par défaut) ; une levée anticipée suit la procédure de `RUNBOOKS.md`
   (retirer la règle, vérifier le témoin de rechargement).
3. Gels comptables : un compte gelé par un playbook reste gelé jusqu'à
   décision humaine — la seule étape qui exige l'humain.
4. Analyse d'après-incident : rapport archivé (politique, playbook,
   actions, preuves, délais) ; journaux conservés.
5. Action corrective le cas échéant, tracée dans la matrice de risques.

### 4.5 Sauvegarde et restauration

Les instantanés du grand livre sont produits automatiquement par les
playbooks avant toute manipulation d'état, et déposés dans un volume
dédié ; la procédure complète est documentée dans `RUNBOOKS.md`
(procédure R7). En cas de perte du volume de base, la restauration s'appuie
sur un dump horodaté conservé hors du dépôt.

### 4.6 Rôles d'exploitation

| Rôle | Responsabilité |
|------|----------------|
| Opérateur de permanence | Surveille la salle d'opérations ; traite les escalades (quarantaines, échecs de reprise répétés) ; lève les gels après contrôle. |
| Ingénieur sécurité | Exploite les rapports d'incident ; met à jour politiques et seuils ; pilote la rotation des secrets et des clés. |
| Responsable de la plateforme | Redémarrages hors moteur ; valide les restaurations ; porte le PCA/PRA devant la direction. |

---

## 5. Mise en regard NIS2

Le règlement (UE) 2022/2555 s'applique aux prestataires de services de
paiement. Le tableau fait le lien entre chaque exigence pertinente et le
dispositif ; les points « non démontrables » sont ceux qu'un exercice de
quatre jours ne peut pas établir — listés tels quels, sans être présentés
comme couverts.

| Exigence NIS2 | Couverture | Comment |
|---------------|-----------|---------|
| Gestion des risques (art. 21, p) | Oui | Analyse EBIOS RM (section 2), matrice de risques, arbitrages documentés (section 7). |
| Politiques de sécurité (art. 21, a) | Oui | Mesures formalisées par couche (section 3) ; politiques et playbooks déclaratifs sous contrôle de version. |
| Procédures de traitement des incidents (art. 21, c) | Oui | Boucle détection-remédiation-vérification complète ; rapports d'incident automatisés ; escalade humaine si les preuves manquent. |
| Continuité et gestion des crises (art. 21, d) | Partiel | PCA/PRA avec RTO/RPO par composant (section 4), reprise prouvée sur les trois scénarios et les pannes ordinaires. Non démontrable : continuité sur sinistre prolongé, plans de repli de la direction. |
| Chaînes d'approvisionnement (art. 21, g) | Partiel | Images de base identifiées, empreintes d'image vérifiées contre référence (contrôle de dérive), dépendances versionnées. Non démontrable : diligence envers les fournisseurs tiers, mises à jour en continu. |
| Cryptographie et secrets (art. 21, h) | Partiel | Secrets chiffrés au dépôt, coffre, rotation post-incident, jetons à courte durée, clé de signature rotative. Non démontrable : chaîne de certificats de confiance externe, cycle de vie complet. |
| Formation et sensibilisation (art. 21, k) | Non démontrable | Hors périmètre d'un sprint de quatre jours ; la traçabilité intégrale du moteur en facilite la mise en place. |
| Assurances cyber (art. 21, l) | Non démontrable | Pilotage financier, hors périmètre technique de l'exercice. |
| Notification des incidents (art. 23) | Non démontrable | Le dispositif produit le MTTD et le rapport qui alimenteraient la notification ; la capacité organisationnelle de notifier en 24 h puis 72 h n'est pas testée. |
| Vérifications périodiques (art. 21, n) | Partiel | Vérifications de bout en bout automatisées, rejeuables à la demande. Non démontrable : calendrier de tests sur le long terme. |

Synthèse : la matière technique des articles 21 et 23 est couverte
(mesures, incidents, continuité, secrets, approvisionnement au niveau des
images) ; les dimensions organisationnelles (formation, assurance,
notification dans les délais, audits périodiques) ne peuvent pas être
certifiées par un workshop.

---

## 6. Mise en regard DORA

Le règlement (UE) 2022/2554 est directement applicable au prestataire de
paiement. Exigences de résilience opérationnelle numérique et rapport au
dispositif :

| Exigence DORA | Rapport au dispositif |
|---------------|----------------------|
| Inventaire des systèmes d'information critiques (art. 6) | Le dispositif fournit l'inventaire par conteneur, réseau et volume (23 conteneurs, 5 réseaux dont 3 internes) ; les systèmes critiques se distinguent : bordure, trois services applicatifs, base, chaîne de détection. |
| Évaluation des risques ICT (art. 8) | L'analyse EBIOS RM (section 2) est la méthode retenue. DORA exige qu'elle tienne compte des fournisseurs essentiels et de la concentration : la concentration (base unique, modèle unique) est un risque identifié, traité par la redondance des chemins de détection et la reproductibilité du modèle. |
| Incidents ICT : classification et notification (art. 19) | Pour chaque incident, le moteur produit la gravité, la politique déclenchée, les actions, le MTTD/MTTR et l'état final — la matière première d'une notification. La classification « incident majeur » et les canaux vers l'autorité compétente relèvent de l'organisation. |
| Tests et exercices (art. 24-25) | Le banc offensif borné (A1, A2, A3 ; durée et volume plafonnés, refus de cibler une adresse hors périmètre autorisé, marquage horodaté) est l'équivalent miniature d'un exercice type TLPT : il rejoue les scénarios de manière reproductible et bornée. Un TLPT complet (adversaire habilité, non annoncé) est hors portée du sprint. |
| Exigences de résilience (art. 16-23) | Le dispositif matérialise l'identification des systèmes critiques (section 4.2), les plans de continuité et de reprise (section 4.3), la tolérance à la défaillance d'une chaîne de détection (section 3.3) et la protection de la continuité des données (journal en ajout seul, instantanés du grand livre, restauration documentée). |
| Transparence et supervision | Les preuves de rétablissement (V1 à V6) et les rapports d'incident automatisés sont des artefacts auditables, alignés sur l'attente DORA de justifier la résilience face à l'autorité de contrôle. |

Synthèse : sur le périmètre technique (inventaire, évaluation des risques,
plans, tests, preuves), le dispositif est construit pour être conforme ;
sur le périmètre organisationnel (comités, cycles de revue, notification
réglementaire, fournisseurs critiques), le workshop produit les artefacts
qui alimenteront cette gouvernance.

---

## 7. Arbitrages explicites

Chaque arbitrage est formulé : option retenue / option écartée / motif /
conséquence assumée.

**A1 — Modèle d'anomalie non supervisé.** Retenu : forêt d'isolation, 18
variables, fenêtre de 60 s, seuil au 99,8e centile du trafic nominal
simulé. Écarté : classifieur supervisé sur attaques réelles. Motif : en
quatre jours aucun corpus d'attaques réelles n'existe ; le non supervisé
n'attend que le trafic nominal produit par le banc de simulation et borne
les faux positifs (zéro sur 30 minutes de trafic nominal). Conséquence
assumée : le modèle signale l'écart à la norme sans « comprendre » l'attaque ;
la qualification est déléguée aux politiques — séparation assumée entre
détection et décision.

**A2 — Redondance de détection à capacités inégales.** Retenu : deux
chemins inégaux par conception — le chemin modèle identifie l'adresse
d'origine (peut confiner) ; le chemin alertes Prometheus ne transporte pas
d'adresse (remet en état, vérifie, sans confinement). Écarté : un seul
chemin, ou deux chemins de capacités égales. Motif : la tolérance à la
panne exige la redondance ; équilibrer les capacités aurait coûté le
transport de la source dans chaque alerte sans bénéfice. Conséquence
assumée : si seul le chemin alertes fonctionne, le service est remis en
état mais la source n'est pas coupée — l'attaque peut reprendre ; risque
explicitement porté.

**A3 — Rotation de clé plutôt que révocation un à un (réponse à A2).**
Retenu : rotation de la clé RS256, qui invalide instantanément tous les
jetons émis sans énumération. Écarté : révocation jeton par jeton. Motif :
en cas de compromission on ne sait pas quels jetons émis sont volés ; les
invalider tous est la seule réponse sûre, coût borné. Conséquence assumée :
tout client est déconnecté, pas seulement l'attaquant ; un jeton conservé
par l'attaquant reste valide jusqu'à sa courte expiration (15 minutes),
mitigé par la durée de vie courte et par la rotation elle-même.

**A4 — Coffre de secrets en mode développement.** Retenu : Vault en mode
développement, scellé au plus juste, alimenté au démarrage depuis les
dépôts chiffrés du dépôt. Écarté : coffre haute disponibilité (mode
production, sauvegardes de la racine, audit complet). Motif : un sprint de
quatre jours ne permet pas de dimensionner un coffre de production ; le
mode développement suffit à prouver la mécanique (distribution, rotation).
Conséquence assumée : les secrets ne survivraient pas au conteneur du
coffre ; en production, le mode doit être levé.

**A5 — Blocage d'adresse par fichier relu, avec témoin.** Retenu : le
moteur écrit la liste de blocage dans un volume partagé ; un surveillant
de la bordure détecte le changement, relance le rechargement de la
configuration nginx et publie un témoin horodaté (empreinte, résultat) que
le moteur relit pour vérifier que la règle est réellement active. Écarté :
accès privilégié du moteur au conteneur de bordure (rechargement direct).
Motif : la bordure doit rester hermétique aux composants internes ; le
volume partagé avec témoin préserve ce principe et élimine l'écueil de
supposer qu'un fichier écrit est une règle appliquée. Conséquence assumée :
le blocage met quelques secondes à se propager (test, rechargement), délai
compté dans les cibles et largement sous les seuils.

**A6 — Journal d'audit en ajout seul, garanti par les privilèges SQL.**
Retenu : la table d'audit d'authentification est en ajout seul pour tous ;
l'absence de droits de mise à jour et de suppression garantit qu'aucun
acteur — pas même un service compromis — ne réécrit l'histoire. Écarté :
contrainte applicative ou droit de suppression réservé à un rôle
d'administration. Motif : une contrainte dans le code est contournable si
le code est compromis ; un droit SQL absent ne l'est pas. Conséquence
assumée : la table croît sans borne ; en production, un archivage
horodaté serait ajouté sans ouvrir de droit de suppression.

**A7 — Gel plutôt que correction automatique des soldes.** Retenu : en cas
d'exposition comptable (A3), le dispositif gèle le compte exposé et
recalcule les soldes depuis le journal des jambes ; il n'écrit jamais un
solde « corrigé ». Écarté : correction automatique des soldes incohérents.
Motif : écrire dans les comptes sans jugement humain sur la cause serait
une action irréversible de trop pour une automatisation ; le journal des
jambes fait autorité, le recalcul est réversible et prouvable. Conséquence
assumée : le compte gelé reste bloqué pour son titulaire jusqu'à décision
humaine — le seul point de la boucle qui exige l'humain.

**A8 — Assistant local de quelques milliards de paramètres, non affiné.**
Retenu : inférence embarquée, sans affinement, interface de
questionnement sur la documentation. Écarté : affinement sur le corpus ou
accès direct aux données opérationnelles. Motif : l'affinement coûte plus
qu'un sprint ; l'accès aux données opérationnelles élargirait la surface
d'attaque sans bénéfice démontrable. Conséquence assumée : les réponses
peuvent contenir des inexactitudes ; l'assistant est un aide-mémoire, pas
une source de décision — les décisions s'appuient sur les données
mesurées du dispositif.

---

## 8. Limites du dispositif et recommandations à la direction

### 8.1 Limites structurelles

1. **Coffre de secrets en mode développement** (A4) : les secrets ne
   survivent pas à la perte du conteneur du coffre.
2. **Certificats auto-signés** : un intermédiaire malveillant ne serait
   pas détecté sans import de l'autorité locale.
3. **Validité résiduelle d'un jeton compromis** (A3) : jusqu'à rotation
   de clé ou expiration (15 minutes), un jeton émis reste valide.
4. **Borne du confinement par adresse** (A2) : un attaquant opérant
   depuis des adresses diffuses y échappe ; le chemin « alertes » n'a pas
   cette capacité.
5. **Modèle non affiné** (A1, A8) : la détection par écart à la norme ne
   distingue pas intention malveillante et simple anomalie ; la
   qualification est déléguée aux politiques et aux seuils.
6. **Périmètre d'un exercice** : la résistance à un adversaire non borné,
   persistant ou coordonné n'est pas démontrée.
7. **Base unique, point de concentration** : la perte totale est couverte
   par la restauration documentée, pas par une réplication active.

### 8.2 Recommandations à la direction, hiérarchisées

**Priorité 1 — lever les risques résiduels**

1. Coffre de secrets en mode production (repli des clés racine, accès
   audités, sauvegardes), en conservant les dépôts chiffrés comme point de
   départ.
2. Certificat émis par une autorité externe, rotation automatisée ;
   autorité interne conservée en repli.
3. Réplication active de la base pour abaisser le RPO du grand livre sous
   la restauration documentée.
4. Confinement au-delà de l'adresse IP (reconnaissance d'identité, scores
   de confiance) pour couvrir les attaques depuis des adresses diffuses.

**Priorité 2 — consolider la détection**

5. Recalibrage périodique du seuil sur le trafic réel, avec suivi des
   faux positifs et procédure documentée.
6. Contrôle des connexions sortantes (proxy d'égress avec liste blanche)
   pour réduire l'incertitude sur l'exfiltration, aujourd'hui mesurée par
   le volume sortant seul.
7. Industrialisation des tests de reprise : rejouer A1, A2, A3 et O1/O2 à
   chaque mise à jour, mêmes critères de sortie (MTTD < 60 s, MTTR < 180 s,
   six preuves).

**Priorité 3 — étendre la gouvernance**

8. Matrice de risques transformée en registre vivant : revue trimestrielle,
   propriétaires par risque, traçabilité des mesures.
9. Formalisation de l'astreinte : planning, canal de notification,
   délégations ; l'humain couvre les exceptions (quarantaines, gels
   comptables, échecs de reprise répétés).
10. Exercice d'intrusion (annoncé puis non annoncé) en sortie de workshop
    pour transformer la démonstration bornée en validation d'adversaire.
11. Intégration au circuit NIS2/DORA : désignation des systèmes critiques,
    articulation avec les obligations de notification, dossier de
    justification pour l'autorité de contrôle (rapports d'incident, preuves
    V1-V6, RTO/RPO).

### 8.3 Position synthétique

Le dispositif prouve, en quatre jours, que la boucle
détection-remédiation-vérification tient : MTTD < 60 s, MTTR < 180 s,
reprise autonome sur les trois scénarios d'attaque, intégrité comptable
préservée après incident. Les limites de la section 8.1 en marquent les
frontières exactes ; la recommandation n'est pas d'attendre, mais de
prolonger, dans l'ordre des priorités, ce que le sprint a rendu
démontrable.

---

*Document de gouvernance — v1.0, produit dans le cadre de PROJECT
RESILIENCE-ALPHA. À relire à chaque évolution du dispositif.*
