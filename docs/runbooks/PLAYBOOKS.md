# Playbooks et politiques : PROJECT RESILIENCE-ALPHA

Documentation de la couche de réaction autonome du moteur de remédiation :
les **politiques** (`infra/policies/`) qui qualifient un signalement et
choisissent un scénario, et les **playbooks** (`infra/playbooks/`) qui
exécutent une suite d'actions ordonnées pour se remettre en état. Ce
complément à `RUNBOOKS.md` décrit ce que fait le moteur, automatiquement,
sans intervention humaine ; `RUNBOOKS.md` décrit ce que fait l'opérateur.

## Principes de fonctionnement

- **Une politique ne déclare pas une attaque.** Elle n'est évaluée que sur
  un signalement déjà qualifié par le détecteur d'anomalie (chemin « modèle »)
  ou par une alerte d'exploitation Prometheus (chemin « alertes »), ou par
  un événement de détection runtime Falco (chemin « SIEM »). Elle répond à la
  question : « cette situation anormale correspond-elle à un scénario connu,
  et que déclenche-t-on ? »
- **Plusieurs sources, un même signalement.** Chaque politique précise ses
  `sources` : `detector`, `alertmanager` ou `falco`. Les conditions sont
  évaluées en `match: any` : une seule condition remplie suffit.
- **Hiérarchie par priorité.** Quand plusieurs politiques correspondent, la
  plus forte `priority` l'emporte. Les politiques du chemin « modèle » sont
  volontairement prioritaires sur celles du chemin « alertes », car le chemin
  modèle sait quelle adresse bloquer.
- **Anti-boucle par temporisation.** `cooldown_seconds` est le délai minimal
  avant qu'une même politique puisse se redéclencher ; il empêche une
  situation persistante de faire boucler le moteur indéfiniment.
- **Seuils volontairement élevés.** Les seuils sont placés au-dessus de la
  plage de trafic nominal mesurée à l'entraînement (jusqu'à ~36 requêtes/s en
  pointe, ~9 % d'échecs d'authentification ordinaires) : un pic d'activité
  légitime ne doit jamais déclencher de remédiation.
- **Conduite en cas d'échec d'étape.** Chaque étape porte `on_failure` :
  `abort` interrompt le playbook (défaut), `continue` poursuit mais marque
  l'incident en échec, `continue_anyway` poursuit en traitant l'étape comme
  non bloquante. Une étape marquée `critical: true` est une étape clé dont
  l'échec est significatif pour l'état final.
- **Substitution du signalement.** `${event.*}` est résolu depuis le
  signalement déclencheur (`source_ip`, `service`, `container`, `kind`,
  `message`). Le connecteur accepte le nom court d'un service (`api-payment`)
  et le traduit en nom de conteneur (`alphaplat-api-payment`) après contrôle
  du périmètre autorisé.
- **Vérification finale.** `verify.recovery_suite` est exécutée en dernier,
  sur l'état final : c'est la seule à pouvoir conduire l'incident à l'état
  « rétabli ». Le détail des contrôles est défini dans `DESIGN.md`.

### Phases de reprise

| Jeton | Phase | Sens |
|-------|-------|------|
| `CONTAINING` | Confinement | Couper la capacité de nuisance (source, jetons, conteneur) sans détruire les preuves. |
| `ERADICATING` | Éradication | Retirer la cause : rotation de clé, gel de compte, point de retour. |
| `RECOVERING` | Remise en état | Redémarrer, recalculer, attendre un état sain. |
| `VERIFYING` | Vérification | Prouver le rétablissement ; rendre la main à l'humain si besoin. |

### Chemins de détection

| Chemin | Source | Capacité | Confinement |
|--------|--------|----------|-------------|
| Modèle | `detector` | Identifie l'adresse d'origine | Oui |
| Alertes | `alertmanager` | Met en état et vérifie | Non (pas d'adresse transportée) |
| SIEM | `falco` | Quarantaine de conteneur | Oui (quarantaine réseau) |

---

## 1. Politiques de réaction aux anomalies détectées (`infra/policies/10-attaques.yaml`)

Ces trois politiques répondent aux trois scénarios d'attaque du workshop.
Elles s'appuient sur le chemin « modèle » ou « alertes ».

### POL-A3-INJECTION : Injection applicative et tentative d'exfiltration

- **Sévérité / priorité / temporisation :** critical / 300 / 240 s
- **Sources :** detector, alertmanager
- **Déclencheur (l'une des conditions, match any) :**
  - part de charges d'injection `injection_token_ratio >= 0.04`
  - part de charges XSS `xss_token_ratio >= 0.04`
  - part de requêtes bloquées par le WAF `waf_block_ratio >= 0.30`
  - volume sortant anormal `outgoing_bytes_ratio >= 6.0`
- **Playbook :** PB-A3-CONFINER-ET-REPARER
- **Fondement :** priorité la plus haute des trois, car ce scénario suppose
  une compromission avérée ; le WAF a intercepté les charges utiles et c'est
  le volume sortant qui fait craindre une exfiltration.

### POL-A2-IDENTITES : Bourrage d'identifiants ou jetons compromis

- **Sévérité / priorité / temporisation :** critical / 200 / 240 s
- **Sources :** detector, alertmanager
- **Déclencheur (match any) :**
  - part d'échecs d'authentification `auth_failure_ratio >= 0.45`
  - essais par identité `auth_attempts_per_identity >= 12.0`
  - identités distinctes concernées `unique_identities >= 25.0`
- **Playbook :** PB-A2-ROTATION-DE-CLES
- **Fondement :** de nombreux échecs combinés à de nombreuses identités
  distinctes depuis une même origine est la signature d'un bourrage
  d'identifiants ou de l'usage de jetons volés.

### POL-A1-RAFALE : Rafale volumétrique (déni de service)

- **Sévérité / priorité / temporisation :** critical / 100 / 180 s
- **Sources :** detector, alertmanager
- **Déclencheur (match any) :**
  - volumétrie `requests_per_second >= 70.0`
  - part de requêtes en erreur `error_ratio >= 0.45`
  - latence en queue `latency_p99_ms >= 2500.0`
- **Playbook :** PB-A1-CONFINER-ET-REDEMARRER
- **Fondement :** une volumétrie très supérieure à la pointe légitime,
  assortie d'erreurs et d'une latence en pic, caractérise une rafale.

---

## 2. Politiques déclenchées par les alertes Prometheus (`infra/policies/15-alertes.yaml`)

Deuxième chemin de détection. Il matérialise la redondance : si le modèle
d'anomalie est indisponible ou inadapté, les seuils d'exploitation produisent
les mêmes effets. Sa limite assumée est documentée : ces alertes ne
transportent pas d'adresse d'origine, donc **elles remettent le service en
état et le vérifient, sans confinement**.

### POL-ALERTE-INJECTION : Injection confirmée par supervision

- **Sévérité / priorité / temporisation :** critical / 240 / 180 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayInjectionSurge` (part de charges
  d'injection au-dessus du seuil de supervision)
- **Playbook :** PB-ALERTE-REPRISE

### POL-ALERTE-EXFILTRATION : Volume sortant hors tendance

- **Sévérité / priorité / temporisation :** critical / 238 / 180 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayExfiltrationSuspectee` (volume sortant
  hors de la tendance longue)
- **Playbook :** PB-ALERTE-REPRISE
- **Fondement :** le service exposé est redémarré après prise d'un
  instantané, afin qu'aucune donnée incohérente ne survive à l'incident.

### POL-ALERTE-AUTH : Bourrage d'identifiants par supervision

- **Sévérité / priorité / temporisation :** critical / 190 / 180 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayAuthAbuse` (taux d'échec
  d'authentification élevé)
- **Playbook :** PB-ALERTE-REPRISE
- **Fondement :** priorité inférieure à celle de `POL-A2-IDENTITES` : si le
  modèle a déjà qualifié la situation, sa politique : qui sait quelle adresse
  bloquer : reste prioritaire.

### POL-ALERTE-LATENCE : Latence durablement dégradée

- **Sévérité / priorité / temporisation :** warning / 80 / 600 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayLatencyDegraded` (latence p95 du service
  de paiement au-dessus du seuil)
- **Playbook :** PB-ALERTE-REPRISE
- **Fondement :** réponse proportionnée à un incident non critique. Le
  redémarrage est vérifié ; si la dégradation provient d'un état interne
  accumulé, elle disparaît ; sinon la vérification échoue et la main est
  rendue à l'opérateur, ce qui évite de boucler indéfiniment. La forte
  temporisation (600 s) limite l'effet d'un phénomène passager.

---

## 3. Politiques d'exploitation (`infra/policies/20-exploitation.yaml`)

Ces politiques traitent des défaillances ordinaires : service indisponible,
invariant comptable rompu : qui doivent aussi être réparées sans
intervention humaine. Un système qui ne se relève que des attaques n'est
résilient qu'à moitié. L'intégrité comptable y prime sur la disponibilité.

### POL-EXPL-INTEGRITE : Invariant comptable rompu

- **Sévérité / priorité / temporisation :** critical / 260 / 180 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayLedgerImbalance` (déséquilibre du grand
  livre, différent de zéro)
- **Playbook :** PB-INTEGRITE-COMPTABLE

### POL-EXPL-INDISPONIBLE : Service applicatif indisponible

- **Sévérité / priorité / temporisation :** critical / 150 / 120 s
- **Source :** alertmanager
- **Déclencheur (match any) :** règle `AlphaPayServiceDown` (conteneur hors
  ligne) **ou** `AlphaPayErrorRateHigh` (part de requêtes en erreur élevée)
- **Playbook :** PB-REDEMARRAGE-SERVICE
- **Fondement :** une alerte d'exploitation ne suffit pas à déclarer la
  reprise ; la suite de vérification reste exigée.

### POL-EXPL-VERIFICATION : Preuves de rétablissement non réunies

- **Sévérité / priorité / temporisation :** warning / 90 / 120 s
- **Source :** alertmanager
- **Déclencheur :** règle `AlphaPayVerificationFailed` (état `FAILED` du
  moteur, c'est-à-dire ses propres preuves non réunies)
- **Playbook :** PB-REDEMARRAGE-SERVICE
- **Fondement :** quand le moteur signale qu'il n'arrive pas à prouver le
  rétablissement, on redémarre la chaîne de paiement avant d'escalader.

---

## 4. Politiques de détection d'exécution : SIEM (`infra/policies/30-execution.yaml`)

Falco observe les appels système des conteneurs. Ces politiques ne
remplacent pas le détecteur d'anomalies : elles couvrent des comportements
dont la malveillance est intrinsèque (exécution d'un shell dans un conteneur
de service, écriture dans un binaire système) que le modèle statistique n'a
pas vocation à qualifier. **Elles ne bloquent jamais la bordure** : elles
quarantinent le conteneur, la bonne réponse à une exécution suspecte.

### POL-SIEM-CONTAINER : Exécution suspecte dans un conteneur

- **Sévérité / priorité / temporisation :** critical / 250 / 300 s
- **Source :** falco
- **Déclencheur (match any) :** `kind` contenant `Shell`, `Container` ou
  `Privilege`, **ou** `severity == critical`
- **Playbook :** PB-SIEM-CONFINER-CONTENEUR

### POL-SIEM-ECRITURE : Écriture dans un binaire système

- **Sévérité / priorité / temporisation :** critical / 249 / 300 s
- **Source :** falco
- **Déclencheur (match any) :** `kind == Write below binary dir` **ou**
  `kind == Write below etc`
- **Playbook :** PB-SIEM-CONFINER-CONTENEUR

---

## 5. Playbooks de sécurité (`infra/playbooks/10-securite.yaml`)

### PB-A1-CONFINER-ET-REDEMARRER : Confinement d'une rafale et remise en service

- **Déclencheur :** `POL-A1-RAFALE`
- **Vérification finale exigée :** oui
- **Phases traversées :** Confinement → Remise en état → Vérification
- **Actions :**
  1. `bloquer-source` (Confinement) : `edge.block_ip` sur `${event.source_ip}`,
     TTL 900 s, délai 15 s, `abort`, critique. Coupe la source à la bordure,
     sans redémarrage de celle-ci.
  2. `revoquer-jetons` (Confinement) : `auth.revoke_by_source`, délai 15 s,
     `continue_anyway`. Invalide les jetons émis depuis cette adresse.
  3. `redemarrer-paiement` (Remise en état) : `docker.restart` du conteneur
     `alphaplat-api-payment`, grâce 5 s, délai 90 s, `continue`.
  4. `attendre-sante` (Remise en état) : `docker.wait_healthy` sur
     `alphaplat-api-payment`, délai 120 s, `continue`.
  5. `verifier` (Vérification) : `verify.recovery_suite`.
- **Vérification finale :** la suite de vérification de bout en bout
  (santé, transaction synthétique, intégrité comptable, confinement effectif,
  absence de dérive d'image, intégrité de l'authentification).
- **Durée attendue :** ordre de dizaines de secondes ; la phase de
  redémarrage attend au plus ~90 s plus l'attente de santé (~90 s). Le
  confinement précède la remise en service : redémarrer sans bloquer la
  source reviendrait à réadmettre l'attaque.

### PB-A2-ROTATION-DE-CLES : Confinement et remplacement de la clé de signature

- **Déclencheur :** `POL-A2-IDENTITES`
- **Vérification finale exigée :** oui
- **Phases traversées :** Confinement → Éradication → Remise en état → Vérification
- **Actions :**
  1. `bloquer-source` (Confinement) : `edge.block_ip` sur `${event.source_ip}`,
     TTL 1800 s, délai 15 s, `abort`, critique.
  2. `revoquer-jetons` (Confinement) : `auth.revoke_by_source`, délai 15 s,
     `continue_anyway`. Retire les jetons de rafraîchissement issus de cette
     adresse.
  3. `rotation-cle` (Éradication) : `auth.rotate_signing_key`, délai 20 s,
     `abort`, critique. Remplace la clé RS256 : **tous** les jetons émis
     deviennent invalides, sans énumération.
  4. `instantane` (Remise en état) : `ledger.snapshot`, délai 30 s,
     `continue_anyway`. Photographie le grand livre après confinement.
  5. `redemarrer-auth` (Remise en état) : `docker.restart` du conteneur
     `alphaplat-api-auth`, grâce 5 s, délai 90 s, `continue`. Le service
     repart sur la nouvelle clé.
  6. `attendre-sante` (Remise en état) : `docker.wait_healthy` sur
     `alphaplat-api-auth`, délai 120 s, `continue`.
  7. `verifier` (Vérification) : `verify.recovery_suite`.
- **Vérification finale :** suite de vérification complète, dont le contrôle
  qu'aucun jeton signé par une clé compromise n'est accepté.
- **Durée attendue :** la rotation de clé (~20 s) et le redémarrage du
  service d'authentification dominent le budget ; l'ordre de grandeur reste
  compatible avec la cible MTTR < 180 s. Coût assumé : tout client est
  déconnecté, pas seulement l'attaquant, mais le coût (reconnexion) est borné.

### PB-A3-CONFINER-ET-REPARER : Confinement d'une injection et contrôle comptable

- **Déclencheur :** `POL-A3-INJECTION`
- **Vérification finale exigée :** oui
- **Phases traversées :** Confinement → Éradication → Remise en état → Vérification
- **Actions :**
  1. `bloquer-source` (Confinement) : `edge.block_ip` sur `${event.source_ip}`,
     TTL 3600 s, délai 15 s, `abort`, critique.
  2. `instantane` (Confinement) : `ledger.snapshot`, délai 30 s,
     `continue_anyway`. Prend le grand livre immédiatement après
     confinement.
  3. `geler-compte` (Éradication) : `ledger.freeze_account` sur le compte
     exposé (`CUST-000001`, `frozen: true`), délai 20 s, `continue_anyway`.
     Le gel est préféré à la correction automatique d'un solde : on n'écrit
     pas dans les comptes tant qu'un humain n'a pas statué.
  4. `reconcilier` (Remise en état) : `ledger.reconcile`, délai 30 s,
     `continue`. Recalcule les soldes depuis le journal des jambes.
  5. `verifier` (Vérification) : `verify.recovery_suite`.
- **Vérification finale :** intégrité comptable conforme et transaction de
  vérification ; le compte gelé reste gelé en attendant la décision humaine.
- **Durée attendue :** budget dominé par les instantanés et la
  réconciliation (quelques dizaines de secondes). Le gel laisse un état
  qui attend un humain : la seule étape de la boucle qui exige l'intervention
  humaine en aval.

### PB-SIEM-CONFINER-CONTENEUR : Quarantaine d'un conteneur suspect

- **Déclencheur :** `POL-SIEM-CONTAINER` ou `POL-SIEM-ECRITURE`
- **Vérification finale exigée :** non (le rétablissement n'est pas automatique)
- **Phases traversées :** Confinement → Vérification
- **Actions :**
  1. `isoler` (Confinement) : `docker.isolate` du conteneur
     `${event.container}`, délai 20 s, `abort`, critique. Le conteneur est
     retiré du réseau applicatif (quarantaine) plutôt que redémarré :
     redémarrer détruirait les preuves, la quarantaine les préserve tout en
     coupant la capacité de nuisance.
  2. `informer` (Confinement) : `notify.operator`, sévérité critical, délai
     5 s, `continue_anyway`. Informe l'opérateur de permanence.
  3. `escalader` (Vérification) : `escalate.human`, délai 5 s,
     `continue_anyway`. La levée de quarantaine exige une décision humaine
     (analyse forensique requise).
- **Vérification finale :** aucune suite automatique : la main est rendue
  à l'opérateur. L'état reste en attente de décision humaine.
- **Durée attendue :** quelques secondes (isolation + notification +
  escalade). Ce playbook ne se clôt pas tout seul : c'est un point d'arrêt
  intentionnel.

---

## 6. Playbooks d'exploitation (`infra/playbooks/20-exploitation.yaml`)

### PB-REDEMARRAGE-SERVICE : Redémarrage contrôlé et vérification fonctionnelle

- **Déclencheur :** `POL-EXPL-INDISPONIBLE` ou `POL-EXPL-VERIFICATION`
- **Vérification finale exigée :** oui
- **Phases traversées :** Remise en état → Vérification
- **Actions :**
  1. `redemarrer` (Remise en état) : `docker.restart` du service signalé
     `${event.service}`, grâce 5 s, délai 90 s, `abort`, critique.
  2. `attendre-sante` (Remise en état) : `docker.wait_healthy` sur
     `${event.service}`, délai 120 s, `continue`.
  3. `verifier` (Vérification) : `verify.recovery_suite`.
- **Vérification finale :** un redémarrage n'est jamais la preuve d'un
  rétablissement ; la suite complète : dont un paiement réel de bout en bout -
  doit passer.
- **Durée attendue :** le redémarrage (~90 s) plus l'attente de santé
  dominent le budget.

### PB-INTEGRITE-COMPTABLE : Restauration de l'invariant comptable

- **Déclencheur :** `POL-EXPL-INTEGRITE`
- **Vérification finale exigée :** oui
- **Phases traversées :** Éradication → Remise en état → Vérification
- **Actions :**
  1. `instantane-fautif` (Éradication) : `ledger.snapshot`, délai 30 s,
     `continue_anyway`. Photographie l'état fautif **avant** toute écriture :
     c'est la seule trace exploitable pour l'analyse.
  2. `reconcilier` (Remise en état) : `ledger.reconcile`, délai 30 s,
     `abort`, critique. Recalcule les soldes depuis le journal des jambes,
     source d'autorité.
  3. `verifier` (Vérification) : `verify.recovery_suite`. Contrôle
     d'intégrité et paiement de vérification.
- **Vérification finale :** un solde n'est jamais corrigé à la main ; il est
  recalculé. L'ordre (instantané d'abord, puis recalcul) est imposé pour
  préserver la traçabilité.
- **Durée attendue :** courte (instantané + recalcul, quelques dizaines de
  secondes).

---

## 7. Playbook de reprise par supervision (`infra/playbooks/30-alertes.yaml`)

### PB-ALERTE-REPRISE : Reprise vérifiée d'un service signalé par la supervision

- **Déclencheur :** `POL-ALERTE-INJECTION`, `POL-ALERTE-EXFILTRATION`,
  `POL-ALERTE-AUTH` ou `POL-ALERTE-LATENCE`
- **Vérification finale exigée :** oui
- **Phases traversées :** Éradication → Remise en état → Vérification
- **Actions :**
  1. `instantane` (Éradication) : `ledger.snapshot`, délai 30 s,
     `continue_anyway`. Point de retour avant toute manipulation d'état.
  2. `redemarrage` (Remise en état) : `docker.restart` du service signalé
     `${event.service}`, grâce 5 s, délai 45 s, `abort`.
  3. `attente-sante` (Remise en état) : `docker.wait_healthy` sur
     `${event.service}`, délai 130 s, `abort`.
  4. `verification` (Vérification) : `verify.recovery_suite`. Transaction
     synthétique de bout en bout et contrôle comptable.
  5. `notification` (Vérification) : `notify.operator`, délai 10 s,
     `continue_anyway`. Trace de la reprise dans la salle d'opérations.
- **Vérification finale :** transaction synthétique de bout en bout et
  contrôle comptable ; aucune action destructive : un service sain est
  simplement redémarré. **Ce playbook ne confine pas** : une alerte
  Prometheus ne transporte pas l'adresse d'origine. Sa valeur est la
  redondance : il agit même si le modèle d'anomalie est indisponible.
- **Durée attendue :** budget dominé par le redémarrage et l'attente de
  santé ; compatible avec la cible MTTR < 180 s.

---

## 8. Tableau récapitulatif

### 8.1 Politique → playbook

| Politique | Chemin | Sévérité | Priorité | Temporisation | Playbook | Confinement |
|-----------|--------|----------|----------|---------------|----------|-------------|
| POL-A3-INJECTION | modèle / alertes | critical | 300 | 240 s | PB-A3-CONFINER-ET-REPARER | Oui (source) + gel |
| POL-SIEM-CONTAINER | falco | critical | 250 | 300 s | PB-SIEM-CONFINER-CONTENEUR | Oui (quarantaine) |
| POL-SIEM-ECRITURE | falco | critical | 249 | 300 s | PB-SIEM-CONFINER-CONTENEUR | Oui (quarantaine) |
| POL-ALERTE-INJECTION | alertes | critical | 240 | 180 s | PB-ALERTE-REPRISE | Non |
| POL-ALERTE-EXFILTRATION | alertes | critical | 238 | 180 s | PB-ALERTE-REPRISE | Non |
| POL-A2-IDENTITES | modèle / alertes | critical | 200 | 240 s | PB-A2-ROTATION-DE-CLES | Oui (source) + rotation de clé |
| POL-ALERTE-AUTH | alertes | critical | 190 | 180 s | PB-ALERTE-REPRISE | Non |
| POL-EXPL-INDISPONIBLE | alertes | critical | 150 | 120 s | PB-REDEMARRAGE-SERVICE | Non |
| POL-A1-RAFALE | modèle / alertes | critical | 100 | 180 s | PB-A1-CONFINER-ET-REDEMARRER | Oui (source) |
| POL-EXPL-VERIFICATION | alertes | warning | 90 | 120 s | PB-REDEMARRAGE-SERVICE | Non |
| POL-ALERTE-LATENCE | alertes | warning | 80 | 600 s | PB-ALERTE-REPRISE | Non |

### 8.2 Playbooks

| Playbook | Déclenché par | Phases | Vérification | Se clôt seul |
|----------|---------------|--------|--------------|--------------|
| PB-A1-CONFINER-ET-REDEMARRER | POL-A1-RAFALE | Confinement, Remise, Vérif. | Oui | Oui (si preuves) |
| PB-A2-ROTATION-DE-CLES | POL-A2-IDENTITES | Conf., Érad., Remise, Vérif. | Oui | Oui (si preuves) |
| PB-A3-CONFINER-ET-REPARER | POL-A3-INJECTION | Conf., Érad., Remise, Vérif. | Oui | Partiel (gel à trancher) |
| PB-SIEM-CONFINER-CONTENEUR | POL-SIEM-CONTAINER / POL-SIEM-ECRITURE | Conf., Vérif. | Non | Non (humain) |
| PB-REDEMARRAGE-SERVICE | POL-EXPL-INDISPONIBLE / POL-EXPL-VERIFICATION | Remise, Vérif. | Oui | Oui (si preuves) |
| PB-INTEGRITE-COMPTABLE | POL-EXPL-INTEGRITE | Érad., Remise, Vérif. | Oui | Oui (si preuves) |
| PB-ALERTE-REPRISE | 4 politiques d'alertes | Érad., Remise, Vérif. | Oui | Oui (si preuves) |

### 8.3 Actions élémentaires mobilisées

| Action | Fournisseur | Effet | Reversible |
|--------|-------------|-------|------------|
| `edge.block_ip` | bordure | Blocage d'adresse par la liste dynamique (TTL) | Oui (expire / levée) |
| `auth.revoke_by_source` | api-auth | Révoque les jetons émis depuis une source | Non (jetons annulés) |
| `auth.rotate_signing_key` | api-auth | Remplace la clé RS256 ; tous les jetons deviennent invalides | Non |
| `docker.restart` | proxy d'administration Docker | Redémarrage contrôlé d'un conteneur | Oui |
| `docker.wait_healthy` | proxy d'administration Docker | Attend l'état sain déclaré par le conteneur | Oui (lecture) |
| `docker.isolate` | proxy d'administration Docker | Quarantaine réseau (retrait de `net-app`) | Oui (par décision humaine) |
| `ledger.snapshot` | api-ledger | Instantané du grand livre dans le volume dédié | Non (trace) |
| `ledger.reconcile` | api-ledger | Recalcule les soldes depuis le journal des jambes | Oui (récalcul) |
| `ledger.freeze_account` | api-ledger | Gèle un compte exposé, en attente d'un contrôle humain | Oui (par décision humaine) |
| `verify.recovery_suite` | moteur | Suite de vérification de bout en bout | : (preuve) |
| `notify.operator` | moteur | Trace de l'événement dans la salle d'opérations | : (information) |
| `escalate.human` | moteur | Rend la main à un opérateur | : (escalade) |

### 8.4 Lecture des priorités

Plus la priorité est élevée, plus la politique est examinée d'abord ; en cas
de co-occurrence, la plus forte l'emporte. Le chemin « modèle » (priorités
100/200/300) domine donc le chemin « alertes » (priorités 80 à 240) pour un
même phénomène, car il est le plus complet : il sait quelle adresse bloquer.
Le SIEM (priorités 249/250) se positionne entre les alertes critiques et les
politiques de sécurité, car il réagit à des comportements à malveillance
intrinsèque que le modèle statistique ne qualifie pas.
