# AlphaPay : Système de design

> **État courant : thème clair « grand livre ».** La version initiale de ce
> document décrivait un thème sombre ; elle est remplacée. Les valeurs de
> référence sont désormais celles de `frontend/tailwind.config.js`, et les
> maquettes vivent dans le fichier Figma cité en fin de document.

> Direction artistique, tokens et structure d'interface
> Source de vérité commune aux maquettes Figma et à l'implémentation Tailwind.

---

## 1. Sujet, public, objectif

- **Sujet** : une plateforme de paiement et sa **salle d'opérations** de
  cyber-résilience.
- **Public** : un jury technique (coachs EPSI et jury national) qui doit
  comprendre l'état du système **en trois secondes et à trois mètres**, puis
  vérifier le détail au clavier.
- **Objectif unique de l'écran de supervision** : rendre visible et crédible le
  fait que le système s'est **détecté, confiné, rétabli et prouvé tout seul**.

Le vocabulaire visuel vient de là : le **grand livre** (registre, encre, or
bancaire), la **salle de contrôle** (signalétique, voyants, bande
d'enregistreur de vol), la **télémétrie** (chiffres tabulaires, horodatages).

---

## 2. Palette

Fond encre-bleu profond, texte os, **un seul accent : laiton**. Le vert, l'ambre
et le rouge sont **réservés exclusivement à la sémantique d'état** : ils
n'apparaissent jamais comme décoration.

| Rôle | Token | Hex | Usage |
|------|-------|-----|-------|
| Fond racine | `--bg-root` | `#0A0E14` | fond de page |
| Surface 1 | `--bg-surface` | `#111823` | cartes, panneaux |
| Surface 2 | `--bg-raised` | `#18212F` | éléments surélevés, en-têtes de tableau |
| Bordure | `--line` | `#243040` | séparateurs, contours au repos |
| Bordure active | `--line-strong` | `#33445A` | focus, survol |
| Texte primaire | `--ink` | `#E9E4DA` | corps de texte, valeurs |
| Texte secondaire | `--ink-dim` | `#8C97A8` | libellés, unités, aides |
| Texte tertiaire | `--ink-faint` | `#5A6472` | méta, horodatages |
| **Accent (signature)** | `--brass` | `#D9A227` | marque, accent, élément actif, chiffre clé |
| Accent clair | `--brass-soft` | `#F0C75E` | survol de l'accent |
| État nominal | `--st-nominal` | `#3FB27F` | services sains, vérification réussie |
| État dégradé | `--st-warning` | `#E8B03A` | seuils franchis, contention |
| État incident | `--st-critical` | `#E2574C` | incident actif, contrôle échoué |
| État rétabli | `--st-recovered` | `#6FA8DC` | transition RECOVERED (bleu signature d'archive) |
| Donnée ML | `--data-ml` | `#A78BFA` | courbe du score d'anomalie uniquement |

Contraste : `--ink` sur `--bg-root` = 13,4:1 ; `--brass` sur `--bg-root` =
8,1:1 ; `--ink-dim` sur `--bg-surface` = 5,2:1. Tous les textes respectent AA.

---

## 3. Typographie

Trois rôles, trois familles distinctes, toutes disponibles sur Google Fonts
(contrainte : l'application doit fonctionner hors ligne après build, les polices
sont donc **auto-hébergées** via `@fontsource`).

| Rôle | Famille | Réglages | Usage |
|------|---------|----------|-------|
| **Signalétique** | `Archivo` (axe largeur étendu) | 700-800, `font-stretch: 125%`, uppercase, `letter-spacing: 0.04em` | mot d'état global, titres de page, en-têtes de section |
| **Lecture** | `IBM Plex Sans` | 400 / 500 / 600 | corps, libellés, descriptions, messages |
| **Télémétrie** | `IBM Plex Mono` | 400 / 500, `font-variant-numeric: tabular-nums` | chiffres, horodatages, identifiants, valeurs de métriques, logs |

Échelle : `11 / 12 / 14 / 16 / 20 / 28 / 44 / 96` px.
Le **96 px en Archivo étendu majuscules** est réservé au mot d'état : c'est le
seul endroit de l'interface où l'on dépasse 44 px. Cette rupture d'échelle est
volontaire : elle crée la hiérarchie que les dashboards habituels n'ont pas.

Interdits : aucune police à empattement, aucune graisse fine sous 14 px, aucun
texte en majuscules hors de la signalétique.

---

## 4. Grille et structure

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  RAIL D'ÉTAT  : plein cadre, hauteur 132 px                                  │
│  ALPHAPAY · RESILIENCE-ALPHA            [ÉTAT EN 96px]        MTTD  00:41    │
│  ▁▂▃▅▇▅▃▂▁  courbe de vie du score d'anomalie (sparkline 100% largeur)  MTTR │
├───────────────┬──────────────────────────────────────┬───────────────────────┤
│  SYSTÈMES     │  BANDES DE MESURE                    │  REMÉDIATION          │
│  3 colonnes   │  6 colonnes                          │  3 colonnes           │
│               │                                      │                       │
│  18 lignes    │  Débit (tx/s)      ▁▂▃▅▇▅▃          │  Playbook             │
│  voyant + nom │  Latence p95 (ms)  ▁▂▃▅▇▅▃          │   ✓ block_source      │
│  + barres     │  Taux d'erreur     ▁▂▃▅▇▅▃          │   ✓ revoke_tokens     │
│  ressources   │  Score anomalie    ▁▂▃▅▇  ─ seuil    │   ⟳ verify            │
│               │                                      │                       │
│               │  ── Flux d'événements corrélés ──    │  Vérifications V1..V6 │
│               │  (liste dense, monospace, horodatée) │   ✓ ✓ ✓ ✓ ✓ ⟳         │
├───────────────┴──────────────────────────────────────┴───────────────────────┤
│  BANDE-ENREGISTREUR  : plein cadre, hauteur 148 px                           │
│  A1 attaque │ détection │ confinement │ remédiation │ vérification │ rétabli │
│  ├──────────┼───────────┼─────────────┼──────────────┼──────────────┤        │
│      MTTD (41 s)          MTTR (2 min 12 s)                                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- Largeur de référence : **1440 px**, grille 12 colonnes, gouttière 16 px,
  marge 24 px. Paliers : 1440 / 1280 / 1024 (empilement sous 1024).
- Rayon : 4 px partout. Une seule valeur : la discipline prime sur la variété.
- Ombres : aucune. La profondeur est donnée par les surfaces et les bordures.
- Espacement : échelle 4 / 8 / 12 / 16 / 24 / 32 / 48.

---

## 5. Élément signature : la bande-enregistreur

Un seul élément mémorable, et il porte tout le propos du projet.

Une **bande horizontale pleine largeur** en bas de l'écran de supervision, sur
laquelle sont épinglés, en temps réel, les moments de l'incident :

- chaque instant est un **trait vertical** sur une règle de temps ;
- les traits sont colorés par **origine du signal** (ML, Falco, WAF, alerte,
  action de remédiation) ;
- les intervalles **MTTD** et **MTTR** sont dessinés comme des **portées
  horizontales mesurées** sous la règle, avec leur valeur ;
- la zone « pendant l'incident » est ombrée `--st-critical` à 8 % d'opacité, la
  zone « après rétablissement » `--st-nominal` à 8 %.

C'est le seul objet de l'interface qui encode la thèse entière : *un système de
paiement qui se répare seul et qui peut le prouver, horodatage par horodatage*.
Tout le reste de l'interface est volontairement sobre pour que cette bande
ressorte.

---

## 6. Composants

| Composant | Description | États |
|-----------|-------------|-------|
| `StatusRail` | Rail d'état plein cadre, mot d'état 96 px, compteurs, sparkline | nominal / dégradé / incident / reprise / rétabli |
| `ServiceRow` | Ligne de service : voyant, nom, empreinte de version, barres CPU/RAM | sain / lent / en quarantaine / arrêté |
| `MetricBand` | Bande de mesure : libellé, valeur mono, sparkline, seuil optionnel | normal / seuil franchi |
| `EventStream` | Flux dense d'événements horodatés, source colorée, `trace_id` copiable | vide / nominal / incident |
| `PlaybookSteps` | Étapes du playbook, statut, durée, `on_failure` | en attente / en cours / ok / échec / ignorée |
| `VerificationGrid` | 6 contrôles V1..V6, preuve au survol | en attente / en cours / réussi / échoué |
| `RecorderStrip` | **Signature** : bande-enregistreur | survol d'un instant = détail |
| `AssistantPanel` | Chat RAG, citations obligatoires, badge de mode dégradé | disponible / indisponible |
| `PayForm` | Montant, bénéficiaire, récapitulatif, confirmation | validation / refus / succès |

Pictogrammes : trait 1,5 px, aucune icône décorative : chaque icône signale un
état ou une action nommable.

---

## 7. Écriture

- Le nom d'un contrôle dit ce qu'il fait : « Bloquer la source », pas « Exécuter ».
- Le même mot du début à la fin : le bouton « Lancer le scénario » produit
  l'événement « Scénario lancé ».
- Les erreurs nomment la cause et la suite : « Grand livre déséquilibré sur la
  transaction 4f2a : réconciliation lancée », jamais « Une erreur est survenue ».
- Les vides invitent à agir : « Aucun incident enregistré. Le système est
  nominal depuis 3 h 12. »
- Aucun emoji, aucune exclamation, aucune formulation commerciale.

---

## 8. Mouvement

Le mouvement sert la lecture de l'état, jamais la décoration.

| Moment | Animation | Durée |
|--------|-----------|-------|
| Transition d'état global | fondu de couleur du rail + balayage du mot d'état | 400 ms |
| Nouvel événement dans le flux | insertion avec décalage de 6 px vers le bas | 180 ms |
| Étape de playbook qui se valide | le voyant passe de rotation à coche | 220 ms |
| Franchissement du seuil d'anomalie | pulsation de la ligne de seuil, 2 cycles | 900 ms |
| Épinglage d'un instant sur la bande-enregistreur | trait qui descend de 0 à sa hauteur | 260 ms |

`prefers-reduced-motion: reduce` remplace toutes ces animations par des
transitions d'opacité de 0 ms. La bande-enregistreur reste lisible.

---

## 9. Accessibilité

- Focus visible : anneau `--brass` 2 px, décalage 2 px, jamais supprimé.
- Tout état est porté par **un texte** en plus de la couleur (un voyant rouge est
  toujours accompagné du mot « incident »).
- Cibles tactiles ≥ 44 px sur les actions.
- Ordre de tabulation : rail → systèmes → mesures → remédiation → bande.
- Navigation clavier complète de la bande-enregistreur (flèches = instant
  précédent/suivant, Entrée = détail).

---

## 10. Correspondance Tailwind

Les tokens sont déclarés dans `frontend/tailwind.config.ts` (`theme.extend`) et
dans `frontend/src/design/tokens.css` sous forme de variables CSS. Toute valeur
de couleur, d'espacement ou de police utilisée dans l'application **doit**
provenir d'un token : aucune valeur littérale dans les composants.

```ts
// extrait de frontend/tailwind.config.ts
colors: {
  bg:      { root: '#0A0E14', surface: '#111823', raised: '#18212F' },
  line:    { DEFAULT: '#243040', strong: '#33445A' },
  ink:     { DEFAULT: '#E9E4DA', dim: '#8C97A8', faint: '#5A6472' },
  brass:   { DEFAULT: '#D9A227', soft: '#F0C75E' },
  state:   { nominal: '#3FB27F', warning: '#E8B03A', critical: '#E2574C', recovered: '#6FA8DC' },
  data:    { ml: '#A78BFA' },
},
fontFamily: {
  signal: ['Archivo Variable', 'system-ui', 'sans-serif'],
  sans:   ['IBM Plex Sans', 'system-ui', 'sans-serif'],
  mono:   ['IBM Plex Mono', 'ui-monospace', 'monospace'],
},
```

---

*Système de design : v1.0*
