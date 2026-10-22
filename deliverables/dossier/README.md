# Dossier d'ingénierie et de gouvernance (livrable 7.1)

Ce dossier contient les sources du livrable `Workshop2026-M2-G1-Dossier.pdf`,
placé dans `deliverables/` (les binaires PDF, PPTX et MP4 ne sont pas versionnés).

## Contenu

| Chemin | Rôle |
|---|---|
| `src/*.html` | Un fragment par page du dossier, dans l'ordre de lecture |
| `diagrammes/*.mmd` | Schémas Mermaid (architecture, flux, détection, reprise, preuves) |
| `style.css` | Charte du dossier, reprise des jetons de `docs/DESIGN-SYSTEM.md` |
| `polices/` | Archivo, IBM Plex Sans, IBM Plex Mono (Google Fonts, licence OFL) |
| `marque.svg` | Marque AlphaPay redessinée en vectoriel pour la page de garde |
| `assembler.py` | Assemble les fragments en pages A4 avec en-tête et pied |
| `injecter.py` | Injecte les SVG Mermaid dans le HTML (polices héritées) |
| `render.sh` | Chaîne complète : assemblage, schémas, injection, impression, contrôle |

## Régénérer le PDF

```bash
bash deliverables/dossier/render.sh
```

Prérequis, à installer une fois :

```bash
# Mermaid CLI et son navigateur
npm install -g @mermaid-js/mermaid-cli
bash deliverables/dossier/install-chrome.sh   # Chrome for Testing dans /opt/data/puppeteer-cache

# Outils de contrôle (pypdf, pypdfium2, pillow) dans un venv
uv venv /opt/data/.venv-doc
uv pip install --python /opt/data/.venv-doc/bin/python pypdf pypdfium2 pillow
```

## Choix de fabrication

- **Pagination explicite.** Chrome headless ne place pas un élément `position: fixed`
  dans la marge de `@page` : une valeur négative est rendue à l'opposé (un `top`
  négatif tombe en bas de page). Chaque page est donc une `.feuille` A4 de hauteur
  fixe, avec son en-tête et son pied. Conséquence : une section qui déborde est
  rognée silencieusement, d'où le contrôle du nombre de pages après chaque rendu.
- **Schémas Mermaid en SVG inline.** Un SVG référencé par `<img>` n'hérite pas des
  polices `@font-face` du document ; les schémas sont donc inlinés.
- **Hauteurs de schéma plafonnées.** Un schéma large et plat posé sur 182 mm de
  large donne un texte illisible : les schémas sont dessinés en disposition
  verticale et leur hauteur est bornée par classe (`figure`, `.moyenne`, `.haute`,
  `.petite`).

## Contrôle après rendu

```bash
/opt/data/.venv-doc/bin/python deliverables/dossier/build/planche.py   # planche des pages
```

Le script `render.sh` affiche le nombre de pages et vérifie que l'en-tête et le
pied sont présents sur chacune. Le dossier doit faire 12 pages : une page de garde
et onze sections (le sujet demande 8 à 12 pages hors annexes).
