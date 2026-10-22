#!/usr/bin/env bash
# ============================================================================
# Rendu du dossier d'ingenierie et de gouvernance (groupe 1).
#   1. schemas Mermaid (.mmd) -> SVG
#   2. SVG inlines dans le HTML
#   3. HTML -> PDF via Chromium (impression A4)
#   4. controle : nombre de pages et presence des en-tetes
# ============================================================================
set -euo pipefail

export PATH=/opt/data/node22/bin:$PATH
export PUPPETEER_EXECUTABLE_PATH=/opt/data/puppeteer-cache/chrome-linux64/chrome

DOSSIER=/opt/data/projects/resilience-alpha/deliverables/dossier
CHROME=/opt/data/puppeteer-cache/chrome-linux64/chrome
PY=/opt/data/.venv-doc/bin/python
SORTIE=/opt/data/projects/resilience-alpha/deliverables/Workshop2026-M2-G1-Dossier.pdf

cd "$DOSSIER"
mkdir -p build/svg

echo "[1/5] assemblage des fragments"
"$PY" assembler.py "$DOSSIER" "$DOSSIER/dossier.html"

echo "[2/5] schemas Mermaid"
for f in diagrammes/*.mmd; do
  nom=$(basename "$f" .mmd)
  mmdc -i "$f" -o "build/svg/$nom.svg" \
       -c mermaid-config.json -b transparent -q \
       -p puppeteer-config.json
  echo "  $nom.svg"
done

echo "[3/5] injection des SVG dans le HTML"
"$PY" injecter.py dossier.html dossier-inline.html build/svg

echo "[4/5] impression PDF"
"$CHROME" --headless --no-sandbox --disable-gpu --disable-dev-shm-usage \
  --no-pdf-header-footer --no-margins \
  --virtual-time-budget=12000 \
  --print-to-pdf="$SORTIE" "file://$DOSSIER/dossier-inline.html" 2>&1 | grep -i "written" || true

echo "[5/5] controle du PDF"
"$PY" - "$SORTIE" <<'PYEOF'
import sys
from pypdf import PdfReader
r = PdfReader(sys.argv[1])
pages = len(r.pages)
sans_entete, sans_pied = [], []
for i, p in enumerate(r.pages, 1):
    t = (p.extract_text() or "").upper().replace(" ", "")
    if "ALPHAPAY" not in t:
        sans_entete.append(i)
    if "WORKSHOP2026" not in t:
        sans_pied.append(i)
print(f"  pages : {pages}")
print(f"  pages sans en-tete : {sans_entete or 'aucune'}")
print(f"  pages sans pied : {sans_pied or 'aucune'}")
PYEOF
ls -la "$SORTIE"
