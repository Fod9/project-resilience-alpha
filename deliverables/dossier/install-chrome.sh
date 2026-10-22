#!/usr/bin/env bash
# Recupere un Chromium utilisable pour le rendu Mermaid et l'impression PDF.
set -euo pipefail

CACHE=/opt/data/puppeteer-cache
VERSION=156.0.8078.47
DEST="$CACHE/chrome-linux64"
URL="https://storage.googleapis.com/chrome-for-testing-public/$VERSION/linux64/chrome-linux64.zip"
ZIP="$CACHE/chrome-$VERSION.zip"

mkdir -p "$CACHE"
if [ ! -x "$DEST/chrome" ]; then
  echo "telechargement $URL"
  curl -fL --retry 3 -o "$ZIP" "$URL"
  ls -la "$ZIP"
  python3 - "$ZIP" "$DEST" <<'PY'
import sys, zipfile, pathlib
zip_path, dest = sys.argv[1], sys.argv[2]
cible = pathlib.Path(dest)
cible.mkdir(parents=True, exist_ok=True)
n = 0
with zipfile.ZipFile(zip_path) as z:
    for membre in z.namelist():
        # l'archive porte un dossier racine chrome-linux64/ : on l'ecarte
        if "/" not in membre:
            continue
        chemin = cible / membre.split("/", 1)[1]
        if membre.endswith("/"):
            chemin.mkdir(parents=True, exist_ok=True)
            continue
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_bytes(z.read(membre))
        n += 1
print("extrait", n, "fichiers dans", dest)
PY
  # l'extraction Python ne preserve pas les droits d'execution
  chmod +x "$DEST/chrome" "$DEST/chrome_crashpad_handler" "$DEST/chrome_sandbox" 2>/dev/null || true
fi

echo "--- binaire ---"
ls -la "$DEST/chrome"
echo "--- version ---"
"$DEST/chrome" --version || echo "lancement echoue"
echo "--- libs manquantes ---"
ldd "$DEST/chrome" 2>/dev/null | grep -i "not found" || echo "aucune lib manquante"
