#!/usr/bin/env python3
"""Capture l'interface réelle d'AlphaPay depuis la pile en service.

Sert à deux usages : montrer l'interface telle qu'elle est, et alimenter les
maquettes Figma à partir du rendu réel plutôt que d'une intention.

    PLAYWRIGHT_BROWSERS_PATH=/opt/data/tmp/pw-browsers \
        python3 deliverables/capturer_interface.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = os.environ.get("ALPHAPAY_URL", "http://dind")
SORTIE = Path(__file__).resolve().parent / "captures"

ECRANS = [
    ("salle_des_operations", "/ops", True),
    ("paiement_client", "/", False),
]


def main() -> int:
    SORTIE.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as navigateur:
        instance = navigateur.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage", "--force-device-scale-factor=2"]
        )
        contexte = instance.new_context(
            viewport={"width": 1600, "height": 1000},
            device_scale_factor=2,
            locale="fr-FR",
            ignore_https_errors=True,
        )
        page = contexte.new_page()
        erreurs: list[str] = []
        page.on("console", lambda m: erreurs.append(f"{m.type}: {m.text}") if m.type == "error" else None)
        page.on("pageerror", lambda e: erreurs.append(f"pageerror: {e}"))

        for nom, chemin, attendre_donnees in ECRANS:
            url = f"{BASE}{chemin}"
            print(f"--- {nom} : {url}")
            page.goto(url, wait_until="networkidle", timeout=60000)
            # Laisse deux cycles de sondage s'écouler pour que les panneaux
            # affichent des valeurs réelles et non leur état vide.
            page.wait_for_timeout(9000 if attendre_donnees else 3000)

            fichier = SORTIE / f"{nom}.png"
            page.screenshot(path=str(fichier))
            print(f"    capture : {fichier} ({fichier.stat().st_size} octets)")

            fichier_complet = SORTIE / f"{nom}_complet.png"
            page.screenshot(path=str(fichier_complet), full_page=True)
            print(f"    page complète : {fichier_complet} ({fichier_complet.stat().st_size} octets)")

            texte = page.inner_text("body")
            fichier_texte = SORTIE / f"{nom}.txt"
            fichier_texte.write_text(texte, encoding="utf-8")
            print(f"    texte : {len(texte)} caractères")

        if erreurs:
            print("\n--- erreurs console ---")
            for erreur in erreurs[:15]:
                print(f"    {erreur}")

        instance.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
