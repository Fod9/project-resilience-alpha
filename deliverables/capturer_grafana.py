#!/usr/bin/env python3
"""Capture les tableaux de bord Grafana depuis la pile en service."""

import os
import re
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

RACINE = Path("/opt/data/projects/resilience-alpha")
SORTIE = RACINE / "deliverables" / "captures" / "grafana"
SORTIE.mkdir(parents=True, exist_ok=True)


def lire_env(cle: str, defaut: str = "") -> str:
    chemin = RACINE / ".env"
    if not chemin.exists():
        return defaut
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        if ligne.startswith(f"{cle}="):
            return ligne.split("=", 1)[1].strip()
    return defaut


def main() -> int:
    base = os.getenv("GRAFANA_URL", f"http://dind:{lire_env('GRAFANA_PORT', '3000')}")
    utilisateur = lire_env("GRAFANA_ADMIN_USER", "admin")
    motdepasse = lire_env("GRAFANA_ADMIN_PASSWORD")
    tableaux = [
        ("alphapay-vue-ensemble", "vue_ensemble"),
        ("alphapay-detection", "detection"),
        ("alphapay-reprise", "reprise_autonome"),
        ("alphapay-securite", "securite"),
    ]
    sorties = []
    with sync_playwright() as pw:
        nav = pw.chromium.launch(args=["--no-sandbox", "--disable-dev-shm-usage"])
        page = nav.new_page(viewport={"width": 1920, "height": 1200})
        page.goto(f"{base}/login", wait_until="domcontentloaded", timeout=60000)
        try:
            page.fill("input[name='user']", utilisateur)
            page.fill("input[name='password']", motdepasse)
            page.click("button[type='submit']")
            page.wait_for_timeout(4000)
        except Exception as erreur:  # noqa: BLE001
            print(f"    connexion ignorée : {type(erreur).__name__}")

        for uid, nom in tableaux:
            page.goto(f"{base}/d/{uid}?kiosk&from=now-15m&to=now",
                      wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(9000)
            chemin = SORTIE / f"{nom}.png"
            page.screenshot(path=str(chemin))
            texte = page.inner_text("body")
            panneaux = len(re.findall(r"(?i)aucune donn|no data", texte))
            sorties.append((nom, chemin, len(texte), panneaux))
            print(f"  {nom:<18} -> {chemin.name} | texte {len(texte)} car. | "
                  f"mentions 'aucune donnée' : {panneaux}")
        nav.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
