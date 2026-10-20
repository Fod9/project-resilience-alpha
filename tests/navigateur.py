#!/usr/bin/env python3
"""Test navigateur reel : charge les pages et releve TOUTES les reponses en echec.

Usage :
    PLAYWRIGHT_BROWSERS_PATH=... python tests/navigateur.py [http://127.0.0.1]

Pourquoi ce script existe : le script de capture d'ecran ne relevait que les
messages de console. Un 503 sur un appel d'API n'y apparait pas forcement, et
c'est precisement ce qui a ete rate. Ici, chaque reponse HTTP de code >= 400 est
enregistree avec son URL et son origine, et chaque erreur JavaScript est relevee.
"""

import sys
from playwright.sync_api import sync_playwright

CIBLE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1").rstrip("/")

PAGES = [("/", "page de paiement"), ("/ops", "tableau de bord")]


def tester(page, chemin: str, libelle: str) -> tuple[int, list[str], list[str]]:
    """Charge une page et retourne (code HTTP du document, echecs, erreurs JS)."""
    echecs: list[str] = []
    erreurs_js: list[str] = []

    def sur_reponse(reponse):
        try:
            if reponse.status >= 400:
                echecs.append(f"{reponse.status} {reponse.request.method} {reponse.url}")
        except Exception:
            pass

    def sur_console(message):
        if message.type == "error":
            erreurs_js.append(message.text[:200])

    page.on("response", sur_reponse)
    page.on("console", sur_console)

    reponse = page.goto(f"{CIBLE}{chemin}", wait_until="networkidle", timeout=45000)
    # Laisser les sondes periodiques s'executer : c'est la que le 503 apparaissait.
    page.wait_for_timeout(9000)

    return (reponse.status if reponse else 0), echecs, erreurs_js


def main() -> int:
    total_echecs = 0
    with sync_playwright() as p:
        navigateur = p.chromium.launch()
        contexte = navigateur.new_context(viewport={"width": 1600, "height": 1000})
        page = contexte.new_page()

        for chemin, libelle in PAGES:
            print(f"=== {libelle} : {CIBLE}{chemin} ===")
            # Une page neuve par URL : les ecouteurs d'une page survivent au
            # chargement suivant, et les echecs de la premiere page se
            # retrouveraient comptes dans la seconde.
            page = contexte.new_page()
            code, echecs, erreurs_js = tester(page, chemin, libelle)
            print(f"  document          : {code}")
            texte = page.inner_text("body")
            print(f"  texte rendu       : {len(texte)} caracteres")

            if echecs:
                print(f"  REPONSES EN ECHEC : {len(echecs)}")
                for ligne in dict.fromkeys(echecs):
                    print(f"     {ligne}")
                    total_echecs += 1
            else:
                print("  reponses en echec : aucune")

            if erreurs_js:
                print(f"  erreurs JavaScript: {len(erreurs_js)}")
                for ligne in dict.fromkeys(erreurs_js):
                    print(f"     {ligne}")

            attendus = ("ALPHAPAY", "Services", "Incidents") if chemin == "/ops" else ("ALPHAPAY", "Payer")
            for attendu in attendus:
                present = attendu.lower() in texte.lower()
                print(f"  contenu '{attendu}' : {'present' if present else 'ABSENT'}")

            page.close()
            print()

        navigateur.close()

    print(f"total des reponses en echec : {total_echecs}")
    return 1 if total_echecs else 0


if __name__ == "__main__":
    raise SystemExit(main())
