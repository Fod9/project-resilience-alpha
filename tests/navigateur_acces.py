#!/usr/bin/env python3
"""Test navigateur reel : acces au tableau de bord AlphaPay.

Ouvre un vrai Chromium sur la pile, accepte le certificat auto-signe, autorise
une camera simulee et releve toutes les reponses HTTP >= 400.
Ne prouve pas le defi actif : la camera simulee diffuse une mire, pas un visage.
"""

import sys

from playwright.sync_api import sync_playwright

CIBLE = sys.argv[1] if len(sys.argv) > 1 else "https://127.0.0.1"
OPERATEUR = ("operateur", "AlphaPay-Ops-2026!")

echecs: list[str] = []
erreurs_js: list[str] = []
appels: list[tuple[bool, str]] = []
modeles: list[str] = []


def texte(page) -> str:
    return page.text_content("body") or ""


def principal() -> int:
    with sync_playwright() as p:
        nav = p.chromium.launch(
            headless=True,
            args=[
                "--ignore-certificate-errors",
                "--use-fake-ui-for-media-stream",
                "--use-fake-device-for-media-stream",
            ],
        )
        ctx = nav.new_context(ignore_https_errors=True, permissions=["camera"])
        page = ctx.new_page()

        def sur_reponse(rep):
            if rep.status >= 400:
                echecs.append(f"{rep.status} {rep.request.method} {rep.url}")

        def sur_console(msg):
            if msg.type == "error":
                erreurs_js.append(msg.text[:200])

        def sur_requete(req):
            entetes = {c.lower() for c in req.headers}
            if "/api/supervision/" in req.url:
                appels.append(("authorization" in entetes, req.url))
            if "/models/" in req.url:
                modeles.append(req.url)

        page.on("response", sur_reponse)
        page.on("console", sur_console)
        page.on("request", sur_requete)

        print("1. /ops sans session")
        page.goto(f"{CIBLE}/ops", wait_until="networkidle", timeout=45000)
        t = texte(page)
        print("   ecran d'acces affiche      :", "Ouvrir la session" in t)
        print("   onglet facial propose      :", "Reconnaissance faciale" in t)
        print("   appels supervision         :", len(appels))

        print("2. onglet facial, camera simulee")
        page.get_by_role("button", name="Reconnaissance faciale", exact=True).click()
        page.wait_for_timeout(12000)
        video = page.evaluate(
            "() => { const v = document.querySelector('video');"
            " return v ? { largeur: v.videoWidth, hauteur: v.videoHeight,"
            " flux: !!v.srcObject } : null; }"
        )
        print("   flux camera                :", video)
        print("   modeles telecharges        :", len(modeles))
        t = texte(page)
        print("   etapes du defi affichees   :", "Clignement" in t, "|", "Rotation" in t)

        print("3. connexion par mot de passe")
        page.get_by_role("button", name="Mot de passe", exact=True).click()
        page.wait_for_timeout(600)
        champs = page.locator("input")
        champs.nth(0).fill(OPERATEUR[0])
        champs.nth(1).fill(OPERATEUR[1])
        page.get_by_role("button", name="Ouvrir la session").click()
        page.wait_for_timeout(7000)
        t = texte(page)
        print("   session ouverte            :", OPERATEUR[0] in t)
        print("   onglet salle d'operations  :", "Tableau de bord" in t)
        avec = sum(1 for marque, _ in appels if marque)
        print(f"   appels supervision         : {len(appels)}, dont {avec} avec jeton")

        print("4. enrolement du gabarit")
        page.get_by_role("button", name="Mon visage").click()
        page.wait_for_timeout(10000)
        t = texte(page)
        print("   enrolement ouvert          :", "Enregistrer le gabarit" in t)
        print("   bouton de capture          :", "Capturer une vue" in t)

        print("5. retour puis fermeture de session")
        page.get_by_role("button", name="Fermer", exact=True).click()
        page.wait_for_timeout(2500)
        page.get_by_role("button", name="Fermer la session", exact=True).click()
        page.wait_for_timeout(3000)
        print("   retour a l'ecran d'acces   :", "Ouvrir la session" in texte(page))
        nav.close()

    print()
    print(f"reponses HTTP >= 400 : {len(echecs)}")
    for ligne in echecs[:15]:
        print("   ", ligne)
    print(f"erreurs JavaScript   : {len(erreurs_js)}")
    for ligne in erreurs_js[:10]:
        print("   ", ligne)
    return 0


if __name__ == "__main__":
    sys.exit(principal())
