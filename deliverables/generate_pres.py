#!/usr/bin/env python3
"""Génère Pres.pptx, la présentation de soutenance de PROJECT RESILIENCE-ALPHA.

Style : celui de l'application. Papier comptable clair, filets d'un pixel,
Bitter pour les titres, Inter pour le texte, IBM Plex Mono pour les données,
filet de marge terre cuite. La maquette de référence est la page SOUTENANCE du
fichier Figma SacCkouYmlKojpdNol2dO4 : les deux doivent rester alignés.

Les chiffres structurels (services suivis, réseaux, politiques, playbooks,
seuil du modèle) sont lus dans le dépôt, aucun n'est saisi à la main. Les
mesures de la dernière exécution se lisent dans MESURES : elles viennent du
journal du banc (ops.incidents, ops.actions) et ne peuvent pas être déduites du
dépôt.

    python3 deliverables/generate_pres.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Emu, Pt

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "deliverables" / "Pres.pptx"

# --- Jetons du système de design (docs/DESIGN-SYSTEM.md) ---------------------
PAPIER = RGBColor(0xF6, 0xF7, 0xF5)
SURFACE = RGBColor(0xFF, 0xFF, 0xFF)
LIGNE = RGBColor(0xDC, 0xE0, 0xDA)
LIGNE_FORT = RGBColor(0xB9, 0xC0, 0xB4)
ENCRE = RGBColor(0x15, 0x1A, 0x1E)
ENCRE_DIM = RGBColor(0x5C, 0x66, 0x70)
ACCENT = RGBColor(0x2E, 0x6B, 0x5A)
MARGE = RGBColor(0xB4, 0x52, 0x3F)
NOMINAL = RGBColor(0x2F, 0x6B, 0x4F)

BITTER = "Bitter"
INTER = "Inter"
MONO = "IBM Plex Mono"

#: Une diapositive fait 1280 x 720 points-image, soit 13,333 x 7,5 pouces : le
#: format 16/9 de PowerPoint. Tout est positionné dans cet espace, comme dans la
#: maquette Figma, ce qui rend les deux comparables ligne à ligne.
LARGEUR, HAUTEUR = 1280, 720
PX = 9525  # 1 point-image à 96 dpi

#: Mesures relevées dans le journal du banc à la dernière validation de la
#: chaîne A1 (incident RECOVERED). À rafraîchir après chaque tir de référence.
MESURES: dict[str, Any] = {
    "releve": "21 octobre 2026",
    "mttd_s": 60.0,
    "cible_mttd_s": 60.0,
    "mttr_s": 2.8,
    "cible_mttr_s": 180.0,
    "etapes": [
        ("confiner-signature", "edge.block_signature", "23 ms"),
        ("bloquer-source", "edge.block_ip", "1 219 ms"),
        ("revoquer-jetons", "auth.revoke_by_source", "20 ms"),
        ("redemarrer-paiement", "docker.restart", "755 ms"),
        ("attendre-sante", "docker.wait_healthy", "532 ms"),
        ("verifier", "verify.recovery_suite", "188 ms"),
    ],
    "preuves": [
        ("bordure joignable", "GET /healthz, code 200"),
        ("services sains", "17 conteneurs inspectés"),
        ("paiement synthétique", "CUST-000002 vers MERCHANT-0001, code 201"),
        ("intégrité du grand livre", "débits égaux aux crédits"),
        ("confinement effectif", "signature du banc refusée, code 403"),
    ],
}


def faits() -> dict[str, Any]:
    """Chiffres structurels lus dans le dépôt, sans valeur inventée."""
    compose = (RACINE / "docker-compose.yml").read_text(encoding="utf-8")
    connecteurs = (RACINE / "services/remediation/app/connectors.py").read_text(encoding="utf-8")

    suivi = re.search(r"SERVICES_SUIVIS[^=]*=\s*\((.*?)\)", connecteurs, re.S)
    services_suivis = len(re.findall(r'"([a-z][a-z0-9-]*)"', suivi.group(1))) if suivi else 0

    politiques = sum(
        len(re.findall(r"^  - id:", chemin.read_text(encoding="utf-8"), re.M))
        for chemin in sorted((RACINE / "infra/policies").glob("*.yaml"))
    )
    playbooks = sum(
        len(re.findall(r"^  - id: PB-", chemin.read_text(encoding="utf-8"), re.M))
        for chemin in sorted((RACINE / "infra/playbooks").glob("*.yaml"))
    )

    modele = json.loads((RACINE / "ml/artifacts/model-meta.json").read_text(encoding="utf-8"))

    return {
        "services_suivis": services_suivis,
        "reseaux": len(re.findall(r"^  net-[a-z]+:", compose, re.M)),
        "reseaux_internes": compose.count("internal: true"),
        "politiques": politiques,
        "playbooks": playbooks,
        "variables": len(modele["feature_names"]),
        "arbre": "Isolation Forest",
    }


# --- Mise en page -----------------------------------------------------------
def px(valeur: float) -> Emu:
    return Emu(int(round(valeur * PX)))


def fond(diapo, couleur: RGBColor = PAPIER) -> None:
    remplissage = diapo.background.fill
    remplissage.solid()
    remplissage.fore_color.rgb = couleur


def planche(diapo, gauche: float, haut: float, largeur: float, hauteur: float):
    """Cadre de texte sans marge interne : le texte commence exactement à la
    position demandée, comme dans la maquette."""
    cadre = diapo.shapes.add_textbox(px(gauche), px(haut), px(largeur), px(hauteur))
    cadre.text_frame.word_wrap = True
    for marge in ("margin_left", "margin_right", "margin_top", "margin_bottom"):
        setattr(cadre.text_frame, marge, 0)
    cadre.text_frame.vertical_anchor = MSO_ANCHOR.TOP
    return cadre.text_frame


def ecrire(
    cadre,
    contenu: str,
    *,
    taille: float,
    couleur: RGBColor = ENCRE,
    police: str = INTER,
    gras: bool = False,
    majuscules: bool = False,
    interlettre: float = 0.0,
    interligne: float = 1.05,
    aligne_droite: bool = False,
) -> None:
    """Écrit un paragraphe. ``taille`` et ``interlettre`` sont en points-image."""
    paragraphe = (
        cadre.paragraphs[0]
        if not cadre.paragraphs[0].runs and len(cadre.paragraphs) == 1
        else cadre.add_paragraph()
    )
    paragraphe.line_spacing = interligne
    paragraphe.space_before = Pt(0)
    paragraphe.space_after = Pt(0)
    if aligne_droite:
        paragraphe.alignment = PP_ALIGN.RIGHT
    morceau = paragraphe.add_run()
    morceau.text = contenu.upper() if majuscules else contenu
    police_ = morceau.font
    police_.name = police
    police_.size = Pt(round(taille * 0.75, 1))
    police_.color.rgb = couleur
    police_.bold = gras
    if interlettre:
        # L'interlettre CSS s'exprime en pourcentage du corps ; le format pptx en
        # centièmes de point. La conversion évite de retoucher chaque titre.
        centiemes = interlettre / 100 * taille * 0.75 * 100
        police_._rPr.set("spc", str(int(round(centiemes))))


def _sans_style(forme) -> None:
    """Retire le style de thème que python-pptx pose sur les formes.

    Ce style applique un effet de relief et une ombre aux rectangles : les
    filets d'un pixel ressortaient biseautés au rendu. Un filet doit être un
    trait net, sans relief.
    """
    style = forme._element.find(qn("p:style"))
    if style is not None:
        forme._element.remove(style)
    forme.shadow.inherit = False


def filet(
    diapo,
    x: float,
    y: float,
    largeur: float,
    hauteur: float = 1,
    couleur: RGBColor = LIGNE,
):
    forme = diapo.shapes.add_shape(MSO_SHAPE.RECTANGLE, px(x), px(y), px(largeur), px(hauteur))
    forme.fill.solid()
    forme.fill.fore_color.rgb = couleur
    forme.line.fill.background()
    _sans_style(forme)
    return forme


def bloc(
    diapo,
    x: float,
    y: float,
    largeur: float,
    hauteur: float,
    *,
    remplissage: RGBColor | None = None,
    bordure: RGBColor | None = None,
):
    forme = diapo.shapes.add_shape(MSO_SHAPE.RECTANGLE, px(x), px(y), px(largeur), px(hauteur))
    if remplissage is None:
        forme.fill.background()
    else:
        forme.fill.solid()
        forme.fill.fore_color.rgb = remplissage
    if bordure is None:
        forme.line.fill.background()
    else:
        forme.line.color.rgb = bordure
        forme.line.width = Pt(0.75)
    _sans_style(forme)
    return forme


def nouvelle_diapo(prs, numero: str, nom: str, *, chrome: bool = True):
    diapo = prs.slides.add_slide(prs.slide_layouts[6])  # mise en page vierge
    fond(diapo)
    if not chrome:
        return diapo
    filet(diapo, 56, 112, 1, 508, MARGE)  # filet de marge imprimé
    cadre = planche(diapo, 56, 34, 400, 30)
    ecrire(cadre, "ALPHAPAY", taille=20, police=BITTER, gras=True, interlettre=22)
    cadre = planche(diapo, 700, 44, 524, 20)
    ecrire(cadre, "PROJECT RESILIENCE-ALPHA", taille=9, couleur=ENCRE_DIM, police=MONO, aligne_droite=True)
    filet(diapo, 56, 84, 1168)
    filet(diapo, 56, 648, 1168)
    cadre = planche(diapo, 56, 660, 400, 20)
    ecrire(cadre, "AlphaPay 2026©", taille=9, couleur=ENCRE_DIM)
    cadre = planche(diapo, 700, 660, 524, 20)
    ecrire(cadre, f"{numero} / 06", taille=9, couleur=ENCRE_DIM, police=MONO, aligne_droite=True)
    return diapo


def entete(diapo, surtitre: str, titre: str) -> None:
    cadre = planche(diapo, 88, 106, 600, 20)
    ecrire(cadre, surtitre, taille=9, couleur=ACCENT, police=INTER, gras=True,
           majuscules=True, interlettre=10)
    cadre = planche(diapo, 88, 126, 1104, 80)
    ecrire(cadre, titre, taille=30, police=BITTER, gras=True, interligne=1.0)


def construire(f: dict[str, Any]) -> Presentation:
    prs = Presentation()
    prs.slide_width = px(LARGEUR)
    prs.slide_height = px(HAUTEUR)

    # --- 01 Couverture -----------------------------------------------------
    d = nouvelle_diapo(prs, "01", "Couverture", chrome=False)
    cadre = planche(d, 56, 44, 500, 40)
    ecrire(cadre, "ALPHAPAY", taille=22, police=BITTER, gras=True, interlettre=22)
    filet(d, 56, 110, 1168, 2, LIGNE_FORT)
    cadre = planche(d, 56, 200, 1150, 120)
    ecrire(cadre, "PROJECT RESILIENCE-ALPHA", taille=54, police=BITTER, gras=True, interligne=1.0)
    cadre = planche(d, 56, 328, 780, 80)
    ecrire(
        cadre,
        "Une plateforme de paiement qui détecte l'attaque, se confine, se rétablit, "
        "et fournit la preuve de son rétablissement.",
        taille=17,
        couleur=ENCRE_DIM,
        interligne=1.15,
    )
    filet(d, 56, 456, 1168, 2, LIGNE_FORT)
    cadre = planche(d, 56, 472, 500, 20)
    ecrire(cadre, "Tom Dernoncourt", taille=10, gras=True, majuscules=True, interlettre=10)
    cadre = planche(d, 700, 472, 524, 20)
    ecrire(cadre, "Soutenance · octobre 2026", taille=10, couleur=ENCRE_DIM, police=MONO,
           aligne_droite=True)
    cadre = planche(d, 56, 540, 600, 20)
    ecrire(cadre, "bande-enregistreur, douze dernières minutes", taille=9, couleur=ENCRE_DIM,
           police=MONO)
    filet(d, 56, 590, 1168)
    for i in range(13):
        filet(d, 56 + i * (1168 / 12), 584, 1, 12, LIGNE_FORT if i % 3 == 0 else LIGNE)
    for x in (300, 620, 940):
        marque = bloc(d, x, 586, 8, 8, remplissage=ENCRE)
        marque.rotation = 45
    cadre = planche(d, 56, 604, 300, 20)
    ecrire(cadre, "il y a 12 min", taille=8, couleur=ENCRE_DIM, police=MONO)
    cadre = planche(d, 924, 604, 300, 20)
    ecrire(cadre, "maintenant", taille=8, couleur=ENCRE_DIM, police=MONO, aligne_droite=True)
    filet(d, 56, 648, 1168)
    cadre = planche(d, 56, 660, 400, 20)
    ecrire(cadre, "AlphaPay 2026©", taille=9, couleur=ENCRE_DIM)
    cadre = planche(d, 700, 660, 524, 20)
    ecrire(cadre, "01 / 06", taille=9, couleur=ENCRE_DIM, police=MONO, aligne_droite=True)

    # --- 02 Sujet ----------------------------------------------------------
    d = nouvelle_diapo(prs, "02", "Sujet")
    entete(d, "Sujet", "Un système autonome ne vaut que par ce qu'il prouve")
    blocs = [
        ("La détection ne suffit pas",
         "Un score d'anomalie sans suite laisse l'incident ouvert et l'attaquant à l'intérieur."),
        ("L'opérateur ne doit pas être confiné",
         "Un confinement par adresse coupe aussi celui qui pilote la salle d'opérations."),
        ("Un rétablissement non prouvé n'en est pas un",
         "Redémarrer un service ne démontre pas que la plateforme fonctionne de nouveau."),
    ]
    for i, (titre, texte) in enumerate(blocs):
        y = 236 + i * 120
        filet(d, 88, y, 520, 2, LIGNE_FORT)
        cadre = planche(d, 88, y + 12, 520, 40)
        ecrire(cadre, titre, taille=12, gras=True, interligne=1.05)
        cadre = planche(d, 88, y + 40, 520, 60)
        ecrire(cadre, texte, taille=11, couleur=ENCRE_DIM, interligne=1.15)
    cadre = planche(d, 680, 206, 544, 20)
    ecrire(cadre, "Cibles imposées", taille=9, couleur=ENCRE_DIM, police=MONO, majuscules=True,
           interlettre=8)
    filet(d, 680, 232, 544, 2, LIGNE_FORT)
    cibles = [
        ("Délai de détection", f"≤ {int(MESURES['cible_mttd_s'])} s"),
        ("Délai de rétablissement", f"≤ {int(MESURES['cible_mttr_s'])} s"),
        ("Preuves exigées", f"{len(MESURES['preuves'])} sur {len(MESURES['preuves'])}"),
        ("Actions sur la fenêtre", "6 au plus"),
    ]
    for i, (libelle, valeur) in enumerate(cibles):
        y = 250 + i * 46
        cadre = planche(d, 680, y, 300, 20)
        ecrire(cadre, libelle, taille=10, couleur=ENCRE_DIM, police=MONO, majuscules=True,
               interlettre=4)
        cadre = planche(d, 1000, y - 4, 224, 24)
        ecrire(cadre, valeur, taille=12, police=MONO, gras=True, aligne_droite=True)
        filet(d, 680, y + 30, 544)

    # --- 03 Architecture ---------------------------------------------------
    d = nouvelle_diapo(prs, "03", "Architecture")
    entete(d, "Architecture", "Trois plans étanches, du seul point exposé au moteur de reprise")
    plans = [
        ("Bordure", "edge, docker-proxy",
         "Le seul point exposé. WAF ModSecurity avec le jeu de règles OWASP, limite de débit, "
         "liste de blocage rechargée à chaud."),
        ("Détection", "telemetry, detector, prometheus, loki, alertmanager",
         f"Agrégation en fenêtres de 60 s, {f['arbre']} sur {f['variables']} variables, "
         "deux fenêtres consécutives avant notification."),
        ("Reprise", "remediation, vault, falco, playbooks",
         "Politiques déclaratives, playbooks versionnés, plafond d'actions, coupe-circuit, "
         "et preuves vérifiées avant toute clôture."),
    ]
    for i, (nom, services, texte) in enumerate(plans):
        y = 236 + i * 128
        filet(d, 88, y, 1104, 2, LIGNE_FORT)
        cadre = planche(d, 88, y + 14, 300, 20)
        ecrire(cadre, nom, taille=11, couleur=ACCENT, police=MONO, gras=True, majuscules=True,
               interlettre=6)
        cadre = planche(d, 88, y + 36, 1104, 20)
        ecrire(cadre, services, taille=9, couleur=ENCRE_DIM, police=MONO)
        cadre = planche(d, 88, y + 58, 1000, 60)
        ecrire(cadre, texte, taille=11, interligne=1.15)
    cadre = planche(d, 88, 612, 1104, 20)
    ecrire(
        cadre,
        f"{f['reseaux']} réseaux dont {f['reseaux_internes']} internes · "
        f"{f['services_suivis']} services suivis · {f['politiques']} politiques · "
        f"{f['playbooks']} playbooks · aucun port publié hors 443",
        taille=10,
        couleur=ENCRE_DIM,
        police=MONO,
    )

    # --- 04 Chaîne A1 ------------------------------------------------------
    d = nouvelle_diapo(prs, "04", "Chaine A1")
    entete(d, "Chaîne A1", "Détecter, confiner, redémarrer, vérifier")
    cadre = planche(d, 88, 206, 600, 20)
    ecrire(cadre, "Part de la cible consommée", taille=9, couleur=ENCRE_DIM, police=MONO,
           majuscules=True, interlettre=8)
    mesures = [
        ("Détection", MESURES["mttd_s"], MESURES["cible_mttd_s"],
         f"{MESURES['mttd_s']:.0f} s sur {MESURES['cible_mttd_s']:.0f} s"),
        ("Rétablissement", MESURES["mttr_s"], MESURES["cible_mttr_s"],
         f"{MESURES['mttr_s']:g} s sur {MESURES['cible_mttr_s']:.0f} s"
         .replace(".", ",")),
    ]
    for i, (libelle, valeur, cible, mention) in enumerate(mesures):
        y = 232 + i * 48
        cadre = planche(d, 88, y, 300, 20)
        ecrire(cadre, libelle, taille=10, police=MONO)
        cadre = planche(d, 1000, y, 192, 20)
        ecrire(cadre, mention, taille=10, police=MONO, aligne_droite=True)
        filet(d, 88, y + 32, 1104)
        part = max(4.0, min(1.0, valeur / cible) * 1104)
        filet(d, 88, y + 30, part, 3, NOMINAL)
    cadre = planche(d, 88, 354, 300, 20)
    ecrire(cadre, "Étape", taille=9, couleur=ENCRE_DIM, police=MONO, majuscules=True,
           interlettre=8)
    cadre = planche(d, 460, 354, 400, 20)
    ecrire(cadre, "Action du moteur", taille=9, couleur=ENCRE_DIM, police=MONO, majuscules=True,
           interlettre=8)
    cadre = planche(d, 1000, 354, 192, 20)
    ecrire(cadre, "Durée", taille=9, couleur=ENCRE_DIM, police=MONO, majuscules=True,
           interlettre=8, aligne_droite=True)
    filet(d, 88, 380, 1104, 1, LIGNE_FORT)
    for i, (etape, action, duree) in enumerate(MESURES["etapes"]):
        y = 388 + i * 28
        cadre = planche(d, 88, y, 340, 20)
        ecrire(cadre, etape, taille=10, police=MONO)
        cadre = planche(d, 460, y, 500, 20)
        ecrire(cadre, action, taille=10, couleur=ENCRE_DIM, police=MONO)
        cadre = planche(d, 1000, y, 192, 20)
        ecrire(cadre, duree, taille=10, police=MONO, aligne_droite=True)
        filet(d, 88, y + 22, 1104)
    cadre = planche(d, 88, 576, 1104, 20)
    ecrire(
        cadre,
        f"Incident clos RECOVERED · MTTR mesuré {MESURES['mttr_s']:g} s · "
        "plafond d'actions remis à zéro".replace(".", ","),
        taille=10,
        couleur=ENCRE_DIM,
        police=MONO,
    )

    # --- 05 Preuves --------------------------------------------------------
    d = nouvelle_diapo(prs, "05", "Preuves")
    entete(d, "Preuves", "Cinq contrôles avant de déclarer le rétablissement")
    for i, (nom, preuve) in enumerate(MESURES["preuves"]):
        y = 236 + i * 58
        filet(d, 88, y, 700)
        bloc(d, 88, y + 6, 8, 8, remplissage=NOMINAL)
        cadre = planche(d, 112, y, 660, 20)
        ecrire(cadre, nom, taille=11, gras=True)
        cadre = planche(d, 112, y + 20, 660, 24)
        ecrire(cadre, preuve, taille=10, couleur=ENCRE_DIM, police=MONO)
    bloc(d, 880, 230, 344, 300, remplissage=SURFACE, bordure=LIGNE_FORT)
    cadre = planche(d, 904, 254, 296, 20)
    ecrire(cadre, "État de la plateforme", taille=9, couleur=ENCRE_DIM, majuscules=True,
           interlettre=10)
    cadre = planche(d, 904, 280, 296, 70)
    ecrire(cadre, "RÉTABLI", taille=44, couleur=NOMINAL, police=BITTER, gras=True, interligne=1.0)
    filet(d, 904, 366, 296, 1, LIGNE_FORT)
    etat = [
        ("incident", "RECOVERED"),
        ("durée constatée", f"{MESURES['mttr_s']:g} s".replace(".", ",")),
        ("preuves", f"{len(MESURES['preuves'])} sur {len(MESURES['preuves'])}"),
        ("clôture", "automatique"),
    ]
    for i, (libelle, valeur) in enumerate(etat):
        y = 384 + i * 30
        cadre = planche(d, 904, y, 160, 20)
        ecrire(cadre, libelle, taille=9, couleur=ENCRE_DIM, police=MONO, majuscules=True,
               interlettre=4)
        cadre = planche(d, 904, y, 296, 20)
        ecrire(cadre, valeur, taille=10, police=MONO, aligne_droite=True)

    # --- 06 Limites --------------------------------------------------------
    d = nouvelle_diapo(prs, "06", "Limites")
    entete(d, "Limites", "Ce que le système ne prétend pas faire")
    limites = [
        ("Le confinement vise la signature du banc",
         "Une attaque qui imiterait un navigateur ordinaire échapperait à ce critère ; "
         "l'adresse reste disponible en second recours."),
        ("Le seuil est propre à ce déploiement",
         "Le seuil du détecteur est calibré sur le trafic simulé ; un autre profil de charge "
         "demande une recalibration."),
        ("La reprise reste locale",
         "Le moteur agit sur cette pile ; aucun scénario multi-région n'est couvert."),
        ("La vérification ne remplace pas un audit",
         "Cinq contrôles automatiques ne valent pas une revue humaine des journaux."),
    ]
    for i, (titre, texte) in enumerate(limites):
        y = 236 + i * 92
        filet(d, 88, y, 1104, 2, LIGNE_FORT)
        cadre = planche(d, 88, y + 12, 1104, 24)
        ecrire(cadre, titre, taille=12, gras=True)
        cadre = planche(d, 88, y + 40, 1000, 44)
        ecrire(cadre, texte, taille=11, couleur=ENCRE_DIM, interligne=1.15)
    cadre = planche(d, 88, 612, 1104, 20)
    ecrire(cadre, "Chaque limite est mesurée sur le banc, pas supposée.", taille=10,
           couleur=ENCRE_DIM, police=MONO)

    return prs


def main() -> None:
    faits_du_depot = faits()
    prs = construire(faits_du_depot)
    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    prs.save(SORTIE)
    print(f"{SORTIE} écrit : {len(prs.slides._sldIdLst)} diapositives")
    print(json.dumps(faits_du_depot, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
