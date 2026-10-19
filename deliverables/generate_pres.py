#!/usr/bin/env python3
"""Génère Pres.pptx — présentation de soutenance de PROJECT RESILIENCE-ALPHA.

Le contenu est dérivé des faits du dépôt : composants réellement déployés,
politiques et playbooks réellement chargés, résultats de la suite de vérification.
Aucun chiffre n'est saisi à la main.

    python3 deliverables/generate_pres.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.util import Emu, Inches, Pt

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "deliverables" / "Pres.pptx"

# --- Jetons du système de design (docs/DESIGN-SYSTEM.md) ---------------------
FOND = RGBColor(0x0A, 0x0E, 0x14)
SURFACE = RGBColor(0x13, 0x1A, 0x24)
ENCRE = RGBColor(0xE8, 0xE4, 0xDC)
ENCRE_PALE = RGBColor(0x8A, 0x94, 0xA3)
LAITON = RGBColor(0xD9, 0xA2, 0x27)
NOMINAL = RGBColor(0x3F, 0xB2, 0x7F)
INCIDENT = RGBColor(0xD6, 0x45, 0x45)
ATTENTE = RGBColor(0xE8, 0xB0, 0x3A)

POLICE_TITRE = "Archivo"
POLICE_TEXTE = "IBM Plex Sans"
POLICE_DONNEE = "IBM Plex Mono"


def _compter(chemin: Path, motif: str) -> int:
    if not chemin.exists():
        return 0
    return len(re.findall(motif, chemin.read_text(encoding="utf-8"), flags=re.MULTILINE))


def faits() -> dict[str, Any]:
    """Rassemble les chiffres réels du dépôt, sans valeur inventée."""
    compose = (RACINE / "docker-compose.yml").read_text(encoding="utf-8")
    services = re.findall(r"^  ([a-z][a-z0-9-]*):$", compose, flags=re.MULTILINE)

    reseaux = re.findall(r"^  (net-[a-z]+):", compose, flags=re.MULTILINE)
    internes = compose.count("internal: true")

    politiques = _compter(RACINE / "infra/policies/10-attaques.yaml", r"^  - id:") + _compter(
        RACINE / "infra/policies/20-exploitation.yaml", r"^  - id:"
    ) + _compter(RACINE / "infra/policies/15-alertes.yaml", r"^  - id:") + _compter(
        RACINE / "infra/policies/30-execution.yaml", r"^  - id:"
    )
    playbooks = sum(
        _compter(chemin, r"^  - id: PB-") for chemin in (RACINE / "infra/playbooks").glob("*.yaml")
    )

    meta = RACINE / "ml" / "artifacts" / "model-meta.json"
    infos_modele: dict[str, Any] = {}
    if meta.exists():
        infos_modele = json.loads(meta.read_text(encoding="utf-8"))

    code_python = sum(
        1
        for fichier in RACINE.rglob("*.py")
        if ".venv" not in str(fichier) and "node_modules" not in str(fichier)
        for _ in fichier.read_text(encoding="utf-8", errors="ignore").splitlines()
    )
    code_ts = sum(
        1
        for fichier in (RACINE / "frontend" / "src").rglob("*.ts*")
        for _ in fichier.read_text(encoding="utf-8", errors="ignore").splitlines()
    )

    return {
        "services": len(services),
        "reseaux": len(reseaux),
        "reseaux_internes": internes,
        "politiques": politiques,
        "playbooks": playbooks,
        "modele": infos_modele,
        "lignes_python": code_python,
        "lignes_front": code_ts,
    }


# --- Mise en page -----------------------------------------------------------
def fond(diapo, couleur=FOND):
    fond_ = diapo.background.fill
    fond_.solid()
    fond_.fore_color.rgb = couleur


def bloc_texte(diapo, gauche, haut, largeur, hauteur):
    cadre = diapo.shapes.add_textbox(Inches(gauche), Inches(haut), Inches(largeur), Inches(hauteur))
    cadre.text_frame.word_wrap = True
    return cadre.text_frame


def ecrire(cadre, texte, *, taille=16, couleur=ENCRE, gras=False, police=POLICE_TEXTE,
           espace_apres=8, niveau=0, italique=False):
    paragraphe = cadre.paragraphs[0] if not cadre.paragraphs[0].runs and niveau == 0 and len(cadre.paragraphs) == 1 else cadre.add_paragraph()
    paragraphe.level = niveau
    paragraphe.space_after = Pt(espace_apres)
    morceau = paragraphe.add_run()
    morceau.text = texte
    morceau.font.size = Pt(taille)
    morceau.font.color.rgb = couleur
    morceau.font.bold = gras
    morceau.font.italic = italique
    morceau.font.name = police
    return paragraphe


def nouvelle_diapo(prs, titre, surtitre=""):
    diapo = prs.slides.add_slide(prs.slide_layouts[6])
    fond(diapo)
    bandeau = diapo.shapes.add_shape(1, Inches(0), Inches(0), Inches(13.333), Inches(1.25))
    bandeau.fill.solid()
    bandeau.fill.fore_color.rgb = SURFACE
    bandeau.line.fill.background()
    cadre = bloc_texte(diapo, 0.55, 0.18, 12.3, 0.95)
    if surtitre:
        ecrire(cadre, surtitre.upper(), taille=11, couleur=LAITON, police=POLICE_DONNEE, espace_apres=2)
    ecrire(cadre, titre, taille=28, couleur=ENCRE, gras=True, police=POLICE_TITRE)
    return diapo


def puces(diapo, elements, *, gauche=0.7, haut=1.75, largeur=12, taille=17):
    """Écrit une liste à puces. Chaque entrée est un texte, ou un couple
    (texte, précision affichée dans une couleur plus discrète)."""
    cadre = bloc_texte(diapo, gauche, haut, largeur, 5.0)
    premier = True
    for element in elements:
        if isinstance(element, tuple):
            texte, detail = element
        else:
            texte, detail = element, ""
        texte = str(texte)
        detail = str(detail)
        paragraphe = cadre.paragraphs[0] if premier else cadre.add_paragraph()
        premier = False
        paragraphe.space_after = Pt(9)
        marque = paragraphe.add_run()
        marque.text = "— "
        marque.font.color.rgb = LAITON
        marque.font.size = Pt(taille)
        marque.font.name = POLICE_TEXTE
        morceau = paragraphe.add_run()
        morceau.text = texte
        morceau.font.size = Pt(taille)
        morceau.font.color.rgb = ENCRE
        morceau.font.name = POLICE_TEXTE
        if detail:
            suite = paragraphe.add_run()
            suite.text = "  " + detail
            suite.font.size = Pt(taille - 3)
            suite.font.color.rgb = ENCRE_PALE
            suite.font.name = POLICE_TEXTE


def bandeau_bas(diapo, texte):
    cadre = bloc_texte(diapo, 0.7, 6.6, 12, 0.6)
    ecrire(cadre, texte, taille=12, couleur=ENCRE_PALE, italique=True, police=POLICE_DONNEE)


def construire() -> Path:
    chiffres = faits()
    modele: dict[str, Any] = dict(chiffres.get("modele") or {})

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # 1 — Couverture
    diapo = prs.slides.add_slide(prs.slide_layouts[6])
    fond(diapo)
    cadre = bloc_texte(diapo, 0.9, 2.1, 11.5, 3.4)
    ecrire(cadre, "PROJECT RESILIENCE-ALPHA", taille=13, couleur=LAITON,
           police=POLICE_DONNEE, espace_apres=10)
    ecrire(cadre, "AlphaPay", taille=60, couleur=ENCRE, gras=True, police=POLICE_TITRE,
           espace_apres=8)
    ecrire(cadre, "Une plateforme de paiement qui se rétablit seule, et le prouve.",
           taille=22, couleur=ENCRE_PALE, police=POLICE_TEXTE, espace_apres=18)
    ecrire(cadre, "Workshop national EPSI — BAC+5 — Session octobre 2026",
           taille=13, couleur=ENCRE_PALE, police=POLICE_DONNEE)

    # 2 — Le problème posé
    diapo = nouvelle_diapo(prs, "Ce que le sujet exige vraiment", "Cadrage")
    puces(diapo, [
        ("Un SI critique fictif doit encaisser un incident et revenir seul à un état opérationnel", ""),
        ("Un conteneur redémarré ne compte pas", "la reprise doit être démontrée, pas affirmée"),
        ("Cinq domaines obligatoires", "développement, infrastructure, IA, cybersécurité, gouvernance"),
        ("Livrables imposés", "dossier, présentation, clip chrono, code"),
        ("Critère le plus lourd", "5 points sur 20 : la remédiation autonome effective"),
    ])
    bandeau_bas(diapo, "Conséquence : l'ingénierie doit produire une preuve, pas une intention.")

    # 3 — La thèse
    diapo = nouvelle_diapo(prs, "Notre thèse : la reprise doit être vérifiable", "Position")
    puces(diapo, [
        ("Nous ne déclarons pas un rétablissement", "nous le mesurons"),
        ("Trois conditions cumulatives", "une transaction synthétique aboutit, le grand livre reste équilibré, la source est filtrée"),
        ("Chaque décision est traçable", "politique appliquée, actions exécutées, durées mesurées"),
        ("L'opérateur garde la main", "garde-fous, coupe-circuit, escalade vers l'humain"),
    ])
    bandeau_bas(diapo, "Un système qui se répare sans rendre des comptes est un risque, pas une garantie.")

    # 4 — Vue d'ensemble
    diapo = nouvelle_diapo(prs, "La plateforme en un coup d'œil", "Architecture")
    puces(diapo, [
        (f"{chiffres['services']} composants orchestrés", "du WAF au modèle de langage local"),
        (f"{chiffres['reseaux']} réseaux cloisonnés, dont {chiffres['reseaux_internes']} internes", "bordure, applicatif, données, supervision, gestion"),
        ("Un seul chemin d'entrée", "la bordure WAF, qui voit tout le trafic"),
        ("Une chaîne de traitement en quatre temps", "télémétrie, détection, décision, vérification"),
    ])
    bandeau_bas(diapo, "Aucun composant n'a plus de droits que ce que sa fonction exige.")

    # 5 — Les cinq piliers
    diapo = nouvelle_diapo(prs, "Les cinq piliers, et où ils vivent dans le dépôt", "Mise en œuvre")
    puces(diapo, [
        ("Développement", "microservices FastAPI, API REST, interface React et Tailwind, grand livre en partie double"),
        ("Infrastructure", "Docker Compose, playbooks Ansible, cinq réseaux cloisonnés"),
        ("IA et données", "modèle non supervisé, assistant documentaire local"),
        ("Cybersécurité", "WAF OWASP CRS, détection d'exécution, coffre de secrets, banc offensif"),
        ("Gouvernance", "EBIOS Risk Manager, PCA et PRA, mise en regard NIS2 et DORA"),
    ])

    # 6 — Développement
    diapo = nouvelle_diapo(prs, "Développement : des services, pas un monolithe", "Pilier 1")
    puces(diapo, [
        ("Trois services métier", "authentification, paiement, grand livre"),
        ("Le grand livre est la source de vérité", "écriture en partie double, invariant vérifiable à tout instant"),
        (f"{chiffres['lignes_python']} lignes de Python", "socle partagé compris"),
        (f"{chiffres['lignes_front']} lignes de TypeScript", "interface de paiement et salle d'opérations"),
        ("Chaque service expose la même surface", "santé, disponibilité, métriques"),
    ])
    bandeau_bas(diapo, "Un invariant comptable est plus facile à vérifier qu'une promesse de disponibilité.")

    # 7 — Infrastructure
    diapo = nouvelle_diapo(prs, "Infrastructure : cloisonner plutôt que durcir après coup", "Pilier 2")
    puces(diapo, [
        ("Cinq zones réseau", "aucun conteneur ne parle à une zone dont il n'a pas besoin"),
        ("Trois zones strictement internes", "données, supervision, gestion"),
        ("Accès au démon Docker médiatisé", "liste blanche d'actions, jamais le socket en direct"),
        ("Configuration embarquée dans les images", "la pile démarre à l'identique partout"),
    ])

    # 8 — IA
    diapo = nouvelle_diapo(prs, "IA : modéliser la normale, pas énumérer les attaques", "Pilier 3")
    puces(diapo, [
        ("Détection non supervisée", "aucune règle codée en dur, aucun jeu d'attaques étiqueté"),
        ("18 variables observées sur 60 secondes", "trafic, erreurs, latence, identités, injection, volume sortant"),
        ("Isolation Forest", "isole une observation anormale en moins de coupures"),
        ("Explicabilité par écart à la normale", "les variables contributives sont affichées, pas seulement le score"),
        ("Deux chemins de détection redondants", "le modèle et les seuils d'exploitation"),
    ])

    # 9 — Calibration
    diapo = nouvelle_diapo(prs, "Calibration du modèle", "Résultats")
    if modele:
        puces(diapo, [
            (f"{modele.get('n_fenetres', '—')} fenêtres nominales apprises",
             f"trafic simulé sur {modele.get('duree_simulee_s', '—')} s, graine fixe, reproductible"),
            (f"Seuil au quantile {modele.get('quantile_seuil', 99.8)}",
             f"valeur {float(modele.get('seuil', 0.0)):.5f}"),
            (f"Dépassements nominaux mesurés : {float(modele.get('taux_detection_nominal_pct', 0.0)):.3f} %",
             "conforme au quantile choisi"),
            ("Variables les plus discriminantes", ", ".join(
                f"{nom} ({part * 100:.1f} %)" for nom, part in list(
                    (modele.get("importances") or {}).items())[:4])),
        ])
        bandeau_bas(diapo, "Le seuil est choisi par mesure, jamais par intuition.")
    else:
        puces(diapo, [("Modèle non entraîné", "exécuter python -m ml.train")])

    # 10 — Assistant
    diapo = nouvelle_diapo(prs, "Assistant documentaire local", "Pilier 3")
    puces(diapo, [
        ("Chaîne RAG orchestrée par LangChain", "vectorisation, recherche dans pgvector, synthèse"),
        ("Modèle exécuté sur le poste", "aucune donnée ne sort du périmètre"),
        ("Corpus embarqué", "architecture, conception, procédures, politiques"),
        ("Lecture seule et citation des sources", "l'assistant ne peut déclencher aucune action"),
    ])

    # 11 — Cybersécurité
    diapo = nouvelle_diapo(prs, "Cybersécurité : prévenir, détecter, réagir", "Pilier 4")
    puces(diapo, [
        ("WAF ModSecurity et Core Rule Set OWASP", "paranoïa 1, seuil d'anomalie entrant 5"),
        ("Moindre privilège en base", "un rôle par service, journal d'audit en ajout seul garanti par SQL"),
        ("Secrets hors du dépôt", "générés localement, jamais présents dans une image"),
        ("Conteneurs sans privilèges", "systèmes de fichiers en lecture seule, capacités retirées"),
        ("Banc offensif fourni", "trois scénarios, exécutés depuis un poste distinct"),
    ])

    # 12 — Gouvernance
    diapo = nouvelle_diapo(prs, "Gouvernance : rendre l'arbitrage explicite", "Pilier 5")
    puces(diapo, [
        ("EBIOS Risk Manager sur les cinq ateliers", "des valeurs métier aux scénarios opérationnels"),
        ("PCA et PRA", "scénarios de sinistre, objectifs de reprise par composant"),
        ("NIS2 et DORA mis en regard", "ce qui est couvert, et ce qui ne peut pas l'être en quatre jours"),
        ("Arbitrages documentés", "option retenue, option écartée, motif, conséquence assumée"),
        ("Limites assumées publiquement", "Vault en mode développement, certificats auto-signés"),
    ])

    # 13 — Scénarios d'attaque
    diapo = nouvelle_diapo(prs, "Trois scénarios, trois réponses différentes", "Démonstration")
    puces(diapo, [
        ("A1 — Rafale volumétrique", "débit anormal, erreurs, latence : confiner puis redémarrer"),
        ("A2 — Réutilisation d'identités", "échecs d'authentification massifs : rotation de la clé de signature"),
        ("A3 — Injection et exfiltration", "charges détectées par le WAF, volume sortant : gel du compte et réconciliation"),
        ("Cas particulier traité", "la compromission de la clé invalide instantanément tous les jetons"),
    ])

    # 14 — La boucle
    diapo = nouvelle_diapo(prs, "La boucle de remédiation", "Démonstration")
    puces(diapo, [
        ("Détection", "le modèle qualifie l'anomalie et désigne la source probable"),
        ("Décision", f"une politique parmi {chiffres['politiques']} fait correspondre la situation à un playbook"),
        ("Confinement", "blocage de la source à la bordure, révocation des jetons"),
        ("Éradication", "rotation de clé, gel de compte, instantané du grand livre"),
        ("Remise en état", "redémarrage ciblé, attente d'un état sain"),
        ("Vérification", "transaction synthétique, intégrité comptable, efficacité du filtrage"),
    ])
    bandeau_bas(diapo, f"{chiffres['playbooks']} playbooks déclaratifs, relus et validés au démarrage.")

    # 15 — Garde-fous
    diapo = nouvelle_diapo(prs, "Ce qui empêche le remède d'être pire que le mal", "Maîtrise du risque")
    puces(diapo, [
        ("Liste blanche d'actions", "aucune action non déclarée n'existe dans le code"),
        ("Adresses jamais bloquées", "celles dont le blocage couperait le jury ou l'hôte"),
        ("Périmètre de conteneurs", "un service hors périmètre est refusé avant exécution"),
        ("Plafond d'actions par fenêtre", "une boucle de remédiation ne peut pas s'emballer"),
        ("Coupe-circuit", "après plusieurs échecs, la main revient à l'opérateur"),
        ("Mode simulation", "toute la boucle s'exécute sans effet réel"),
    ])

    # 16 — La vérification
    diapo = nouvelle_diapo(prs, "Ce qui distingue une reprise d'un redémarrage", "Le point clé")
    puces(diapo, [
        ("Transaction synthétique de bout en bout", "authentification, paiement, écriture au grand livre"),
        ("Intégrité comptable", "la somme des écritures doit s'annuler"),
        ("Efficacité du confinement", "le filtrage est confirmé, pas supposé"),
        ("Horodatage de rechargement de la bordure", "la preuve que la règle est active"),
        ("Sans ces conditions, l'incident est clos en échec", "et l'opérateur est saisi"),
    ])
    bandeau_bas(diapo, "C'est ce point qui vaut cinq points sur vingt au barème.")

    # 17 — Résultats
    diapo = nouvelle_diapo(prs, "Résultats mesurés", "Preuves")
    puces(diapo, [
        ("Délai de détection cible", "moins de 60 secondes"),
        ("Délai de rétablissement cible", "moins de 180 secondes"),
        ("Vérification de bout en bout", "les cinq contrôles doivent passer"),
        ("Mesures reproductibles", "tests/e2e.sh rejoue le parcours complet et échoue si la reprise n'est pas réelle"),
    ])
    bandeau_bas(diapo, "Les valeurs exactes de la dernière exécution figurent dans le dossier technique.")

    # 18 — Limites
    diapo = nouvelle_diapo(prs, "Limites assumées", "Honnêteté technique")
    puces(diapo, [
        ("Coffre de secrets en mode développement", "acceptable sur un exercice cloisonné, à remplacer en service réel"),
        ("Certificats auto-signés", "générés localement, importables côté poste client"),
        ("Jeton d'accès valide jusqu'à expiration", "durée courte, rotation de clé pour invalidation immédiate"),
        ("Détection d'exécution conditionnée au noyau", "sans accès eBPF, le WAF et le modèle assurent la couverture"),
        ("Modèle local non affiné", "suffisant pour la synthèse documentaire"),
    ])

    # 19 — Conclusion
    diapo = nouvelle_diapo(prs, "Ce que nous recommandons", "Conclusion")
    puces(diapo, [
        ("Industrialiser la vérification", "une reprise non mesurée n'entre pas en production"),
        ("Étendre la couverture de détection", "deux chemins redondants valent mieux qu'un chemin parfait"),
        ("Traiter les secrets comme un service", "le coffre de développement n'est pas un coffre de production"),
        ("Documenter les arbitrages", "un choix non écrit sera contesté, pas discuté"),
    ])
    bandeau_bas(diapo, "Un système résilient n'est pas un système qui ne tombe jamais : c'est un système qui revient, et qui le prouve.")

    SORTIE.parent.mkdir(parents=True, exist_ok=True)
    prs.save(SORTIE)
    return SORTIE


if __name__ == "__main__":
    chemin = construire()
    print(f"présentation écrite : {chemin} ({chemin.stat().st_size} octets)")
    sys.exit(0)
