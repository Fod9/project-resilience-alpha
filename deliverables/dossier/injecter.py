#!/usr/bin/env python3
"""Assemble le dossier : injecte les SVG Mermaid inline dans le HTML.

Les SVG sont inlines (et non references par <img>) pour que les polices
auto-hebergees du dossier s'appliquent aussi aux schemas.

Usage : python3 injecter.py dossier.html build/dossier-inline.html build/svg
"""
import re
import sys
from pathlib import Path


def nettoyer_svg(texte: str) -> str:
    texte = re.sub(r"<\?xml[^>]*\?>", "", texte, count=1)
    texte = re.sub(r"<!DOCTYPE[^>]*>", "", texte, count=1)
    # Retire largeur/hauteur figees : le CSS du dossier pilote la taille.
    texte = re.sub(r'(<svg[^>]*?)\s(width|height)="[^"]*"', r"\1", texte, count=1)
    # Mermaid ajoute un style max-width, on le neutralise pour un rendu plein cadre.
    texte = texte.replace("style=\"max-width:", "style=\"max-width:none;")
    return texte.strip()


def main() -> int:
    source, cible, dossier_svg = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    html = source.read_text(encoding="utf-8")
    manquants = []
    for cle in sorted(set(re.findall(r"<!--SVG:([a-zA-Z0-9_-]+)-->", html))):
        fichier = dossier_svg / f"{cle}.svg"
        if not fichier.is_file():
            manquants.append(cle)
            continue
        html = html.replace(f"<!--SVG:{cle}-->", nettoyer_svg(fichier.read_text(encoding="utf-8")))
    if manquants:
        print(f"ERREUR : schemas absents : {', '.join(manquants)}", file=sys.stderr)
        return 2
    cible.write_text(html, encoding="utf-8")
    restants = re.findall(r"<!--SVG:[a-zA-Z0-9_-]+-->", html)
    print(f"HTML assemble : {cible} ({len(html)} caracteres, {len(restants)} emplacement(s) non resolu(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
