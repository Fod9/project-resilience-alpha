#!/usr/bin/env python3
"""Assemble le dossier HTML a partir des fragments de src/.

Chaque fragment devient une feuille A4 explicite, portant son en-tete et son
pied. Le fichier produit est ecrit a la racine du dossier (et non dans build/)
pour que les chemins relatifs style.css, polices et marque.svg restent valides.

Chrome headless ne sait pas placer un element position:fixed dans la marge de
@page : il rend les valeurs negatives a l'oppose (un top negatif tombe en bas).
La pagination est donc explicite, ce qui garantit aussi qu'aucune section ne se
coupe en deux.
"""
from __future__ import annotations

import sys
from pathlib import Path

SQUELETTE = """<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>AlphaPay, dossier d'ingenierie et de gouvernance</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
{corps}
</body>
</html>
"""

ENTETE = """  <div class="entete"><span class="marque">AlphaPay</span><span class="ref">Dossier d'ingénierie et de gouvernance</span></div>"""


def pied(numero: int, total: int) -> str:
    return (
        '  <div class="pied"><span>Project Resilience-Alpha &middot; Workshop 2026 &middot; '
        f'groupe 1</span><span class="num">page {numero} sur {total}</span></div>'
    )


def main() -> int:
    if len(sys.argv) != 3:
        print("usage : assembler.py <dossier> <sortie>")
        return 2
    dossier = Path(sys.argv[1])
    sortie = Path(sys.argv[2])

    fragments = sorted((dossier / "src").glob("*.html"))
    if not fragments:
        print("aucun fragment dans src/")
        return 1

    total = len(fragments)
    feuilles = []
    for index, fragment in enumerate(fragments, 1):
        contenu = fragment.read_text(encoding="utf-8").rstrip()
        garde = fragment.name.startswith("00")
        morceaux = [f'<div class="feuille">']
        if not garde:
            morceaux.append(ENTETE)
        morceaux.append(f'  <div class="corps">\n{contenu}\n  </div>')
        morceaux.append(pied(index, total))
        morceaux.append("</div>")
        feuilles.append(f"<!-- {fragment.name} -->\n" + "\n".join(morceaux))

    sortie.write_text(SQUELETTE.format(corps="\n\n".join(feuilles)), encoding="utf-8")
    print(f"assemble : {sortie} ({total} feuilles, {sortie.stat().st_size} octets)")
    for f in fragments:
        print(f"  {f.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
