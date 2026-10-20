"""Suivi incrémental de fichiers de journaux.

Ne relit jamais ce qui a déjà été lu, résiste à la rotation des fichiers, et
n'amorce pas l'historique : au démarrage, on se place à la fin de chaque
fichier. Sans cette précaution, un redémarrage de la télémétrie ferait
apparaître tout l'historique comme un unique pic de trafic, ce qui déclencherait
une détection d'anomalie parfaitement injustifiée.
"""

from __future__ import annotations

import os
from collections.abc import Iterable


class SuiveurDeFichiers:
    def __init__(self, chemins: Iterable[str]) -> None:
        self._chemins = list(chemins)
        self._positions: dict[str, int] = {}
        self._amorce = False

    @property
    def chemins(self) -> list[str]:
        return list(self._chemins)

    def _position(self, chemin: str) -> int:
        if chemin not in self._positions:
            try:
                self._positions[chemin] = os.path.getsize(chemin)
            except OSError:
                self._positions[chemin] = 0
        return self._positions[chemin]

    def amorcer(self) -> None:
        """Se place à la fin de chaque fichier existant."""
        for chemin in self._chemins:
            self._position(chemin)
        self._amorce = True

    def ajouter(self, chemins: Iterable[str]) -> list[str]:
        """Ajoute les chemins pas encore suivis, et renvoie les nouveaux.

        Les fichiers de journaux n'existent pas tous au démarrage : chaque
        service crée le sien au premier événement qu'il écrit, et le répertoire
        lui-même peut être monté après le lancement. Une liste figée au départ
        ignore donc à jamais tout ce qui apparaît ensuite — et la télémétrie
        peut passer sa vie entière avec zéro fichier suivi, donc zéro événement,
        sans le moindre message d'erreur. C'est exactement ce qui s'était
        produit : le répertoire a été créé six secondes après le démarrage, et
        les 279 fenêtres publiées ensuite étaient toutes vides.
        """
        nouveaux = [
            chemin
            for chemin in chemins
            if chemin not in self._chemins and chemin not in self._positions
        ]
        for chemin in nouveaux:
            self._chemins.append(chemin)
            if self._amorce:
                # On se place à la fin : un fichier découvert en cours de route ne
                # doit pas rejouer tout son historique comme un pic de trafic.
                self._position(chemin)
        return nouveaux

    def lire(self) -> list[tuple[str, str]]:
        """Renvoie la liste des nouvelles lignes, sous forme (chemin, contenu)."""
        if not self._amorce:
            self.amorcer()
        lignes: list[tuple[str, str]] = []
        for chemin in self._chemins:
            try:
                taille = os.path.getsize(chemin)
            except OSError:
                continue
            position = self._position(chemin)
            # Rotation : le fichier est devenu plus petit, ou a été remplacé.
            if taille < position:
                position = 0
            if taille == position:
                continue
            try:
                with open(chemin, encoding="utf-8", errors="replace") as fichier:
                    fichier.seek(position)
                    for ligne in fichier:
                        ligne = ligne.rstrip("\n")
                        if ligne:
                            lignes.append((chemin, ligne))
                    self._positions[chemin] = fichier.tell()
            except OSError:
                continue
        return lignes
