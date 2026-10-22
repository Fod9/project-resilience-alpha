#!/usr/bin/env python3
"""Verifie le modele de detection REELLEMENT en place sur la plateforme.

Trois questions, dans cet ordre, et aucune ne se deduit des deux autres :

1. quel modele est charge, avec quel seuil ;
2. la derniere fenetre notee est-elle fraiche, ou le detecteur n'a-t-il
   simplement plus rien eu a noter ;
3. les fenetres d'attaque reellement mesurees franchissent-elles ce seuil.

Le point 2 est un piege courant : `/score/current` sert la derniere fenetre
*notee*, pas la fenetre courante. Sur une plateforme sans trafic metier, il
ressert indefiniment la meme lecture et le dispositif parait gele.

Usage, depuis la racine du depot :

    # 1. recuperer le modele en place
    docker compose exec -T detector cat /models/model.joblib > /tmp/modele-en-place.joblib

    # 2. verifier
    python3 ml/verifier_modele_en_place.py --modele /tmp/modele-en-place.joblib

Options :
    --base      racine de la telemetrie   (defaut http://127.0.0.1/api/telemetry)
    --detecteur racine du detecteur       (defaut http://127.0.0.1/api/detector)
    --limite    fenetres d'historique     (defaut 360)
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

import joblib
import numpy as np

MARQUES_OFFENSIVES = ("redteam",)


def lire(url, timeout=20):
    contexte = ssl.create_default_context()
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    requete = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(requete, timeout=timeout, context=contexte) as reponse:
        return json.loads(reponse.read().decode("utf-8", "replace"))


def noter(modele, scaler, fenetres, noms):
    if not fenetres:
        return np.array([])
    matrice = np.array(
        [[float((f.get("features") or {}).get(n) or 0.0) for n in noms] for f in fenetres],
        dtype=float,
    )
    return np.array(
        [-modele.decision_function(scaler.transform([v]))[0] for v in matrice], dtype=float
    )


def agression(fenetre):
    diagnostics = fenetre.get("diagnostics") or {}
    agents = [str(a).lower() for a in (diagnostics.get("agents_offensifs") or [])]
    if diagnostics.get("agent_offensif"):
        agents.append(str(diagnostics["agent_offensif"]).lower())
    for agent in agents:
        for marque in MARQUES_OFFENSIVES:
            if marque in agent:
                return True
    return False


def metier(fenetre):
    diagnostics = fenetre.get("diagnostics") or {}
    valeur = diagnostics.get("edge_events_metier")
    if valeur is None:
        valeur = fenetre.get("edge_events_in_window")
    return int(valeur or 0)


MODELES_CONNUS = (
    "/models/model.joblib",
    "/app/artifacts/model.joblib",
)


def charger(chemin: str):
    """Charge le modele demande, ou le cherche aux emplacements connus.

    `/models` est le volume ou la calibration ecrit ; il est vide tant qu'aucune
    recalibration n'a tourne, et le detecteur retombe alors sur l'artefact
    embarque dans l'image. Confondre les deux, c'est croire qu'on verifie le
    modele recalibre alors qu'on lit celui du depot.
    """
    candidats = [chemin] if chemin else list(MODELES_CONNUS)
    for candidat in candidats:
        try:
            return candidat, joblib.load(candidat)
        except FileNotFoundError:
            continue
    raise SystemExit(
        "aucun modele trouve. Cherche : %s" % ", ".join(candidats)
    )


def main() -> int:
    analyseur = argparse.ArgumentParser(description="Verifie le modele en place.")
    analyseur.add_argument("--modele", default=None, help="chemin du modele ; cherche /models puis /app/artifacts")
    analyseur.add_argument("--base", default="http://127.0.0.1/api/telemetry")
    analyseur.add_argument("--detecteur", default="http://127.0.0.1/api/detector")
    analyseur.add_argument("--limite", type=int, default=360)
    args = analyseur.parse_args()

    chemin, paquet = charger(args.modele)
    modele = paquet["modele"]
    scaler = paquet["scaler"]
    noms = list(paquet.get("feature_names") or [])
    seuil = float(paquet["seuil"])

    print("=== modele charge depuis le fichier")
    print("  fichier      : %s" % chemin)
    print("  version      : %s" % paquet.get("version"))
    print("  origine      : %s" % paquet.get("source_calibrage"))
    print("  seuil        : %.6f" % seuil)
    print("  variables    : %d" % len(noms))
    for cle in ("score_max_nominal", "score_min_attaque", "marge_separabilite",
                "reference_attaque", "n_fenetres", "n_fenetres_mesurees"):
        if paquet.get(cle) is not None:
            print("  %-12s : %s" % (cle, paquet[cle]))

    try:
        annonce = lire(args.detecteur.rstrip("/") + "/model")
        print("=== modele annonce par le detecteur (source de verite)")
        print("  version      : %s" % annonce.get("version"))
        print("  seuil annonce: %s" % annonce.get("threshold"))
        print("  fenetres     : %s" % annonce.get("trained_windows"))
        ecart = abs(float(annonce.get("threshold") or 0.0) - seuil)
        print("  concordance avec le fichier : %s" % ("oui" if ecart < 1e-9 else "NON, ecart %.6f" % ecart))
    except urllib.error.URLError as erreur:
        print("detecteur injoignable sur %s (%s)" % (args.detecteur, erreur))
        return 1

    try:
        courant = lire(args.detecteur.rstrip("/") + "/score/current")
    except urllib.error.URLError:
        courant = {}
    print("=== derniere fenetre notee")
    print("  available    : %s" % courant.get("available", "oui"))
    print("  detecte le   : %s" % courant.get("detected_at"))
    print("  fenetre      : %s -> %s" % (courant.get("window_start"), courant.get("window_end")))
    if courant.get("score") is not None:
        print("  score        : %.6f   seuil %.6f   depassement %.2f" % (
            float(courant["score"]), float(courant.get("threshold") or seuil),
            float(courant.get("exceedance") or 0.0)))
        print("  anormal      : %s (fenetres consecutives %s, il en faut 2)" % (
            courant.get("anomalous"), courant.get("consecutive_windows")))
    print("  rappel       : cette lecture est la derniere fenetre NOTEE, pas la")
    print("                 fenetre courante. Comparez 'detecte le' a l'heure qu'il")
    print("                 est avant d'en conclure que le dispositif est gele.")

    historique = (lire(args.base.rstrip("/") + "/features/history?limit=%d" % args.limite)
                  .get("windows") or [])
    utiles = [f for f in historique if metier(f) > 0]
    attaques = [f for f in utiles if agression(f)]
    nominales = [f for f in utiles if not agression(f)]
    print("=== historique : %d fenetres, %d avec du trafic metier" % (len(historique), len(utiles)))
    print("  dont %d portant la marque du banc offensif, %d nominales" % (len(attaques), len(nominales)))

    scores_nominales = noter(modele, scaler, nominales, noms)
    scores_attaques = noter(modele, scaler, attaques, noms)
    if scores_nominales.size:
        print("  nominal : mediane %.4f, maximum %.4f" % (
            float(np.median(scores_nominales)), float(scores_nominales.max())))
    for etiquette, scores in (("ATT", scores_attaques),):
        for fenetre, score in sorted(zip(attaques, scores.tolist()), key=lambda p: -p[1]):
            features = fenetre.get("features") or {}
            print("  %s %s score %.4f %s  rps %.1f  err %.3f" % (
                etiquette, str(fenetre.get("window_end"))[11:19], score,
                "AU-DESSUS" if score >= seuil else "sous seuil",
                float(features.get("requests_per_second") or 0.0),
                float(features.get("error_ratio") or 0.0)))

    if not attaques:
        print("=== verdict")
        print("  aucune agression mesuree dans l'historique : le modele ne peut pas")
        print("  etre juge sur des faits. Rejouez une attaque, puis relancez ce script.")
        return 0

    # Le score d'atypie est une synthese sur 18 variables : quand il ne separe
    # pas, il faut savoir si une variable, elle, separe. C'est ce qui distingue
    # un probleme de seuil d'un probleme de variables.
    print("=== separation variable par variable (mesuree)")
    print("  %-24s %10s %10s %10s" % ("variable", "nom max", "ATT min", "rapport"))
    separantes = []
    for nom in noms:
        valeurs_nom = [
            float((f.get("features") or {}).get(nom) or 0.0) for f in nominales
        ]
        valeurs_att = [
            float((f.get("features") or {}).get(nom) or 0.0) for f in attaques
        ]
        if not valeurs_nom or not valeurs_att:
            continue
        haut = max(valeurs_nom)
        bas = min(valeurs_att)
        if bas > haut > 0:
            rapport = bas / haut
            print("  %-24s %10.4f %10.4f %10.2f  SEPARE" % (nom, haut, bas, rapport))
            separantes.append((rapport, nom, haut, bas))
        elif bas > 0 and haut <= 0:
            print("  %-24s %10.4f %10.4f %10s  SEPARE" % (nom, haut, bas, "infini"))
            separantes.append((float("inf"), nom, haut, bas))
    if not separantes:
        print("  aucune variable ne separe les deux bandes mesurees.")
    else:
        separantes.sort(reverse=True)
        print("  variables separantes, de la plus nette a la moins nette :")
        for rapport, nom, haut, bas in separantes[:6]:
            print("    %-24s nominal <= %.4f  <  attaque >= %.4f" % (nom, haut, bas))

    print("=== verdict")
    haut_nominal = float(scores_nominales.max()) if scores_nominales.size else float("-inf")
    bas_attaque = float(scores_attaques.min())
    if bas_attaque <= seuil:
        pires = (scores_attaques >= seuil).sum()
        print("  %d fenetre(s) d'attaque sur %d franchissent le seuil." % (pires, len(attaques)))
        print("  Le modele en place ne detecte pas l'attaque mesuree : la plus faible")
        print("  est notee %.4f pour un seuil de %.4f." % (bas_attaque, seuil))
        return 2
    print("  toutes les fenetres d'attaque franchissent le seuil (min %.4f > %.4f)." % (
        bas_attaque, seuil))
    if bas_attaque <= haut_nominal:
        print("  Mais le maximum nominal mesure (%.4f) les atteint aussi : le seuil ne" % haut_nominal)
        print("  separe pas les deux bandes, et la detection reste inexploitable.")
        return 2
    print("  Le seuil separe les deux bandes mesurees : nominal haut %.4f, attaque basse %.4f." % (
        haut_nominal, bas_attaque))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
