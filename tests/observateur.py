#!/usr/bin/env python3
"""Observe le tableau de bord pendant une attaque et releve ce qui change.

Usage :
    python tests/observateur.py [http://127.0.0.1] [duree_secondes]

Ce script ne juge pas des captures d'ecran a l'oeil : il lit les classes CSS
reellement appliquees. Une phase « allumee » porte bg-nominal, une pastille en
defaut porte bg-incident, etc. C'est la seule mesure objective de « est-ce que
l'interface reagit ».

Il releve a intervalle regulier :
  - le mot d'etat (NOMINAL, INCIDENT, RECOVERED, FAILED)
  - le score d'anomalie et le seuil
  - les elements colores, avec leur libelle
  - les reponses HTTP en echec
"""

import json
import sys
import time

from playwright.sync_api import sync_playwright

CIBLE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1").rstrip("/")
DUREE = float(sys.argv[2]) if len(sys.argv) > 2 else 110.0
INTERVALLE = 10.0

PROBE = """
() => {
  const colores = [];
  document.querySelectorAll('div,span,li').forEach((el) => {
    const c = typeof el.className === 'string' ? el.className : '';
    let ton = null;
    if (c.includes('bg-incident')) ton = 'ROUGE';
    else if (c.includes('bg-degraded')) ton = 'AMBRE';
    else if (c.includes('bg-nominal')) ton = 'VERT';
    else if (c.includes('bg-accent')) ton = 'ACCENT';
    if (!ton) return;
    if (el.children.length > 0) return;   // on ne garde que les feuilles
    const txt = (el.textContent || '').trim().slice(0, 28);
    colores.push(ton + '|' + txt);
  });
  const mot = document.querySelector('.mot-etat');
  const corps = document.body.innerText || '';
  const score = (corps.match(/SCORE ANOMALIE\\s*\\n?\\s*([-0-9,.]+)/) || [])[1] || '?';
  const seuil = (corps.match(/seuil\\s*([-0-9,.]+)/) || [])[1] || '?';
  const phases = [];
  ['CONFINEMENT', 'ÉRADICATION', 'REMISE EN ÉTAT', 'VÉRIFICATION'].forEach((p) => {
    // Chaque jalon est un div.flex-1 contenant une barre puis son libelle.
    const blocs = Array.from(document.querySelectorAll('div.flex-1'));
    const bloc = blocs.find((d) => (d.textContent || '').toUpperCase().includes(p));
    if (!bloc) { phases.push(p + '=absent'); return; }
    const barre = bloc.querySelector('div');
    const c = barre && typeof barre.className === 'string' ? barre.className : '';
    const etat = c.includes('bg-nominal') ? 'VERT'
      : c.includes('bg-brass') || c.includes('bg-accent') ? 'AMBRE'
      : c.includes('bg-incident') ? 'ROUGE' : 'gris';
    phases.push(p + '=' + etat);
  });
  const attente = corps.includes('Aucune action engagee') || corps.includes('Aucune action engagée');
  return {
    etat: mot ? mot.textContent.trim() : '?',
    score: score, seuil: seuil,
    colores: colores,
    phases: phases,
    attente: attente,
    debut_gardien: corps.includes('en cours de démarrage'),
  };
}
"""


def main() -> int:
    echecs: list[str] = []
    releves: list[dict] = []

    with sync_playwright() as p:
        navigateur = p.chromium.launch()
        page = navigateur.new_context(viewport={"width": 1600, "height": 1000}).new_page()
        page.on(
            "response",
            lambda r: echecs.append(f"{r.status} {r.url}")
            if r.status >= 400
            else None,
        )
        page.goto(f"{CIBLE}/ops", wait_until="networkidle", timeout=45000)

        debut = time.time()
        while time.time() - debut < DUREE:
            releve = page.evaluate(PROBE)
            releve["t"] = round(time.time() - debut, 1)
            releves.append(releve)
            print(
                f"  t={releve['t']:>5}s  etat={releve['etat']:<10} "
                f"score={releve['score']:>7} seuil={releve['seuil']:>6} "
                f"colores={len(releve['colores'])} phases={len(releve['phases'])}"
                + ("  [AUCUNE ACTION]" if releve["attente"] else "")
            )
            page.wait_for_timeout(INTERVALLE * 1000)

        page.screenshot(path="/opt/data/projects/resilience-alpha/deliverables/captures/pendant_attaque.png")
        navigateur.close()

    print("\n=== ce qui a ete colore au dernier releve ===")
    if releves:
        for ligne in releves[-1]["colores"]:
            print(f"     {ligne}")

    print("\n=== evolution du mot d'etat ===")
    vus: list[str] = []
    for r in releves:
        if not vus or vus[-1] != r["etat"]:
            vus.append(r["etat"])
            print(f"     t={r['t']}s -> {r['etat']}")

    print("\n=== etat de chaque jalon (dernier releve) ===")
    for phase in (releves[-1]["phases"] if releves else []):
        print(f"     {phase}")

    uniques = sorted(set(echecs))
    print(f"\n=== reponses HTTP en echec : {len(uniques)} ===")
    for ligne in uniques[:14]:
        print(f"     {ligne}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
