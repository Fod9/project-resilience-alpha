/**
 * Prouve la regle de detection du clignement, hors navigateur.
 *
 * Le defi se joue sur des durees courtes : un clignement dure une centaine de
 * millisecondes. Une regle trop grossiere ne le voit pas, et une regle trop
 * sensible prend le bruit de mesure pour une paupiere. Ce script eprouve la
 * regle reelle sur des sequences synthetiques, a la cadence de la boucle.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { build } from "esbuild";

const dossier = mkdtempSync(join(tmpdir(), "defi-"));
const sortie = join(dossier, "defi.mjs");
await build({
  entryPoints: ["src/defi.ts"],
  outfile: sortie,
  bundle: true,
  format: "esm",
  logLevel: "warning",
});
const { SuiviClignement, ouvertureDesYeux, lacetEstime } = await import(
  pathToFileURL(sortie).href
);

const CADENCE_MS = 60;
let echecs = 0;

function verifier(nom, obtenu, attendu) {
  const ok = obtenu === attendu;
  if (!ok) echecs += 1;
  console.log(`  [${ok ? " OK " : "ECHEC"}] ${nom} : ${obtenu} (attendu ${attendu})`);
}

function suite(nom, mesures, attendu) {
  const suivi = new SuiviClignement();
  let vu = false;
  mesures.forEach((ouverture, rang) => {
    if (suivi.mesurer(ouverture, rang * CADENCE_MS)) vu = true;
  });
  verifier(nom, vu, attendu);
}

const ouverts = (n, valeur = 0.31) => Array.from({ length: n }, () => valeur);

console.log("Regle de clignement, a la cadence reelle de la boucle (60 ms)");

suite("clignement de 120 ms", [...ouverts(10), 0.14, 0.13, ...ouverts(10)], true);
suite("cillement isole au-dessus du plancher", [...ouverts(10), 0.19, ...ouverts(10)], false);
suite("fermeture franche d une seule mesure", [...ouverts(10), 0.1, ...ouverts(10)], true);
suite("regard baisse de 2,4 s", [...ouverts(10), ...ouverts(40, 0.12), ...ouverts(10)], false);
suite("yeux peu ouverts, reference adaptative", [
  ...ouverts(10, 0.42),
  0.28,
  0.27,
  ...ouverts(10, 0.42),
], true);
suite("aucun clignement", ouverts(30), false);
suite("visage absent puis clignement", [...ouverts(10), 0.12, 0.12, ...ouverts(6)], true);

console.log("");
console.log("Geometrie des mesures");
const oeilOuvert = [
  { x: 0, y: 0 }, { x: 2.5, y: 2 }, { x: 5, y: 2.5 },
  { x: 10, y: 0 }, { x: 5, y: -2.5 }, { x: 2.5, y: -2 },
];
const oeilFerme = oeilOuvert.map((p) => ({ x: p.x, y: p.y * 0.05 }));
const points = Array.from({ length: 68 }, () => ({ x: 0, y: 0 }));
const poser = (rangs, forme) => rangs.forEach((rang, i) => { points[rang] = forme[i]; });
poser([36, 37, 38, 39, 40, 41], oeilOuvert);
poser([42, 43, 44, 45, 46, 47], oeilOuvert);
verifier("ouverture d un oeil ouvert", Number(ouvertureDesYeux(points).toFixed(2)), 0.45);
poser([36, 37, 38, 39, 40, 41], oeilFerme);
poser([42, 43, 44, 45, 46, 47], oeilFerme);
verifier("ouverture d un oeil ferme", Number(ouvertureDesYeux(points).toFixed(2)), 0.02);

const cadre = { x: 0, y: 0, width: 100, height: 100 };
points[30] = { x: 50, y: 40 };
verifier("lacet, nez au centre", lacetEstime(points, cadre), 0);
points[30] = { x: 75, y: 40 };
verifier("lacet, nez a droite", lacetEstime(points, cadre), 22.5);

console.log("");
if (echecs === 0) {
  console.log("TOUT PASSE");
  process.exit(0);
}
console.log(echecs + " verification(s) en echec");
process.exit(1);
