/**
 * Copie les poids du modèle facial depuis la dépendance installée vers
 * `public/models`, d'où ils sont servis comme fichiers statiques.
 *
 * Pourquoi ne pas les versionner : ce sont 7 Mo de binaires, ils n'ont pas leur
 * place dans l'historique Git. Ils sont régénérés à chaque construction à
 * partir de la version figée dans `package.json`, donc la construction reste
 * reproductible et l'image livrée ne dépend d'aucun réseau externe à
 * l'exécution.
 *
 * Trois modèles suffisent, et c'est un choix : le détecteur de visage, les 68
 * points de repère (qui portent le défi actif : clignement et rotation) et le
 * réseau de reconnaissance qui produit le descripteur de 128 nombres.
 */
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const racine = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(racine, "node_modules", "@vladmandic", "face-api", "model");
const cible = join(racine, "public", "models");

const fichiers = [
  "tiny_face_detector_model-weights_manifest.json",
  "tiny_face_detector_model.bin",
  "face_landmark_68_model-weights_manifest.json",
  "face_landmark_68_model.bin",
  "face_recognition_model-weights_manifest.json",
  "face_recognition_model.bin",
];

if (!existsSync(source)) {
  console.error(
    `[modeles] dossier source absent : ${source}\n` +
      "[modeles] lancez `npm install` avant la construction.",
  );
  process.exit(1);
}

mkdirSync(cible, { recursive: true });
for (const fichier of fichiers) {
  const origine = join(source, fichier);
  if (!existsSync(origine)) {
    console.error(`[modeles] fichier de poids manquant : ${origine}`);
    process.exit(1);
  }
  copyFileSync(origine, join(cible, fichier));
}
console.log(`[modeles] ${fichiers.length} fichiers copiés vers public/models`);
