import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// L'interface est servie derrière la bordure, sous le même domaine que l'API.
// Les appels partent donc vers des chemins relatifs (`/api/...`) : aucun
// renseignement d'adresse n'est nécessaire au moment de la construction, et
// l'image produite reste identique quel que soit le poste hôte du groupe.
export default defineConfig({
  plugins: [react()],
  server: { host: "0.0.0.0", port: 5173 },
  build: {
    outDir: "dist",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
  },
});
