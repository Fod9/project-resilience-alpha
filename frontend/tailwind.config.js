/** @type {import('tailwindcss').Config} */
// Jetons du système de design AlphaPay : thème clair « grand livre ».
//
// Source de vérité : docs/DESIGN-SYSTEM.md. Le fichier Figma
// (https://www.figma.com/design/SacCkouYmlKojpdNol2dO4) et ce fichier doivent
// rester alignés : toute retouche de couleur se fait ici ET là-bas.
//
// Parti pris : ce n'est pas un tableau de bord sombre. Le sujet est un grand
// livre de paiement : papier comptable, encre de document, cuivre oxydé. Les
// deux couleurs d'état ne sont jamais vives : une salle d'opérations qui crie
// en permanence ne signale plus rien.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Papier
        base: "#F6F7F5",
        surface: "#FFFFFF",
        "surface-2": "#F1F3F0",
        line: "#DCE0DA",
        "line-fort": "#B9C0B4",
        // Encre
        ink: "#151A1E",
        "ink-dim": "#5C6670",
        // Accent unique : vert-de-gris du cuivre oxydé des coffres.
        accent: { DEFAULT: "#2E6B5A", dim: "#1F4C40" },
        // Filet de marge imprimé, comme dans un registre comptable.
        marge: "#B4523F",
        // États : sourds par construction.
        nominal: "#2F6B4F",
        degraded: "#96690C",
        incident: "#9C2B24",
      },
      fontFamily: {
        // Slab serif : la typographie de l'imprimé de relevé bancaire.
        display: ['"Bitter"', "Georgia", "serif"],
        sans: ['"Inter"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      letterSpacing: {
        etat: "-0.03em",
        marque: "0.22em",
      },
      gridTemplateColumns: {
        ops: "minmax(0, 44fr) 44px minmax(0, 56fr)",
      },
      borderRadius: {
        // Le papier comptable n'a pas d'angles arrondis : un rayon nul est ici
        // un choix de sujet, pas une négligence.
        none: "0",
      },
    },
  },
  plugins: [],
};
