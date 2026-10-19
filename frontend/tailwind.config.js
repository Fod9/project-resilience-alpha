/** @type {import('tailwindcss').Config} */
// Jetons du système de design AlphaPay.
// Source de vérité : docs/DESIGN-SYSTEM.md — toute modification doit y être
// reportée, faute de quoi les maquettes Figma et le code divergeraient.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0A0E14",
        surface: "#131A24",
        "surface-2": "#1B2431",
        line: "#26303D",
        ink: "#E8E4DC",
        "ink-dim": "#8A94A3",
        brass: { DEFAULT: "#D9A227", dim: "#8A6717" },
        nominal: "#3FB27F",
        degraded: "#E8B03A",
        incident: "#D64545",
      },
      fontFamily: {
        display: ['"Archivo"', "system-ui", "sans-serif"],
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      letterSpacing: {
        etat: "-0.03em",
        marque: "0.22em",
      },
      gridTemplateColumns: {
        ops: "320px minmax(0, 1fr) 360px",
      },
    },
  },
  plugins: [],
};
