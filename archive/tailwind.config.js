/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./packages/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        foundation: {
          dark: "#090B0E",
          card: "#12151B",
          cardHover: "#181D26",
          border: "#232936",
          gold: "#D4AF37",
          goldLight: "#F3E5AB",
          goldDark: "#997A15",
          accent: "#E5B94E",
          emerald: "#10B981",
          rose: "#EF4444",
          amber: "#F59E0B",
          cyan: "#06B6D4",
        },
      },
      fontFamily: {
        mono: ['"IBM Plex Mono"', "monospace"],
        sans: ['"Montserrat"', "Inter", "sans-serif"],
      },
      boxShadow: {
        oled: "0 0 50px -10px rgba(0, 0, 0, 0.9)",
        goldGlow: "0 0 25px -5px rgba(212, 175, 55, 0.3)",
        emeraldGlow: "0 0 25px -5px rgba(16, 185, 129, 0.3)",
        roseGlow: "0 0 25px -5px rgba(239, 68, 68, 0.3)",
      },
    },
  },
  plugins: [],
};
