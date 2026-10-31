import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";
import tailwindcss from "tailwindcss";
import autoprefixer from "autoprefixer";

export default defineConfig({
  plugins: [react()],
  css: {
    postcss: {
      plugins: [tailwindcss(), autoprefixer()],
    },
  },
  resolve: {
    alias: {
      "@core-crypto": path.resolve(__dirname, "./packages/core-crypto"),
      "@keyos-app": path.resolve(__dirname, "./packages/keyos-incogid-app"),
      "lucide-react": path.resolve(__dirname, "./node_modules/lucide-react/dist/cjs/lucide-react.js"),
    },
  },
  server: {
    port: 3000,
    host: true,
  },
});
