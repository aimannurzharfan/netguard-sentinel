import path from "node:path"
import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

// The production bundle is served by the Flask app (web/server.py).
// base "./" keeps asset URLs relative so they resolve under any mount point;
// outDir writes the built SPA into web/dist with hashed assets under static/.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  base: "./",
  build: {
    outDir: path.resolve(__dirname, "../web/dist"),
    assetsDir: "static",
    emptyOutDir: true,
  },
  server: {
    // Local dev: proxy the API calls to the running Flask server so the
    // one-click /scan flow works identically in `npm run dev`.
    proxy: {
      "/scan": "http://127.0.0.1:5000",
      "/triage": "http://127.0.0.1:5000",
    },
  },
})
