import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The production build is embedded into the Go binary via go:embed (see
// web/embed.go). During development, `npm run dev` proxies /api to a locally
// running selfsight server on :8080.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
});
