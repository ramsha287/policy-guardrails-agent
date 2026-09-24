import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Served by the control plane at /console. In development, API calls go to a local control plane
// (or `npm run dev:mock`) through the proxy below, so the browser stays same-origin as in production.
export default defineConfig({
  base: "/console/",
  plugins: [react()],
  build: {
    outDir: "dist",
    sourcemap: false,
    // one small bundle; no inline scripts or styles so the strict CSP (script-src 'self') holds
    assetsInlineLimit: 0,
  },
  server: {
    port: 5173,
    proxy: { "/cp": process.env.CONTROL_PLANE_URL ?? "http://localhost:8200" },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
