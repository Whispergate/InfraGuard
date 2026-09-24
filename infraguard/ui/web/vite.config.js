// Minimal Vite build for the InfraGuard dashboard.
//
// Emits hashed asset bundles into static/dist/, which the Starlette
// route in infraguard/ui/api/app.py serves under /static/dist/. The
// generated static/dist/manifest.json lets the Python side map logical
// entry names (e.g. "dashboard") to their hashed filenames without a
// server-side render.
//
// The v0.5 refactor keeps the raw HTML/JS files under static/ as a
// working fallback for airgapped deploys. New feature work should land
// as ES modules under src/ and get bundled here.

import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  root: __dirname,
  build: {
    outDir: "static/dist",
    emptyOutDir: true,
    manifest: true,
    rollupOptions: {
      input: {
        dashboard: resolve(__dirname, "src/dashboard.js"),
        decoys: resolve(__dirname, "src/decoys.js"),
      },
      output: {
        entryFileNames: "[name]-[hash].js",
        assetFileNames: "[name]-[hash][extname]",
      },
    },
  },
});
