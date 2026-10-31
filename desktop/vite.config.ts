/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import process from "node:process";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig(() => ({
  plugins: [react(), tailwindcss()],

  // Tauri-specific dev server options
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: { ignored: ["**/src-tauri/**"] },
  },

  test: process.env.E2E
    ? // `npm run test:e2e`: talks to a running backend over real HTTP (no DOM).
      { environment: "node", include: ["src/e2e/**/*.test.ts"], testTimeout: 60_000 }
    : { environment: "jsdom", setupFiles: ["./src/test-setup.ts"], globals: true, include: ["src/**/*.test.{ts,tsx}"], exclude: ["src/e2e/**", "node_modules/**"] },
}));
