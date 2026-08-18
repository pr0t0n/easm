import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // The isolated Playwright browser runner reaches the dev UI by its Docker
    // DNS name. Keep the allow-list narrow so arbitrary Host headers remain
    // rejected while first-party application smoke tests can run.
    allowedHosts: ["frontend"],
    proxy: {
      "/api": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/health": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://backend:8000",
        ws: true,
        changeOrigin: true,
      },
    },
  },
});
