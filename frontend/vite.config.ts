import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During local development the Vite dev server proxies API calls to the
// FastAPI container so cookies stay first-party.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_TARGET ?? "http://localhost:8000",
        changeOrigin: false,
      },
    },
  },
});
