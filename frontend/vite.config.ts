import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// In development, /api calls are forwarded to the FastAPI backend.
// Bind to 127.0.0.1 explicitly: the default "localhost" can bind IPv6 (::1) only, so IPv4 connections hang and
// the UI reports "Failed to fetch". strictPort stops a second dev server silently moving to another port.
export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1", port: 5173, strictPort: true, proxy: { "/api": "http://127.0.0.1:8000" } },
});
