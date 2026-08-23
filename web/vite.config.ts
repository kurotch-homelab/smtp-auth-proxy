import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The production bundle is written straight into the Go embed directory so a
// single `go build` produces a binary that already serves the admin UI.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  build: {
    outDir: '../internal/webui/dist',
    emptyOutDir: true,
    sourcemap: true,
  },
  server: {
    port: 5173,
    // `make run` serves the API on :8080; proxy so the dev server needs no CORS.
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: false },
    },
  },
})
