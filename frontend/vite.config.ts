import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `npm run dev` proxies /api to the Docker stack's nginx (https://localhost:8443) so the
// browser sees one origin. For the full demo, build the app and let nginx serve it instead
// (see the root README).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'https://localhost:8443',
        changeOrigin: true,
        secure: false, // the stack uses its own development CA
      },
    },
  },
})
