import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Custos Control isn't running on Vite's own port, so during
    // development every /api call is forwarded to a real Control instance
    // (`cargo run -p custos-control -- run`) instead. `changeOrigin` rewrites
    // the request's Host header to match the target, which some servers
    // (not Control today, but a reasonable default) check against.
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8788',
        changeOrigin: true,
      },
    },
  },
})
