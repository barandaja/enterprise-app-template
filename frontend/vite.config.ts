import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { securityHeadersPlugin } from './src/security/securityHeaders'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), securityHeadersPlugin()],
})
