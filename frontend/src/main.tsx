import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import './services/api/test-login'
import './services/api/test-direct'
import './services/api/test-simple'
import { validateEnvironment } from './config/env'
import { httpsEnforcement } from './security/securityHeaders'
import { initializeCSRFProtection } from './security/csrf'

// Validate environment configuration
validateEnvironment();

// Enforce HTTPS in production
httpsEnforcement.enforceHTTPS();

// Initialize CSRF protection
initializeCSRFProtection();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
