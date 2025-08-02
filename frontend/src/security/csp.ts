/**
 * Content Security Policy (CSP) Configuration
 * Provides security headers to prevent XSS, clickjacking, and other attacks
 */

import { config } from '../config/env';

/**
 * CSP Directive types
 */
export type CSPDirective =
  | 'default-src'
  | 'script-src'
  | 'style-src'
  | 'img-src'
  | 'font-src'
  | 'connect-src'
  | 'media-src'
  | 'object-src'
  | 'frame-src'
  | 'frame-ancestors'
  | 'base-uri'
  | 'form-action'
  | 'manifest-src'
  | 'worker-src'
  | 'child-src'
  | 'report-uri'
  | 'report-to';

/**
 * CSP Source Values
 */
export type CSPSource = 
  | "'self'"
  | "'unsafe-inline'"
  | "'unsafe-eval'"
  | "'none'"
  | "'strict-dynamic'"
  | "'report-sample'"
  | string; // URLs, schemes, nonces, hashes

/**
 * CSP Configuration interface
 */
export interface CSPConfig {
  directives: Partial<Record<CSPDirective, CSPSource[]>>;
  reportOnly?: boolean;
  reportUri?: string;
  nonceGenerator?: () => string;
}

/**
 * Get API domain from config URL
 */
function getApiDomain(): string {
  try {
    const url = new URL(config.apiUrl);
    return `${url.protocol}//${url.host}`;
  } catch {
    return "'self'";
  }
}

/**
 * Default secure CSP configuration
 */
export const defaultCSPConfig: CSPConfig = {
  directives: {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'strict-dynamic'"],
    'style-src': ["'self'", "'unsafe-inline'"], // unsafe-inline needed for Tailwind
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'"],
    'connect-src': ["'self'", getApiDomain()],
    'media-src': ["'self'"],
    'object-src': ["'none'"],
    'frame-src': ["'none'"],
    'frame-ancestors': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'manifest-src': ["'self'"],
    'worker-src': ["'self'"],
  },
  reportOnly: false,
  reportUri: '/api/csp-report'
};

/**
 * Development CSP configuration (more permissive)
 */
export const developmentCSPConfig: CSPConfig = {
  directives: {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'http://localhost:*'],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:', 'http:'],
    'font-src': ["'self'", 'data:'],
    'connect-src': ["'self'", 'http://localhost:*', 'ws://localhost:*', getApiDomain()],
    'media-src': ["'self'"],
    'object-src': ["'none'"],
    'frame-src': ["'self'"],
    'frame-ancestors': ["'self'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
  },
  reportOnly: true
};

/**
 * CSP Builder class
 */
export class CSPBuilder {
  private config: CSPConfig;
  private nonce?: string;

  constructor(config: CSPConfig = defaultCSPConfig) {
    this.config = config;
  }

  /**
   * Generate a nonce for inline scripts
   */
  generateNonce(): string {
    if (!this.nonce) {
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
      this.nonce = btoa(String.fromCharCode(...array));
    }
    return this.nonce;
  }

  /**
   * Add nonce to script-src directive
   */
  withNonce(nonce?: string): CSPBuilder {
    const nonceValue = nonce || this.generateNonce();
    const scriptSrc = this.config.directives['script-src'] || [];
    
    this.config.directives['script-src'] = [
      ...scriptSrc.filter(src => !src.startsWith("'nonce-")),
      `'nonce-${nonceValue}'`
    ];
    
    return this;
  }

  /**
   * Add hash for inline script
   */
  withScriptHash(hash: string): CSPBuilder {
    const scriptSrc = this.config.directives['script-src'] || [];
    this.config.directives['script-src'] = [...scriptSrc, `'sha256-${hash}'`];
    return this;
  }

  /**
   * Add trusted domain
   */
  addTrustedDomain(directive: CSPDirective, domain: string): CSPBuilder {
    const sources = this.config.directives[directive] || [];
    this.config.directives[directive] = [...sources, domain];
    return this;
  }

  /**
   * Build CSP header value
   */
  build(): string {
    const directives = Object.entries(this.config.directives)
      .filter(([_, sources]) => sources && sources.length > 0)
      .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
      .join('; ');

    if (this.config.reportUri) {
      return `${directives}; report-uri ${this.config.reportUri}`;
    }

    return directives;
  }

  /**
   * Get header name
   */
  getHeaderName(): string {
    return this.config.reportOnly 
      ? 'Content-Security-Policy-Report-Only' 
      : 'Content-Security-Policy';
  }

  /**
   * Get complete header object
   */
  getHeader(): Record<string, string> {
    return {
      [this.getHeaderName()]: this.build()
    };
  }
}

/**
 * React hook for CSP nonce
 */
export function useCSPNonce(): string {
  // In a real app, this would be provided by the server
  // For client-side only, we generate per session
  const nonce = sessionStorage.getItem('csp-nonce') || generateCSPNonce();
  
  if (!sessionStorage.getItem('csp-nonce')) {
    sessionStorage.setItem('csp-nonce', nonce);
  }
  
  return nonce;
}

/**
 * Generate CSP nonce
 */
export function generateCSPNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

/**
 * Apply CSP meta tag (for SPAs without server)
 */
export function applyCSPMetaTag(config: CSPConfig = defaultCSPConfig): void {
  const builder = new CSPBuilder(config);
  const csp = builder.build();
  
  // Remove existing CSP meta tag
  const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (existing) {
    existing.remove();
  }
  
  // Add new CSP meta tag
  const meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = csp;
  document.head.appendChild(meta);
}

/**
 * Initialize CSP for the application
 */
export function initializeCSP(): void {
  const isDevelopment = process.env.NODE_ENV === 'development';
  const config = isDevelopment ? developmentCSPConfig : defaultCSPConfig;
  
  // Apply CSP meta tag for SPA
  applyCSPMetaTag(config);
  
  // Set up CSP violation reporting
  if (config.reportUri) {
    setupCSPReporting(config.reportUri);
  }
}

/**
 * Set up CSP violation reporting
 */
function setupCSPReporting(reportUri: string): void {
  // Listen for security policy violation events
  window.addEventListener('securitypolicyviolation', (event) => {
    const violation = {
      documentUri: event.documentURI,
      referrer: event.referrer,
      blockedUri: event.blockedURI,
      violatedDirective: event.violatedDirective,
      effectiveDirective: event.effectiveDirective,
      originalPolicy: event.originalPolicy,
      disposition: event.disposition,
      sourceFile: event.sourceFile,
      lineNumber: event.lineNumber,
      columnNumber: event.columnNumber,
      sample: event.sample,
      statusCode: 0,
      timestamp: new Date().toISOString()
    };
    
    // Send violation report
    fetch(reportUri, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ 'csp-report': violation })
    }).catch(error => {
      console.error('Failed to send CSP report:', error);
    });
  });
}

/**
 * Security headers configuration
 */
export interface SecurityHeaders {
  'Content-Security-Policy'?: string;
  'X-Content-Type-Options'?: string;
  'X-Frame-Options'?: string;
  'X-XSS-Protection'?: string;
  'Referrer-Policy'?: string;
  'Permissions-Policy'?: string;
  'Strict-Transport-Security'?: string;
}

/**
 * Get all security headers
 */
export function getSecurityHeaders(cspConfig?: CSPConfig): SecurityHeaders {
  const builder = new CSPBuilder(cspConfig);
  
  return {
    'Content-Security-Policy': builder.build(),
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

/**
 * Middleware for Express/Node.js apps
 */
export function securityHeadersMiddleware(config?: CSPConfig) {
  const headers = getSecurityHeaders(config);
  
  return (req: any, res: any, next: any) => {
    Object.entries(headers).forEach(([header, value]) => {
      if (value) {
        res.setHeader(header, value);
      }
    });
    next();
  };
}

/**
 * Calculate SHA-256 hash for inline script
 */
export async function calculateScriptHash(script: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(script);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return btoa(String.fromCharCode(...hashArray));
}

/**
 * CSP configuration for specific environments
 */
export const cspPresets = {
  strict: {
    directives: {
      'default-src': ["'none'"],
      'script-src': ["'self'"],
      'style-src': ["'self'"],
      'img-src': ["'self'"],
      'font-src': ["'self'"],
      'connect-src': ["'self'"],
      'media-src': ["'none'"],
      'object-src': ["'none'"],
      'frame-src': ["'none'"],
      'frame-ancestors': ["'none'"],
      'base-uri': ["'none'"],
      'form-action': ["'self'"],
    }
  },
  
  moderate: defaultCSPConfig.directives,
  
  permissive: {
    directives: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https:'],
      'style-src': ["'self'", "'unsafe-inline'", 'https:'],
      'img-src': ["'self'", 'data:', 'https:'],
      'font-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'", 'https:'],
    }
  }
};