/**
 * Security headers configuration and middleware
 * Implements comprehensive security headers for OWASP compliance
 */

/**
 * Content Security Policy configuration
 */
export interface CSPConfig {
  defaultSrc?: string[];
  scriptSrc?: string[];
  styleSrc?: string[];
  imgSrc?: string[];
  fontSrc?: string[];
  connectSrc?: string[];
  mediaSrc?: string[];
  objectSrc?: string[];
  frameSrc?: string[];
  frameAncestors?: string[];
  formAction?: string[];
  baseUri?: string[];
  reportUri?: string;
  upgradeInsecureRequests?: boolean;
}

/**
 * Generate Content Security Policy string
 */
export function generateCSP(config: CSPConfig): string {
  const directives: string[] = [];

  // Helper to format directive values
  const formatDirective = (name: string, values?: string[]): void => {
    if (values && values.length > 0) {
      directives.push(`${name} ${values.join(' ')}`);
    }
  };

  formatDirective('default-src', config.defaultSrc || ["'self'"]);
  formatDirective('script-src', config.scriptSrc);
  formatDirective('style-src', config.styleSrc);
  formatDirective('img-src', config.imgSrc);
  formatDirective('font-src', config.fontSrc);
  formatDirective('connect-src', config.connectSrc);
  formatDirective('media-src', config.mediaSrc);
  formatDirective('object-src', config.objectSrc || ["'none'"]);
  formatDirective('frame-src', config.frameSrc);
  formatDirective('frame-ancestors', config.frameAncestors || ["'none'"]);
  formatDirective('form-action', config.formAction || ["'self'"]);
  formatDirective('base-uri', config.baseUri || ["'self'"]);

  if (config.reportUri) {
    directives.push(`report-uri ${config.reportUri}`);
  }

  if (config.upgradeInsecureRequests) {
    directives.push('upgrade-insecure-requests');
  }

  return directives.join('; ');
}

/**
 * Get API URL for CSP configuration
 */
function getApiUrlForCSP(): string {
  const apiUrl = import.meta.env.VITE_API_URL || (
    import.meta.env.DEV 
      ? 'http://localhost:3000'
      : 'https://api.example.com'
  );
  
  try {
    const url = new URL(apiUrl);
    return `${url.protocol}//${url.host}`;
  } catch {
    return "'self'";
  }
}

/**
 * Default CSP configuration for production
 */
export const defaultCSPConfig: CSPConfig = {
  defaultSrc: ["'self'"],
  scriptSrc: ["'self'", "'strict-dynamic'"],
  styleSrc: ["'self'", "'unsafe-inline'"], // Consider using nonces instead
  imgSrc: ["'self'", 'data:', 'https:'],
  fontSrc: ["'self'"],
  connectSrc: ["'self'", getApiUrlForCSP()],
  mediaSrc: ["'none'"],
  objectSrc: ["'none'"],
  frameAncestors: ["'none'"],
  formAction: ["'self'"],
  baseUri: ["'self'"],
  upgradeInsecureRequests: true,
};

/**
 * Strict CSP configuration (recommended)
 */
export const strictCSPConfig: CSPConfig = {
  defaultSrc: ["'none'"],
  scriptSrc: ["'self'", "'strict-dynamic'"],
  styleSrc: ["'self'"],
  imgSrc: ["'self'"],
  fontSrc: ["'self'"],
  connectSrc: ["'self'"],
  mediaSrc: ["'none'"],
  objectSrc: ["'none'"],
  frameAncestors: ["'none'"],
  formAction: ["'self'"],
  baseUri: ["'self'"],
  upgradeInsecureRequests: true,
};

/**
 * Security headers configuration
 */
export interface SecurityHeaders {
  'Content-Security-Policy'?: string;
  'X-Content-Type-Options'?: string;
  'X-Frame-Options'?: string;
  'X-XSS-Protection'?: string;
  'Strict-Transport-Security'?: string;
  'Referrer-Policy'?: string;
  'Permissions-Policy'?: string;
  'Cross-Origin-Embedder-Policy'?: string;
  'Cross-Origin-Opener-Policy'?: string;
  'Cross-Origin-Resource-Policy'?: string;
}

/**
 * Get recommended security headers
 */
export function getSecurityHeaders(options: {
  cspConfig?: CSPConfig;
  enableHSTS?: boolean;
  hstsMaxAge?: number;
  enableFrameOptions?: boolean;
  frameOptions?: 'DENY' | 'SAMEORIGIN';
  referrerPolicy?: string;
} = {}): SecurityHeaders {
  const {
    cspConfig = defaultCSPConfig,
    enableHSTS = true,
    hstsMaxAge = 31536000, // 1 year
    enableFrameOptions = true,
    frameOptions = 'DENY',
    referrerPolicy = 'strict-origin-when-cross-origin',
  } = options;

  const headers: SecurityHeaders = {
    'Content-Security-Policy': generateCSP(cspConfig),
    'X-Content-Type-Options': 'nosniff',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': referrerPolicy,
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
  };

  if (enableHSTS) {
    headers['Strict-Transport-Security'] = `max-age=${hstsMaxAge}; includeSubDomains; preload`;
  }

  if (enableFrameOptions) {
    headers['X-Frame-Options'] = frameOptions;
  }

  return headers;
}

/**
 * Add security headers to HTML meta tags
 */
export function addSecurityMetaTags(): void {
  const head = document.head;

  // CSP meta tag
  const cspMeta = document.createElement('meta');
  cspMeta.httpEquiv = 'Content-Security-Policy';
  cspMeta.content = generateCSP(defaultCSPConfig);
  head.appendChild(cspMeta);

  // Other security-related meta tags
  const metaTags = [
    { httpEquiv: 'X-Content-Type-Options', content: 'nosniff' },
    { httpEquiv: 'X-Frame-Options', content: 'DENY' },
    { httpEquiv: 'X-XSS-Protection', content: '1; mode=block' },
    { name: 'referrer', content: 'strict-origin-when-cross-origin' },
  ];

  metaTags.forEach(tag => {
    const meta = document.createElement('meta');
    if (tag.httpEquiv) {
      meta.httpEquiv = tag.httpEquiv;
    } else {
      meta.name = tag.name!;
    }
    meta.content = tag.content;
    head.appendChild(meta);
  });
}

/**
 * Vite plugin for security headers
 */
export const securityHeadersPlugin = () => ({
  name: 'security-headers',
  configureServer(server: any) {
    server.middlewares.use((req: any, res: any, next: any) => {
      const headers = getSecurityHeaders();
      
      Object.entries(headers).forEach(([key, value]) => {
        if (value) {
          res.setHeader(key, value);
        }
      });

      next();
    });
  },
  transformIndexHtml(html: string) {
    // Add security meta tags to HTML
    const securityMeta = `
    <meta http-equiv="Content-Security-Policy" content="${generateCSP(defaultCSPConfig)}">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    `.trim();

    return html.replace('</head>', `${securityMeta}\n  </head>`);
  },
});

/**
 * Generate nonce for inline scripts/styles
 */
export function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode.apply(null, Array.from(array)));
}

/**
 * CSP violation reporter
 */
export class CSPViolationReporter {
  private violations: any[] = [];
  private reportEndpoint: string;

  constructor(reportEndpoint: string) {
    this.reportEndpoint = reportEndpoint;
    this.setupListener();
  }

  private setupListener(): void {
    document.addEventListener('securitypolicyviolation', (e) => {
      const violation = {
        timestamp: new Date().toISOString(),
        documentUri: e.documentURI,
        blockedUri: e.blockedURI,
        violatedDirective: e.violatedDirective,
        effectiveDirective: e.effectiveDirective,
        originalPolicy: e.originalPolicy,
        sourceFile: e.sourceFile,
        lineNumber: e.lineNumber,
        columnNumber: e.columnNumber,
        statusCode: e.statusCode,
        userAgent: navigator.userAgent,
      };

      this.violations.push(violation);
      this.reportViolation(violation);
    });
  }

  private async reportViolation(violation: any): Promise<void> {
    try {
      await fetch(this.reportEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(violation),
      });
    } catch (error) {
      console.error('Failed to report CSP violation:', error);
    }
  }

  getViolations(): any[] {
    return [...this.violations];
  }

  clearViolations(): void {
    this.violations = [];
  }
}

/**
 * Security headers validator for testing
 */
export function validateHeaders(headers: Headers): {
  valid: boolean;
  missing: string[];
  warnings: string[];
} {
  const required = [
    'Content-Security-Policy',
    'X-Content-Type-Options',
    'X-Frame-Options',
    'Strict-Transport-Security',
  ];

  const missing = required.filter(header => !headers.has(header));
  const warnings: string[] = [];

  // Validate CSP
  const csp = headers.get('Content-Security-Policy');
  if (csp) {
    if (csp.includes('unsafe-inline') && !csp.includes('nonce-')) {
      warnings.push('CSP uses unsafe-inline without nonce');
    }
    if (csp.includes('unsafe-eval')) {
      warnings.push('CSP uses unsafe-eval');
    }
    if (!csp.includes('upgrade-insecure-requests')) {
      warnings.push('CSP missing upgrade-insecure-requests');
    }
  }

  // Validate HSTS
  const hsts = headers.get('Strict-Transport-Security');
  if (hsts && !hsts.includes('includeSubDomains')) {
    warnings.push('HSTS missing includeSubDomains');
  }

  return {
    valid: missing.length === 0,
    missing,
    warnings,
  };
}

/**
 * HTTPS enforcement utilities
 */
export const httpsEnforcement = {
  /**
   * Redirect to HTTPS if not already
   */
  enforceHTTPS(): void {
    if (window.location.protocol === 'http:' && window.location.hostname !== 'localhost') {
      window.location.href = window.location.href.replace('http:', 'https:');
    }
  },

  /**
   * Check if current connection is secure
   */
  isSecure(): boolean {
    return window.location.protocol === 'https:' || window.location.hostname === 'localhost';
  },

  /**
   * Validate URL uses HTTPS
   */
  validateHTTPS(url: string): boolean {
    try {
      const parsed = new URL(url);
      return parsed.protocol === 'https:' || parsed.hostname === 'localhost';
    } catch {
      return false;
    }
  },
};