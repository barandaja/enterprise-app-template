/**
 * Security Headers Validation and Monitoring
 * Frontend utilities for validating and monitoring security headers
 */

/**
 * Security headers that should be validated on the frontend
 */
export interface SecurityHeaders {
  'content-security-policy': string;
  'strict-transport-security': string;
  'x-frame-options': string;
  'x-content-type-options': string;
  'referrer-policy': string;
  'permissions-policy': string;
}

/**
 * CSP violation report structure
 */
export interface CSPViolationReport {
  'blocked-uri': string;
  'column-number'?: number;
  'document-uri': string;
  'line-number'?: number;
  'original-policy': string;
  'referrer'?: string;
  'script-sample'?: string;
  'source-file'?: string;
  'violated-directive': string;
}

/**
 * Validate that required security headers are present
 */
export function validateSecurityHeaders(headers: Headers): boolean {
  const requiredHeaders: (keyof SecurityHeaders)[] = [
    'content-security-policy',
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy'
  ];
  
  const missingHeaders: string[] = [];
  
  for (const header of requiredHeaders) {
    if (!headers.has(header)) {
      missingHeaders.push(header);
    }
  }
  
  if (missingHeaders.length > 0) {
    console.warn('Missing security headers:', missingHeaders);
    return false;
  }
  
  // Validate header values
  const frameOptions = headers.get('x-frame-options');
  if (frameOptions && !['DENY', 'SAMEORIGIN'].includes(frameOptions.toUpperCase())) {
    console.warn('Invalid X-Frame-Options value:', frameOptions);
    return false;
  }
  
  const contentTypeOptions = headers.get('x-content-type-options');
  if (contentTypeOptions && contentTypeOptions.toLowerCase() !== 'nosniff') {
    console.warn('Invalid X-Content-Type-Options value:', contentTypeOptions);
    return false;
  }
  
  return true;
}

/**
 * Check if running in secure context (HTTPS)
 */
export function isSecureContext(): boolean {
  return window.isSecureContext || window.location.protocol === 'https:';
}

/**
 * Monitor CSP violations
 */
export function monitorCSPViolations(callback?: (report: CSPViolationReport) => void): void {
  // Listen for CSP violation reports
  document.addEventListener('securitypolicyviolation', (event) => {
    const report: CSPViolationReport = {
      'blocked-uri': event.blockedURI,
      'column-number': event.columnNumber,
      'document-uri': event.documentURI,
      'line-number': event.lineNumber,
      'original-policy': event.originalPolicy,
      'referrer': event.referrer,
      'script-sample': event.sample,
      'source-file': event.sourceFile,
      'violated-directive': event.violatedDirective
    };
    
    console.error('CSP Violation:', report);
    
    // Call custom callback if provided
    if (callback) {
      callback(report);
    }
    
    // In production, send to monitoring service
    if (process.env.NODE_ENV === 'production') {
      reportCSPViolation(report);
    }
  });
}

/**
 * Report CSP violation to monitoring service
 */
function reportCSPViolation(report: CSPViolationReport): void {
  // Send to your monitoring endpoint
  fetch('/api/security/csp-report', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      type: 'csp-violation',
      report,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      url: window.location.href
    })
  }).catch(error => {
    console.error('Failed to report CSP violation:', error);
  });
}

/**
 * Check for mixed content issues
 */
export function monitorMixedContent(): void {
  if (window.location.protocol === 'https:') {
    // Monitor for mixed content warnings
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      const url = args[0];
      if (typeof url === 'string' && url.startsWith('http://')) {
        console.warn('Mixed content warning: HTTP request on HTTPS page:', url);
      }
      return originalFetch.apply(this, args);
    };
    
    // Monitor image loads
    const checkImageSrc = (img: HTMLImageElement) => {
      if (img.src && img.src.startsWith('http://')) {
        console.warn('Mixed content warning: HTTP image on HTTPS page:', img.src);
      }
    };
    
    // Check existing images
    document.querySelectorAll('img').forEach(checkImageSrc);
    
    // Monitor new images
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node instanceof HTMLImageElement) {
            checkImageSrc(node);
          }
        });
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
}

/**
 * Validate response headers for API calls
 */
export function validateAPIResponseHeaders(response: Response): void {
  // Check for security headers in API responses
  const securityHeaders = [
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy'
  ];
  
  for (const header of securityHeaders) {
    if (!response.headers.has(header)) {
      console.warn(`API response missing security header: ${header}`);
    }
  }
  
  // Validate specific header values
  const contentType = response.headers.get('content-type');
  if (contentType && !contentType.includes('application/json') && !contentType.includes('text/')) {
    console.warn('Unexpected content type:', contentType);
  }
}

/**
 * Initialize security monitoring
 */
export function initializeSecurityMonitoring(): void {
  // Check secure context
  if (!isSecureContext()) {
    if (process.env.NODE_ENV === 'production') {
      console.error('Application must be served over HTTPS in production');
    } else {
      console.warn('Running in insecure context (HTTP)');
    }
  }
  
  // Monitor CSP violations
  monitorCSPViolations();
  
  // Monitor mixed content
  monitorMixedContent();
  
  // Validate initial page headers (if available via performance API)
  if (window.performance && window.performance.getEntriesByType) {
    const navigationEntries = window.performance.getEntriesByType('navigation') as PerformanceNavigationTiming[];
    if (navigationEntries.length > 0) {
      // Note: Browser security prevents accessing response headers from navigation timing
      // This would need server-side implementation to expose headers safely
      console.info('Page loaded with secure context:', isSecureContext());
    }
  }
  
  // Monitor for iframe attempts
  if (window.self !== window.top) {
    console.error('Page is being framed. X-Frame-Options should prevent this.');
    // Attempt frame busting as fallback
    try {
      window.top!.location.href = window.self.location.href;
    } catch (e) {
      console.error('Frame busting failed:', e);
    }
  }
}

/**
 * Security headers configuration for development
 */
export const RECOMMENDED_SECURITY_HEADERS: SecurityHeaders = {
  'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self';",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'accelerometer=(), camera=(), geolocation=(self), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
};

/**
 * Get security headers status
 */
export function getSecurityStatus(): {
  secureContext: boolean;
  headers: Partial<SecurityHeaders>;
  warnings: string[];
} {
  const warnings: string[] = [];
  const headers: Partial<SecurityHeaders> = {};
  
  // Check secure context
  if (!isSecureContext()) {
    warnings.push('Not running in secure context (HTTPS)');
  }
  
  // Check if framed
  if (window.self !== window.top) {
    warnings.push('Page is being displayed in an iframe');
  }
  
  // Note: Cannot access response headers from client-side JavaScript
  // This information would need to come from server or be injected during build
  
  return {
    secureContext: isSecureContext(),
    headers,
    warnings
  };
}