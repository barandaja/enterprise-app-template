/**
 * CSRF (Cross-Site Request Forgery) Protection
 * Implements double-submit cookie pattern and synchronizer token pattern
 */

import { securityUtils } from './secureStorage';

/**
 * CSRF token management
 */
class CSRFTokenManager {
  private static instance: CSRFTokenManager;
  private static hasLoggedDevWarning = false;
  private token: string | null = null;
  private readonly tokenHeader = 'X-CSRF-Token';
  private readonly cookieName = 'csrf_token';
  private readonly storageKey = 'csrf_token_sync';

  private constructor() {
    this.initializeToken();
  }

  static getInstance(): CSRFTokenManager {
    if (!CSRFTokenManager.instance) {
      CSRFTokenManager.instance = new CSRFTokenManager();
    }
    return CSRFTokenManager.instance;
  }

  /**
   * Initialize CSRF token on page load
   */
  private initializeToken(): void {
    // Try to get existing token from cookie (set by server)
    const cookieToken = this.getTokenFromCookie();
    if (cookieToken) {
      this.token = cookieToken;
      return;
    }

    // Try to get existing token from meta tag (server-rendered)
    const metaToken = this.getTokenFromMeta();
    if (metaToken) {
      this.token = metaToken;
      return;
    }

    // SECURITY: Never generate CSRF tokens client-side
    // Token must always come from the server
    console.warn('CSRF token not found. Server must provide CSRF token via cookie or meta tag.');
  }

  /**
   * @deprecated Client-side token generation removed for security
   * CSRF tokens must be generated server-side only
   */

  /**
   * Get token from cookie (set by server)
   */
  private getTokenFromCookie(): string | null {
    const cookies = document.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === this.cookieName) {
        return decodeURIComponent(value);
      }
    }
    return null;
  }

  /**
   * Get token from meta tag (if server-rendered)
   */
  private getTokenFromMeta(): string | null {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : null;
  }

  /**
   * @deprecated Token storage removed for security
   * CSRF tokens must be managed server-side only
   */

  /**
   * Set CSRF token as cookie (double-submit pattern)
   * In production, this should be httpOnly and set by server
   */
  /**
   * @deprecated Client-side cookie setting removed for security
   * CSRF cookies must be httpOnly and set by server only
   */

  /**
   * Get current CSRF token
   */
  getToken(): string {
    // Always try to read from cookie first (server-set token)
    const cookieToken = this.getTokenFromCookie();
    if (cookieToken) {
      this.token = cookieToken;
      return cookieToken;
    }

    // Try meta tag as fallback
    const metaToken = this.getTokenFromMeta();
    if (metaToken) {
      this.token = metaToken;
      return metaToken;
    }

    // SECURITY: Never generate tokens client-side
    // Server must always provide CSRF token
    // In development mode, return empty string to prevent errors while maintaining security awareness
    if (process.env.NODE_ENV === 'development') {
      // Only log once to avoid console spam
      if (!CSRFTokenManager.hasLoggedDevWarning) {
        console.info('CSRF: Running in development mode without server-provided token. This is expected for local development.');
        CSRFTokenManager.hasLoggedDevWarning = true;
      }
      return '';
    }
    
    // In production, strict enforcement - throw error
    throw new CSRFError('CSRF token not found. Server must provide token via cookie or meta tag.');
  }

  /**
   * Get CSRF header name
   */
  getHeaderName(): string {
    return this.tokenHeader;
  }

  /**
   * Get CSRF headers for requests
   */
  getHeaders(): Record<string, string> {
    return {
      [this.tokenHeader]: this.getToken(),
    };
  }

  /**
   * Refresh CSRF token
   */
  refreshToken(): void {
    // SECURITY: Token refresh must be done server-side
    // Client should request new token from server
    if (process.env.NODE_ENV === 'development') {
      // In development, skip refresh since we don't have a CSRF endpoint
      console.debug('CSRF: Token refresh skipped in development mode');
      return;
    }
    throw new CSRFError('CSRF token refresh must be performed by the server. Request a new token from /api/csrf/refresh');
  }

  /**
   * Validate CSRF token from response
   */
  validateToken(responseToken: string): boolean {
    const currentToken = this.getToken();
    
    // In development mode with empty token, skip validation but log warning
    if (process.env.NODE_ENV === 'development' && !currentToken) {
      console.warn('CSRF token validation skipped in development mode - no token available');
      return true;
    }
    
    return securityUtils.secureCompare(currentToken, responseToken);
  }

  /**
   * Clear CSRF token (on logout)
   */
  clearToken(): void {
    this.token = null;
    // Note: httpOnly cookies cannot be cleared from JavaScript
    // Server should clear the CSRF cookie on logout
  }
}

// Export singleton instance
export const csrfTokenManager = CSRFTokenManager.getInstance();

/**
 * Helper function to get CSRF token from cookie
 * Used by API client and other services
 */
export function getCSRFToken(): string | null {
  // CSRFTokenManager now handles development mode gracefully internally
  const token = csrfTokenManager.getToken();
  return token || null;
}

/**
 * CSRF protection middleware for fetch/axios
 */
export interface CSRFProtectionConfig {
  enabled: boolean;
  excludePaths?: string[];
  customHeader?: string;
  validateResponses?: boolean;
}

const defaultCSRFConfig: CSRFProtectionConfig = {
  enabled: true,
  excludePaths: ['/api/auth/login', '/api/auth/register'], // Public endpoints
  validateResponses: false, // Enable if server echoes token
};

/**
 * Check if a request should include CSRF token
 */
export function shouldIncludeCSRFToken(
  url: string,
  method: string,
  config: CSRFProtectionConfig = defaultCSRFConfig
): boolean {
  // Only include for state-changing methods
  const stateMethods = ['POST', 'PUT', 'PATCH', 'DELETE'];
  if (!stateMethods.includes(method.toUpperCase())) {
    return false;
  }

  // Check if CSRF is enabled
  if (!config.enabled) {
    return false;
  }

  // Check excluded paths
  if (config.excludePaths) {
    const pathname = new URL(url, window.location.origin).pathname;
    if (config.excludePaths.some(path => pathname.startsWith(path))) {
      return false;
    }
  }

  return true;
}

/**
 * Add CSRF token to request headers
 */
export function addCSRFToken(
  headers: Record<string, string>,
  url: string,
  method: string,
  config: CSRFProtectionConfig = defaultCSRFConfig
): Record<string, string> {
  if (shouldIncludeCSRFToken(url, method, config)) {
    const headerName = config.customHeader || csrfTokenManager.getHeaderName();
    const token = csrfTokenManager.getToken();
    
    // Only add header if token is not empty (handles development mode gracefully)
    if (token) {
      return {
        ...headers,
        [headerName]: token,
      };
    }
  }
  return headers;
}

/**
 * CSRF protection for forms
 */
export function CSRFTokenInput(): string {
  const token = csrfTokenManager.getToken();
  return `<input type="hidden" name="csrf_token" value="${token}" />`;
}

/**
 * React hook for CSRF token
 */
export function useCSRFToken(): {
  token: string;
  headerName: string;
  refreshToken: () => void;
} {
  // CSRFTokenManager now handles development mode gracefully internally
  const token = csrfTokenManager.getToken();
  
  return {
    token,
    headerName: csrfTokenManager.getHeaderName(),
    refreshToken: () => csrfTokenManager.refreshToken(),
  };
}

/**
 * Validate CSRF token in form data
 */
export function validateFormCSRFToken(formData: FormData): boolean {
  const token = formData.get('csrf_token');
  if (typeof token === 'string') {
    return csrfTokenManager.validateToken(token);
  }
  return false;
}

/**
 * CSRF error class
 */
export class CSRFError extends Error {
  constructor(message: string = 'CSRF validation failed') {
    super(message);
    this.name = 'CSRFError';
  }
}

/**
 * Initialize CSRF protection
 */
export function initializeCSRFProtection(): void {
  // Token is initialized automatically via singleton
  
  // Add event listener for token refresh on window focus
  window.addEventListener('focus', () => {
    // Optionally refresh token on window focus
    // This helps with long-running sessions
    const lastActivity = sessionStorage.getItem('last_activity');
    if (lastActivity) {
      const elapsed = Date.now() - parseInt(lastActivity, 10);
      // Refresh if more than 30 minutes
      if (elapsed > 30 * 60 * 1000) {
        try {
          csrfTokenManager.refreshToken();
        } catch (error) {
          // Log error but don't break the application
          console.debug('CSRF: Token refresh failed:', error);
        }
      }
    }
    sessionStorage.setItem('last_activity', Date.now().toString());
  });

  // Clear token on logout events
  window.addEventListener('logout', () => {
    csrfTokenManager.clearToken();
  });
}