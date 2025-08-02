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

    // In development only - generate new token
    // In production, server should always provide token
    if (process.env.NODE_ENV === 'development') {
      this.token = this.generateToken();
      this.storeToken();
    }
  }

  /**
   * Generate a new CSRF token
   */
  private generateToken(): string {
    return securityUtils.generateSecureRandom(32);
  }

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
   * Store token in session storage for synchronizer pattern
   * Only used in development - production tokens come from server
   */
  private storeToken(): void {
    if (this.token && process.env.NODE_ENV === 'development') {
      // Store in sessionStorage for same-tab access (dev only)
      sessionStorage.setItem(this.storageKey, this.token);
      
      // Set cookie in development
      this.setTokenCookie(this.token);
    }
  }

  /**
   * Set CSRF token as cookie (double-submit pattern)
   * In production, this should be httpOnly and set by server
   */
  private setTokenCookie(token: string): void {
    // In development, we can't set httpOnly from JavaScript
    // This is for demonstration - in production, server sets httpOnly cookie
    const isSecure = window.location.protocol === 'https:';
    const sameSite = 'Strict';
    
    document.cookie = `${this.cookieName}=${token}; ` +
      `SameSite=${sameSite}; ` +
      `Path=/; ` +
      (isSecure ? 'Secure; ' : '');
  }

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

    // Fallback to stored token
    if (!this.token) {
      // In development, we might have a token in sessionStorage
      if (process.env.NODE_ENV === 'development') {
        this.token = sessionStorage.getItem(this.storageKey) || this.generateToken();
        this.storeToken();
      } else {
        // In production, server should always provide token
        throw new CSRFError('CSRF token not found. Server must set csrf_token cookie.');
      }
    }
    return this.token;
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
    this.token = this.generateToken();
    this.storeToken();
  }

  /**
   * Validate CSRF token from response
   */
  validateToken(responseToken: string): boolean {
    return securityUtils.secureCompare(this.getToken(), responseToken);
  }

  /**
   * Clear CSRF token (on logout)
   */
  clearToken(): void {
    this.token = null;
    sessionStorage.removeItem(this.storageKey);
    
    // Clear cookie
    document.cookie = `${this.cookieName}=; ` +
      'expires=Thu, 01 Jan 1970 00:00:00 UTC; ' +
      'Path=/; ' +
      'SameSite=Strict';
  }
}

// Export singleton instance
export const csrfTokenManager = CSRFTokenManager.getInstance();

/**
 * Helper function to get CSRF token from cookie
 * Used by API client and other services
 */
export function getCSRFToken(): string | null {
  try {
    return csrfTokenManager.getToken();
  } catch (error) {
    if (process.env.NODE_ENV === 'development') {
      console.warn('CSRF token not available:', error);
      return null;
    }
    throw error;
  }
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
    return {
      ...headers,
      [headerName]: csrfTokenManager.getToken(),
    };
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
  return {
    token: csrfTokenManager.getToken(),
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
        csrfTokenManager.refreshToken();
      }
    }
    sessionStorage.setItem('last_activity', Date.now().toString());
  });

  // Clear token on logout events
  window.addEventListener('logout', () => {
    csrfTokenManager.clearToken();
  });
}