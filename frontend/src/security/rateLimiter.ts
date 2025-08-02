/**
 * Client-side rate limiting implementation
 * Provides protection against abuse and coordinates with server-side rate limiting
 */

interface RateLimitConfig {
  maxAttempts: number;
  windowMs: number;
  blockDurationMs?: number;
  key?: string;
}

interface RateLimitEntry {
  attempts: number;
  firstAttempt: number;
  blockedUntil?: number;
}

class RateLimiter {
  private limits: Map<string, RateLimitEntry> = new Map();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Clean up expired entries every minute
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
  }

  /**
   * Check if an action is rate limited
   */
  isRateLimited(config: RateLimitConfig): boolean {
    const key = config.key || 'default';
    const now = Date.now();
    const entry = this.limits.get(key);

    if (!entry) {
      return false;
    }

    // Check if currently blocked
    if (entry.blockedUntil && now < entry.blockedUntil) {
      return true;
    }

    // Check if window has expired
    if (now - entry.firstAttempt > config.windowMs) {
      this.limits.delete(key);
      return false;
    }

    // Check if limit exceeded
    return entry.attempts >= config.maxAttempts;
  }

  /**
   * Record an attempt
   */
  recordAttempt(config: RateLimitConfig): { allowed: boolean; retriesAfter?: number } {
    const key = config.key || 'default';
    const now = Date.now();
    let entry = this.limits.get(key);

    // Initialize entry if doesn't exist
    if (!entry) {
      entry = {
        attempts: 0,
        firstAttempt: now,
      };
      this.limits.set(key, entry);
    }

    // Check if currently blocked
    if (entry.blockedUntil && now < entry.blockedUntil) {
      return {
        allowed: false,
        retriesAfter: Math.ceil((entry.blockedUntil - now) / 1000),
      };
    }

    // Reset if window expired
    if (now - entry.firstAttempt > config.windowMs) {
      entry.attempts = 0;
      entry.firstAttempt = now;
      entry.blockedUntil = undefined;
    }

    // Increment attempts
    entry.attempts++;

    // Check if limit exceeded
    if (entry.attempts > config.maxAttempts) {
      // Apply block duration if specified
      if (config.blockDurationMs) {
        entry.blockedUntil = now + config.blockDurationMs;
      }
      
      return {
        allowed: false,
        retriesAfter: config.blockDurationMs 
          ? Math.ceil(config.blockDurationMs / 1000)
          : Math.ceil((config.windowMs - (now - entry.firstAttempt)) / 1000),
      };
    }

    return { allowed: true };
  }

  /**
   * Reset rate limit for a specific key
   */
  reset(key: string = 'default'): void {
    this.limits.delete(key);
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.limits.entries()) {
      // Remove entries that have expired and are not blocked
      if (
        now - entry.firstAttempt > 3600000 && // 1 hour
        (!entry.blockedUntil || now > entry.blockedUntil)
      ) {
        this.limits.delete(key);
      }
    }
  }

  /**
   * Destroy the rate limiter
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.limits.clear();
  }
}

// Singleton instance
export const rateLimiter = new RateLimiter();

// Predefined rate limit configurations
export const RATE_LIMITS = {
  // Authentication endpoints
  LOGIN: {
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
    blockDurationMs: 30 * 60 * 1000, // 30 minutes block after limit
    key: 'auth:login',
  },
  REGISTER: {
    maxAttempts: 3,
    windowMs: 60 * 60 * 1000, // 1 hour
    blockDurationMs: 60 * 60 * 1000, // 1 hour block
    key: 'auth:register',
  },
  PASSWORD_RESET: {
    maxAttempts: 3,
    windowMs: 60 * 60 * 1000, // 1 hour
    blockDurationMs: 2 * 60 * 60 * 1000, // 2 hour block
    key: 'auth:password-reset',
  },
  
  // API endpoints
  API_GENERAL: {
    maxAttempts: 100,
    windowMs: 60 * 1000, // 1 minute
    key: 'api:general',
  },
  API_SEARCH: {
    maxAttempts: 20,
    windowMs: 60 * 1000, // 1 minute
    key: 'api:search',
  },
  API_UPLOAD: {
    maxAttempts: 10,
    windowMs: 60 * 60 * 1000, // 1 hour
    key: 'api:upload',
  },
  
  // Form submissions
  FORM_SUBMISSION: {
    maxAttempts: 10,
    windowMs: 60 * 1000, // 1 minute
    key: 'form:submission',
  },
  CONTACT_FORM: {
    maxAttempts: 5,
    windowMs: 60 * 60 * 1000, // 1 hour
    key: 'form:contact',
  },
};

/**
 * Rate limit decorator for async functions
 */
export function withRateLimit<T extends (...args: any[]) => Promise<any>>(
  fn: T,
  config: RateLimitConfig
): T {
  return (async (...args: Parameters<T>) => {
    const result = rateLimiter.recordAttempt(config);
    
    if (!result.allowed) {
      throw new RateLimitError(
        `Rate limit exceeded. Please try again in ${result.retriesAfter} seconds.`,
        result.retriesAfter
      );
    }
    
    return fn(...args);
  }) as T;
}

/**
 * React hook for rate limiting
 */
export function useRateLimit(config: RateLimitConfig): {
  checkLimit: () => { allowed: boolean; retriesAfter?: number };
  isLimited: boolean;
  reset: () => void;
} {
  const checkLimit = () => rateLimiter.recordAttempt(config);
  const isLimited = rateLimiter.isRateLimited(config);
  const reset = () => rateLimiter.reset(config.key || 'default');

  return { checkLimit, isLimited, reset };
}

/**
 * Custom error class for rate limit errors
 */
export class RateLimitError extends Error {
  public readonly retriesAfter?: number;
  
  constructor(message: string, retriesAfter?: number) {
    super(message);
    this.name = 'RateLimitError';
    this.retriesAfter = retriesAfter;
  }
}

/**
 * Middleware for Axios to handle rate limiting
 */
export function createRateLimitInterceptor() {
  return {
    request: (config: any) => {
      // Determine rate limit config based on endpoint
      let rateLimitConfig = RATE_LIMITS.API_GENERAL;
      
      if (config.url?.includes('/auth/login')) {
        rateLimitConfig = RATE_LIMITS.LOGIN;
      } else if (config.url?.includes('/auth/register')) {
        rateLimitConfig = RATE_LIMITS.REGISTER;
      } else if (config.url?.includes('/auth/reset-password')) {
        rateLimitConfig = RATE_LIMITS.PASSWORD_RESET;
      } else if (config.url?.includes('/search')) {
        rateLimitConfig = RATE_LIMITS.API_SEARCH;
      } else if (config.url?.includes('/upload')) {
        rateLimitConfig = RATE_LIMITS.API_UPLOAD;
      }
      
      const result = rateLimiter.recordAttempt(rateLimitConfig);
      
      if (!result.allowed) {
        return Promise.reject(new RateLimitError(
          `Rate limit exceeded. Please try again in ${result.retriesAfter} seconds.`,
          result.retriesAfter
        ));
      }
      
      return config;
    },
    
    response: (response: any) => {
      // Handle rate limit headers from server
      const remaining = response.headers['x-ratelimit-remaining'];
      const reset = response.headers['x-ratelimit-reset'];
      
      if (remaining === '0' && reset) {
        const resetTime = parseInt(reset, 10) * 1000;
        const now = Date.now();
        const retriesAfter = Math.ceil((resetTime - now) / 1000);
        
        // Sync with server rate limits
        console.warn(`Server rate limit approaching. Resets in ${retriesAfter} seconds.`);
      }
      
      return response;
    },
    
    responseError: (error: any) => {
      // Handle 429 Too Many Requests
      if (error.response?.status === 429) {
        const retryAfter = error.response.headers['retry-after'];
        const retriesAfter = retryAfter ? parseInt(retryAfter, 10) : 60;
        
        throw new RateLimitError(
          `Server rate limit exceeded. Please try again in ${retriesAfter} seconds.`,
          retriesAfter
        );
      }
      
      return Promise.reject(error);
    },
  };
}