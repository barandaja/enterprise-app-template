/**
 * Token Manager Service
 * Centralized token management with mutex protection and advanced security features
 */

import { TokenRefreshMutex } from '../../utils/mutex';
import { tokenStorage } from '../../security/secureStorage';
import { authApi } from '../api/auth.service';
import { ApiError } from '../api/types';

/**
 * Token pair structure
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresAt?: number;
}

/**
 * Token manager configuration
 */
export interface TokenManagerConfig {
  /** Time before expiry to trigger refresh (in ms) */
  refreshBufferTime?: number;
  /** Maximum number of refresh retries */
  maxRetries?: number;
  /** Base retry delay (in ms) */
  baseRetryDelay?: number;
  /** Maximum retry delay (in ms) */
  maxRetryDelay?: number;
  /** Enable debug logging */
  enableDebugLogging?: boolean;
  /** Custom logger function */
  logger?: (message: string, data?: any) => void;
}

/**
 * Token refresh error with details
 */
export class TokenRefreshError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly isRetryable: boolean = false,
    public readonly details?: any
  ) {
    super(message);
    this.name = 'TokenRefreshError';
  }
}

/**
 * JWT payload interface
 */
interface JWTPayload {
  exp?: number;
  iat?: number;
  sub?: string;
  [key: string]: any;
}

/**
 * Token Manager Service
 * Handles all token operations with thread safety and security
 */
export class TokenManager {
  private mutex: TokenRefreshMutex;
  private config: Required<TokenManagerConfig>;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private retryCount = 0;
  private tokenChangeCallbacks = new Set<(tokens: TokenPair | null) => void>();

  constructor(config: TokenManagerConfig = {}) {
    this.config = {
      refreshBufferTime: config.refreshBufferTime ?? 5 * 60 * 1000, // 5 minutes
      maxRetries: config.maxRetries ?? 3,
      baseRetryDelay: config.baseRetryDelay ?? 1000,
      maxRetryDelay: config.maxRetryDelay ?? 30000,
      enableDebugLogging: config.enableDebugLogging ?? false,
      logger: config.logger ?? console.log
    };

    this.mutex = new TokenRefreshMutex({
      refreshToken: this.performTokenRefresh.bind(this),
      isTokenValid: this.isTokenValid.bind(this),
      timeout: 30000, // 30 second timeout
      debug: this.config.enableDebugLogging,
      logger: this.config.logger
    });
  }

  /**
   * Initialize token manager with existing tokens
   */
  async initialize(): Promise<void> {
    try {
      const tokens = await tokenStorage.getTokens();
      if (tokens.accessToken && tokens.refreshToken) {
        await this.setTokens({
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken
        });
      }
    } catch (error) {
      this.log('Failed to initialize tokens', error);
    }
  }

  /**
   * Get valid access token (refreshing if necessary)
   */
  async getValidToken(): Promise<string> {
    const token = await this.mutex.getValidToken();
    if (!token) {
      throw new TokenRefreshError(
        'No valid token available',
        'NO_TOKEN',
        false
      );
    }
    return token;
  }

  /**
   * Get current tokens without refresh
   */
  async getCurrentTokens(): Promise<TokenPair | null> {
    const tokens = await tokenStorage.getTokens();
    if (tokens.accessToken && tokens.refreshToken) {
      return {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: this.getTokenExpiry(tokens.accessToken)
      };
    }
    return null;
  }

  /**
   * Set new tokens
   */
  async setTokens(tokens: TokenPair): Promise<void> {
    await tokenStorage.setTokens(tokens.accessToken, tokens.refreshToken);
    
    // Update mutex with new token
    await this.mutex.setToken(tokens.accessToken);
    
    // Schedule refresh
    this.scheduleTokenRefresh(tokens.accessToken);
    
    // Notify listeners
    this.notifyTokenChange(tokens);
    
    // Reset retry count on successful token update
    this.retryCount = 0;
  }

  /**
   * Clear all tokens
   */
  async clearTokens(): Promise<void> {
    // Cancel scheduled refresh
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }

    // Clear storage
    await tokenStorage.clearTokens();
    
    // Clear mutex
    await this.mutex.setToken(null);
    
    // Notify listeners
    this.notifyTokenChange(null);
  }

  /**
   * Force token refresh
   */
  async forceRefresh(): Promise<TokenPair> {
    this.log('Forcing token refresh');
    const token = await this.mutex.forceRefresh();
    
    if (!token) {
      throw new TokenRefreshError(
        'Force refresh failed',
        'REFRESH_FAILED',
        false
      );
    }

    const tokens = await this.getCurrentTokens();
    if (!tokens) {
      throw new TokenRefreshError(
        'Tokens not available after refresh',
        'TOKENS_MISSING',
        false
      );
    }

    return tokens;
  }

  /**
   * Register callback for token changes
   */
  onTokenChange(callback: (tokens: TokenPair | null) => void): () => void {
    this.tokenChangeCallbacks.add(callback);
    return () => this.tokenChangeCallbacks.delete(callback);
  }

  /**
   * Perform the actual token refresh
   */
  private async performTokenRefresh(): Promise<string | null> {
    const tokens = await tokenStorage.getTokens();
    
    if (!tokens.refreshToken) {
      throw new TokenRefreshError(
        'No refresh token available',
        'NO_REFRESH_TOKEN',
        false
      );
    }

    try {
      this.log('Performing token refresh');
      
      const response = await authApi.refreshToken(tokens.refreshToken);
      
      if (!response.success || !response.data) {
        throw new TokenRefreshError(
          response.message || 'Token refresh failed',
          response.code || 'REFRESH_FAILED',
          true,
          response
        );
      }

      const { accessToken, refreshToken } = response.data;
      
      // Store new tokens
      await this.setTokens({ accessToken, refreshToken });
      
      this.log('Token refresh successful');
      return accessToken;
      
    } catch (error) {
      // Handle different error types
      if (error instanceof TokenRefreshError) {
        throw error;
      }
      
      if (error instanceof ApiError) {
        const isRetryable = error.status >= 500 || error.status === 429;
        throw new TokenRefreshError(
          error.message,
          error.code || 'API_ERROR',
          isRetryable,
          error
        );
      }

      // Network errors are retryable
      const isNetworkError = error instanceof Error && 
        (error.message.includes('network') || error.message.includes('fetch'));
      
      throw new TokenRefreshError(
        'Token refresh failed',
        'UNKNOWN_ERROR',
        isNetworkError,
        error
      );
    }
  }

  /**
   * Check if token is valid
   */
  private isTokenValid(token: string | null): boolean {
    if (!token) return false;

    try {
      const expiry = this.getTokenExpiry(token);
      if (!expiry) return false;

      const now = Date.now();
      const timeUntilExpiry = expiry - now;
      
      // Token is valid if it won't expire within the buffer time
      return timeUntilExpiry > this.config.refreshBufferTime;
    } catch {
      return false;
    }
  }

  /**
   * Extract expiry from JWT token
   */
  private getTokenExpiry(token: string): number | null {
    try {
      const payload = this.parseJWT(token);
      if (payload.exp) {
        return payload.exp * 1000; // Convert to milliseconds
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Parse JWT token
   */
  private parseJWT(token: string): JWTPayload {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const payload = parts[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch (error) {
      throw new TokenRefreshError(
        'Failed to parse JWT',
        'INVALID_JWT',
        false,
        error
      );
    }
  }

  /**
   * Schedule automatic token refresh
   */
  private scheduleTokenRefresh(token: string): void {
    // Cancel existing timer
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }

    const expiry = this.getTokenExpiry(token);
    if (!expiry) {
      this.log('Unable to schedule refresh: no expiry in token');
      return;
    }

    const now = Date.now();
    const timeUntilExpiry = expiry - now;
    const refreshTime = timeUntilExpiry - this.config.refreshBufferTime;

    if (refreshTime > 0) {
      this.log(`Scheduling token refresh in ${refreshTime}ms`);
      
      this.refreshTimer = setTimeout(async () => {
        try {
          await this.forceRefresh();
        } catch (error) {
          this.log('Scheduled refresh failed', error);
          
          // Implement exponential backoff retry
          if (error instanceof TokenRefreshError && error.isRetryable) {
            this.scheduleRetry();
          }
        }
      }, refreshTime);
    } else {
      // Token already needs refresh
      this.log('Token needs immediate refresh');
      this.forceRefresh().catch(error => {
        this.log('Immediate refresh failed', error);
        if (error instanceof TokenRefreshError && error.isRetryable) {
          this.scheduleRetry();
        }
      });
    }
  }

  /**
   * Schedule retry with exponential backoff
   */
  private scheduleRetry(): void {
    if (this.retryCount >= this.config.maxRetries) {
      this.log('Max retries reached, giving up');
      this.clearTokens();
      return;
    }

    this.retryCount++;
    const delay = Math.min(
      this.config.baseRetryDelay * Math.pow(2, this.retryCount - 1),
      this.config.maxRetryDelay
    );

    this.log(`Scheduling retry ${this.retryCount}/${this.config.maxRetries} in ${delay}ms`);
    
    setTimeout(() => {
      this.forceRefresh().catch(error => {
        this.log('Retry failed', error);
        if (error instanceof TokenRefreshError && error.isRetryable) {
          this.scheduleRetry();
        }
      });
    }, delay);
  }

  /**
   * Notify listeners of token changes
   */
  private notifyTokenChange(tokens: TokenPair | null): void {
    this.tokenChangeCallbacks.forEach(callback => {
      try {
        callback(tokens);
      } catch (error) {
        this.log('Token change callback error', error);
      }
    });
  }

  /**
   * Log message if debug is enabled
   */
  private log(message: string, data?: any): void {
    if (this.config.enableDebugLogging) {
      this.config.logger(`[TokenManager] ${message}`, data);
    }
  }

  /**
   * Clean up resources
   */
  dispose(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
    this.tokenChangeCallbacks.clear();
    this.mutex.dispose();
  }
}

// Create singleton instance
export const tokenManager = new TokenManager({
  enableDebugLogging: process.env.NODE_ENV === 'development'
});

// Initialize on module load
if (typeof window !== 'undefined') {
  tokenManager.initialize().catch(error => {
    console.error('Failed to initialize token manager:', error);
  });
}