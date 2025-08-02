/**
 * Comprehensive mutex utility for handling concurrent operations in TypeScript
 * Provides thread-safe synchronization primitives with timeout support and debugging capabilities
 * 
 * @fileoverview This module exports Mutex and TokenRefreshMutex classes for managing
 * concurrent access to shared resources in TypeScript applications.
 * 
 * @author Enterprise Development Team
 * @version 1.0.0
 */

/**
 * Configuration options for mutex timeout behavior
 */
export interface MutexTimeoutOptions {
  /** Timeout duration in milliseconds */
  timeout: number;
  /** Custom error message for timeout scenarios */
  timeoutMessage?: string;
}

/**
 * Configuration options for mutex debugging
 */
export interface MutexDebugOptions {
  /** Enable debug logging */
  enabled: boolean;
  /** Custom logger function (defaults to console.log) */
  logger?: (message: string, ...args: unknown[]) => void;
  /** Include stack trace in debug logs */
  includeStackTrace?: boolean;
}

/**
 * Internal queue item for managing mutex acquisition requests
 */
interface MutexQueueItem<T = unknown> {
  /** Unique identifier for this acquisition request */
  readonly id: string;
  /** Promise resolver for successful acquisition */
  readonly resolve: (value: T) => void;
  /** Promise rejector for failed acquisition */
  readonly reject: (reason: unknown) => void;
  /** Timestamp when the request was queued */
  readonly queuedAt: number;
  /** Optional timeout handle */
  timeoutHandle?: ReturnType<typeof setTimeout>;
}

/**
 * Custom error class for mutex-related errors
 */
export class MutexError extends Error {
  public readonly code: 'TIMEOUT' | 'DISPOSED' | 'INVALID_STATE';
  
  constructor(
    message: string,
    code: 'TIMEOUT' | 'DISPOSED' | 'INVALID_STATE' = 'INVALID_STATE'
  ) {
    super(message);
    this.name = 'MutexError';
    this.code = code;
    Object.setPrototypeOf(this, MutexError.prototype);
  }
}

/**
 * Type guard to check if a value is a MutexError
 */
export function isMutexError(error: unknown): error is MutexError {
  return error instanceof MutexError;
}

/**
 * Type for mutex execution function that can be async or sync
 */
export type MutexExecutor<T> = () => T | Promise<T>;

/**
 * Result type for mutex execution with error handling
 */
export type MutexResult<T> = {
  success: true;
  data: T;
  executionTime: number;
} | {
  success: false;
  error: Error;
  executionTime: number;
};

/**
 * Promise-based mutex implementation for preventing race conditions
 * 
 * @template T The type of value returned by operations executed within the mutex
 * 
 * @example
 * ```typescript
 * const mutex = new Mutex({ debug: { enabled: true } });
 * 
 * const result = await mutex.acquire(async () => {
 *   // Critical section - only one execution at a time
 *   await someAsyncOperation();
 *   return 'success';
 * });
 * ```
 */
export class Mutex<T = unknown> {
  private readonly queue: MutexQueueItem<T>[] = [];
  private isLocked = false;
  private readonly debugOptions: Required<MutexDebugOptions>;
  private readonly name: string;
  private isDisposed = false;
  private lockCount = 0;
  private totalWaitTime = 0;
  
  /**
   * Creates a new Mutex instance
   * 
   * @param options Configuration options for the mutex
   * @param options.debug Debug configuration
   * @param options.name Optional name for debugging purposes
   */
  constructor(options: {
    debug?: Partial<MutexDebugOptions>;
    name?: string;
  } = {}) {
    this.name = options.name || `Mutex-${Math.random().toString(36).substring(2, 11)}`;
    this.debugOptions = {
      enabled: options.debug?.enabled ?? false,
      logger: options.debug?.logger ?? console.log,
      includeStackTrace: options.debug?.includeStackTrace ?? false,
    };
    
    this.debug('Mutex created', { name: this.name });
  }

  /**
   * Acquires the mutex and executes the provided function
   * 
   * @param executor Function to execute while holding the mutex
   * @param timeoutOptions Optional timeout configuration
   * @returns Promise resolving to the executor's return value
   * 
   * @throws {MutexError} When timeout occurs or mutex is disposed
   * 
   * @example
   * ```typescript
   * const result = await mutex.acquire(
   *   async () => {
   *     return await criticalOperation();
   *   },
   *   { timeout: 5000, timeoutMessage: 'Operation timed out' }
   * );
   * ```
   */
  public async acquire(
    executor: MutexExecutor<T>,
    timeoutOptions?: MutexTimeoutOptions
  ): Promise<T> {
    if (this.isDisposed) {
      throw new MutexError('Cannot acquire disposed mutex', 'DISPOSED');
    }

    const startTime = Date.now();
    const requestId = this.generateRequestId();
    
    this.debug('Acquire requested', { requestId, queueLength: this.queue.length });

    try {
      await this.waitForTurn(requestId, timeoutOptions);
      
      const waitTime = Date.now() - startTime;
      this.totalWaitTime += waitTime;
      
      this.debug('Lock acquired', { requestId, waitTime });
      
      // Execute the critical section
      const executionStart = Date.now();
      const result = await executor();
      const executionTime = Date.now() - executionStart;
      
      this.debug('Execution completed', { requestId, executionTime });
      
      return result;
    } finally {
      this.releaseLock();
    }
  }

  /**
   * Tries to acquire the mutex without waiting
   * 
   * @param executor Function to execute if mutex is available
   * @returns Promise resolving to the result or null if mutex is busy
   * 
   * @example
   * ```typescript
   * const result = await mutex.tryAcquire(async () => {
   *   return await quickOperation();
   * });
   * 
   * if (result === null) {
   *   console.log('Mutex was busy, operation skipped');
   * }
   * ```
   */
  public async tryAcquire(executor: MutexExecutor<T>): Promise<T | null> {
    if (this.isDisposed) {
      throw new MutexError('Cannot acquire disposed mutex', 'DISPOSED');
    }

    if (this.isLocked) {
      this.debug('Try acquire failed - already locked');
      return null;
    }

    return this.acquire(executor);
  }

  /**
   * Executes a function with mutex protection and returns a detailed result
   * 
   * @param executor Function to execute
   * @param timeoutOptions Optional timeout configuration
   * @returns Promise resolving to execution result with metadata
   */
  public async runWithResult(
    executor: MutexExecutor<T>,
    timeoutOptions?: MutexTimeoutOptions
  ): Promise<MutexResult<T>> {
    const startTime = Date.now();
    
    try {
      const data = await this.acquire(executor, timeoutOptions);
      const executionTime = Date.now() - startTime;
      
      return {
        success: true,
        data,
        executionTime,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;
      
      return {
        success: false,
        error: error instanceof Error ? error : new Error(String(error)),
        executionTime,
      };
    }
  }

  /**
   * Checks if the mutex is currently locked
   */
  public get locked(): boolean {
    return this.isLocked;
  }

  /**
   * Gets the current queue length
   */
  public get queueLength(): number {
    return this.queue.length;
  }

  /**
   * Gets mutex statistics
   */
  public getStats(): {
    name: string;
    locked: boolean;
    queueLength: number;
    lockCount: number;
    averageWaitTime: number;
    totalWaitTime: number;
  } {
    return {
      name: this.name,
      locked: this.isLocked,
      queueLength: this.queue.length,
      lockCount: this.lockCount,
      averageWaitTime: this.lockCount > 0 ? this.totalWaitTime / this.lockCount : 0,
      totalWaitTime: this.totalWaitTime,
    };
  }

  /**
   * Disposes the mutex and rejects all pending acquisitions
   */
  public dispose(): void {
    if (this.isDisposed) {
      return;
    }

    this.debug('Disposing mutex', { pendingCount: this.queue.length });
    
    this.isDisposed = true;
    
    // Reject all pending acquisitions
    const disposedError = new MutexError('Mutex has been disposed', 'DISPOSED');
    
    while (this.queue.length > 0) {
      const item = this.queue.shift()!;
      if (item.timeoutHandle) {
        clearTimeout(item.timeoutHandle);
      }
      item.reject(disposedError);
    }
    
    this.debug('Mutex disposed');
  }

  /**
   * Waits for the mutex to become available
   */
  private async waitForTurn(
    requestId: string,
    timeoutOptions?: MutexTimeoutOptions
  ): Promise<void> {
    if (!this.isLocked) {
      this.isLocked = true;
      this.lockCount++;
      return;
    }

    return new Promise<void>((resolve, reject) => {
      const queueItem: MutexQueueItem<void> = {
        id: requestId,
        resolve,
        reject,
        queuedAt: Date.now(),
      };

      // Set up timeout if specified
      if (timeoutOptions) {
        queueItem.timeoutHandle = setTimeout(() => {
          this.removeFromQueue(requestId);
          const message = timeoutOptions.timeoutMessage || 
            `Mutex acquisition timed out after ${timeoutOptions.timeout}ms`;
          reject(new MutexError(message, 'TIMEOUT'));
        }, timeoutOptions.timeout);
      }

      this.queue.push(queueItem as MutexQueueItem<T>);
      this.debug('Added to queue', { requestId, position: this.queue.length });
    });
  }

  /**
   * Releases the mutex lock and processes the next item in queue
   */
  private releaseLock(): void {
    if (this.queue.length > 0) {
      const nextItem = this.queue.shift()!;
      
      if (nextItem.timeoutHandle) {
        clearTimeout(nextItem.timeoutHandle);
      }
      
      this.debug('Lock transferred', { requestId: nextItem.id });
      this.lockCount++;
      nextItem.resolve(undefined as T);
    } else {
      this.isLocked = false;
      this.debug('Lock released');
    }
  }

  /**
   * Removes an item from the queue by ID
   */
  private removeFromQueue(requestId: string): void {
    const index = this.queue.findIndex(item => item.id === requestId);
    if (index !== -1) {
      const [removed] = this.queue.splice(index, 1);
      if (removed.timeoutHandle) {
        clearTimeout(removed.timeoutHandle);
      }
      this.debug('Removed from queue', { requestId, position: index });
    }
  }

  /**
   * Generates a unique request ID
   */
  private generateRequestId(): string {
    return `${this.name}-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Logs debug messages if debugging is enabled
   */
  private debug(message: string, data?: Record<string, unknown>): void {
    if (!this.debugOptions.enabled) return;

    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${this.name}] ${message}`;
    
    if (data) {
      this.debugOptions.logger(logMessage, data);
    } else {
      this.debugOptions.logger(logMessage);
    }

    if (this.debugOptions.includeStackTrace) {
      const stack = new Error().stack?.split('\n').slice(2).join('\n');
      this.debugOptions.logger('Stack trace:', stack);
    }
  }
}

/**
 * Configuration for TokenRefreshMutex
 */
export interface TokenRefreshConfig {
  /** Function to refresh the token */
  refreshToken: () => Promise<string>;
  /** Function to check if token is valid */
  isTokenValid: (token: string | null) => boolean;
  /** Initial token value */
  initialToken?: string | null;
  /** Timeout for refresh operations */
  refreshTimeout?: number;
  /** Debug options */
  debug?: Partial<MutexDebugOptions>;
}

/**
 * Specialized mutex for managing token refresh operations
 * Prevents multiple simultaneous token refresh requests and ensures all waiting
 * operations receive the refreshed token
 * 
 * @example
 * ```typescript
 * const tokenMutex = new TokenRefreshMutex({
 *   refreshToken: async () => {
 *     const response = await fetch('/api/refresh-token', { method: 'POST' });
 *     const { token } = await response.json();
 *     return token;
 *   },
 *   isTokenValid: (token) => {
 *     if (!token) return false;
 *     // Add your token validation logic here
 *     return true;
 *   },
 *   initialToken: localStorage.getItem('authToken'),
 *   refreshTimeout: 10000,
 *   debug: { enabled: true }
 * });
 * 
 * // Use in API calls
 * const token = await tokenMutex.getValidToken();
 * ```
 */
export class TokenRefreshMutex {
  private readonly mutex: Mutex<string>;
  private readonly config: Required<Omit<TokenRefreshConfig, 'initialToken' | 'debug'>>;
  private currentToken: string | null;
  private isRefreshing = false;
  private lastRefreshTime = 0;
  private refreshCount = 0;

  constructor(config: TokenRefreshConfig) {
    this.config = {
      refreshToken: config.refreshToken,
      isTokenValid: config.isTokenValid,
      refreshTimeout: config.refreshTimeout ?? 30000,
    };
    
    this.currentToken = config.initialToken ?? null;
    this.mutex = new Mutex<string>({
      name: 'TokenRefreshMutex',
      debug: config.debug,
    });
  }

  /**
   * Gets a valid token, refreshing if necessary
   * 
   * @returns Promise resolving to a valid token
   * @throws {MutexError} When token refresh fails or times out
   */
  public async getValidToken(): Promise<string> {
    // If current token is valid, return it immediately
    if (this.config.isTokenValid(this.currentToken)) {
      return this.currentToken!;
    }

    // Use mutex to ensure only one refresh operation at a time
    return this.mutex.acquire(async () => {
      // Double-check pattern: token might have been refreshed by another request
      if (this.config.isTokenValid(this.currentToken)) {
        return this.currentToken!;
      }

      return this.performTokenRefresh();
    }, {
      timeout: this.config.refreshTimeout,
      timeoutMessage: `Token refresh timed out after ${this.config.refreshTimeout}ms`,
    });
  }

  /**
   * Forces a token refresh regardless of current token validity
   * 
   * @returns Promise resolving to the new token
   */
  public async forceRefresh(): Promise<string> {
    return this.mutex.acquire(async () => {
      return this.performTokenRefresh();
    }, {
      timeout: this.config.refreshTimeout,
      timeoutMessage: `Forced token refresh timed out after ${this.config.refreshTimeout}ms`,
    });
  }

  /**
   * Gets the current token without validation or refresh
   */
  public getCurrentToken(): string | null {
    return this.currentToken;
  }

  /**
   * Checks if a token refresh is currently in progress
   */
  public get isRefreshInProgress(): boolean {
    return this.isRefreshing;
  }

  /**
   * Gets statistics about token refresh operations
   */
  public getRefreshStats(): {
    refreshCount: number;
    lastRefreshTime: number;
    timeSinceLastRefresh: number;
    isRefreshing: boolean;
    currentTokenValid: boolean;
  } {
    return {
      refreshCount: this.refreshCount,
      lastRefreshTime: this.lastRefreshTime,
      timeSinceLastRefresh: this.lastRefreshTime > 0 ? Date.now() - this.lastRefreshTime : 0,
      isRefreshing: this.isRefreshing,
      currentTokenValid: this.config.isTokenValid(this.currentToken),
    };
  }

  /**
   * Sets the current token value
   * Used when tokens are updated externally (e.g., after login)
   */
  public setToken(token: string | null): void {
    this.currentToken = token;
    if (token) {
      this.lastRefreshTime = Date.now();
    }
  }

  /**
   * Invalidates the current token, forcing a refresh on next access
   */
  public invalidateToken(): void {
    this.currentToken = null;
  }

  /**
   * Disposes the token refresh mutex
   */
  public dispose(): void {
    this.mutex.dispose();
  }

  /**
   * Performs the actual token refresh operation
   */
  private async performTokenRefresh(): Promise<string> {
    this.isRefreshing = true;
    const refreshStartTime = Date.now();

    try {
      const newToken = await this.config.refreshToken();
      
      if (!this.config.isTokenValid(newToken)) {
        throw new MutexError('Refresh token returned invalid token', 'INVALID_STATE');
      }

      this.currentToken = newToken;
      this.lastRefreshTime = Date.now();
      this.refreshCount++;

      const refreshDuration = this.lastRefreshTime - refreshStartTime;
      console.debug(`Token refreshed successfully in ${refreshDuration}ms`);

      return newToken;
    } catch (error) {
      const refreshDuration = Date.now() - refreshStartTime;
      console.error(`Token refresh failed after ${refreshDuration}ms:`, error);
      
      // Clear the current token on refresh failure
      this.currentToken = null;
      
      if (error instanceof MutexError) {
        throw error;
      }
      
      throw new MutexError(
        `Token refresh failed: ${error instanceof Error ? error.message : String(error)}`,
        'INVALID_STATE'
      );
    } finally {
      this.isRefreshing = false;
    }
  }
}

/**
 * Utility function to create a mutex with common debugging configuration
 * 
 * @param name Optional name for the mutex
 * @param enableDebug Whether to enable debug logging
 * @returns New Mutex instance
 */
export function createMutex<T = unknown>(
  name?: string,
  enableDebug = false
): Mutex<T> {
  return new Mutex<T>({
    name,
    debug: { enabled: enableDebug },
  });
}

/**
 * Utility function to create a token refresh mutex with common configuration
 * 
 * @param config Token refresh configuration
 * @returns New TokenRefreshMutex instance
 */
export function createTokenRefreshMutex(
  config: TokenRefreshConfig
): TokenRefreshMutex {
  return new TokenRefreshMutex(config);
}

/**
 * Higher-order function that wraps a function with mutex protection
 * 
 * @param fn Function to wrap
 * @param mutex Mutex to use for protection
 * @returns Wrapped function that acquires mutex before execution
 * 
 * @example
 * ```typescript
 * const mutex = createMutex();
 * const protectedFunction = withMutex(
 *   async (data: string) => {
 *     // This will be executed with mutex protection
 *     return await processData(data);
 *   },
 *   mutex
 * );
 * 
 * // Usage
 * const result = await protectedFunction('test data');
 * ```
 */
export function withMutex<TArgs extends unknown[], TReturn>(
  fn: (...args: TArgs) => Promise<TReturn>,
  mutex: Mutex<TReturn>
): (...args: TArgs) => Promise<TReturn> {
  return async (...args: TArgs): Promise<TReturn> => {
    return mutex.acquire(() => fn(...args));
  };
}

// Types are already exported above, no need to re-export