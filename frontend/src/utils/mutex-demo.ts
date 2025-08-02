/**
 * Demonstration of the mutex utility in a practical scenario
 * This file shows how to use the mutex in real-world applications
 */

import { 
  Mutex, 
  TokenRefreshMutex, 
  createMutex, 
  withMutex,
  type MutexResult 
} from './mutex';

/**
 * Example 1: Database Connection Pool Manager
 * Prevents race conditions when acquiring database connections
 */
class DatabaseConnectionPool {
  private connectionMutex = createMutex<string>('DBConnectionPool', true);
  private availableConnections: string[] = [];
  private maxConnections = 5;
  private connectionCounter = 0;

  async getConnection(): Promise<string> {
    return this.connectionMutex.acquire(async () => {
      // Check if we have available connections
      if (this.availableConnections.length > 0) {
        const connection = this.availableConnections.pop()!;
        console.log(`Reusing connection: ${connection}`);
        return connection;
      }

      // Create new connection if under limit
      if (this.connectionCounter < this.maxConnections) {
        this.connectionCounter++;
        const newConnection = `conn_${this.connectionCounter}`;
        console.log(`Created new connection: ${newConnection}`);
        return newConnection;
      }

      // Wait for a connection to become available
      throw new Error('No connections available');
    });
  }

  async releaseConnection(connectionId: string): Promise<void> {
    return this.connectionMutex.acquire(async () => {
      this.availableConnections.push(connectionId);
      console.log(`Released connection: ${connectionId}`);
    });
  }
}

/**
 * Example 2: Cache Manager with Race Condition Prevention
 * Ensures cache updates don't interfere with each other
 */
class CacheManager<T> {
  private cache = new Map<string, { data: T; timestamp: number }>();
  private cacheMutex = new Mutex<T>({ 
    name: 'CacheManager',
    debug: { enabled: true }
  });
  private readonly TTL = 5 * 60 * 1000; // 5 minutes

  async get(key: string, fetcher: () => Promise<T>): Promise<T> {
    return this.cacheMutex.acquire(async () => {
      const cached = this.cache.get(key);
      
      // Return cached value if valid
      if (cached && Date.now() - cached.timestamp < this.TTL) {
        console.log(`Cache hit for key: ${key}`);
        return cached.data;
      }

      // Fetch new data
      console.log(`Cache miss for key: ${key}, fetching...`);
      const data = await fetcher();
      
      // Update cache
      this.cache.set(key, { 
        data, 
        timestamp: Date.now() 
      });
      
      return data;
    }, {
      timeout: 10000,
      timeoutMessage: `Cache fetch timeout for key: ${key}`
    });
  }

  async invalidate(key: string): Promise<void> {
    return this.cacheMutex.acquire(async () => {
      this.cache.delete(key);
      console.log(`Invalidated cache for key: ${key}`);
    });
  }

  getStats() {
    return {
      cacheSize: this.cache.size,
      mutexStats: this.cacheMutex.getStats()
    };
  }
}

/**
 * Example 3: File Upload Manager
 * Prevents concurrent uploads of the same file
 */
class FileUploadManager {
  private uploadMutexes = new Map<string, Mutex<string>>();

  async uploadFile(fileId: string, uploadFn: () => Promise<string>): Promise<MutexResult<string>> {
    // Get or create mutex for this specific file
    if (!this.uploadMutexes.has(fileId)) {
      this.uploadMutexes.set(fileId, new Mutex<string>({
        name: `FileUpload-${fileId}`,
        debug: { enabled: true }
      }));
    }

    const mutex = this.uploadMutexes.get(fileId)!;

    // Use runWithResult for detailed error handling
    const result = await mutex.runWithResult(uploadFn, {
      timeout: 30000,
      timeoutMessage: `File upload timeout for ${fileId}`
    });

    // Clean up mutex if successful or failed
    if (result.success || !mutex.locked) {
      mutex.dispose();
      this.uploadMutexes.delete(fileId);
    }

    return result;
  }

  getActiveUploads(): string[] {
    return Array.from(this.uploadMutexes.entries())
      .filter(([, mutex]) => mutex.locked)
      .map(([fileId]) => fileId);
  }
}

/**
 * Example 4: API Client with Token Management
 * Handles authentication token refresh automatically
 */
class ApiClient {
  private baseUrl: string;
  private tokenMutex: TokenRefreshMutex;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
    this.tokenMutex = new TokenRefreshMutex({
      refreshToken: this.performTokenRefresh.bind(this),
      isTokenValid: this.validateToken.bind(this),
      initialToken: this.getStoredToken(),
      refreshTimeout: 15000,
      debug: { enabled: process.env.NODE_ENV === 'development' }
    });
  }

  private async performTokenRefresh(): Promise<string> {
    const response = await fetch(`${this.baseUrl}/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status}`);
    }

    const { accessToken } = await response.json();
    this.storeToken(accessToken);
    return accessToken;
  }

  private validateToken(token: string | null): boolean {
    if (!token) return false;

    try {
      // Simple JWT expiration check
      const payload = JSON.parse(atob(token.split('.')[1]));
      const isExpired = payload.exp * 1000 <= Date.now();
      return !isExpired;
    } catch {
      return false;
    }
  }

  private getStoredToken(): string | null {
    try {
      return localStorage.getItem('authToken');
    } catch {
      return null;
    }
  }

  private storeToken(token: string): void {
    try {
      localStorage.setItem('authToken', token);
    } catch (error) {
      console.warn('Failed to store token:', error);
    }
  }

  async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const token = await this.tokenMutex.getValidToken();

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    });

    if (response.status === 401) {
      // Token might be invalid, invalidate and retry once
      this.tokenMutex.invalidateToken();
      const newToken = await this.tokenMutex.getValidToken();
      
      const retryResponse = await fetch(`${this.baseUrl}${endpoint}`, {
        ...options,
        headers: {
          ...options.headers,
          'Authorization': `Bearer ${newToken}`,
          'Content-Type': 'application/json'
        }
      });

      if (!retryResponse.ok) {
        throw new Error(`API request failed: ${retryResponse.status}`);
      }

      return retryResponse.json();
    }

    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }

    return response.json();
  }

  getTokenStats() {
    return this.tokenMutex.getRefreshStats();
  }
}

/**
 * Example 5: Protected Function Decorator
 * Higher-order function that adds mutex protection to any async function
 */
function createProtectedFunction<TArgs extends unknown[], TReturn>(
  name: string,
  fn: (...args: TArgs) => Promise<TReturn>,
  timeoutMs = 5000
) {
  const mutex = createMutex<TReturn>(name, true);
  
  return {
    execute: withMutex(fn, mutex),
    tryExecute: async (...args: TArgs): Promise<TReturn | null> => {
      return mutex.tryAcquire(() => fn(...args));
    },
    getStats: () => mutex.getStats(),
    dispose: () => mutex.dispose()
  };
}

// Usage examples
export const demos = {
  DatabaseConnectionPool,
  CacheManager,
  FileUploadManager,
  ApiClient,
  createProtectedFunction
};

/**
 * Demonstration runner
 */
export async function runDemonstrations(): Promise<void> {
  console.log('🚀 Starting Mutex Utility Demonstrations\n');

  // Demo 1: Database Connection Pool
  console.log('=== Demo 1: Database Connection Pool ===');
  const dbPool = new DatabaseConnectionPool();
  
  try {
    const connections = await Promise.all([
      dbPool.getConnection(),
      dbPool.getConnection(),
      dbPool.getConnection()
    ]);
    
    console.log('Acquired connections:', connections);
    
    // Release connections
    await Promise.all(connections.map(conn => dbPool.releaseConnection(conn)));
  } catch (error) {
    console.error('Database pool demo error:', error);
  }

  // Demo 2: Cache Manager
  console.log('\n=== Demo 2: Cache Manager ===');
  const cache = new CacheManager<string>();
  
  const fetchData = async (key: string) => {
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 100));
    return `Data for ${key} at ${Date.now()}`;
  };

  try {
    // Multiple concurrent requests for the same key
    const results = await Promise.all([
      cache.get('user:123', () => fetchData('user:123')),
      cache.get('user:123', () => fetchData('user:123')),
      cache.get('user:456', () => fetchData('user:456'))
    ]);
    
    console.log('Cache results:', results);
    console.log('Cache stats:', cache.getStats());
  } catch (error) {
    console.error('Cache demo error:', error);
  }

  // Demo 3: Protected Function
  console.log('\n=== Demo 3: Protected Function ===');
  let counter = 0;
  
  const protectedIncrement = createProtectedFunction(
    'Increment',
    async (amount: number) => {
      const current = counter;
      // Simulate async work
      await new Promise(resolve => setTimeout(resolve, 50));
      counter = current + amount;
      return counter;
    }
  );

  try {
    const results = await Promise.all([
      protectedIncrement.execute(1),
      protectedIncrement.execute(2),
      protectedIncrement.execute(3)
    ]);
    
    console.log('Protected increment results:', results);
    console.log('Final counter value:', counter);
    console.log('Function stats:', protectedIncrement.getStats());
    
    protectedIncrement.dispose();
  } catch (error) {
    console.error('Protected function demo error:', error);
  }

  console.log('\n✅ All demonstrations completed!');
}

// Export for use in other parts of the application
export {
  DatabaseConnectionPool,
  CacheManager,
  FileUploadManager,
  ApiClient,
  createProtectedFunction
};