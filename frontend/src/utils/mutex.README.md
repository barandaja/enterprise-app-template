# Mutex Utility Documentation

A comprehensive, production-ready mutex implementation for TypeScript applications that provides thread-safe synchronization primitives with timeout support, debugging capabilities, and specialized token refresh functionality.

## Features

- **Promise-based Mutex**: Prevents race conditions in async operations
- **Timeout Support**: Configurable timeouts to prevent deadlocks
- **Debug Logging**: Comprehensive debugging with customizable loggers
- **Token Refresh Mutex**: Specialized mutex for managing API token refresh
- **TypeScript First**: Advanced typing with generics and type guards
- **Production Ready**: Comprehensive error handling and resource management

## Table of Contents

- [Basic Usage](#basic-usage)
- [API Reference](#api-reference)
- [Advanced Usage](#advanced-usage)
- [Token Refresh Mutex](#token-refresh-mutex)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Basic Usage

### Simple Mutex

```typescript
import { Mutex } from '@/utils/mutex';

const mutex = new Mutex<string>({
  debug: { enabled: true },
  name: 'MyMutex'
});

// Protect a critical section
const result = await mutex.acquire(async () => {
  // Only one execution at a time
  await someAsyncOperation();
  return 'success';
});
```

### Quick Creation

```typescript
import { createMutex } from '@/utils/mutex';

const mutex = createMutex<string>('MyMutex', true); // name, debug enabled
```

## API Reference

### Mutex Class

#### Constructor Options

```typescript
interface MutexOptions {
  debug?: {
    enabled: boolean;
    logger?: (message: string, ...args: unknown[]) => void;
    includeStackTrace?: boolean;
  };
  name?: string;
}
```

#### Methods

##### `acquire<T>(executor: () => T | Promise<T>, timeoutOptions?: MutexTimeoutOptions): Promise<T>`

Acquires the mutex and executes the provided function.

```typescript
const result = await mutex.acquire(
  async () => {
    return await criticalOperation();
  },
  { 
    timeout: 5000, 
    timeoutMessage: 'Operation timed out' 
  }
);
```

##### `tryAcquire<T>(executor: () => T | Promise<T>): Promise<T | null>`

Tries to acquire the mutex without waiting. Returns `null` if mutex is busy.

```typescript
const result = await mutex.tryAcquire(async () => {
  return await quickOperation();
});

if (result === null) {
  console.log('Mutex was busy, operation skipped');
}
```

##### `runWithResult<T>(executor: () => T | Promise<T>, timeoutOptions?: MutexTimeoutOptions): Promise<MutexResult<T>>`

Executes a function and returns detailed result information.

```typescript
const result = await mutex.runWithResult(async () => {
  return await operation();
});

if (result.success) {
  console.log('Data:', result.data);
  console.log('Execution time:', result.executionTime);
} else {
  console.error('Error:', result.error);
}
```

##### `getStats(): MutexStats`

Returns mutex statistics.

```typescript
const stats = mutex.getStats();
console.log('Lock count:', stats.lockCount);
console.log('Average wait time:', stats.averageWaitTime);
```

##### `dispose(): void`

Disposes the mutex and rejects all pending acquisitions.

#### Properties

- `locked: boolean` - Whether the mutex is currently locked
- `queueLength: number` - Current queue length

### TokenRefreshMutex Class

Specialized mutex for managing API token refresh operations.

#### Configuration

```typescript
interface TokenRefreshConfig {
  refreshToken: () => Promise<string>;
  isTokenValid: (token: string | null) => boolean;
  initialToken?: string | null;
  refreshTimeout?: number;
  debug?: Partial<MutexDebugOptions>;
}
```

#### Methods

##### `getValidToken(): Promise<string>`

Gets a valid token, refreshing if necessary.

```typescript
const tokenMutex = new TokenRefreshMutex({
  refreshToken: async () => {
    const response = await fetch('/api/refresh', { method: 'POST' });
    const { token } = await response.json();
    return token;
  },
  isTokenValid: (token) => token !== null && !isExpired(token),
  initialToken: localStorage.getItem('authToken')
});

const token = await tokenMutex.getValidToken();
```

##### `forceRefresh(): Promise<string>`

Forces a token refresh regardless of current validity.

##### `getCurrentToken(): string | null`

Gets the current token without validation.

##### `invalidateToken(): void`

Invalidates the current token, forcing refresh on next access.

## Advanced Usage

### Timeout Handling

```typescript
try {
  const result = await mutex.acquire(
    () => longRunningOperation(),
    { 
      timeout: 10000,
      timeoutMessage: 'Operation exceeded 10 second limit'
    }
  );
} catch (error) {
  if (isMutexError(error) && error.code === 'TIMEOUT') {
    console.log('Operation timed out');
  }
}
```

### Higher-Order Function Protection

```typescript
const protectedFunction = withMutex(
  async (data: string) => {
    return await processData(data);
  },
  mutex
);

// All calls to protectedFunction are now mutex-protected
const result = await protectedFunction('test data');
```

### Custom Error Handling

```typescript
import { MutexError, isMutexError } from '@/utils/mutex';

try {
  await mutex.acquire(() => operation());
} catch (error) {
  if (isMutexError(error)) {
    switch (error.code) {
      case 'TIMEOUT':
        console.log('Operation timed out');
        break;
      case 'DISPOSED':
        console.log('Mutex was disposed');
        break;
      case 'INVALID_STATE':
        console.log('Invalid mutex state');
        break;
    }
  }
}
```

## Token Refresh Mutex

The `TokenRefreshMutex` is specifically designed for managing API authentication tokens:

### Use Cases

1. **Preventing Multiple Refresh Requests**: Ensures only one token refresh happens at a time
2. **Sharing Refreshed Tokens**: All waiting operations receive the same refreshed token
3. **Automatic Validation**: Only refreshes when the current token is invalid

### Example Implementation

```typescript
// API service with token refresh
class ApiService {
  private tokenMutex = new TokenRefreshMutex({
    refreshToken: async () => {
      const response = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error('Token refresh failed');
      }
      
      const { accessToken } = await response.json();
      return accessToken;
    },
    
    isTokenValid: (token) => {
      if (!token) return false;
      
      // Check if token is expired
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.exp * 1000 > Date.now();
      } catch {
        return false;
      }
    },
    
    initialToken: localStorage.getItem('accessToken'),
    refreshTimeout: 30000,
    debug: { enabled: process.env.NODE_ENV === 'development' }
  });

  async makeAuthenticatedRequest(url: string, options: RequestInit = {}) {
    const token = await this.tokenMutex.getValidToken();
    
    return fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${token}`
      }
    });
  }
}
```

## Best Practices

### 1. Naming and Debugging

Always provide meaningful names and enable debugging in development:

```typescript
const mutex = new Mutex({
  name: 'UserProfileUpdate',
  debug: { 
    enabled: process.env.NODE_ENV === 'development',
    includeStackTrace: true
  }
});
```

### 2. Timeout Configuration

Set appropriate timeouts to prevent deadlocks:

```typescript
// For network operations
const networkTimeout = 30000;

// For database operations
const dbTimeout = 10000;

// For quick computations
const computeTimeout = 5000;
```

### 3. Resource Management

Always dispose of mutexes when they're no longer needed:

```typescript
// In React components
useEffect(() => {
  const mutex = new Mutex({ name: 'ComponentMutex' });
  
  // Use mutex...
  
  return () => {
    mutex.dispose();
  };
}, []);
```

### 4. Error Handling

Use specific error handling for different scenarios:

```typescript
const result = await mutex.runWithResult(async () => {
  return await riskyOperation();
});

if (!result.success) {
  // Log error details
  console.error('Operation failed:', {
    error: result.error.message,
    executionTime: result.executionTime,
    mutexStats: mutex.getStats()
  });
  
  // Handle specific error types
  if (result.error instanceof NetworkError) {
    // Retry logic
  }
}
```

### 5. Monitoring and Metrics

Use mutex statistics for monitoring:

```typescript
setInterval(() => {
  const stats = mutex.getStats();
  
  if (stats.averageWaitTime > 1000) {
    console.warn('High mutex contention detected', stats);
  }
  
  // Send metrics to monitoring system
  metrics.gauge('mutex.queue_length', stats.queueLength);
  metrics.gauge('mutex.average_wait_time', stats.averageWaitTime);
}, 60000);
```

## Examples

See `mutex.test.ts` for comprehensive examples demonstrating:

- Basic mutex usage
- Timeout handling
- Token refresh scenarios
- Higher-order function protection
- Error handling patterns
- Statistics and monitoring

## TypeScript Support

The mutex utility is built with TypeScript-first design:

- Full generic support for typed return values
- Comprehensive type guards for error handling
- Strict null checks and proper error types
- Advanced utility types for configuration options

## Performance Considerations

- **Queue Management**: Uses efficient array operations for queue management
- **Memory Usage**: Automatically cleans up timeout handles and disposed resources
- **Debugging Overhead**: Debug logging can be disabled in production
- **Statistics**: Minimal overhead for collecting usage statistics

## Migration Guide

### From Basic Locks

```typescript
// Before: Manual promise coordination
let isOperationRunning = false;
const pendingPromises: Promise<any>[] = [];

// After: Mutex-based coordination
const mutex = new Mutex();
const result = await mutex.acquire(() => operation());
```

### From Custom Token Management

```typescript
// Before: Manual token refresh
let refreshPromise: Promise<string> | null = null;

async function getToken() {
  if (refreshPromise) {
    return refreshPromise;
  }
  // ... complex logic
}

// After: TokenRefreshMutex
const tokenMutex = new TokenRefreshMutex(config);
const token = await tokenMutex.getValidToken();
```

## Contributing

When contributing to the mutex utility:

1. Maintain TypeScript strict mode compliance
2. Add comprehensive JSDoc documentation
3. Include unit tests for new features
4. Update this README for API changes
5. Consider backward compatibility

## License

This mutex utility is part of the enterprise application template and follows the same licensing terms as the parent project.