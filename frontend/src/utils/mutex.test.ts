/**
 * Test file to verify mutex functionality
 * This file demonstrates usage and validates the mutex implementation
 */

import { 
  Mutex, 
  TokenRefreshMutex, 
  MutexError, 
  isMutexError,
  createMutex,
  createTokenRefreshMutex,
  withMutex 
} from './mutex';

// Mock functions for testing
async function simulateAsyncOperation(delay: number = 100, result: string = 'success'): Promise<string> {
  return new Promise(resolve => {
    setTimeout(() => resolve(result), delay);
  });
}

// Example 1: Basic Mutex Usage
async function basicMutexExample() {
  const mutex = new Mutex<string>({
    debug: { enabled: true },
    name: 'BasicExample'
  });

  console.log('=== Basic Mutex Example ===');
  
  // Simulate concurrent operations
  const operations = [
    mutex.acquire(() => simulateAsyncOperation(100, 'Operation 1')),
    mutex.acquire(() => simulateAsyncOperation(50, 'Operation 2')),
    mutex.acquire(() => simulateAsyncOperation(75, 'Operation 3')),
  ];

  try {
    const results = await Promise.all(operations);
    console.log('Results:', results);
    console.log('Mutex stats:', mutex.getStats());
  } catch (error) {
    console.error('Error:', error);
  }
}

// Example 2: Mutex with Timeout
async function mutexTimeoutExample() {
  const mutex = new Mutex<string>({
    debug: { enabled: true },
    name: 'TimeoutExample'
  });

  console.log('\n=== Mutex Timeout Example ===');

  try {
    // First operation takes longer
    const slowOperation = mutex.acquire(
      () => simulateAsyncOperation(2000, 'Slow operation'),
      { timeout: 1000, timeoutMessage: 'Operation timed out!' }
    );

    const result = await slowOperation;
    console.log('Result:', result);
  } catch (error) {
    if (isMutexError(error) && error.code === 'TIMEOUT') {
      console.log('Caught timeout error:', error.message);
    } else {
      console.error('Unexpected error:', error);
    }
  }
}

// Example 3: TokenRefreshMutex
async function tokenRefreshExample() {
  console.log('\n=== Token Refresh Mutex Example ===');

  let tokenCounter = 0;
  
  const tokenMutex = createTokenRefreshMutex({
    refreshToken: async () => {
      console.log('Refreshing token...');
      await simulateAsyncOperation(200);
      tokenCounter++;
      return `token_${tokenCounter}`;
    },
    isTokenValid: (token) => {
      // Consider tokens valid for this example
      return token !== null && token.startsWith('token_');
    },
    initialToken: null,
    refreshTimeout: 5000,
    debug: { enabled: true }
  });

  // Simulate multiple concurrent requests that need a token
  const requests = [
    tokenMutex.getValidToken(),
    tokenMutex.getValidToken(),
    tokenMutex.getValidToken(),
  ];

  try {
    const tokens = await Promise.all(requests);
    console.log('All tokens:', tokens);
    console.log('Token stats:', tokenMutex.getRefreshStats());
    
    // Force refresh
    const newToken = await tokenMutex.forceRefresh();
    console.log('Forced refresh result:', newToken);
  } catch (error) {
    console.error('Token refresh error:', error);
  }
}

// Example 4: Higher-order function with mutex
async function higherOrderExample() {
  console.log('\n=== Higher-order Function Example ===');

  const mutex = createMutex<string>('HigherOrderExample', true);

  // Wrap a regular function with mutex protection
  const protectedFunction = withMutex(
    async (data: string) => {
      console.log(`Processing: ${data}`);
      await simulateAsyncOperation(100);
      return `Processed: ${data}`;
    },
    mutex
  );

  // Call the protected function multiple times concurrently
  const operations = [
    protectedFunction('Data 1'),
    protectedFunction('Data 2'),
    protectedFunction('Data 3'),
  ];

  try {
    const results = await Promise.all(operations);
    console.log('Protected function results:', results);
  } catch (error) {
    console.error('Error in protected function:', error);
  }
}

// Example 5: Error handling and result types
async function errorHandlingExample() {
  console.log('\n=== Error Handling Example ===');

  const mutex = new Mutex<string>({
    debug: { enabled: true },
    name: 'ErrorHandlingExample'
  });

  // Function that might throw an error
  const riskyOperation = async (shouldFail: boolean): Promise<string> => {
    await simulateAsyncOperation(50);
    if (shouldFail) {
      throw new Error('Simulated operation failure');
    }
    return 'Success';
  };

  // Use runWithResult for detailed error handling
  const result1 = await mutex.runWithResult(() => riskyOperation(false));
  const result2 = await mutex.runWithResult(() => riskyOperation(true));

  console.log('Successful operation:', result1);
  console.log('Failed operation:', result2);

  // Try acquire - non-blocking
  const quickResult = await mutex.tryAcquire(() => simulateAsyncOperation(10, 'Quick'));
  console.log('Try acquire result:', quickResult);
}

// Run all examples
export async function runMutexExamples(): Promise<void> {
  try {
    await basicMutexExample();
    await mutexTimeoutExample();
    await tokenRefreshExample();
    await higherOrderExample();
    await errorHandlingExample();
    
    console.log('\n✅ All mutex examples completed successfully!');
  } catch (error) {
    console.error('❌ Error running examples:', error);
  }
}

// Export for potential use in other parts of the application
export {
  basicMutexExample,
  mutexTimeoutExample,
  tokenRefreshExample,
  higherOrderExample,
  errorHandlingExample
};

// Uncomment the line below to run examples when this file is imported
// runMutexExamples();