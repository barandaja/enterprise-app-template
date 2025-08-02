import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Status of an async operation
 */
type AsyncStatus = 'idle' | 'pending' | 'success' | 'error';

/**
 * State for async operations
 */
interface AsyncState<T, E = Error> {
  data: T | null;
  error: E | null;
  status: AsyncStatus;
  isIdle: boolean;
  isPending: boolean;
  isSuccess: boolean;
  isError: boolean;
}

/**
 * Options for useAsync hook
 */
interface UseAsyncOptions<T, E = Error> {
  onSuccess?: (data: T) => void;
  onError?: (error: E) => void;
  onSettled?: (data: T | null, error: E | null) => void;
  executeOnMount?: boolean;
  resetOnExecute?: boolean;
}

/**
 * Return type for useAsync hook
 */
interface UseAsyncReturn<T, P extends unknown[] = unknown[], E = Error> extends AsyncState<T, E> {
  execute: (...params: P) => Promise<T>;
  reset: () => void;
  cancel: () => void;
}

/**
 * Hook for managing async operations with comprehensive state management,
 * request cancellation, and error handling
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const { data, isPending, error, execute } = useAsync(fetchUser);
 * 
 * // Execute on mount
 * const { data: user } = useAsync(fetchUser, { executeOnMount: true });
 * 
 * // With parameters and callbacks
 * const { execute: saveUser, isPending: isSaving } = useAsync(
 *   (user: User) => api.saveUser(user),
 *   {
 *     onSuccess: (savedUser) => console.log('User saved:', savedUser),
 *     onError: (error) => toast.error(error.message),
 *   }
 * );
 * 
 * // Usage with cancellation
 * const { execute, cancel } = useAsync(longRunningOperation);
 * useEffect(() => {
 *   execute();
 *   return () => cancel(); // Cancel on unmount
 * }, []);
 * ```
 * 
 * @param asyncFunction - The async function to execute
 * @param options - Configuration options
 * @returns Object with state and control functions
 */
export function useAsync<T, P extends unknown[] = unknown[], E = Error>(
  asyncFunction: (...params: P) => Promise<T>,
  options: UseAsyncOptions<T, E> = {}
): UseAsyncReturn<T, P, E> {
  const {
    onSuccess,
    onError,
    onSettled,
    executeOnMount = false,
    resetOnExecute = true,
  } = options;

  const [state, setState] = useState<AsyncState<T, E>>({
    data: null,
    error: null,
    status: 'idle',
    isIdle: true,
    isPending: false,
    isSuccess: false,
    isError: false,
  });

  const abortControllerRef = useRef<AbortController | null>(null);
  const isMountedRef = useRef(true);

  // Update derived state
  const updateState = useCallback((updates: Partial<AsyncState<T, E>>) => {
    setState(prev => {
      const newStatus = updates.status ?? prev.status;
      return {
        ...prev,
        ...updates,
        status: newStatus,
        isIdle: newStatus === 'idle',
        isPending: newStatus === 'pending',
        isSuccess: newStatus === 'success',
        isError: newStatus === 'error',
      };
    });
  }, []);

  // Cancel any pending request
  const cancel = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
  }, []);

  // Reset state to idle
  const reset = useCallback(() => {
    cancel();
    updateState({
      data: null,
      error: null,
      status: 'idle',
    });
  }, [cancel, updateState]);

  // Execute the async function
  const execute = useCallback(async (...params: P): Promise<T> => {
    // Cancel any existing request
    cancel();

    // Reset state if configured to do so
    if (resetOnExecute) {
      updateState({
        data: null,
        error: null,
        status: 'pending',
      });
    } else {
      updateState({ status: 'pending' });
    }

    // Create new abort controller
    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    try {
      // Execute the async function
      const data = await asyncFunction(...params);

      // Check if request was cancelled or component unmounted
      if (signal.aborted || !isMountedRef.current) {
        throw new Error('Request was cancelled');
      }

      // Update state with success
      updateState({
        data,
        error: null,
        status: 'success',
      });

      // Call success callback
      onSuccess?.(data);

      // Call settled callback
      onSettled?.(data, null);

      return data;
    } catch (error) {
      // Check if request was cancelled
      if (signal.aborted || !isMountedRef.current) {
        // Don't update state for cancelled requests
        return Promise.reject(error);
      }

      const errorObj = error as E;

      // Update state with error
      updateState({
        error: errorObj,
        status: 'error',
      });

      // Call error callback
      onError?.(errorObj);

      // Call settled callback
      onSettled?.(null, errorObj);

      throw error;
    } finally {
      // Clean up abort controller
      abortControllerRef.current = null;
    }
  }, [asyncFunction, cancel, resetOnExecute, updateState, onSuccess, onError, onSettled]);

  // Execute on mount if configured
  useEffect(() => {
    if (executeOnMount) {
      execute();
    }
  }, [executeOnMount]); // Note: intentionally not including execute to avoid re-execution

  // Cleanup on unmount
  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
      cancel();
    };
  }, [cancel]);

  return {
    ...state,
    execute,
    reset,
    cancel,
  };
}

/**
 * Hook for managing async operations that depend on dependencies
 * Automatically re-executes when dependencies change
 * 
 * @example
 * ```tsx
 * const [userId, setUserId] = useState('1');
 * const { data: user, isPending } = useAsyncEffect(
 *   () => fetchUser(userId),
 *   [userId],
 *   { executeOnMount: true }
 * );
 * ```
 * 
 * @param asyncFunction - The async function to execute
 * @param deps - Dependencies that trigger re-execution
 * @param options - Configuration options
 * @returns Object with state and control functions
 */
export function useAsyncEffect<T, E = Error>(
  asyncFunction: () => Promise<T>,
  deps: React.DependencyList,
  options: UseAsyncOptions<T, E> = {}
): Omit<UseAsyncReturn<T, [], E>, 'execute'> & { refetch: () => Promise<T> } {
  const asyncState = useAsync(asyncFunction, options);

  // Re-execute when dependencies change
  useEffect(() => {
    asyncState.execute();
  }, deps);

  return {
    ...asyncState,
    refetch: asyncState.execute,
  };
}

/**
 * Hook for managing multiple async operations
 * Useful for parallel requests or managing multiple endpoints
 * 
 * @example
 * ```tsx
 * const { 
 *   data: { user, posts, comments },
 *   isPending,
 *   execute
 * } = useAsyncAll({
 *   user: () => fetchUser(userId),
 *   posts: () => fetchPosts(userId),
 *   comments: () => fetchComments(userId),
 * });
 * ```
 * 
 * @param asyncFunctions - Object with async functions
 * @param options - Configuration options
 * @returns Object with combined state and control functions
 */
export function useAsyncAll<T extends Record<string, () => Promise<any>>>(
  asyncFunctions: T,
  options: {
    executeOnMount?: boolean;
    onSuccess?: (data: { [K in keyof T]: Awaited<ReturnType<T[K]>> }) => void;
    onError?: (errors: Partial<{ [K in keyof T]: Error }>) => void;
  } = {}
): {
  data: Partial<{ [K in keyof T]: Awaited<ReturnType<T[K]>> }>;
  errors: Partial<{ [K in keyof T]: Error }>;
  isPending: boolean;
  isSuccess: boolean;
  isError: boolean;
  execute: () => Promise<{ [K in keyof T]: Awaited<ReturnType<T[K]>> }>;
  reset: () => void;
} {
  const { executeOnMount = false, onSuccess, onError } = options;
  
  const [state, setState] = useState<{
    data: Partial<{ [K in keyof T]: Awaited<ReturnType<T[K]>> }>;
    errors: Partial<{ [K in keyof T]: Error }>;
    isPending: boolean;
    isSuccess: boolean;
    isError: boolean;
  }>({
    data: {},
    errors: {},
    isPending: false,
    isSuccess: false,
    isError: false,
  });

  const abortControllerRef = useRef<AbortController | null>(null);

  const execute = useCallback(async () => {
    // Cancel any existing requests
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }

    abortControllerRef.current = new AbortController();
    const { signal } = abortControllerRef.current;

    setState(prev => ({
      ...prev,
      isPending: true,
      isSuccess: false,
      isError: false,
      errors: {},
    }));

    try {
      const keys = Object.keys(asyncFunctions) as (keyof T)[];
      const promises = keys.map(async (key) => {
        try {
          const result = await asyncFunctions[key]();
          if (signal.aborted) throw new Error('Aborted');
          return { key, result, error: null };
        } catch (error) {
          if (signal.aborted) throw error;
          return { key, result: null, error: error as Error };
        }
      });

      const results = await Promise.all(promises);
      
      if (signal.aborted) {
        throw new Error('Aborted');
      }

      const data: Partial<{ [K in keyof T]: Awaited<ReturnType<T[K]>> }> = {};
      const errors: Partial<{ [K in keyof T]: Error }> = {};

      results.forEach(({ key, result, error }) => {
        if (error) {
          errors[key] = error;
        } else {
          data[key] = result;
        }
      });

      const hasErrors = Object.keys(errors).length > 0;

      setState({
        data,
        errors,
        isPending: false,
        isSuccess: !hasErrors,
        isError: hasErrors,
      });

      if (hasErrors) {
        onError?.(errors);
      } else {
        onSuccess?.(data as { [K in keyof T]: Awaited<ReturnType<T[K]>> });
      }

      return data as { [K in keyof T]: Awaited<ReturnType<T[K]>> };
    } catch (error) {
      if (signal.aborted) {
        return Promise.reject(error);
      }

      setState(prev => ({
        ...prev,
        isPending: false,
        isError: true,
      }));

      throw error;
    }
  }, [asyncFunctions, onSuccess, onError]);

  const reset = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setState({
      data: {},
      errors: {},
      isPending: false,
      isSuccess: false,
      isError: false,
    });
  }, []);

  // Execute on mount if configured
  useEffect(() => {
    if (executeOnMount) {
      execute();
    }
  }, [executeOnMount]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, []);

  return {
    ...state,
    execute,
    reset,
  };
}