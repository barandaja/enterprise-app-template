import { useState, useEffect, useRef, useCallback } from 'react';

/**
 * Hook that debounces a value with configurable delay and cleanup
 * Perfect for search inputs, API calls, and expensive operations
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const [searchTerm, setSearchTerm] = useState('');
 * const debouncedSearchTerm = useDebounce(searchTerm, 300);
 * 
 * useEffect(() => {
 *   if (debouncedSearchTerm) {
 *     searchAPI(debouncedSearchTerm);
 *   }
 * }, [debouncedSearchTerm]);
 * 
 * // With immediate execution option
 * const debouncedValue = useDebounce(value, 500, { immediate: true });
 * 
 * // With custom comparison
 * const debouncedUser = useDebounce(user, 1000, {
 *   isEqual: (a, b) => a?.id === b?.id
 * });
 * ```
 * 
 * @param value - The value to debounce
 * @param delay - Delay in milliseconds
 * @param options - Optional configuration
 * @returns The debounced value
 */
export function useDebounce<T>(
  value: T,
  delay: number,
  options: {
    immediate?: boolean;
    isEqual?: (a: T, b: T) => boolean;
  } = {}
): T {
  const { immediate = false, isEqual = (a, b) => a === b } = options;
  const [debouncedValue, setDebouncedValue] = useState<T>(value);
  const previousValue = useRef<T>(value);

  useEffect(() => {
    // Don't debounce if value hasn't actually changed
    if (isEqual(value, previousValue.current)) {
      return;
    }

    // Update immediately if immediate option is true and this is the first change
    if (immediate && isEqual(previousValue.current, debouncedValue)) {
      setDebouncedValue(value);
      previousValue.current = value;
      return;
    }

    const timeoutId = setTimeout(() => {
      setDebouncedValue(value);
      previousValue.current = value;
    }, delay);

    return () => {
      clearTimeout(timeoutId);
    };
  }, [value, delay, immediate, isEqual, debouncedValue]);

  // Update previous value reference
  useEffect(() => {
    previousValue.current = value;
  });

  return debouncedValue;
}

/**
 * Hook that provides a debounced callback function
 * Useful when you need to debounce function calls instead of values
 * 
 * @example
 * ```tsx
 * const handleSearch = useDebouncedCallback(
 *   (query: string) => {
 *     searchAPI(query);
 *   },
 *   300,
 *   { maxWait: 1000 }
 * );
 * 
 * // Usage in component
 * <input onChange={(e) => handleSearch(e.target.value)} />
 * ```
 * 
 * @param callback - The function to debounce
 * @param delay - Delay in milliseconds
 * @param options - Optional configuration
 * @returns The debounced callback function and utilities
 */
export function useDebouncedCallback<T extends (...args: any[]) => any>(
  callback: T,
  delay: number,
  options: {
    maxWait?: number;
    leading?: boolean;
    trailing?: boolean;
  } = {}
): {
  callback: T;
  cancel: () => void;
  flush: () => void;
  isPending: () => boolean;
} {
  const { maxWait, leading = false, trailing = true } = options;
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const maxTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const callbackRef = useRef(callback);
  const lastCallTimeRef = useRef<number>(0);
  const lastInvokeTimeRef = useRef<number>(0);
  const argsRef = useRef<Parameters<T>>();
  const resultRef = useRef<ReturnType<T>>();

  // Update callback ref
  callbackRef.current = callback;

  const invokeFunc = useCallback(() => {
    const args = argsRef.current;
    if (!args) return;

    lastInvokeTimeRef.current = Date.now();
    resultRef.current = callbackRef.current(...args);
    return resultRef.current;
  }, []);

  const leadingEdge = useCallback(() => {
    lastInvokeTimeRef.current = Date.now();
    if (leading) {
      return invokeFunc();
    }
  }, [leading, invokeFunc]);

  const remainingWait = useCallback((time: number) => {
    const timeSinceLastCall = time - lastCallTimeRef.current;
    const timeSinceLastInvoke = time - lastInvokeTimeRef.current;
    const timeWaiting = delay - timeSinceLastCall;

    if (maxWait !== undefined) {
      return Math.min(timeWaiting, maxWait - timeSinceLastInvoke);
    }
    return timeWaiting;
  }, [delay, maxWait]);

  const shouldInvoke = useCallback((time: number) => {
    const timeSinceLastCall = time - lastCallTimeRef.current;
    const timeSinceLastInvoke = time - lastInvokeTimeRef.current;

    return (
      lastCallTimeRef.current === 0 ||
      timeSinceLastCall >= delay ||
      timeSinceLastCall < 0 ||
      (maxWait !== undefined && timeSinceLastInvoke >= maxWait)
    );
  }, [delay, maxWait]);

  const timerExpired = useCallback(() => {
    const time = Date.now();
    if (shouldInvoke(time)) {
      return trailingEdge(time);
    }
    
    const remaining = remainingWait(time);
    timeoutRef.current = setTimeout(timerExpired, remaining);
  }, [shouldInvoke, remainingWait]);

  const trailingEdge = useCallback((time: number) => {
    timeoutRef.current = null;

    if (trailing && argsRef.current) {
      return invokeFunc();
    }
    argsRef.current = undefined;
  }, [trailing, invokeFunc]);

  const cancel = useCallback(() => {
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current);
      timeoutRef.current = null;
    }
    if (maxTimeoutRef.current) {
      clearTimeout(maxTimeoutRef.current);
      maxTimeoutRef.current = null;
    }
    
    lastInvokeTimeRef.current = 0;
    lastCallTimeRef.current = 0;
    argsRef.current = undefined;
  }, []);

  const flush = useCallback(() => {
    if (timeoutRef.current) {
      return trailingEdge(Date.now());
    }
  }, [trailingEdge]);

  const isPending = useCallback(() => {
    return timeoutRef.current !== null;
  }, []);

  const debouncedCallback = useCallback((...args: Parameters<T>) => {
    const time = Date.now();
    const isInvoking = shouldInvoke(time);

    argsRef.current = args;
    lastCallTimeRef.current = time;

    if (isInvoking) {
      if (timeoutRef.current === null) {
        return leadingEdge();
      }
      if (maxWait !== undefined) {
        timeoutRef.current = setTimeout(timerExpired, delay);
        maxTimeoutRef.current = setTimeout(invokeFunc, maxWait);
        return leading ? invokeFunc() : resultRef.current;
      }
    }

    if (timeoutRef.current === null) {
      timeoutRef.current = setTimeout(timerExpired, delay);
    }

    return resultRef.current;
  }, [shouldInvoke, leadingEdge, delay, maxWait, leading, timerExpired, invokeFunc]) as T;

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      cancel();
    };
  }, [cancel]);

  return {
    callback: debouncedCallback,
    cancel,
    flush,
    isPending,
  };
}

/**
 * Hook that debounces a state value and provides both current and debounced values
 * Useful for controlled inputs that need immediate updates but debounced side effects
 * 
 * @example
 * ```tsx
 * const [searchState, setSearchTerm] = useDebouncedState('', 300);
 * 
 * // searchState.current - immediate value
 * // searchState.debounced - debounced value
 * // searchState.isPending - true if debounce is waiting
 * 
 * <input 
 *   value={searchState.current} 
 *   onChange={(e) => setSearchTerm(e.target.value)}
 *   placeholder={searchState.isPending ? 'Searching...' : 'Search'}
 * />
 * ```
 * 
 * @param initialValue - Initial state value
 * @param delay - Debounce delay in milliseconds
 * @param options - Optional configuration
 * @returns State object with current, debounced values and utilities
 */
export function useDebouncedState<T>(
  initialValue: T,
  delay: number,
  options: {
    immediate?: boolean;
    isEqual?: (a: T, b: T) => boolean;
  } = {}
): {
  current: T;
  debounced: T;
  isPending: boolean;
  setValue: (value: T | ((prev: T) => T)) => void;
  setDebounced: (value: T) => void;
  reset: () => void;
} {
  const [current, setCurrent] = useState<T>(initialValue);
  const debounced = useDebounce(current, delay, options);
  const [isPending, setIsPending] = useState(false);

  // Track pending state
  useEffect(() => {
    const isCurrentlyPending = current !== debounced;
    setIsPending(isCurrentlyPending);
  }, [current, debounced]);

  const setValue = useCallback((value: T | ((prev: T) => T)) => {
    setCurrent(value);
  }, []);

  const setDebounced = useCallback((value: T) => {
    setCurrent(value);
    // Force immediate update by setting the same value
    // This will skip the debounce and update immediately
  }, []);

  const reset = useCallback(() => {
    setCurrent(initialValue);
  }, [initialValue]);

  return {
    current,
    debounced,
    isPending,
    setValue,
    setDebounced,
    reset,
  };
}