import { useState, useEffect, useCallback } from 'react';

/**
 * Type for JSON-serializable values
 */
type JSONValue = string | number | boolean | null | JSONValue[] | { [key: string]: JSONValue };

/**
 * Hook for managing localStorage with TypeScript safety, SSR compatibility,
 * and cross-tab synchronization
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const [name, setName] = useLocalStorage<string>('user-name', '');
 * 
 * // With complex object
 * interface User { id: string; name: string; }
 * const [user, setUser] = useLocalStorage<User | null>('user', null);
 * 
 * // With custom serialization
 * const [date, setDate] = useLocalStorage<Date | null>('last-visit', null, {
 *   serialize: (value) => value?.toISOString() ?? null,
 *   deserialize: (value) => value ? new Date(value) : null,
 * });
 * ```
 * 
 * @param key - The localStorage key
 * @param initialValue - Initial value if none exists in storage
 * @param options - Optional serialization and error handling options
 * @returns Tuple of [value, setValue, removeValue]
 */
export function useLocalStorage<T extends JSONValue>(
  key: string,
  initialValue: T,
  options?: {
    serialize?: (value: T) => string;
    deserialize?: (value: string) => T;
    onError?: (error: Error) => void;
  }
): [T, (value: T | ((prevValue: T) => T)) => void, () => void] {
  const serialize = options?.serialize ?? JSON.stringify;
  const deserialize = options?.deserialize ?? JSON.parse;

  // Get from local storage then parse stored json or return initialValue
  const [storedValue, setStoredValue] = useState<T>(() => {
    // SSR compatibility - return initial value on server
    if (typeof window === 'undefined') {
      return initialValue;
    }

    try {
      const item = window.localStorage.getItem(key);
      if (item === null) {
        return initialValue;
      }
      return deserialize(item);
    } catch (error) {
      const errorMessage = error instanceof Error ? error : new Error('Failed to read from localStorage');
      options?.onError?.(errorMessage);
      console.warn(`Error reading localStorage key "${key}":`, errorMessage);
      return initialValue;
    }
  });

  // Return a wrapped version of useState's setter function that persists the new value to localStorage
  const setValue = useCallback((value: T | ((prevValue: T) => T)) => {
    try {
      // Allow value to be a function so we have the same API as useState
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      
      // Save state
      setStoredValue(valueToStore);
      
      // Save to local storage (only on client-side)
      if (typeof window !== 'undefined') {
        if (valueToStore === undefined) {
          window.localStorage.removeItem(key);
        } else {
          window.localStorage.setItem(key, serialize(valueToStore));
        }
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error : new Error('Failed to write to localStorage');
      options?.onError?.(errorMessage);
      console.warn(`Error setting localStorage key "${key}":`, errorMessage);
    }
  }, [key, serialize, storedValue, options]);

  // Remove value from localStorage
  const removeValue = useCallback(() => {
    try {
      setStoredValue(initialValue);
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(key);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error : new Error('Failed to remove from localStorage');
      options?.onError?.(errorMessage);
      console.warn(`Error removing localStorage key "${key}":`, errorMessage);
    }
  }, [key, initialValue, options]);

  // Listen for changes to localStorage from other tabs/windows
  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const handleStorageChange = (e: StorageEvent) => {
      if (e.key !== key) {
        return;
      }

      try {
        if (e.newValue === null) {
          setStoredValue(initialValue);
        } else {
          const newValue = deserialize(e.newValue);
          setStoredValue(newValue);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error : new Error('Failed to sync localStorage change');
        options?.onError?.(errorMessage);
        console.warn(`Error syncing localStorage key "${key}":`, errorMessage);
      }
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [key, deserialize, initialValue, options]);

  return [storedValue, setValue, removeValue];
}

/**
 * Hook for managing localStorage with automatic JSON serialization
 * Simplified version that handles most common use cases
 * 
 * @example
 * ```tsx
 * const [settings, setSettings] = useLocalStorageJSON('app-settings', { theme: 'light' });
 * const [todos, setTodos] = useLocalStorageJSON<Todo[]>('todos', []);
 * ```
 */
export function useLocalStorageJSON<T>(
  key: string,
  initialValue: T,
  options?: {
    onError?: (error: Error) => void;
  }
): [T, (value: T | ((prevValue: T) => T)) => void, () => void] {
  return useLocalStorage(key, initialValue, {
    serialize: JSON.stringify,
    deserialize: JSON.parse,
    onError: options?.onError,
  });
}

/**
 * Hook for managing localStorage with string values only
 * Most performant option when you don't need JSON serialization
 * 
 * @example
 * ```tsx
 * const [token, setToken] = useLocalStorageString('auth-token', '');
 * const [theme, setTheme] = useLocalStorageString('theme', 'light');
 * ```
 */
export function useLocalStorageString(
  key: string,
  initialValue: string = '',
  options?: {
    onError?: (error: Error) => void;
  }
): [string, (value: string | ((prevValue: string) => string)) => void, () => void] {
  return useLocalStorage(key, initialValue, {
    serialize: (value) => value,
    deserialize: (value) => value,
    onError: options?.onError,
  });
}

/**
 * Hook for managing localStorage with boolean values
 * 
 * @example
 * ```tsx
 * const [isDarkMode, setIsDarkMode] = useLocalStorageBoolean('dark-mode', false);
 * const [hasSeenTutorial, setHasSeenTutorial] = useLocalStorageBoolean('tutorial-seen', false);
 * ```
 */
export function useLocalStorageBoolean(
  key: string,
  initialValue: boolean = false,
  options?: {
    onError?: (error: Error) => void;
  }
): [boolean, (value: boolean | ((prevValue: boolean) => boolean)) => void, () => void] {
  return useLocalStorage(key, initialValue, {
    serialize: (value) => value.toString(),
    deserialize: (value) => value === 'true',
    onError: options?.onError,
  });
}