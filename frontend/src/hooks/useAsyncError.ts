/**
 * useAsyncError Hook
 * Allows throwing errors from async functions to be caught by Error Boundaries
 */

import { useState, useCallback } from 'react';

export function useAsyncError() {
  const [, setError] = useState();

  return useCallback(
    (error: Error) => {
      setError(() => {
        throw error;
      });
    },
    [setError]
  );
}

// Hook for handling async operations with error boundaries
export function useAsyncErrorHandler() {
  const throwError = useAsyncError();

  const handleError = useCallback(
    (error: unknown) => {
      if (error instanceof Error) {
        throwError(error);
      } else {
        throwError(new Error(String(error)));
      }
    },
    [throwError]
  );

  const runAsync = useCallback(
    async <T,>(asyncFunction: () => Promise<T>): Promise<T | undefined> => {
      try {
        return await asyncFunction();
      } catch (error) {
        handleError(error);
        return undefined;
      }
    },
    [handleError]
  );

  return { handleError, runAsync };
}