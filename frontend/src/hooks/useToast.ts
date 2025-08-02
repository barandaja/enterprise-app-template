import { useCallback } from 'react';
import { useUIStore, useUIActions, useToasts } from '../stores/uiStore';
import type { Toast } from '../stores/uiStore';

/**
 * Toast type shortcuts
 */
export type ToastType = Toast['type'];

/**
 * Toast options for creating toasts
 */
export interface ToastOptions {
  title?: string;
  duration?: number;
  persistent?: boolean;
  action?: {
    label: string;
    onClick: () => void;
  };
}

/**
 * Enhanced toast hook that integrates with the UI store
 * Provides convenient methods for showing different types of toasts
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const toast = useToast();
 * 
 * const handleSuccess = () => {
 *   toast.success('Profile updated successfully!');
 * };
 * 
 * const handleError = () => {
 *   toast.error('Failed to save changes', {
 *     duration: 0, // Persistent
 *     action: {
 *       label: 'Retry',
 *       onClick: () => saveProfile()
 *     }
 *   });
 * };
 * 
 * // Different toast types
 * const handleWarning = () => {
 *   toast.warning('Your session will expire soon', {
 *     title: 'Session Warning',
 *     duration: 10000
 *   });
 * };
 * 
 * const handleInfo = () => {
 *   toast.info('New features available!', {
 *     action: {
 *       label: 'Learn More',
 *       onClick: () => navigate('/features')
 *     }
 *   });
 * };
 * 
 * // Custom toast with full control
 * const handleCustom = () => {
 *   const id = toast.show({
 *     type: 'success',
 *     title: 'Custom Toast',
 *     message: 'This is a custom toast',
 *     duration: 5000,
 *     action: {
 *       label: 'Action',
 *       onClick: () => console.log('Action clicked')
 *     }
 *   });
 * 
 *   // Update the toast later
 *   setTimeout(() => {
 *     toast.update(id, {
 *       message: 'Updated message',
 *       type: 'warning'
 *     });
 *   }, 2000);
 * };
 * 
 * // Promise-based toasts
 * const handleAsyncOperation = async () => {
 *   const promise = saveUserData();
 *   
 *   toast.promise(promise, {
 *     loading: 'Saving user data...',
 *     success: 'User data saved successfully!',
 *     error: (error) => `Failed to save: ${error.message}`
 *   });
 * };
 * ```
 */
export function useToast() {
  const actions = useUIActions();
  const toasts = useToasts();

  // Show a toast with full options
  const show = useCallback((toast: Omit<Toast, 'id' | 'createdAt'>): string => {
    return actions.addToast(toast);
  }, [actions]);

  // Convenience methods for different toast types
  const success = useCallback((message: string, options: ToastOptions = {}): string => {
    return show({
      type: 'success',
      message,
      ...options,
    });
  }, [show]);

  const error = useCallback((message: string, options: ToastOptions = {}): string => {
    return show({
      type: 'error',
      message,
      duration: options.duration ?? 0, // Errors are persistent by default
      ...options,
    });
  }, [show]);

  const warning = useCallback((message: string, options: ToastOptions = {}): string => {
    return show({
      type: 'warning',
      message,
      duration: options.duration ?? 6000, // Warnings last longer
      ...options,
    });
  }, [show]);

  const info = useCallback((message: string, options: ToastOptions = {}): string => {
    return show({
      type: 'info',
      message,
      ...options,
    });
  }, [show]);

  // Update an existing toast
  const update = useCallback((id: string, updates: Partial<Toast>): void => {
    actions.updateToast(id, updates);
  }, [actions]);

  // Remove a specific toast
  const dismiss = useCallback((id?: string): void => {
    if (id) {
      actions.removeToast(id);
    } else {
      // Dismiss the most recent toast if no ID provided
      const mostRecentToast = toasts[toasts.length - 1];
      if (mostRecentToast) {
        actions.removeToast(mostRecentToast.id);
      }
    }
  }, [actions, toasts]);

  // Clear all toasts
  const dismissAll = useCallback((): void => {
    actions.clearAllToasts();
  }, [actions]);

  // Promise-based toast for async operations
  const promise = useCallback(<T,>(
    promise: Promise<T>,
    messages: {
      loading: string;
      success: string | ((data: T) => string);
      error: string | ((error: any) => string);
    },
    options: {
      loadingOptions?: ToastOptions;
      successOptions?: ToastOptions;
      errorOptions?: ToastOptions;
    } = {}
  ): Promise<T> => {
    // Show loading toast
    const loadingId = show({
      type: 'info',
      message: messages.loading,
      persistent: true,
      ...options.loadingOptions,
    });

    return promise
      .then((data) => {
        // Remove loading toast
        dismiss(loadingId);
        
        // Show success toast
        const successMessage = typeof messages.success === 'function' 
          ? messages.success(data) 
          : messages.success;
        
        success(successMessage, options.successOptions);
        
        return data;
      })
      .catch((error) => {
        // Remove loading toast
        dismiss(loadingId);
        
        // Show error toast
        const errorMessage = typeof messages.error === 'function' 
          ? messages.error(error) 
          : messages.error;
        
        useToast().error(errorMessage, options.errorOptions);
        
        throw error;
      });
  }, [show, dismiss, success]);

  // Get current toasts (useful for testing or advanced use cases)
  const getToasts = useCallback(() => toasts, [toasts]);

  // Check if a toast with specific ID exists
  const exists = useCallback((id: string): boolean => {
    return toasts.some(toast => toast.id === id);
  }, [toasts]);

  // Check if any toasts are currently shown
  const hasToasts = useCallback((): boolean => {
    return toasts.length > 0;
  }, [toasts]);

  // Get toasts by type
  const getToastsByType = useCallback((type: ToastType) => {
    return toasts.filter(toast => toast.type === type);
  }, [toasts]);

  return {
    // Core methods
    show,
    update,
    dismiss,
    dismissAll,
    
    // Convenience methods
    success,
    error,
    warning,
    info,
    
    // Advanced features
    promise,
    
    // Utility methods
    getToasts,
    exists,
    hasToasts,
    getToastsByType,
    
    // Current state
    toasts,
  };
}

/**
 * Hook for managing toast notifications with specific patterns
 * Provides common toast patterns and utilities
 * 
 * @example
 * ```tsx
 * const { showApiError, showFormValidationErrors, showConfirmation } = useToastPatterns();
 * 
 * // Handle API errors consistently
 * try {
 *   await api.saveUser(userData);
 * } catch (error) {
 *   showApiError(error, 'Failed to save user');
 * }
 * 
 * // Show form validation errors
 * if (formErrors) {
 *   showFormValidationErrors(formErrors);
 * }
 * 
 * // Show confirmation with action
 * showConfirmation('Are you sure you want to delete this item?', {
 *   onConfirm: () => deleteItem(),
 *   onCancel: () => console.log('Cancelled')
 * });
 * ```
 */
export function useToastPatterns() {
  const toast = useToast();

  // Show API error with consistent formatting
  const showApiError = useCallback((
    error: any, 
    fallbackMessage: string = 'An error occurred',
    options: ToastOptions = {}
  ) => {
    let message = fallbackMessage;
    
    if (error?.response?.data?.message) {
      message = error.response.data.message;
    } else if (error?.message) {
      message = error.message;
    } else if (typeof error === 'string') {
      message = error;
    }

    return toast.error(message, {
      duration: 0,
      ...options,
    });
  }, [toast]);

  // Show form validation errors
  const showFormValidationErrors = useCallback((
    errors: Record<string, string | string[]>,
    title: string = 'Please fix the following errors:'
  ) => {
    const errorMessages = Object.entries(errors).map(([field, error]) => {
      const errorText = Array.isArray(error) ? error.join(', ') : error;
      return `${field}: ${errorText}`;
    });

    return toast.error(errorMessages.join('\n'), {
      title,
      duration: 0,
    });
  }, [toast]);

  // Show confirmation toast with actions
  const showConfirmation = useCallback((
    message: string,
    actions: {
      onConfirm: () => void;
      onCancel?: () => void;
      confirmLabel?: string;
      cancelLabel?: string;
    },
    options: ToastOptions = {}
  ) => {
    const { onConfirm, onCancel, confirmLabel = 'Confirm', cancelLabel = 'Cancel' } = actions;

    return toast.warning(message, {
      duration: 0,
      persistent: true,
      action: {
        label: confirmLabel,
        onClick: () => {
          onConfirm();
          // Note: You might want to add a cancel button as well
          // This would require extending the Toast interface to support multiple actions
        }
      },
      ...options,
    });
  }, [toast]);

  // Show success with undo action
  const showSuccessWithUndo = useCallback((
    message: string,
    onUndo: () => void,
    options: ToastOptions & { undoLabel?: string } = {}
  ) => {
    const { undoLabel = 'Undo', ...toastOptions } = options;

    return toast.success(message, {
      duration: 5000,
      action: {
        label: undoLabel,
        onClick: onUndo,
      },
      ...toastOptions,
    });
  }, [toast]);

  // Show network status toasts
  const showNetworkStatus = useCallback((isOnline: boolean) => {
    if (isOnline) {
      toast.success('Connection restored', {
        duration: 3000,
      });
    } else {
      toast.warning('Connection lost. Some features may not work.', {
        duration: 0,
        persistent: true,
        title: 'Offline',
      });
    }
  }, [toast]);

  // Show loading state for operations
  const showOperation = useCallback((
    operation: Promise<any>,
    messages: {
      loading: string;
      success: string;
      error?: string;
    }
  ) => {
    return toast.promise(operation, {
      loading: messages.loading,
      success: messages.success,
      error: messages.error || 'Operation failed',
    });
  }, [toast]);

  return {
    showApiError,
    showFormValidationErrors,
    showConfirmation,
    showSuccessWithUndo,
    showNetworkStatus,
    showOperation,
  };
}

/**
 * Hook for toast notifications in specific contexts
 * Provides contextual toast methods
 * 
 * @example
 * ```tsx
 * // In a form component
 * const formToasts = useContextualToast('form');
 * formToasts.success('Form saved successfully');
 * 
 * // In an auth component
 * const authToasts = useContextualToast('auth');
 * authToasts.error('Login failed');
 * ```
 */
export function useContextualToast(context: string) {
  const toast = useToast();

  const contextualToast = {
    success: (message: string, options: ToastOptions = {}) =>
      toast.success(message, { title: context, ...options }),
    
    error: (message: string, options: ToastOptions = {}) =>
      toast.error(message, { title: context, ...options }),
    
    warning: (message: string, options: ToastOptions = {}) =>
      toast.warning(message, { title: context, ...options }),
    
    info: (message: string, options: ToastOptions = {}) =>
      toast.info(message, { title: context, ...options }),
  };

  return contextualToast;
}