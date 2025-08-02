/**
 * Custom React Hooks
 * 
 * This module exports all custom hooks for the application.
 * All hooks are fully typed with TypeScript and include comprehensive
 * JSDoc comments with usage examples.
 */

// Storage hooks
export {
  useLocalStorage,
  useLocalStorageJSON,
  useLocalStorageString,
  useLocalStorageBoolean,
} from './useLocalStorage';

// Performance hooks
export {
  useDebounce,
  useDebouncedCallback,
  useDebouncedState,
} from './useDebounce';

// Async operation hooks
export {
  useAsync,
  useAsyncEffect,
  useAsyncAll,
} from './useAsync';

export {
  useAsyncError,
  useAsyncErrorHandler,
} from './useAsyncError';

export {
  useConsentCategory,
  useConsentScript,
  useAnalytics,
  useMarketing,
  usePreferences,
} from './useConsent';

// Authentication hooks
export {
  useAuth,
  useAuthGuard,
  permissions,
} from './useAuth';

// Responsive design hooks
export {
  useMediaQuery,
  useBreakpoint,
  useBreakpoints,
  useViewport,
  useMediaPreferences,
  useResponsiveValue,
  getResponsiveValue,
  breakpoints,
} from './useMediaQuery';

// UI interaction hooks
export {
  useClickOutside,
  useClickOutsideRef,
  useClickOutsideWithEscape,
  useClickOutsideWithFocusTrap,
} from './useClickOutside';

// Form handling hooks
export {
  useForm,
  useFieldValidation,
  useMultiStepForm,
  validationSchemas,
  createPasswordConfirmationSchema,
} from './useForm';

// Notification hooks
export {
  useToast,
  useToastPatterns,
  useContextualToast,
} from './useToast';

// Pagination hooks
export {
  usePagination,
  useCursorPagination,
  useTablePagination,
} from './usePagination';

// Re-export types for convenience
export type { ToastType, ToastOptions } from './useToast';
export type { BreakpointKey } from './useMediaQuery';
export type { AuthStatus, PermissionCheck } from './useAuth';
export type { AsyncStatus } from './useAsync';
export type {
  PaginationOptions,
  PaginationState,
  PaginationActions,
  UsePaginationReturn,
  PaginationRangeItem,
} from './usePagination';

/**
 * Hook categories for documentation and organization
 */
export const hookCategories = {
  storage: [
    'useLocalStorage',
    'useLocalStorageJSON', 
    'useLocalStorageString',
    'useLocalStorageBoolean',
  ],
  performance: [
    'useDebounce',
    'useDebouncedCallback',
    'useDebouncedState',
  ],
  async: [
    'useAsync',
    'useAsyncEffect',
    'useAsyncAll',
  ],
  auth: [
    'useAuth',
    'useAuthGuard',
  ],
  responsive: [
    'useMediaQuery',
    'useBreakpoint',
    'useBreakpoints',
    'useViewport',
    'useMediaPreferences',
    'useResponsiveValue',
  ],
  ui: [
    'useClickOutside',
    'useClickOutsideRef',
    'useClickOutsideWithEscape',
    'useClickOutsideWithFocusTrap',
  ],
  forms: [
    'useForm',
    'useFieldValidation',
    'useMultiStepForm',
  ],
  notifications: [
    'useToast',
    'useToastPatterns',
    'useContextualToast',
  ],
  pagination: [
    'usePagination',
    'useCursorPagination',
    'useTablePagination',
  ],
} as const;