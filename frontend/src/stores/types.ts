/**
 * Advanced TypeScript Store Types
 * 
 * This file contains sophisticated TypeScript patterns for enterprise-grade
 * state management including branded types, conditional types, mapped types,
 * template literal types, and utility types for Zustand stores.
 */

// =============================================================================
// BRANDED TYPES FOR TYPE SAFETY
// =============================================================================

/**
 * Brand utility type to create nominal typing
 */
declare const __brand: unique symbol;
type Brand<T, TBrand extends string> = T & { readonly [__brand]: TBrand };

/**
 * Branded types for sensitive data
 */
export type UserId = Brand<string, 'UserId'>;
export type AccessToken = Brand<string, 'AccessToken'>;
export type RefreshToken = Brand<string, 'RefreshToken'>;
export type SessionId = Brand<string, 'SessionId'>;
export type PermissionId = Brand<string, 'PermissionId'>;
export type NotificationId = Brand<string, 'NotificationId'>;
export type PreferenceKey = Brand<string, 'PreferenceKey'>;

/**
 * Branded type helpers
 */
export const createUserId = (id: string): UserId => id as UserId;
export const createAccessToken = (token: string): AccessToken => token as AccessToken;
export const createRefreshToken = (token: string): RefreshToken => token as RefreshToken;
export const createSessionId = (id: string): SessionId => id as SessionId;
export const createPermissionId = (id: string): PermissionId => id as PermissionId;
export const createNotificationId = (id: string): NotificationId => id as NotificationId;
export const createPreferenceKey = (key: string): PreferenceKey => key as PreferenceKey;

// =============================================================================
// CONDITIONAL TYPES FOR STATE MANAGEMENT
// =============================================================================

/**
 * Async state discriminated union with conditional types
 */
export type AsyncState<T, E = Error> =
  | { status: 'idle'; data: null; error: null; loading: false }
  | { status: 'loading'; data: T | null; error: null; loading: true }
  | { status: 'success'; data: T; error: null; loading: false }
  | { status: 'error'; data: T | null; error: E; loading: false };

/**
 * Conditional type to extract data from AsyncState
 */
export type AsyncStateData<T> = T extends AsyncState<infer U> ? U : never;

/**
 * Conditional type to determine if state is loading
 */
export type IsLoading<T> = T extends AsyncState<any, any>
  ? T['status'] extends 'loading'
    ? true
    : false
  : never;

/**
 * Conditional type to determine if state has error
 */
export type HasError<T> = T extends AsyncState<any, infer E>
  ? T['status'] extends 'error'
    ? E
    : null
  : never;

// =============================================================================
// MAPPED TYPES FOR STORE OPERATIONS
// =============================================================================

/**
 * Extract all async operations from a store type
 */
export type AsyncOperations<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => Promise<any> ? K : never;
}[keyof T];

/**
 * Extract all sync operations from a store type
 */
export type SyncOperations<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => Promise<any> ? never : K;
}[keyof T];

/**
 * Make all async operations in a store optional
 */
export type OptionalAsyncOperations<T> = {
  [K in AsyncOperations<T>]?: T[K];
} & {
  [K in SyncOperations<T>]: T[K];
};

/**
 * Create loading states for all async operations
 */
export type LoadingStates<T> = {
  [K in AsyncOperations<T> as `${string & K}Loading`]: boolean;
};

/**
 * Create error states for all async operations
 */
export type ErrorStates<T> = {
  [K in AsyncOperations<T> as `${string & K}Error`]: Error | null;
};

// =============================================================================
// TEMPLATE LITERAL TYPES FOR DYNAMIC KEYS
// =============================================================================

/**
 * Generate permission keys using template literal types
 */
export type ResourceAction = 'create' | 'read' | 'update' | 'delete';
export type ResourceType = 'user' | 'post' | 'comment' | 'setting' | 'notification';
export type PermissionKey = `${ResourceType}.${ResourceAction}`;

/**
 * Generate preference keys for different categories
 */
export type PreferenceCategory = 'ui' | 'notification' | 'privacy' | 'security' | 'accessibility';
export type PreferenceName = string;
export type PreferenceKeyType = `${PreferenceCategory}.${PreferenceName}`;

/**
 * Generate event keys for store communication
 */
export type EventType = 'created' | 'updated' | 'deleted' | 'restored';
export type EntityType = 'user' | 'notification' | 'preference' | 'permission';
export type EventKey = `${EntityType}.${EventType}`;

// =============================================================================
// RECURSIVE TYPES FOR NESTED STRUCTURES
// =============================================================================

/**
 * Recursive type for nested permission structures
 */
export type NestedPermissions<T = string> = {
  [key: string]: T | NestedPermissions<T>;
};

/**
 * Recursive type for nested preferences
 */
export type NestedPreferences<T = any> = {
  [key: string]: T | NestedPreferences<T>;
};

/**
 * Deep readonly recursive type
 */
export type DeepReadonly<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonly<T[P]> : T[P];
};

/**
 * Deep partial recursive type
 */
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

// =============================================================================
// STORE BASE INTERFACES
// =============================================================================

/**
 * Base store interface with common patterns
 */
export interface BaseStore {
  /** Store initialization timestamp */
  readonly _initialized: number;
  /** Store version for migration purposes */
  readonly _version: string;
  /** Store unique identifier */
  readonly _storeId: string;
}

/**
 * Async store mixin with standardized async patterns
 */
export interface AsyncStoreMixin<T extends Record<string, any>> {
  /** Global loading state for the store */
  readonly isLoading: boolean;
  /** Global error state for the store */
  readonly error: Error | null;
  /** Last operation timestamp */
  readonly lastOperation: number | null;
  /** Clear all errors in the store */
  clearErrors: () => void;
  /** Reset the store to initial state */
  reset: () => void;
  /** Check if store has any pending operations */
  hasPendingOperations: () => boolean;
}

/**
 * Cache store mixin with cache management
 */
export interface CacheStoreMixin<T> {
  /** Cache expiry time in milliseconds */
  readonly cacheExpiry: number;
  /** Last cache update timestamp */
  readonly lastCacheUpdate: number | null;
  /** Check if cache is valid */
  isCacheValid: () => boolean;
  /** Invalidate cache */
  invalidateCache: () => void;
  /** Refresh cached data */
  refreshCache: () => Promise<void>;
}

/**
 * Optimistic updates mixin
 */
export interface OptimisticUpdatesMixin<T> {
  /** Optimistic update data */
  readonly optimisticData: T | null;
  /** Whether optimistic update is active */
  readonly hasOptimisticUpdate: boolean;
  /** Apply optimistic update */
  applyOptimisticUpdate: (data: T) => void;
  /** Revert optimistic update */
  revertOptimisticUpdate: () => void;
  /** Commit optimistic update */
  commitOptimisticUpdate: () => void;
}

// =============================================================================
// STORE EVENT SYSTEM TYPES
// =============================================================================

/**
 * Store event payload type
 */
export interface StoreEvent<T = any> {
  readonly type: EventKey;
  readonly payload: T;
  readonly timestamp: number;
  readonly storeId: string;
  readonly correlationId?: string;
}

/**
 * Store event listener type
 */
export type StoreEventListener<T = any> = (event: StoreEvent<T>) => void;

/**
 * Store event emitter interface
 */
export interface StoreEventEmitter {
  /** Emit an event */
  emit: <T>(type: EventKey, payload: T) => void;
  /** Subscribe to events */
  on: <T>(type: EventKey, listener: StoreEventListener<T>) => () => void;
  /** Subscribe to events once */
  once: <T>(type: EventKey, listener: StoreEventListener<T>) => () => void;
  /** Remove all listeners for a type */
  off: (type: EventKey) => void;
  /** Remove all listeners */
  clear: () => void;
}

// =============================================================================
// STORE SELECTOR TYPES
// =============================================================================

/**
 * Store selector function type
 */
export type StoreSelector<TStore, TResult> = (state: TStore) => TResult;

/**
 * Memoized selector with dependencies
 */
export type MemoizedSelector<TStore, TResult, TDeps extends readonly unknown[] = []> = {
  (state: TStore): TResult;
  dependencies: TDeps;
  clearCache: () => void;
};

/**
 * Computed selector that derives state from multiple stores
 */
export type ComputedSelector<TStores extends Record<string, any>, TResult> = (
  stores: TStores
) => TResult;

// =============================================================================
// STORE SUBSCRIPTION TYPES
// =============================================================================

/**
 * Store subscription options
 */
export interface SubscriptionOptions {
  /** Whether to immediately call the callback with current state */
  immediate?: boolean;
  /** Debounce delay in milliseconds */
  debounce?: number;
  /** Throttle delay in milliseconds */
  throttle?: number;
  /** Only trigger on specific property changes */
  keys?: string[];
  /** Custom equality function */
  equalityFn?: (a: any, b: any) => boolean;
}

/**
 * Store subscription function
 */
export type StoreSubscription<T> = (
  listener: (state: T, previousState: T) => void,
  options?: SubscriptionOptions
) => () => void;

// =============================================================================
// STORE MIDDLEWARE TYPES
// =============================================================================

/**
 * Store middleware function type
 */
export type StoreMiddleware<T> = (
  config: (set: any, get: any, api: any) => T,
  set: any,
  get: any,
  api: any
) => T;

/**
 * Logging middleware options
 */
export interface LoggingOptions {
  /** Enable/disable logging */
  enabled: boolean;
  /** Log level */
  level: 'debug' | 'info' | 'warn' | 'error';
  /** Custom logger function */
  logger?: (level: string, message: string, data?: any) => void;
  /** Actions to exclude from logging */
  excludeActions?: string[];
  /** Maximum log entries to keep */
  maxEntries?: number;
}

/**
 * Performance monitoring middleware options
 */
export interface PerformanceOptions {
  /** Enable/disable performance monitoring */
  enabled: boolean;
  /** Threshold in milliseconds for slow operations */
  slowThreshold: number;
  /** Custom performance reporter */
  reporter?: (operation: string, duration: number, data?: any) => void;
}

// =============================================================================
// STORE VALIDATION TYPES
// =============================================================================

/**
 * Validation rule function
 */
export type ValidationRule<T> = (value: T) => string | null;

/**
 * Store validation schema
 */
export type ValidationSchema<T> = {
  [K in keyof T]?: ValidationRule<T[K]>[];
};

/**
 * Validation result
 */
export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string[]>;
}

/**
 * Store validator interface
 */
export interface StoreValidator<T> {
  /** Validate entire store state */
  validate: (state: T) => ValidationResult;
  /** Validate specific field */
  validateField: <K extends keyof T>(key: K, value: T[K]) => string | null;
  /** Add validation rule */
  addRule: <K extends keyof T>(key: K, rule: ValidationRule<T[K]>) => void;
  /** Remove validation rule */
  removeRule: <K extends keyof T>(key: K, rule: ValidationRule<T[K]>) => void;
}

// =============================================================================
// UTILITY TYPES FOR STORE COMPOSITION
// =============================================================================

/**
 * Extract store state properties (non-functions)
 */
export type StoreState<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => any ? never : T[K];
};

/**
 * Extract store action properties (functions)
 */
export type StoreActions<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => any ? T[K] : never;
};

/**
 * Combine multiple stores into a single type
 */
export type CombinedStores<T extends Record<string, any>> = {
  [K in keyof T]: T[K] extends { getState: () => infer S } ? S : T[K];
};

/**
 * Store slice type for modular store composition
 */
export type StoreSlice<T, K extends keyof T> = Pick<T, K>;

/**
 * Store slice creator function
 */
export type SliceCreator<T, TSlice> = (
  set: (partial: Partial<T> | ((state: T) => Partial<T>)) => void,
  get: () => T,
  api: any
) => TSlice;

// =============================================================================
// TYPE GUARDS AND ASSERTION FUNCTIONS
// =============================================================================

/**
 * Type guard for AsyncState
 */
export const isAsyncState = <T>(value: any): value is AsyncState<T> => {
  return (
    typeof value === 'object' &&
    value !== null &&
    'status' in value &&
    'data' in value &&
    'error' in value &&
    'loading' in value &&
    ['idle', 'loading', 'success', 'error'].includes(value.status)
  );
};

/**
 * Type guard for loading state
 */
export const isLoadingState = <T>(state: AsyncState<T>): state is AsyncState<T> & { status: 'loading' } => {
  return state.status === 'loading';
};

/**
 * Type guard for success state
 */
export const isSuccessState = <T>(state: AsyncState<T>): state is AsyncState<T> & { status: 'success' } => {
  return state.status === 'success';
};

/**
 * Type guard for error state
 */
export const isErrorState = <T>(state: AsyncState<T>): state is AsyncState<T> & { status: 'error' } => {
  return state.status === 'error';
};

/**
 * Assertion function for non-null values
 */
export const assertNonNull = <T>(value: T | null | undefined, message?: string): asserts value is T => {
  if (value == null) {
    throw new Error(message || 'Value must not be null or undefined');
  }
};

/**
 * Assertion function for branded types
 */
export const assertUserId = (value: string): asserts value is UserId => {
  if (!value || typeof value !== 'string') {
    throw new Error('Invalid UserId');
  }
};

export const assertAccessToken = (value: string): asserts value is AccessToken => {
  if (!value || typeof value !== 'string') {
    throw new Error('Invalid AccessToken');
  }
};

// =============================================================================
// ADVANCED UTILITY TYPES
// =============================================================================

/**
 * Create a type with all properties optional except specified keys
 */
export type PartialExcept<T, K extends keyof T> = Partial<T> & Pick<T, K>;

/**
 * Create a type with all properties required except specified keys
 */
export type RequiredExcept<T, K extends keyof T> = Required<T> & Partial<Pick<T, K>>;

/**
 * Extract function return type with Promise unwrapping
 */
export type UnwrapPromise<T> = T extends Promise<infer U> ? U : T;

/**
 * Create a type that excludes functions
 */
export type NonFunctionProperties<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => any ? never : K;
}[keyof T];

/**
 * Create a type that includes only functions
 */
export type FunctionProperties<T> = {
  [K in keyof T]: T[K] extends (...args: any[]) => any ? K : never;
}[keyof T];

/**
 * Create a readonly version of nested object properties
 */
export type DeepReadonlyObject<T> = {
  readonly [P in keyof T]: T[P] extends object ? DeepReadonlyObject<T[P]> : T[P];
};

/**
 * Type-safe keys of an object
 */
export type KeysOf<T> = keyof T;

/**
 * Type-safe values of an object
 */
export type ValuesOf<T> = T[keyof T];

/**
 * Create union type from object values
 */
export type ValueUnion<T> = T[keyof T];

/**
 * Strict extract utility that preserves never types
 */
export type StrictExtract<T, U> = T extends U ? T : never;

/**
 * Create a type with specific properties omitted and others optional
 */
export type OmitAndOptional<T, K extends keyof T, O extends keyof T> = Omit<T, K | O> & Partial<Pick<T, O>>;

// =============================================================================
// CONSTANTS AND DEFAULTS
// =============================================================================

/**
 * Default cache expiry time (5 minutes)
 */
export const DEFAULT_CACHE_EXPIRY = 5 * 60 * 1000;

/**
 * Default debounce delay for subscriptions
 */
export const DEFAULT_DEBOUNCE_DELAY = 300;

/**
 * Default throttle delay for subscriptions
 */
export const DEFAULT_THROTTLE_DELAY = 100;

/**
 * Store version for migration purposes
 */
export const STORE_VERSION = '1.0.0';

/**
 * Default store ID generator
 */
export const generateStoreId = (): string => {
  return `store_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};