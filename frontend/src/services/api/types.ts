/**
 * @fileoverview API Type Definitions
 * 
 * Comprehensive type definitions for API communication including:
 * - Generic response wrappers with advanced TypeScript features
 * - Error response types with discriminated unions
 * - Pagination and filtering types
 * - Request configuration and retry logic types
 * - File upload and progress tracking types
 */

import type { AxiosRequestConfig, AxiosResponse, Method } from 'axios';
import type { ZodSchema } from 'zod';
import type { 
  User, 
  LoginCredentials, 
  RegisterData, 
  UpdateProfileData,
  SearchParams
} from '../../types';

// =============================================================================
// Generic API Response Types
// =============================================================================

/**
 * Base API response wrapper with discriminated union for success/error states
 */
export type ApiResponse<TData = unknown> = 
  | ApiSuccessResponse<TData>
  | ApiErrorResponse;

/**
 * Successful API response
 */
export interface ApiSuccessResponse<TData = unknown> {
  readonly success: true;
  readonly data: TData;
  readonly message?: string;
  readonly meta?: ResponseMeta;
}

/**
 * Error API response with detailed error information
 */
export interface ApiErrorResponse {
  readonly success: false;
  readonly message: string;
  readonly code?: ApiErrorCode;
  readonly errors?: ValidationErrors;
  readonly meta?: ErrorMeta;
  readonly stack?: string; // Only in development
}

/**
 * Response metadata for successful responses
 */
export interface ResponseMeta {
  readonly timestamp: string;
  readonly requestId: string;
  readonly version?: string;
  readonly cached?: boolean;
  readonly pagination?: PaginationMeta;
}

/**
 * Error metadata for failed responses
 */
export interface ErrorMeta {
  readonly timestamp: string;
  readonly requestId: string;
  readonly path: string;
  readonly method: string;
  readonly userAgent?: string;
}

// =============================================================================
// Error Types and Codes
// =============================================================================

/**
 * Standardized API error codes
 */
export enum ApiErrorCode {
  // Authentication errors
  UNAUTHORIZED = 'UNAUTHORIZED',
  FORBIDDEN = 'FORBIDDEN',
  TOKEN_EXPIRED = 'TOKEN_EXPIRED',
  INVALID_CREDENTIALS = 'INVALID_CREDENTIALS',
  
  // Validation errors
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  INVALID_INPUT = 'INVALID_INPUT',
  MISSING_FIELD = 'MISSING_FIELD',
  
  // Resource errors
  NOT_FOUND = 'NOT_FOUND',
  CONFLICT = 'CONFLICT',
  GONE = 'GONE',
  
  // Server errors
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  SERVICE_UNAVAILABLE = 'SERVICE_UNAVAILABLE',
  TIMEOUT = 'TIMEOUT',
  
  // Rate limiting
  RATE_LIMITED = 'RATE_LIMITED',
  QUOTA_EXCEEDED = 'QUOTA_EXCEEDED',
  
  // Network errors
  NETWORK_ERROR = 'NETWORK_ERROR',
  CONNECTION_ERROR = 'CONNECTION_ERROR',
}

/**
 * Validation errors with field-specific messages
 */
export interface ValidationErrors {
  readonly [field: string]: string | string[];
}

/**
 * Custom API error class with enhanced error information
 */
export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly statusCode: number;
  readonly errors?: ValidationErrors;
  readonly meta?: ErrorMeta;
  readonly response?: AxiosResponse;

  constructor(
    message: string,
    code: ApiErrorCode = ApiErrorCode.INTERNAL_ERROR,
    statusCode: number = 500,
    errors?: ValidationErrors,
    meta?: ErrorMeta,
    response?: AxiosResponse
  ) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.statusCode = statusCode;
    this.errors = errors;
    this.meta = meta;
    this.response = response;

    // Maintain proper stack trace for where the error was thrown (V8 only)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ApiError);
    }
  }

  /**
   * Create ApiError from response data
   */
  static fromResponse(response: AxiosResponse<ApiErrorResponse>): ApiError {
    const { data } = response;
    return new ApiError(
      data.message,
      data.code || ApiErrorCode.INTERNAL_ERROR,
      response.status,
      data.errors,
      data.meta,
      response
    );
  }

  /**
   * Check if error is of a specific type
   */
  is(code: ApiErrorCode): boolean {
    return this.code === code;
  }

  /**
   * Get validation error for a specific field
   */
  getFieldError(field: string): string | string[] | undefined {
    return this.errors?.[field];
  }
}

// =============================================================================
// Pagination Types
// =============================================================================

/**
 * Pagination metadata in response
 */
export interface PaginationMeta {
  readonly page: number;
  readonly limit: number;
  readonly total: number;
  readonly totalPages: number;
  readonly hasNext: boolean;
  readonly hasPrev: boolean;
  readonly nextPage?: number;
  readonly prevPage?: number;
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<TData> {
  readonly data: readonly TData[];
  readonly pagination: PaginationMeta;
}

/**
 * Pagination request parameters
 */
export interface PaginationParams {
  readonly page?: number;
  readonly limit?: number;
  readonly offset?: number;
}

/**
 * Sorting parameters
 */
export interface SortParams {
  readonly sortBy?: string;
  readonly sortOrder?: 'asc' | 'desc';
}

/**
 * Combined search, pagination, and sorting parameters
 */
export interface QueryParams extends PaginationParams, SortParams {
  readonly search?: string;
  readonly filters?: Record<string, unknown>;
}

// =============================================================================
// Request Configuration Types
// =============================================================================

/**
 * Extended Axios request configuration with custom options
 */
export interface ApiRequestConfig extends AxiosRequestConfig {
  readonly retryConfig?: RetryConfig;
  readonly skipAuth?: boolean;
  readonly skipRefresh?: boolean;
  readonly skipErrorHandling?: boolean;
  readonly timeout?: number;
  readonly cacheKey?: string;
  readonly cacheTTL?: number;
  readonly onUploadProgress?: (progress: UploadProgress) => void;
  readonly onDownloadProgress?: (progress: DownloadProgress) => void;
}

/**
 * Retry configuration
 */
export interface RetryConfig {
  readonly attempts: number;
  readonly delay: number;
  readonly backoff: 'linear' | 'exponential';
  readonly maxDelay: number;
  readonly retryCondition?: (error: ApiError) => boolean;
  readonly onRetry?: (attempt: number, error: ApiError) => void;
}

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  attempts: 3,
  delay: 1000,
  backoff: 'exponential',
  maxDelay: 10000,
  retryCondition: (error) => {
    const retryableStatuses = [408, 429, 500, 502, 503, 504];
    return retryableStatuses.includes(error.statusCode);
  },
} as const;

// =============================================================================
// File Upload Types
// =============================================================================

/**
 * File upload progress information
 */
export interface UploadProgress {
  readonly loaded: number;
  readonly total: number;
  readonly progress: number;
  readonly rate?: number;
  readonly estimated?: number;
}

/**
 * File download progress information
 */
export interface DownloadProgress {
  readonly loaded: number;
  readonly total: number;
  readonly progress: number;
  readonly rate?: number;
  readonly estimated?: number;
}

/**
 * File upload request data
 */
export interface FileUploadData {
  readonly file: File;
  readonly field?: string;
  readonly metadata?: Record<string, unknown>;
}

/**
 * File upload response
 */
export interface FileUploadResponse {
  readonly id: string;
  readonly filename: string;
  readonly originalName: string;
  readonly mimeType: string;
  readonly size: number;
  readonly url: string;
  readonly thumbnailUrl?: string;
  readonly uploadedAt: string;
}

/**
 * Multipart form data builder
 */
export interface MultipartFormData {
  readonly files: FileUploadData[];
  readonly fields?: Record<string, string | number | boolean>;
}

// =============================================================================
// Notification Types
// =============================================================================

/**
 * Notification priority levels
 */
export enum NotificationPriority {
  LOW = 'low',
  NORMAL = 'normal',
  HIGH = 'high',
  URGENT = 'urgent',
}

/**
 * Notification types
 */
export enum NotificationType {
  INFO = 'info',
  SUCCESS = 'success',
  WARNING = 'warning',
  ERROR = 'error',
  SECURITY = 'security',
  SYSTEM = 'system',
  MARKETING = 'marketing',
}

/**
 * Notification delivery channels
 */
export enum NotificationChannel {
  IN_APP = 'in_app',
  EMAIL = 'email',
  PUSH = 'push',
  SMS = 'sms',
  WEBHOOK = 'webhook',
}

/**
 * Base notification interface
 */
export interface BaseNotification {
  readonly id: string;
  readonly userId: string;
  readonly type: NotificationType;
  readonly priority: NotificationPriority;
  readonly title: string;
  readonly message: string;
  readonly data?: Record<string, unknown>;
  readonly channels: NotificationChannel[];
  readonly isRead: boolean;
  readonly isArchived: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly expiresAt?: string;
  readonly actionUrl?: string;
  readonly actionText?: string;
}

/**
 * Notification with delivery status
 */
export interface NotificationWithStatus extends BaseNotification {
  readonly deliveryStatus: Record<NotificationChannel, {
    readonly status: 'pending' | 'sent' | 'delivered' | 'failed' | 'bounced';
    readonly sentAt?: string;
    readonly deliveredAt?: string;
    readonly error?: string;
  }>;
}

/**
 * Notification template
 */
export interface NotificationTemplate {
  readonly id: string;
  readonly name: string;
  readonly type: NotificationType;
  readonly subject: string;
  readonly htmlContent: string;
  readonly textContent: string;
  readonly variables: string[];
  readonly isActive: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * Notification subscription preferences
 */
export interface NotificationSubscription {
  readonly userId: string;
  readonly channels: Partial<Record<NotificationChannel, {
    readonly enabled: boolean;
    readonly types: NotificationType[];
    readonly quietHours?: {
      readonly start: string; // HH:mm format
      readonly end: string;   // HH:mm format
      readonly timezone: string;
    };
  }>>;
  readonly globalSettings: {
    readonly enabled: boolean;
    readonly allowMarketing: boolean;
    readonly allowSystem: boolean;
    readonly frequency: 'immediate' | 'hourly' | 'daily' | 'weekly';
  };
}

/**
 * Batch notification operation
 */
export interface BatchNotificationRequest {
  readonly notifications: Array<Omit<BaseNotification, 'id' | 'createdAt' | 'updatedAt'>>;
  readonly options?: {
    readonly batchSize?: number;
    readonly delayBetweenBatches?: number;
    readonly failureHandling?: 'continue' | 'stop' | 'retry';
  };
}

/**
 * Batch operation result
 */
export interface BatchOperationResult<T = unknown> {
  readonly success: boolean;
  readonly totalCount: number;
  readonly successCount: number;
  readonly failureCount: number;
  readonly results: Array<{
    readonly success: boolean;
    readonly data?: T;
    readonly error?: string;
  }>;
  readonly metadata: {
    readonly processingTime: number;
    readonly batchId: string;
    readonly timestamp: string;
  };
}

/**
 * Real-time notification event
 */
export interface NotificationEvent {
  readonly type: 'notification.created' | 'notification.updated' | 'notification.deleted' | 'notification.read';
  readonly payload: BaseNotification;
  readonly timestamp: string;
  readonly userId: string;
}

// =============================================================================
// Preferences Types
// =============================================================================

/**
 * Preference value types
 */
export type PreferenceValue = string | number | boolean | object | null;

/**
 * Preference data types for validation
 */
export enum PreferenceDataType {
  STRING = 'string',
  NUMBER = 'number',
  BOOLEAN = 'boolean',
  JSON = 'json',
  ARRAY = 'array',
}

/**
 * Preference definition with schema
 */
export interface PreferenceDefinition {
  readonly key: string;
  readonly name: string;
  readonly description?: string;
  readonly dataType: PreferenceDataType;
  readonly defaultValue: PreferenceValue;
  readonly validationSchema?: ZodSchema<PreferenceValue>;
  readonly isRequired: boolean;
  readonly isSecret: boolean; // For sensitive preferences
  readonly category: string;
  readonly tags: string[];
}

/**
 * User preference entry
 */
export interface UserPreferenceEntry {
  readonly key: string;
  readonly value: PreferenceValue;
  readonly encryptedValue?: string; // For secret preferences
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly syncedAt?: string;
}

/**
 * Preference group for organization
 */
export interface PreferenceGroup {
  readonly category: string;
  readonly name: string;
  readonly description?: string;
  readonly order: number;
  readonly preferences: PreferenceDefinition[];
}

/**
 * Preference backup
 */
export interface PreferenceBackup {
  readonly id: string;
  readonly userId: string;
  readonly preferences: Record<string, PreferenceValue>;
  readonly version: string;
  readonly createdAt: string;
  readonly metadata: {
    readonly deviceInfo?: string;
    readonly appVersion?: string;
    readonly reason: 'manual' | 'auto' | 'migration';
  };
}

/**
 * Preference sync conflict
 */
export interface PreferenceSyncConflict {
  readonly key: string;
  readonly localValue: PreferenceValue;
  readonly remoteValue: PreferenceValue;
  readonly localTimestamp: string;
  readonly remoteTimestamp: string;
  readonly resolution?: 'local' | 'remote' | 'merge' | 'manual';
}

// =============================================================================
// Permissions Types
// =============================================================================

/**
 * Permission resource types
 */
export type PermissionResource = 
  | 'user'
  | 'notification'
  | 'preference'
  | 'role'
  | 'system'
  | 'audit'
  | string; // Allow custom resources

/**
 * Permission actions
 */
export type PermissionAction = 
  | 'create'
  | 'read' 
  | 'update'
  | 'delete'
  | 'list'
  | 'execute'
  | 'manage'
  | string; // Allow custom actions

/**
 * Permission scope for contextual permissions
 */
export interface PermissionScope {
  readonly type: 'global' | 'organization' | 'team' | 'user' | 'resource';
  readonly value?: string; // ID of the scoped entity
  readonly conditions?: Record<string, unknown>;
}

/**
 * Base permission definition
 */
export interface Permission {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly resource: PermissionResource;
  readonly action: PermissionAction;
  readonly scope: PermissionScope;
  readonly conditions?: Record<string, unknown>;
  readonly isSystem: boolean;
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * Role definition with hierarchical support
 */
export interface Role {
  readonly id: string;
  readonly name: string;
  readonly description?: string;
  readonly permissions: Permission[];
  readonly parentRole?: Role;
  readonly childRoles: Role[];
  readonly isSystem: boolean;
  readonly isActive: boolean;
  readonly metadata: {
    readonly level: number;
    readonly priority: number;
    readonly tags: string[];
  };
  readonly createdAt: string;
  readonly updatedAt: string;
}

/**
 * User role assignment
 */
export interface UserRoleAssignment {
  readonly id: string;
  readonly userId: string;
  readonly roleId: string;
  readonly role: Role;
  readonly scope: PermissionScope;
  readonly grantedBy: string;
  readonly grantedAt: string;
  readonly expiresAt?: string;
  readonly isActive: boolean;
}

/**
 * Permission check request
 */
export interface PermissionCheckRequest {
  readonly userId: string;
  readonly resource: PermissionResource;
  readonly action: PermissionAction;
  readonly scope?: PermissionScope;
  readonly context?: Record<string, unknown>;
}

/**
 * Permission check result
 */
export interface PermissionCheckResult {
  readonly granted: boolean;
  readonly reason?: string;
  readonly matchingPermissions: Permission[];
  readonly effectiveRole?: Role;
  readonly context: {
    readonly checkedAt: string;
    readonly userId: string;
    readonly resource: PermissionResource;
    readonly action: PermissionAction;
  };
}

/**
 * Permission audit log entry
 */
export interface PermissionAuditLog {
  readonly id: string;
  readonly userId: string;
  readonly action: 'grant' | 'revoke' | 'check' | 'modify';
  readonly resource: PermissionResource;
  readonly resourceAction: PermissionAction;
  readonly scope?: PermissionScope;
  readonly result: boolean;
  readonly reason?: string;
  readonly metadata: {
    readonly ipAddress: string;
    readonly userAgent: string;
    readonly sessionId?: string;
    readonly timestamp: string;
  };
  readonly createdAt: string;
}

// =============================================================================
// Authentication Types
// =============================================================================

/**
 * Token response from authentication endpoints
 */
export interface TokenResponse {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly tokenType: 'Bearer';
  readonly expiresIn: number;
  readonly expiresAt: string;
  readonly scope?: string[];
}

/**
 * Login response with user data and tokens
 */
export interface LoginResponse {
  readonly user: User;
  readonly tokens: TokenResponse;
  readonly isFirstLogin?: boolean;
  readonly requiresPasswordChange?: boolean;
  readonly requiresTwoFactor?: boolean;
}

/**
 * Registration response
 */
export interface RegisterResponse {
  readonly user: User;
  readonly tokens: TokenResponse;
  readonly requiresVerification?: boolean;
  readonly verificationSent?: boolean;
}

/**
 * Password reset request
 */
export interface PasswordResetRequest {
  readonly email: string;
  readonly redirectUrl?: string;
}

/**
 * Password reset confirmation
 */
export interface PasswordResetConfirm {
  readonly token: string;
  readonly password: string;
  readonly confirmPassword: string;
}

/**
 * Email verification request
 */
export interface EmailVerificationRequest {
  readonly email: string;
  readonly redirectUrl?: string;
}

/**
 * Email verification confirmation
 */
export interface EmailVerificationConfirm {
  readonly token: string;
  readonly email?: string;
}

/**
 * Change password request
 */
export interface ChangePasswordRequest {
  readonly currentPassword: string;
  readonly newPassword: string;
  readonly confirmPassword: string;
}

// =============================================================================
// API Endpoint Configuration
// =============================================================================

/**
 * API endpoint definition (legacy - use TypedApiEndpoint for new code)
 */
export interface ApiEndpoint<TRequest = unknown, TResponse = unknown> {
  readonly method: Method;
  readonly path: string;
  readonly requestSchema?: ZodSchema<TRequest>;
  readonly responseSchema?: ZodSchema<TResponse>;
  readonly config?: Partial<ApiRequestConfig>;
}

/**
 * API endpoints collection
 */
export interface ApiEndpoints {
  readonly auth: {
    readonly login: ApiEndpoint<LoginCredentials, LoginResponse>;
    readonly register: ApiEndpoint<RegisterData, RegisterResponse>;
    readonly logout: ApiEndpoint<void, void>;
    readonly refresh: ApiEndpoint<{ refreshToken: string }, TokenResponse>;
    readonly passwordReset: ApiEndpoint<PasswordResetRequest, void>;
    readonly passwordResetConfirm: ApiEndpoint<PasswordResetConfirm, void>;
    readonly emailVerification: ApiEndpoint<EmailVerificationRequest, void>;
    readonly emailVerificationConfirm: ApiEndpoint<EmailVerificationConfirm, void>;
    readonly changePassword: ApiEndpoint<ChangePasswordRequest, void>;
  };
  readonly user: {
    readonly profile: ApiEndpoint<void, User>;
    readonly updateProfile: ApiEndpoint<UpdateProfileData, User>;
    readonly uploadAvatar: ApiEndpoint<FileUploadData, FileUploadResponse>;
    readonly deleteAccount: ApiEndpoint<{ password: string }, void>;
    readonly preferences: ApiEndpoint<void, UserPreferences>;
    readonly updatePreferences: ApiEndpoint<Partial<UserPreferences>, UserPreferences>;
  };
}

/**
 * User preferences type
 */
export interface UserPreferences {
  readonly theme: 'light' | 'dark' | 'system';
  readonly language: string;
  readonly timezone: string;
  readonly notifications: {
    readonly email: boolean;
    readonly push: boolean;
    readonly sms: boolean;
    readonly marketing: boolean;
  };
  readonly privacy: {
    readonly profileVisible: boolean;
    readonly showEmail: boolean;
    readonly allowMessaging: boolean;
  };
}

// =============================================================================
// Request Cancellation Types
// =============================================================================

/**
 * Request cancellation controller
 */
export interface RequestController {
  readonly cancel: (reason?: string) => void;
  readonly isCancelled: boolean;
  readonly signal: AbortSignal;
}

/**
 * Request cancellation registry
 */
export interface CancellationRegistry {
  readonly register: (key: string, controller: RequestController) => void;
  readonly cancel: (key: string, reason?: string) => boolean;
  readonly cancelAll: (reason?: string) => void;
  readonly cleanup: (key: string) => void;
}

// =============================================================================
// Response Transformation Types
// =============================================================================

/**
 * Response transformer function
 */
export type ResponseTransformer<TInput, TOutput> = (data: TInput) => TOutput;

/**
 * Request transformer function
 */
export type RequestTransformer<TInput, TOutput> = (data: TInput) => TOutput;

/**
 * Transformation configuration
 */
export interface TransformConfig<TRequest = unknown, TResponse = unknown> {
  readonly request?: RequestTransformer<TRequest, unknown>;
  readonly response?: ResponseTransformer<unknown, TResponse>;
}

// =============================================================================
// API Client Configuration
// =============================================================================

/**
 * API client configuration
 */
export interface ApiClientConfig {
  readonly baseURL: string;
  readonly timeout: number;
  readonly retryConfig: RetryConfig;
  readonly headers: Record<string, string>;
  readonly withCredentials: boolean;
  readonly validateStatus: (status: number) => boolean;
  readonly maxContentLength: number;
  readonly maxBodyLength: number;
  readonly enableLogging: boolean;
  readonly enableCaching: boolean;
  readonly cacheTTL: number;
}

/**
 * Default API client configuration
 */
// Debug environment variable
console.log('[API Config] VITE_API_URL:', import.meta.env.VITE_API_URL);
console.log('[API Config] DEV mode:', import.meta.env.DEV);

export const DEFAULT_API_CONFIG: ApiClientConfig = {
  baseURL: import.meta.env.VITE_API_URL || (
    import.meta.env.DEV 
      ? 'http://localhost:8000/api/v1'  // Development default - updated to correct port
      : 'https://api.example.com/api/v1' // Production default (should be overridden)
  ),
  timeout: 30000,
  retryConfig: DEFAULT_RETRY_CONFIG,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  withCredentials: true,
  validateStatus: (status) => status >= 200 && status < 300,
  maxContentLength: 10 * 1024 * 1024, // 10MB
  maxBodyLength: 10 * 1024 * 1024, // 10MB
  enableLogging: import.meta.env.DEV,
  enableCaching: false,
  cacheTTL: 5 * 60 * 1000, // 5 minutes
} as const;

// =============================================================================
// Advanced TypeScript Patterns
// =============================================================================

/**
 * Template literal types for dynamic endpoint generation
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type ApiPath = `/${string}`;
export type ApiEndpointKey = `${Lowercase<HttpMethod>}:${ApiPath}`;

/**
 * Conditional types for different HTTP methods
 */
export type MethodRequiresBody<T extends HttpMethod> = T extends 'GET' | 'DELETE' ? false : true;
export type EndpointWithBody<TMethod extends HttpMethod> = MethodRequiresBody<TMethod> extends true
  ? { method: TMethod; data: unknown }
  : { method: TMethod; data?: never };

/**
 * Advanced endpoint definition with conditional typing
 */
export interface TypedApiEndpoint<
  TMethod extends HttpMethod = HttpMethod,
  TRequest = unknown,
  TResponse = unknown,
  TPath extends ApiPath = ApiPath
> {
  readonly method: TMethod;
  readonly path: TPath;
  readonly requestSchema?: ZodSchema<TRequest>;
  readonly responseSchema?: ZodSchema<TResponse>;
  readonly config?: Partial<ApiRequestConfig>;
  readonly middleware?: MiddlewareFunction[];
  readonly cache?: CacheConfig;
  readonly rateLimit?: RateLimitConfig;
}

/**
 * Branded error types for different API failures
 */
export type NetworkError = ApiError & { readonly __brand: 'NetworkError' };
export type ValidationError = ApiError & { readonly __brand: 'ValidationError' };
export type AuthenticationError = ApiError & { readonly __brand: 'AuthenticationError' };
export type AuthorizationError = ApiError & { readonly __brand: 'AuthorizationError' };
export type ServerError = ApiError & { readonly __brand: 'ServerError' };
export type RateLimitError = ApiError & { readonly __brand: 'RateLimitError' };

/**
 * Discriminated union for all possible API errors
 */
export type ApiErrorUnion = 
  | NetworkError
  | ValidationError
  | AuthenticationError
  | AuthorizationError
  | ServerError
  | RateLimitError;

/**
 * Type-safe query builder types
 */
export interface QueryBuilder<T extends Record<string, unknown> = Record<string, unknown>> {
  where<K extends keyof T>(field: K, operator: ComparisonOperator, value: T[K]): QueryBuilder<T>;
  whereIn<K extends keyof T>(field: K, values: T[K][]): QueryBuilder<T>;
  whereBetween<K extends keyof T>(field: K, min: T[K], max: T[K]): QueryBuilder<T>;
  orderBy<K extends keyof T>(field: K, direction?: 'asc' | 'desc'): QueryBuilder<T>;
  limit(count: number): QueryBuilder<T>;
  offset(count: number): QueryBuilder<T>;
  page(number: number, size?: number): QueryBuilder<T>;
  build(): QueryParams;
}

export type ComparisonOperator = '=' | '!=' | '>' | '>=' | '<' | '<=' | 'like' | 'ilike' | 'in' | 'not_in';

/**
 * Middleware function type
 */
export interface MiddlewareContext {
  readonly request: AxiosRequestConfig;
  readonly response?: AxiosResponse;
  readonly error?: Error;
  readonly client: ApiClient;
}

export type MiddlewareFunction = (
  context: MiddlewareContext,
  next: () => Promise<AxiosResponse>
) => Promise<AxiosResponse>;

/**
 * Cache configuration
 */
export interface CacheConfig {
  readonly enabled: boolean;
  readonly ttl: number; // Time to live in milliseconds
  readonly key?: string | ((config: AxiosRequestConfig) => string);
  readonly invalidateOn?: ApiEndpointKey[];
  readonly tags?: string[];
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  readonly maxRequests: number;
  readonly windowMs: number;
  readonly skipSuccessfulRequests?: boolean;
  readonly skipFailedRequests?: boolean;
  readonly keyGenerator?: (config: AxiosRequestConfig) => string;
}

/**
 * Performance monitoring configuration
 */
export interface PerformanceConfig {
  readonly enabled: boolean;
  readonly threshold: number; // Log slow requests above this threshold (ms)
  readonly trackMemory: boolean;
  readonly trackMetrics: boolean;
}

/**
 * Optimistic update configuration
 */
export interface OptimisticUpdateConfig<TData = unknown> {
  readonly enabled: boolean;
  readonly updateKey: string;
  readonly optimisticData: TData | ((currentData: TData) => TData);
  readonly rollbackOnError: boolean;
}

/**
 * Background sync configuration
 */
export interface BackgroundSyncConfig {
  readonly enabled: boolean;
  readonly syncInterval: number; // Interval in milliseconds
  readonly conflictResolution: 'client-wins' | 'server-wins' | 'merge' | 'manual';
  readonly retryAttempts: number;
}

// =============================================================================
// Extended API Request Configuration
// =============================================================================

/**
 * Enhanced API request configuration with enterprise features
 */
export interface EnhancedApiRequestConfig extends ApiRequestConfig {
  readonly middleware?: MiddlewareFunction[];
  readonly cache?: CacheConfig;
  readonly rateLimit?: RateLimitConfig;
  readonly performance?: PerformanceConfig;
  readonly optimisticUpdate?: OptimisticUpdateConfig;
  readonly backgroundSync?: BackgroundSyncConfig;
  readonly priority?: 'low' | 'normal' | 'high' | 'critical';
  readonly tags?: string[];
  readonly metadata?: Record<string, unknown>;
}

// =============================================================================
// Utility Types
// =============================================================================

/**
 * Extract request type from API endpoint
 */
export type ExtractRequestType<T> = T extends TypedApiEndpoint<any, infer R, any, any> ? R : never;

/**
 * Extract response type from API endpoint
 */
export type ExtractResponseType<T> = T extends TypedApiEndpoint<any, any, infer R, any> ? R : never;

/**
 * Extract method type from API endpoint
 */
export type ExtractMethodType<T> = T extends TypedApiEndpoint<infer M, any, any, any> ? M : never;

/**
 * Extract path type from API endpoint
 */
export type ExtractPathType<T> = T extends TypedApiEndpoint<any, any, any, infer P> ? P : never;

/**
 * Make all properties of an API response readonly
 */
export type ReadonlyApiResponse<T> = T extends ApiSuccessResponse<infer TData>
  ? ApiSuccessResponse<Readonly<TData>>
  : T extends ApiErrorResponse
  ? Readonly<T>
  : never;

/**
 * Extract data type from API response
 */
export type ExtractDataType<T> = T extends ApiSuccessResponse<infer TData> ? TData : never;

/**
 * Create a union of all possible endpoint paths
 */
export type EndpointPaths<T> = T extends Record<string, Record<string, TypedApiEndpoint<any, any, any, infer P>>>
  ? P
  : never;

/**
 * Type-safe method builder
 */
export interface TypedApiMethods {
  readonly get: <TResponse = unknown>(
    url: string,
    config?: EnhancedApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly post: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: EnhancedApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly put: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: EnhancedApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly patch: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: EnhancedApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly delete: <TResponse = unknown>(
    url: string,
    config?: EnhancedApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;

  readonly query: <T extends Record<string, unknown> = Record<string, unknown>>() => QueryBuilder<T>;
}

/**
 * Legacy API method signatures for backward compatibility
 */
export interface ApiMethods {
  readonly get: <TResponse = unknown>(
    url: string,
    config?: ApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly post: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: ApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly put: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: ApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly patch: <TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config?: ApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
  
  readonly delete: <TResponse = unknown>(
    url: string,
    config?: ApiRequestConfig
  ) => Promise<ApiResponse<TResponse>>;
}