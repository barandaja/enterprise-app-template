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
 * API endpoint definition
 */
export interface ApiEndpoint<TRequest = unknown, TResponse = unknown> {
  readonly method: Method;
  readonly path: string;
  readonly requestSchema?: unknown; // Zod schema for request validation
  readonly responseSchema?: unknown; // Zod schema for response validation
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
export const DEFAULT_API_CONFIG: ApiClientConfig = {
  baseURL: import.meta.env.VITE_API_URL || (
    import.meta.env.DEV 
      ? 'http://localhost:3000/api/v1'  // Development default
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
// Utility Types
// =============================================================================

/**
 * Extract request type from API endpoint
 */
export type ExtractRequestType<T> = T extends ApiEndpoint<infer R, unknown> ? R : never;

/**
 * Extract response type from API endpoint
 */
export type ExtractResponseType<T> = T extends ApiEndpoint<unknown, infer R> ? R : never;

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
 * API method signatures
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