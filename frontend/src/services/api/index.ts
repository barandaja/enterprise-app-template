/**
 * @fileoverview Main API Service Export
 * 
 * Centralized API interface providing:
 * - Type-safe endpoint definitions
 * - Unified API client access
 * - Response transformers and validators
 * - Service layer abstractions
 * - Request builders and utilities
 * - Configuration management
 */

import { z } from 'zod';
import { apiClient, type ApiClient } from './client';
import { authService, type AuthService } from './auth.service';
import { userService, type UserService } from './user.service';
import { notificationService, type NotificationService } from './notification.service';
import { preferencesService, type PreferencesService } from './preferences.service';
import { permissionsService, type PermissionsService } from './permissions.service';
import { cacheService, type CacheService } from './cache.service';
import type {
  ApiResponse,
  ApiSuccessResponse,
  ApiErrorResponse,
  ApiRequestConfig,
  ApiEndpoints,
  ApiClientConfig,
  TokenResponse,
  LoginResponse,
  RegisterResponse,
  PaginatedResponse,
  FileUploadResponse,
  UserPreferences,
  MiddlewareFunction,
  MiddlewareContext,
} from './types';
import {
  validateApiResponse,
  validatePaginatedResponse,
  createResponseValidator,
  extractErrorMessage,
  createUserFriendlyError,
  buildQueryParams,
  buildValidatedQueryParams,
  extractPaginationParams,
  generateRequestCacheKey,
} from '../utils/api-helpers';
import type { User, LoginCredentials, RegisterData, UpdateProfileData } from '../../types';

// =============================================================================
// Response Validators
// =============================================================================

/**
 * User response schema
 */
const userSchema = z.object({
  id: z.string(),
  email: z.string().email(),
  firstName: z.string(),
  lastName: z.string(),
  avatar: z.string().optional(),
  role: z.enum(['admin', 'user', 'moderator']),
  isActive: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
});

/**
 * User response validator
 */
const userValidator = createResponseValidator(userSchema);

/**
 * Login response schema
 */
const loginResponseSchema = z.object({
  user: z.object({
    id: z.string(),
    email: z.string().email(),
    firstName: z.string(),
    lastName: z.string(),
    avatar: z.string().optional(),
    role: z.enum(['admin', 'user', 'moderator']),
    isActive: z.boolean(),
    createdAt: z.string(),
    updatedAt: z.string(),
  }),
  tokens: z.object({
    accessToken: z.string(),
    refreshToken: z.string(),
    tokenType: z.literal('Bearer'),
    expiresIn: z.number(),
    expiresAt: z.string(),
    scope: z.array(z.string()).optional(),
  }),
  isFirstLogin: z.boolean().optional(),
  requiresPasswordChange: z.boolean().optional(),
  requiresTwoFactor: z.boolean().optional(),
});

/**
 * Login response validator
 */
const loginResponseValidator = createResponseValidator(loginResponseSchema);

/**
 * Token response schema
 */
const tokenResponseSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  tokenType: z.literal('Bearer'),
  expiresIn: z.number(),
  expiresAt: z.string(),
  scope: z.array(z.string()).optional(),
});

/**
 * Token response validator
 */
const tokenResponseValidator = createResponseValidator(tokenResponseSchema);

/**
 * File upload response schema
 */
const fileUploadSchema = z.object({
  id: z.string(),
  filename: z.string(),
  originalName: z.string(),
  mimeType: z.string(),
  size: z.number(),
  url: z.string().url(),
  thumbnailUrl: z.string().url().optional(),
  uploadedAt: z.string(),
});

/**
 * File upload response validator
 */
const fileUploadValidator = createResponseValidator(fileUploadSchema);

/**
 * User preferences schema
 */
const userPreferencesSchema = z.object({
  theme: z.enum(['light', 'dark', 'system']),
  language: z.string(),
  timezone: z.string(),
  notifications: z.object({
    email: z.boolean(),
    push: z.boolean(),
    sms: z.boolean(),
    marketing: z.boolean(),
  }),
  privacy: z.object({
    profileVisible: z.boolean(),
    showEmail: z.boolean(),
    allowMessaging: z.boolean(),
  }),
});

// =============================================================================
// API Endpoint Configurations
// =============================================================================

/**
 * Complete API endpoint configuration with validation schemas
 */
export const apiEndpoints: ApiEndpoints = {
  auth: {
    login: {
      method: 'POST',
      path: '/auth/login',
      requestSchema: z.object({
        email: z.string().email(),
        password: z.string().min(1),
        rememberMe: z.boolean().optional(),
      }),
      responseSchema: loginResponseSchema,
      config: { skipAuth: true },
    },
    register: {
      method: 'POST',
      path: '/auth/register',
      requestSchema: z.object({
        email: z.string().email(),
        password: z.string().min(8),
        firstName: z.string().min(1),
        lastName: z.string().min(1),
      }),
      responseSchema: loginResponseSchema,
      config: { skipAuth: true },
    },
    logout: {
      method: 'POST',
      path: '/auth/logout',
      responseSchema: z.void(),
    },
    refresh: {
      method: 'POST',
      path: '/auth/refresh',
      requestSchema: z.object({
        refreshToken: z.string(),
      }),
      responseSchema: tokenResponseSchema,
      config: { skipAuth: true, skipRefresh: true },
    },
    passwordReset: {
      method: 'POST',
      path: '/auth/password/reset',
      requestSchema: z.object({
        email: z.string().email(),
        redirectUrl: z.string().url().optional(),
      }),
      responseSchema: z.void(),
      config: { skipAuth: true },
    },
    passwordResetConfirm: {
      method: 'POST',
      path: '/auth/password/reset/confirm',
      requestSchema: z.object({
        token: z.string(),
        password: z.string().min(8),
        confirmPassword: z.string(),
      }),
      responseSchema: z.void(),
      config: { skipAuth: true },
    },
    emailVerification: {
      method: 'POST',
      path: '/auth/email/verify',
      requestSchema: z.object({
        email: z.string().email(),
        redirectUrl: z.string().url().optional(),
      }),
      responseSchema: z.void(),
      config: { skipAuth: true },
    },
    emailVerificationConfirm: {
      method: 'POST',
      path: '/auth/email/verify/confirm',
      requestSchema: z.object({
        token: z.string(),
        email: z.string().email().optional(),
      }),
      responseSchema: z.void(),
      config: { skipAuth: true },
    },
    changePassword: {
      method: 'POST',
      path: '/auth/password/change',
      requestSchema: z.object({
        currentPassword: z.string(),
        newPassword: z.string().min(8),
        confirmPassword: z.string(),
      }),
      responseSchema: z.void(),
    },
  },
  user: {
    profile: {
      method: 'GET',
      path: '/users/profile',
      responseSchema: userSchema,
    },
    updateProfile: {
      method: 'PATCH',
      path: '/users/profile',
      requestSchema: z.object({
        firstName: z.string().optional(),
        lastName: z.string().optional(),
        avatar: z.string().optional(),
      }),
      responseSchema: userSchema,
    },
    uploadAvatar: {
      method: 'POST',
      path: '/users/avatar',
      responseSchema: fileUploadSchema,
    },
    deleteAccount: {
      method: 'POST',
      path: '/users/delete',
      requestSchema: z.object({
        password: z.string(),
      }),
      responseSchema: z.void(),
    },
    preferences: {
      method: 'GET',
      path: '/users/preferences',
      responseSchema: userPreferencesSchema,
    },
    updatePreferences: {
      method: 'PATCH',
      path: '/users/preferences',
      requestSchema: z.object({
        theme: z.enum(['light', 'dark', 'system']).optional(),
        language: z.string().optional(),
        timezone: z.string().optional(),
        notifications: z.object({
          email: z.boolean().optional(),
          push: z.boolean().optional(),
          sms: z.boolean().optional(),
          marketing: z.boolean().optional(),
        }).optional(),
        privacy: z.object({
          profileVisible: z.boolean().optional(),
          showEmail: z.boolean().optional(),
          allowMessaging: z.boolean().optional(),
        }).optional(),
      }),
      responseSchema: userPreferencesSchema,
    },
  },
};

// =============================================================================
// Request Builders
// =============================================================================

/**
 * Type-safe request builder for API endpoints
 */
export class RequestBuilder<TRequest = unknown, TResponse = unknown> {
  constructor(
    private readonly client: ApiClient,
    private readonly endpoint: {
      method: string;
      path: string;
      requestSchema?: z.ZodType<TRequest>;
      responseSchema?: z.ZodType<TResponse>;
      config?: Partial<ApiRequestConfig>;
    }
  ) {}

  /**
   * Execute the request with optional data and configuration
   */
  async execute(
    data?: TRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    // Validate request data if schema is provided
    if (this.endpoint.requestSchema && data !== undefined) {
      try {
        this.endpoint.requestSchema.parse(data);
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new Error(`Request validation failed: ${error.errors.map((e: z.ZodIssue) => e.message).join(', ')}`);
        }
        throw error;
      }
    }

    // Merge configurations
    const mergedConfig = {
      ...this.endpoint.config,
      ...config,
    };

    // Execute request based on method
    let response: ApiResponse<unknown>;
    
    switch (this.endpoint.method.toUpperCase()) {
      case 'GET':
        response = await this.client.get(this.endpoint.path, mergedConfig);
        break;
      case 'POST':
        response = await this.client.post(this.endpoint.path, data, mergedConfig);
        break;
      case 'PUT':
        response = await this.client.put(this.endpoint.path, data, mergedConfig);
        break;
      case 'PATCH':
        response = await this.client.patch(this.endpoint.path, data, mergedConfig);
        break;
      case 'DELETE':
        response = await this.client.delete(this.endpoint.path, mergedConfig);
        break;
      default:
        throw new Error(`Unsupported HTTP method: ${this.endpoint.method}`);
    }

    // Validate response if schema is provided
    if (this.endpoint.responseSchema && response.success) {
      try {
        const validatedData = this.endpoint.responseSchema.parse(response.data);
        return {
          ...response,
          data: validatedData,
        } as ApiResponse<TResponse>;
      } catch (error) {
        if (error instanceof z.ZodError) {
          throw new Error(`Response validation failed: ${error.errors.map((e: z.ZodIssue) => e.message).join(', ')}`);
        }
        throw error;
      }
    }

    return response as ApiResponse<TResponse>;
  }
}

// =============================================================================
// Main API Class
// =============================================================================

/**
 * Main API service class providing centralized access to all API operations
 */
export class ApiService {
  public readonly client: ApiClient;
  public readonly auth: AuthService;
  public readonly user: UserService;

  constructor(config?: Partial<ApiClientConfig>) {
    this.client = config ? new (apiClient.constructor as typeof ApiClient)(config) : apiClient;
    this.auth = authService;
    this.user = userService;
  }

  // ===========================================================================
  // Request Builder Factory Methods
  // ===========================================================================

  /**
   * Create a type-safe request builder for authentication endpoints
   */
  createAuthRequest<K extends keyof ApiEndpoints['auth']>(
    endpoint: K
  ): RequestBuilder<any, any> {
    return new RequestBuilder(this.client, apiEndpoints.auth[endpoint]);
  }

  /**
   * Create a type-safe request builder for user endpoints
   */
  createUserRequest<K extends keyof ApiEndpoints['user']>(
    endpoint: K
  ): RequestBuilder<any, any> {
    return new RequestBuilder(this.client, apiEndpoints.user[endpoint]);
  }

  // ===========================================================================
  // Convenience Methods
  // ===========================================================================

  /**
   * Login with credentials
   */
  async login(credentials: LoginCredentials): Promise<ApiResponse<LoginResponse>> {
    const response = await this.auth.login(credentials);
    return loginResponseValidator(response);
  }

  /**
   * Register new user
   */
  async register(data: RegisterData): Promise<ApiResponse<RegisterResponse>> {
    const response = await this.auth.register({
      ...data,
      confirmPassword: data.password, // For compatibility
      acceptTerms: true, // Assume terms are accepted
    });
    return loginResponseValidator(response);
  }

  /**
   * Get current user profile
   */
  async getCurrentUser(): Promise<ApiResponse<User>> {
    const response = await this.user.getProfile();
    return userValidator(response);
  }

  /**
   * Update user profile
   */
  async updateUserProfile(data: UpdateProfileData): Promise<ApiResponse<User>> {
    const response = await this.user.updateProfile(data);
    return userValidator(response);
  }

  /**
   * Upload user avatar
   */
  async uploadUserAvatar(file: File): Promise<ApiResponse<FileUploadResponse>> {
    const response = await this.user.uploadAvatar(file);
    return fileUploadValidator(response);
  }

  /**
   * Get user preferences
   */
  async getUserPreferences(): Promise<ApiResponse<UserPreferences>> {
    return this.user.getPreferences();
  }

  /**
   * Update user preferences
   */
  async updateUserPreferences(
    preferences: Partial<UserPreferences>
  ): Promise<ApiResponse<UserPreferences>> {
    return this.user.updatePreferences(preferences);
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /**
   * Build query parameters for requests
   */
  buildQuery(params: Record<string, unknown>): URLSearchParams {
    return buildQueryParams(params);
  }

  /**
   * Build validated query parameters
   */
  buildValidatedQuery<T extends Record<string, unknown>>(
    params: T,
    schema: z.ZodSchema<T>
  ): URLSearchParams {
    return buildValidatedQueryParams(params, schema);
  }

  /**
   * Extract pagination parameters from query
   */
  extractPagination(params: Record<string, unknown>): {
    page: number;
    limit: number;
    offset: number;
  } {
    return extractPaginationParams(params);
  }

  /**
   * Create user-friendly error message
   */
  createErrorMessage(error: unknown, fallback?: string): string {
    return createUserFriendlyError(error, fallback);
  }

  /**
   * Extract error details
   */
  extractError(error: unknown): {
    message: string;
    code?: string;
    statusCode?: number;
    fieldErrors: Record<string, string[]>;
  } {
    return extractErrorMessage(error);
  }

  /**
   * Cancel request by key
   */
  cancelRequest(key: string, reason?: string): boolean {
    return this.client.cancelRequest(key, reason);
  }

  /**
   * Cancel all pending requests
   */
  cancelAllRequests(reason?: string): void {
    this.client.cancelAllRequests(reason);
  }

  /**
   * Update API configuration
   */
  updateConfig(config: Partial<ApiClientConfig>): void {
    this.client.updateConfig(config);
  }

  /**
   * Get current API configuration
   */
  getConfig(): Readonly<ApiClientConfig> {
    return this.client.getConfig();
  }

  /**
   * Add global middleware
   */
  addMiddleware(middleware: MiddlewareFunction): void {
    this.client.addMiddleware(middleware);
  }
}

// =============================================================================
// Singleton Instance and Exports
// =============================================================================

/**
 * Enterprise API middleware for common functionality
 */
export const commonMiddleware = {
  /**
   * Request logging middleware
   */
  requestLogger: async (context: MiddlewareContext, next: () => Promise<any>) => {
    const start = Date.now();
    console.log(`🚀 ${context.request.method?.toUpperCase()} ${context.request.url}`);
    
    try {
      const response = await next();
      const duration = Date.now() - start;
      console.log(`✅ ${context.request.method?.toUpperCase()} ${context.request.url} - ${response.status} (${duration}ms)`);
      return response;
    } catch (error) {
      const duration = Date.now() - start;
      console.error(`❌ ${context.request.method?.toUpperCase()} ${context.request.url} - Error (${duration}ms):`, error);
      // Make sure we're throwing a proper error
      if (error === undefined || error === null) {
        throw new Error('Unknown error occurred during request');
      }
      throw error;
    }
  },

  /**
   * Performance monitoring middleware
   */
  performanceMonitor: (threshold = 1000) => async (context: MiddlewareContext, next: () => Promise<any>) => {
    const start = Date.now();
    
    try {
      const response = await next();
      const duration = Date.now() - start;
      if (duration > threshold) {
        console.warn(`🐌 Slow request detected: ${context.request.method?.toUpperCase()} ${context.request.url} took ${duration}ms`);
      }
      return response;
    } catch (error) {
      throw error;
    }
  },

  /**
   * Error handling middleware
   */
  errorHandler: async (context: MiddlewareContext, next: () => Promise<any>) => {
    try {
      return await next();
    } catch (error) {
      // Add context to error
      if (error instanceof Error) {
        error.message = `[${context.request.method?.toUpperCase()} ${context.request.url}] ${error.message}`;
      }
      throw error;
    }
  },

  /**
   * Response transformation middleware
   */
  responseTransformer: <T>(transformer: (data: any) => T) => async (context: MiddlewareContext, next: () => Promise<any>) => {
    try {
      const response = await next();
      if (response.data) {
        response.data = transformer(response.data);
      }
      return response;
    } catch (error) {
      throw error;
    }
  },
};

/**
 * Default API service instance with enhanced features
 */
export const api = new ApiService();

// Add default middleware for development
if (import.meta.env.DEV) {
  api.addMiddleware(commonMiddleware.requestLogger);
  api.addMiddleware(commonMiddleware.performanceMonitor(1000));
}

// Always add error handling middleware
api.addMiddleware(commonMiddleware.errorHandler);

// Re-export all types and utilities
export type {
  // Core types
  ApiResponse,
  ApiSuccessResponse,
  ApiErrorResponse,
  ApiRequestConfig,
  EnhancedApiRequestConfig,
  ApiClientConfig,
  
  // Response types
  LoginResponse,
  RegisterResponse,
  TokenResponse,
  FileUploadResponse,
  UserPreferences,
  PaginatedResponse,
  
  // Service types
  // Note: Service type interfaces are not exported from ./types
  
  // Endpoint types
  ApiEndpoints,
  TypedApiEndpoint,
  
  // Advanced types
  MiddlewareFunction,
  QueryBuilder,
  HttpMethod,
  ApiPath,
  
  // Notification types
  BaseNotification,
  NotificationWithStatus,
  NotificationTemplate,
  NotificationSubscription,
  NotificationType,
  NotificationPriority,
  NotificationChannel,
  
  // Preferences types
  PreferenceValue,
  PreferenceDefinition,
  UserPreferenceEntry,
  PreferenceGroup,
  PreferenceBackup,
  
  // Permissions types
  Permission,
  Role,
  UserRoleAssignment,
  PermissionCheckRequest,
  PermissionCheckResult,
  PermissionAuditLog,
  
  // Cache types
  // Note: Cache type interfaces are exported from cache service directly
} from './types';

// Re-export error handling
export { ApiError, ApiErrorCode } from './client';

// Re-export all services for direct access
export { 
  authService, 
  userService, 
  notificationService, 
  preferencesService, 
  permissionsService, 
  cacheService 
};

// Re-export authApi alias for backward compatibility
export { authApi } from './auth.service';

// Re-export utilities
export {
  // Validation utilities
  validateApiResponse,
  validatePaginatedResponse,
  createResponseValidator,
  
  // Error utilities
  extractErrorMessage,
  createUserFriendlyError,
  
  // Query utilities
  buildQueryParams,
  buildValidatedQueryParams,
  extractPaginationParams,
  
  // File utilities
  validateFile,
  createMultipartFormData,
  formatFileSize,
  
  // Request utilities
  generateRequestCacheKey,
  debounce,
  throttle,
} from '../utils/api-helpers';

// Re-export cache utilities
export {
  CacheStorageType,
  InvalidationStrategy,
  DEFAULT_CACHE_CONFIG,
} from './cache.service';

// Re-export notification utilities
export {
  createNotificationSchema,
  updateNotificationSchema,
  subscriptionPreferencesSchema,
  createTemplateSchema,
  NotificationQueryBuilder,
} from './notification.service';

// Re-export preferences utilities
export {
  PREFERENCE_KEYS,
  preferenceValueSchema,
  preferenceDefinitionSchema,
  userPreferenceEntrySchema,
  preferenceGroupSchema,
  createBackupSchema,
  syncConflictResolutionSchema,
} from './preferences.service';

// Re-export permissions utilities
export {
  RESOURCES,
  ACTIONS,
  PERMISSION_SETS,
  SYSTEM_ROLES,
  createPermissionSchema,
  createRoleSchema,
  assignRoleSchema,
  permissionCheckSchema,
  bulkPermissionCheckSchema,
} from './permissions.service';

/**
 * Utility function to create a configured API service instance
 */
export function createApiService(config: {
  baseURL?: string;
  enableLogging?: boolean;
  enableCaching?: boolean;
  enableRealtime?: boolean;
  middleware?: MiddlewareFunction[];
}): ApiService {
  const apiService = new ApiService({
    baseURL: config.baseURL,
    enableLogging: config.enableLogging,
    enableCaching: config.enableCaching,
  });

  // Add common middleware
  if (config.enableLogging) {
    apiService.addMiddleware(commonMiddleware.requestLogger);
    apiService.addMiddleware(commonMiddleware.performanceMonitor(1000));
  }
  
  apiService.addMiddleware(commonMiddleware.errorHandler);
  
  // Add custom middleware
  if (config.middleware) {
    config.middleware.forEach(middleware => {
      apiService.addMiddleware(middleware);
    });
  }

  return apiService;
}

// Default export
export default api;