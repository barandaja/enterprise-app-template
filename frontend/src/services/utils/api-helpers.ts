/**
 * @fileoverview API Helper Utilities
 * 
 * Collection of utility functions for API operations including:
 * - Query string builders with type safety
 * - Response validators using Zod schemas
 * - Error message extractors with localization support
 * - File upload helpers with progress tracking
 * - Pagination helpers with URL management
 * - Request deduplication utilities
 * - Cache management helpers
 */

import { z, type ZodSchema, type ZodError } from 'zod';
import type {
  ApiResponse,
  ApiSuccessResponse,
  ApiErrorResponse,
  ApiError,
  PaginatedResponse,
  PaginationMeta,
  QueryParams,
  ValidationErrors,
  FileUploadData,
  MultipartFormData,
  UploadProgress,
} from '../api/types';

// =============================================================================
// Query String Building Utilities
// =============================================================================

/**
 * Converts an object to a URLSearchParams instance with proper encoding
 * 
 * @param params - Object containing query parameters
 * @returns URLSearchParams instance
 * 
 * @example
 * ```typescript
 * const params = buildQueryParams({
 *   page: 1,
 *   limit: 10,
 *   search: 'hello world',
 *   filters: { category: 'tech', active: true }
 * });
 * console.log(params.toString()); // page=1&limit=10&search=hello+world&filters[category]=tech&filters[active]=true
 * ```
 */
export function buildQueryParams(params: Record<string, unknown>): URLSearchParams {
  const searchParams = new URLSearchParams();

  const addParam = (key: string, value: unknown): void => {
    if (value === null || value === undefined) {
      return;
    }

    if (Array.isArray(value)) {
      value.forEach((item, index) => {
        if (item !== null && item !== undefined) {
          searchParams.append(`${key}[${index}]`, String(item));
        }
      });
    } else if (typeof value === 'object') {
      Object.entries(value as Record<string, unknown>).forEach(([subKey, subValue]) => {
        if (subValue !== null && subValue !== undefined) {
          searchParams.append(`${key}[${subKey}]`, String(subValue));
        }
      });
    } else {
      searchParams.append(key, String(value));
    }
  };

  Object.entries(params).forEach(([key, value]) => {
    addParam(key, value);
  });

  return searchParams;
}

/**
 * Type-safe query parameter builder with validation
 * 
 * @param params - Query parameters object
 * @param schema - Zod schema for validation
 * @returns Validated URLSearchParams
 * 
 * @example
 * ```typescript
 * const schema = z.object({
 *   page: z.number().min(1),
 *   limit: z.number().min(1).max(100),
 *   search: z.string().optional()
 * });
 * 
 * const params = buildValidatedQueryParams({
 *   page: 1,
 *   limit: 20,
 *   search: 'typescript'
 * }, schema);
 * ```
 */
export function buildValidatedQueryParams<T extends Record<string, unknown>>(
  params: T,
  schema: ZodSchema<T>
): URLSearchParams {
  const validatedParams = schema.parse(params);
  return buildQueryParams(validatedParams);
}

/**
 * Extract query parameters from URL with type safety
 * 
 * @param url - URL string or URL object
 * @param schema - Zod schema for validation
 * @returns Parsed and validated query parameters
 * 
 * @example
 * ```typescript
 * const schema = z.object({
 *   page: z.coerce.number().min(1).default(1),
 *   limit: z.coerce.number().min(1).max(100).default(20)
 * });
 * 
 * const params = extractQueryParams('https://api.example.com/users?page=2&limit=50', schema);
 * console.log(params); // { page: 2, limit: 50 }
 * ```
 */
export function extractQueryParams<T>(
  url: string | URL,
  schema: ZodSchema<T>
): T {
  const urlObj = typeof url === 'string' ? new URL(url) : url;
  const searchParams = urlObj.searchParams;
  
  const params: Record<string, unknown> = {};
  
  searchParams.forEach((value, key) => {
    // Handle array-like parameters
    if (key.includes('[') && key.includes(']')) {
      const baseKey = key.substring(0, key.indexOf('['));
      const subKey = key.substring(key.indexOf('[') + 1, key.indexOf(']'));
      
      if (!params[baseKey]) {
        params[baseKey] = isNaN(Number(subKey)) ? {} : [];
      }
      
      if (Array.isArray(params[baseKey])) {
        (params[baseKey] as unknown[])[Number(subKey)] = value;
      } else {
        (params[baseKey] as Record<string, unknown>)[subKey] = value;
      }
    } else {
      params[key] = value;
    }
  });
  
  return schema.parse(params);
}

// =============================================================================
// Response Validation Utilities
// =============================================================================

/**
 * Validates API response using Zod schema
 * 
 * @param response - API response to validate
 * @param schema - Zod schema for data validation
 * @returns Validated response with type-safe data
 * 
 * @example
 * ```typescript
 * const userSchema = z.object({
 *   id: z.string(),
 *   name: z.string(),
 *   email: z.string().email()
 * });
 * 
 * const response = await apiClient.get('/users/123');
 * const validatedResponse = validateApiResponse(response, userSchema);
 * ```
 */
export function validateApiResponse<T>(
  response: ApiResponse<unknown>,
  schema: ZodSchema<T>
): ApiResponse<T> {
  if (!response.success) {
    return response as ApiErrorResponse;
  }

  try {
    const validatedData = schema.parse(response.data);
    return {
      ...response,
      data: validatedData,
    } as ApiSuccessResponse<T>;
  } catch (error) {
    if (error instanceof z.ZodError) {
      throw new Error(`Response validation failed: ${formatZodError(error)}`);
    }
    throw error;
  }
}

/**
 * Validates paginated API response
 * 
 * @param response - Paginated API response
 * @param itemSchema - Zod schema for individual items
 * @returns Validated paginated response
 */
export function validatePaginatedResponse<T>(
  response: ApiResponse<unknown>,
  itemSchema: ZodSchema<T>
): ApiResponse<PaginatedResponse<T>> {
  if (!response.success) {
    return response as ApiErrorResponse;
  }

  const paginatedSchema = z.object({
    data: z.array(itemSchema),
    pagination: z.object({
      page: z.number(),
      limit: z.number(),
      total: z.number(),
      totalPages: z.number(),
      hasNext: z.boolean(),
      hasPrev: z.boolean(),
      nextPage: z.number().optional(),
      prevPage: z.number().optional(),
    }),
  });

  return validateApiResponse(response, paginatedSchema);
}

/**
 * Creates a response validator function for reuse
 * 
 * @param schema - Zod schema for validation
 * @returns Validator function
 * 
 * @example
 * ```typescript
 * const validateUser = createResponseValidator(userSchema);
 * const response = await apiClient.get('/users/123');
 * const validatedResponse = validateUser(response);
 * ```
 */
export function createResponseValidator<T>(
  schema: ZodSchema<T>
): (response: ApiResponse<unknown>) => ApiResponse<T> {
  return (response: ApiResponse<unknown>) => validateApiResponse(response, schema);
}

// =============================================================================
// Error Handling Utilities
// =============================================================================

/**
 * Formats Zod validation errors into human-readable messages
 * 
 * @param error - Zod validation error
 * @returns Formatted error message
 */
export function formatZodError(error: ZodError): string {
  return error.errors
    .map(err => `${err.path.join('.')}: ${err.message}`)
    .join(', ');
}

/**
 * Extracts error messages from API error response
 * 
 * @param error - API error or unknown error
 * @returns Structured error information
 * 
 * @example
 * ```typescript
 * try {
 *   await apiClient.post('/users', userData);
 * } catch (error) {
 *   const errorInfo = extractErrorMessage(error);
 *   console.log('Error:', errorInfo.message);
 *   console.log('Field errors:', errorInfo.fieldErrors);
 * }
 * ```
 */
export function extractErrorMessage(error: unknown): {
  message: string;
  code?: string;
  statusCode?: number;
  fieldErrors: Record<string, string[]>;
} {
  // Handle ApiError instances
  if (error && typeof error === 'object' && 'message' in error) {
    const apiError = error as ApiError;
    return {
      message: apiError.message,
      code: apiError.code,
      statusCode: apiError.statusCode,
      fieldErrors: formatValidationErrors(apiError.errors || {}),
    };
  }

  // Handle generic errors
  if (error instanceof Error) {
    return {
      message: error.message,
      fieldErrors: {},
    };
  }

  // Handle string errors
  if (typeof error === 'string') {
    return {
      message: error,
      fieldErrors: {},
    };
  }

  return {
    message: 'An unknown error occurred',
    fieldErrors: {},
  };
}

/**
 * Formats validation errors for display
 * 
 * @param errors - Validation errors object
 * @returns Formatted field errors
 */
export function formatValidationErrors(errors: ValidationErrors): Record<string, string[]> {
  const formatted: Record<string, string[]> = {};

  Object.entries(errors).forEach(([field, messages]) => {
    formatted[field] = Array.isArray(messages) ? messages : [messages];
  });

  return formatted;
}

/**
 * Creates user-friendly error messages with fallbacks
 * 
 * @param error - Error to format
 * @param fallbackMessage - Default message if error is not recognized
 * @returns User-friendly error message
 */
export function createUserFriendlyError(
  error: unknown,
  fallbackMessage = 'Something went wrong. Please try again.'
): string {
  const errorInfo = extractErrorMessage(error);

  // Map common error codes to user-friendly messages
  const errorCodeMessages: Record<string, string> = {
    UNAUTHORIZED: 'You need to log in to access this resource.',
    FORBIDDEN: 'You do not have permission to perform this action.',
    NOT_FOUND: 'The requested resource was not found.',
    VALIDATION_ERROR: 'Please check your input and try again.',
    RATE_LIMITED: 'Too many requests. Please wait a moment and try again.',
    NETWORK_ERROR: 'Network error. Please check your connection and try again.',
    TIMEOUT: 'Request timed out. Please try again.',
  };

  if (errorInfo.code && errorCodeMessages[errorInfo.code]) {
    return errorCodeMessages[errorInfo.code];
  }

  return errorInfo.message || fallbackMessage;
}

// =============================================================================
// File Upload Utilities
// =============================================================================

/**
 * Validates file before upload
 * 
 * @param file - File to validate
 * @param options - Validation options
 * @returns Validation result
 * 
 * @example
 * ```typescript
 * const result = validateFile(file, {
 *   maxSize: 5 * 1024 * 1024, // 5MB
 *   allowedTypes: ['image/jpeg', 'image/png'],
 *   allowedExtensions: ['.jpg', '.jpeg', '.png']
 * });
 * 
 * if (!result.valid) {
 *   console.error('File validation failed:', result.errors);
 * }
 * ```
 */
export function validateFile(
  file: File,
  options: {
    maxSize?: number;
    minSize?: number;
    allowedTypes?: string[];
    allowedExtensions?: string[];
    requireImageDimensions?: { minWidth: number; minHeight: number; maxWidth: number; maxHeight: number };
  } = {}
): Promise<{ valid: boolean; errors: string[] }> {
  const errors: string[] = [];

  // Size validation
  if (options.maxSize && file.size > options.maxSize) {
    errors.push(`File size must be less than ${formatFileSize(options.maxSize)}`);
  }

  if (options.minSize && file.size < options.minSize) {
    errors.push(`File size must be at least ${formatFileSize(options.minSize)}`);
  }

  // Type validation
  if (options.allowedTypes && !options.allowedTypes.includes(file.type)) {
    errors.push(`File type ${file.type} is not allowed`);
  }

  // Extension validation
  if (options.allowedExtensions) {
    const extension = '.' + file.name.split('.').pop()?.toLowerCase();
    if (!options.allowedExtensions.includes(extension)) {
      errors.push(`File extension ${extension} is not allowed`);
    }
  }

  // Image dimension validation (async)
  return new Promise((resolve) => {
    if (options.requireImageDimensions && file.type.startsWith('image/')) {
      const img = new Image();
      img.onload = () => {
        const { minWidth, minHeight, maxWidth, maxHeight } = options.requireImageDimensions!;
        
        if (img.width < minWidth || img.height < minHeight) {
          errors.push(`Image must be at least ${minWidth}x${minHeight} pixels`);
        }
        
        if (img.width > maxWidth || img.height > maxHeight) {
          errors.push(`Image must be no larger than ${maxWidth}x${maxHeight} pixels`);
        }

        resolve({ valid: errors.length === 0, errors });
      };
      
      img.onerror = () => {
        errors.push('Invalid image file');
        resolve({ valid: false, errors });
      };
      
      img.src = URL.createObjectURL(file);
    } else {
      resolve({ valid: errors.length === 0, errors });
    }
  });
}

/**
 * Creates FormData for multipart upload
 * 
 * @param data - Upload data configuration
 * @returns FormData instance ready for upload
 * 
 * @example
 * ```typescript
 * const formData = createMultipartFormData({
 *   files: [{ file: selectedFile, field: 'avatar' }],
 *   fields: { userId: '123', category: 'profile' }
 * });
 * ```
 */
export function createMultipartFormData(data: MultipartFormData): FormData {
  const formData = new FormData();

  // Add files
  data.files.forEach(({ file, field = 'file', metadata }) => {
    formData.append(field, file);
    
    // Add metadata if provided
    if (metadata) {
      Object.entries(metadata).forEach(([key, value]) => {
        formData.append(`${field}_${key}`, String(value));
      });
    }
  });

  // Add additional fields
  if (data.fields) {
    Object.entries(data.fields).forEach(([key, value]) => {
      formData.append(key, String(value));
    });
  }

  return formData;
}

/**
 * Formats file size in human-readable format
 * 
 * @param bytes - File size in bytes
 * @returns Formatted file size string
 */
export function formatFileSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let size = bytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }

  return `${size.toFixed(1)} ${units[unitIndex]}`;
}

/**
 * Calculates upload progress percentage
 * 
 * @param loaded - Bytes loaded
 * @param total - Total bytes
 * @returns Progress information
 */
export function calculateUploadProgress(loaded: number, total: number): UploadProgress {
  const progress = Math.round((loaded / total) * 100);
  
  return {
    loaded,
    total,
    progress: Math.min(progress, 100),
  };
}

// =============================================================================
// Pagination Utilities
// =============================================================================

/**
 * Calculates pagination metadata
 * 
 * @param page - Current page (1-based)
 * @param limit - Items per page
 * @param total - Total number of items
 * @returns Pagination metadata
 */
export function calculatePaginationMeta(
  page: number,
  limit: number,
  total: number
): PaginationMeta {
  const totalPages = Math.ceil(total / limit);
  const hasNext = page < totalPages;
  const hasPrev = page > 1;

  return {
    page,
    limit,
    total,
    totalPages,
    hasNext,
    hasPrev,
    nextPage: hasNext ? page + 1 : undefined,
    prevPage: hasPrev ? page - 1 : undefined,
  };
}

/**
 * Generates pagination URLs for navigation
 * 
 * @param baseUrl - Base URL without query parameters
 * @param pagination - Pagination metadata
 * @param additionalParams - Additional query parameters to preserve
 * @returns Navigation URLs
 */
export function generatePaginationUrls(
  baseUrl: string,
  pagination: PaginationMeta,
  additionalParams: Record<string, unknown> = {}
): {
  first: string;
  prev?: string;
  next?: string;
  last: string;
} {
  const createUrl = (page: number): string => {
    const params = buildQueryParams({
      ...additionalParams,
      page,
      limit: pagination.limit,
    });
    return `${baseUrl}?${params.toString()}`;
  };

  return {
    first: createUrl(1),
    prev: pagination.hasPrev ? createUrl(pagination.prevPage!) : undefined,
    next: pagination.hasNext ? createUrl(pagination.nextPage!) : undefined,
    last: createUrl(pagination.totalPages),
  };
}

/**
 * Extracts pagination info from query parameters
 * 
 * @param params - Query parameters object
 * @returns Parsed pagination parameters with defaults
 */
export function extractPaginationParams(params: Record<string, unknown>): {
  page: number;
  limit: number;
  offset: number;
} {
  const page = Math.max(1, Number(params.page) || 1);
  const limit = Math.min(100, Math.max(1, Number(params.limit) || 20));
  const offset = (page - 1) * limit;

  return { page, limit, offset };
}

// =============================================================================
// Request Deduplication Utilities
// =============================================================================

/**
 * Generates a cache key for request deduplication
 * 
 * @param method - HTTP method
 * @param url - Request URL
 * @param data - Request data
 * @param params - Query parameters
 * @returns Cache key string
 */
export function generateRequestCacheKey(
  method: string,
  url: string,
  data?: unknown,
  params?: Record<string, unknown>
): string {
  const normalized = {
    method: method.toUpperCase(),
    url: url.toLowerCase(),
    data: data ? JSON.stringify(data) : null,
    params: params ? JSON.stringify(params) : null,
  };

  return btoa(JSON.stringify(normalized));
}

/**
 * Debounces function calls to prevent excessive API requests
 * 
 * @param func - Function to debounce
 * @param delay - Delay in milliseconds
 * @returns Debounced function
 */
export function debounce<T extends (...args: Parameters<T>) => ReturnType<T>>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: ReturnType<typeof setTimeout>;
  
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => func(...args), delay);
  };
}

/**
 * Throttles function calls to limit API request frequency
 * 
 * @param func - Function to throttle
 * @param limit - Time limit in milliseconds
 * @returns Throttled function
 */
export function throttle<T extends (...args: Parameters<T>) => ReturnType<T>>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle: boolean;
  
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

// =============================================================================
// URL and Path Utilities
// =============================================================================

/**
 * Safely joins URL path segments
 * 
 * @param segments - Path segments to join
 * @returns Joined path
 */
export function joinPaths(...segments: string[]): string {
  return segments
    .map(segment => segment.replace(/^\/+|\/+$/g, ''))
    .filter(segment => segment.length > 0)
    .join('/');
}

/**
 * Resolves relative URL against base URL
 * 
 * @param baseUrl - Base URL
 * @param relativePath - Relative path
 * @returns Resolved absolute URL
 */
export function resolveUrl(baseUrl: string, relativePath: string): string {
  try {
    return new URL(relativePath, baseUrl).href;
  } catch {
    // Fallback for invalid URLs
    return `${baseUrl.replace(/\/$/, '')}/${relativePath.replace(/^\//, '')}`;
  }
}

/**
 * Checks if a URL is absolute
 * 
 * @param url - URL to check
 * @returns True if URL is absolute
 */
export function isAbsoluteUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}