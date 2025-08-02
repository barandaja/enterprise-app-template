/**
 * @fileoverview Core API Client
 * 
 * Comprehensive Axios-based API client with:
 * - Type-safe request/response handling
 * - Automatic authentication with token refresh
 * - Request retry logic with exponential backoff
 * - Request deduplication and cancellation
 * - Error handling with custom error types
 * - Request/response logging for development
 * - Upload/download progress tracking
 */

import axios, { 
  type AxiosInstance, 
  type AxiosRequestConfig, 
  type AxiosResponse,
  type AxiosError,
  type InternalAxiosRequestConfig
} from 'axios';
import type {
  ApiResponse,
  ApiSuccessResponse,
  ApiErrorResponse,
  ApiError,
  ApiErrorCode,
  ApiRequestConfig,
  ApiClientConfig,
  ApiMethods,
  RetryConfig,
  RequestController,
  CancellationRegistry,
  DEFAULT_API_CONFIG,
  DEFAULT_RETRY_CONFIG
} from './types';
import { useAuthStore } from '../../stores/authStore';
import { addCSRFToken } from '../../security/csrf';
import { tokenManager } from '../auth/tokenManager';
import { createRateLimitInterceptor, RateLimitError } from '../../security/rateLimiter';

/**
 * Request deduplication manager
 */
class RequestDeduplicator {
  private readonly pendingRequests = new Map<string, Promise<AxiosResponse>>();

  /**
   * Generate cache key for request deduplication
   */
  private generateKey(config: InternalAxiosRequestConfig): string {
    const { method, url, data, params } = config;
    return `${method?.toUpperCase()}-${url}-${JSON.stringify(data)}-${JSON.stringify(params)}`;
  }

  /**
   * Get or create deduplicated request
   */
  deduplicate<T>(
    config: InternalAxiosRequestConfig,
    executor: () => Promise<AxiosResponse<T>>
  ): Promise<AxiosResponse<T>> {
    const key = this.generateKey(config);
    
    if (this.pendingRequests.has(key)) {
      return this.pendingRequests.get(key) as Promise<AxiosResponse<T>>;
    }

    const promise = executor().finally(() => {
      this.pendingRequests.delete(key);
    });

    this.pendingRequests.set(key, promise);
    return promise;
  }

  /**
   * Clear all pending requests
   */
  clear(): void {
    this.pendingRequests.clear();
  }
}

/**
 * Request cancellation manager
 */
class RequestCancellationManager implements CancellationRegistry {
  private readonly controllers = new Map<string, AbortController>();

  register(key: string, controller: RequestController): void {
    // Cancel existing request with same key
    this.cancel(key, 'Replaced by new request');
    
    const abortController = new AbortController();
    this.controllers.set(key, abortController);
    
    // Cleanup when signal is aborted
    abortController.signal.addEventListener('abort', () => {
      this.cleanup(key);
    });
  }

  cancel(key: string, reason = 'Request cancelled'): boolean {
    const controller = this.controllers.get(key);
    if (controller) {
      controller.abort(reason);
      return true;
    }
    return false;
  }

  cancelAll(reason = 'All requests cancelled'): void {
    for (const [key, controller] of this.controllers) {
      controller.abort(reason);
    }
    this.controllers.clear();
  }

  cleanup(key: string): void {
    this.controllers.delete(key);
  }

  createController(key?: string): RequestController {
    const abortController = new AbortController();
    
    if (key) {
      this.register(key, {
        cancel: (reason) => abortController.abort(reason),
        isCancelled: abortController.signal.aborted,
        signal: abortController.signal,
      });
    }

    return {
      cancel: (reason) => abortController.abort(reason),
      isCancelled: abortController.signal.aborted,
      signal: abortController.signal,
    };
  }
}

/**
 * Retry logic manager
 */
class RetryManager {
  /**
   * Calculate delay for retry attempt
   */
  private calculateDelay(attempt: number, config: RetryConfig): number {
    const { delay, backoff, maxDelay } = config;
    
    if (backoff === 'exponential') {
      const exponentialDelay = delay * Math.pow(2, attempt - 1);
      return Math.min(exponentialDelay, maxDelay);
    }
    
    return Math.min(delay * attempt, maxDelay);
  }

  /**
   * Execute request with retry logic
   */
  async executeWithRetry<T>(
    requestFn: () => Promise<AxiosResponse<T>>,
    config: RetryConfig
  ): Promise<AxiosResponse<T>> {
    let lastError: ApiError;
    
    for (let attempt = 1; attempt <= config.attempts; attempt++) {
      try {
        return await requestFn();
      } catch (error) {
        const apiError = this.transformError(error);
        lastError = apiError;
        
        // Don't retry if condition is not met or it's the last attempt
        if (!config.retryCondition?.(apiError) || attempt === config.attempts) {
          break;
        }
        
        // Execute retry callback
        config.onRetry?.(attempt, apiError);
        
        // Wait before retry
        const delay = this.calculateDelay(attempt, config);
        await this.sleep(delay);
      }
    }
    
    throw lastError;
  }

  /**
   * Transform error to ApiError
   */
  private transformError(error: unknown): ApiError {
    if (error instanceof ApiError) {
      return error;
    }
    
    if (axios.isAxiosError(error)) {
      return this.createApiErrorFromAxios(error);
    }
    
    return new ApiError(
      error instanceof Error ? error.message : 'Unknown error',
      ApiErrorCode.INTERNAL_ERROR
    );
  }

  /**
   * Create ApiError from Axios error
   */
  private createApiErrorFromAxios(error: AxiosError): ApiError {
    const response = error.response;
    
    if (response?.data && typeof response.data === 'object') {
      const errorData = response.data as ApiErrorResponse;
      return ApiError.fromResponse(response as AxiosResponse<ApiErrorResponse>);
    }
    
    // Map common HTTP status codes to API error codes
    const statusCodeMap: Record<number, ApiErrorCode> = {
      400: ApiErrorCode.VALIDATION_ERROR,
      401: ApiErrorCode.UNAUTHORIZED,
      403: ApiErrorCode.FORBIDDEN,
      404: ApiErrorCode.NOT_FOUND,
      409: ApiErrorCode.CONFLICT,
      429: ApiErrorCode.RATE_LIMITED,
      500: ApiErrorCode.INTERNAL_ERROR,
      502: ApiErrorCode.SERVICE_UNAVAILABLE,
      503: ApiErrorCode.SERVICE_UNAVAILABLE,
      504: ApiErrorCode.TIMEOUT,
    };
    
    const code = response 
      ? statusCodeMap[response.status] || ApiErrorCode.INTERNAL_ERROR
      : ApiErrorCode.NETWORK_ERROR;
    
    return new ApiError(
      error.message,
      code,
      response?.status || 0,
      undefined,
      undefined,
      response
    );
  }

  /**
   * Sleep utility for retry delays
   */
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Request/Response logger for development
 */
class ApiLogger {
  private readonly isEnabled: boolean;

  constructor(enabled: boolean) {
    this.isEnabled = enabled;
  }

  logRequest(config: InternalAxiosRequestConfig): void {
    if (!this.isEnabled) return;

    console.group(`🚀 API Request: ${config.method?.toUpperCase()} ${config.url}`);
    console.log('Config:', {
      headers: config.headers,
      params: config.params,
      data: config.data,
      timeout: config.timeout,
    });
    console.groupEnd();
  }

  logResponse(response: AxiosResponse): void {
    if (!this.isEnabled) return;

    const { status, statusText, data, config } = response;
    console.group(`✅ API Response: ${config.method?.toUpperCase()} ${config.url} - ${status}`);
    console.log('Status:', status, statusText);
    console.log('Data:', data);
    console.log('Headers:', response.headers);
    console.groupEnd();
  }

  logError(error: AxiosError): void {
    if (!this.isEnabled) return;

    const { response, config, message } = error;
    console.group(`❌ API Error: ${config?.method?.toUpperCase()} ${config?.url}`);
    console.error('Message:', message);
    console.error('Status:', response?.status, response?.statusText);
    console.error('Data:', response?.data);
    console.error('Config:', config);
    console.groupEnd();
  }
}

/**
 * Core API client class
 */
export class ApiClient implements ApiMethods {
  private readonly axiosInstance: AxiosInstance;
  private readonly deduplicator: RequestDeduplicator;
  private readonly cancellation: RequestCancellationManager;
  private readonly retryManager: RetryManager;
  private readonly logger: ApiLogger;
  private readonly config: ApiClientConfig;

  constructor(config: Partial<ApiClientConfig> = {}) {
    this.config = { ...DEFAULT_API_CONFIG, ...config };
    this.deduplicator = new RequestDeduplicator();
    this.cancellation = new RequestCancellationManager();
    this.retryManager = new RetryManager();
    this.logger = new ApiLogger(this.config.enableLogging);

    this.axiosInstance = axios.create({
      baseURL: this.config.baseURL,
      timeout: this.config.timeout,
      headers: this.config.headers,
      withCredentials: this.config.withCredentials,
      validateStatus: this.config.validateStatus,
      maxContentLength: this.config.maxContentLength,
      maxBodyLength: this.config.maxBodyLength,
    });

    this.setupInterceptors();
  }

  /**
   * Setup request and response interceptors
   */
  private setupInterceptors(): void {
    // Rate limiting interceptor
    const rateLimitInterceptor = createRateLimitInterceptor();
    this.axiosInstance.interceptors.request.use(
      (config) => rateLimitInterceptor.request(config).then(() => config),
      (error) => Promise.reject(error)
    );

    // Request interceptor
    this.axiosInstance.interceptors.request.use(
      (config) => this.handleRequest(config),
      (error) => this.handleRequestError(error)
    );

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => {
        // Handle rate limit headers
        rateLimitInterceptor.response(response);
        return this.handleResponse(response);
      },
      (error) => {
        // Handle rate limit errors
        if (error instanceof RateLimitError || error.response?.status === 429) {
          return rateLimitInterceptor.responseError(error);
        }
        return this.handleResponseError(error);
      }
    );
  }

  /**
   * Handle outgoing requests
   */
  private async handleRequest(config: InternalAxiosRequestConfig): Promise<InternalAxiosRequestConfig> {
    // Add authentication header if not skipped
    if (!config.skipAuth) {
      try {
        // Get valid token from TokenManager (handles refresh if needed)
        const token = await tokenManager.getValidToken();
        config.headers.Authorization = `Bearer ${token}`;
      } catch (error) {
        // No valid token available, proceed without auth header
        this.logger.logError(error);
      }
    }

    // Add CSRF token for state-changing requests
    config.headers = addCSRFToken(
      config.headers as Record<string, string>,
      config.url || '',
      config.method || 'GET'
    ) as any;
    
    // Add request ID for tracking
    const requestId = crypto.randomUUID();
    config.headers['X-Request-ID'] = requestId;

    // Add abort signal if not present
    if (!config.signal && config.cancelKey) {
      const controller = this.cancellation.createController(config.cancelKey);
      config.signal = controller.signal;
    }

    // Log request
    this.logger.logRequest(config);

    return config;
  }

  /**
   * Handle request errors
   */
  private handleRequestError(error: AxiosError): Promise<never> {
    this.logger.logError(error);
    return Promise.reject(error);
  }

  /**
   * Handle successful responses
   */
  private handleResponse(response: AxiosResponse): AxiosResponse {
    this.logger.logResponse(response);
    return response;
  }

  /**
   * Handle response errors
   */
  private async handleResponseError(error: AxiosError): Promise<never> {
    this.logger.logError(error);

    const config = error.config as InternalAxiosRequestConfig & ApiRequestConfig;
    
    // Handle token refresh for 401 errors
    if (error.response?.status === 401 && !config.skipRefresh) {
      try {
        // Use TokenManager for thread-safe token refresh
        await tokenManager.forceRefresh();
        
        // Get the new token and update the request
        const newToken = await tokenManager.getValidToken();
        config.headers.Authorization = `Bearer ${newToken}`;
        
        // Retry the original request
        return this.axiosInstance(config);
      } catch (refreshError) {
        // Refresh failed, logout user
        await useAuthStore.getState().logout();
        return Promise.reject(this.createApiError(error));
      }
    }

    return Promise.reject(this.createApiError(error));
  }

  /**
   * Refresh authentication token
   * @deprecated Use tokenManager.forceRefresh() instead
   */
  private async refreshToken(): Promise<void> {
    // Delegate to TokenManager
    await tokenManager.forceRefresh();
  }

  /**
   * Create ApiError from AxiosError
   */
  private createApiError(error: AxiosError): ApiError {
    const response = error.response;
    
    if (response?.data && typeof response.data === 'object') {
      const errorData = response.data as ApiErrorResponse;
      return ApiError.fromResponse(response as AxiosResponse<ApiErrorResponse>);
    }

    return new ApiError(
      error.message,
      ApiErrorCode.NETWORK_ERROR,
      response?.status || 0,
      undefined,
      undefined,
      response
    );
  }

  /**
   * Execute request with retry logic and deduplication
   */
  private async executeRequest<T>(
    config: InternalAxiosRequestConfig & ApiRequestConfig
  ): Promise<ApiResponse<T>> {
    const retryConfig = { ...DEFAULT_RETRY_CONFIG, ...config.retryConfig };
    
    const requestFn = async (): Promise<AxiosResponse<T>> => {
      if (config.deduplication !== false) {
        return this.deduplicator.deduplicate(config, () => this.axiosInstance(config));
      }
      return this.axiosInstance(config);
    };

    try {
      const response = await this.retryManager.executeWithRetry(requestFn, retryConfig);
      
      // Transform response to ApiResponse format
      return {
        success: true,
        data: response.data,
        meta: {
          timestamp: new Date().toISOString(),
          requestId: response.config.headers?.['X-Request-ID'] as string || crypto.randomUUID(),
        },
      } as ApiSuccessResponse<T>;
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw this.createApiError(error as AxiosError);
    }
  }

  // =============================================================================
  // Public API Methods
  // =============================================================================

  /**
   * GET request
   */
  async get<TResponse = unknown>(
    url: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'GET',
      url,
    });
  }

  /**
   * POST request
   */
  async post<TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'POST',
      url,
      data,
    });
  }

  /**
   * PUT request
   */
  async put<TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'PUT',
      url,
      data,
    });
  }

  /**
   * PATCH request
   */
  async patch<TRequest = unknown, TResponse = unknown>(
    url: string,
    data?: TRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'PATCH',
      url,
      data,
    });
  }

  /**
   * DELETE request
   */
  async delete<TResponse = unknown>(
    url: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'DELETE',
      url,
    });
  }

  /**
   * Upload file with progress tracking
   */
  async upload<TResponse = unknown>(
    url: string,
    formData: FormData,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TResponse>> {
    return this.executeRequest<TResponse>({
      ...config,
      method: 'POST',
      url,
      data: formData,
      headers: {
        ...config.headers,
        'Content-Type': 'multipart/form-data',
      },
    });
  }

  /**
   * Get request cancellation controller
   */
  getCancellationController(key?: string): RequestController {
    return this.cancellation.createController(key);
  }

  /**
   * Cancel request by key
   */
  cancelRequest(key: string, reason?: string): boolean {
    return this.cancellation.cancel(key, reason);
  }

  /**
   * Cancel all pending requests
   */
  cancelAllRequests(reason?: string): void {
    this.cancellation.cancelAll(reason);
    this.deduplicator.clear();
  }

  /**
   * Update API configuration
   */
  updateConfig(config: Partial<ApiClientConfig>): void {
    Object.assign(this.config, config);
    
    // Update axios instance defaults
    this.axiosInstance.defaults.baseURL = this.config.baseURL;
    this.axiosInstance.defaults.timeout = this.config.timeout;
    Object.assign(this.axiosInstance.defaults.headers, this.config.headers);
  }

  /**
   * Get current configuration
   */
  getConfig(): Readonly<ApiClientConfig> {
    return { ...this.config };
  }
}

// Create and export singleton API client instance
export const apiClient = new ApiClient();

// Export types and utilities
export { ApiError, ApiErrorCode } from './types';
export type { 
  ApiResponse, 
  ApiSuccessResponse, 
  ApiErrorResponse, 
  ApiRequestConfig,
  RequestController,
  CancellationRegistry 
} from './types';