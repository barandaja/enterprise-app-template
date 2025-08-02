/**
 * API Client Configuration
 * Centralized configuration for the API client with environment-based settings
 */

import { config } from '../../config/env';
import type { ApiClientConfig, RetryConfig } from './types';

/**
 * Default retry configuration
 */
export const DEFAULT_RETRY_CONFIG: RetryConfig = {
  retries: 3,
  retryDelay: 1000,
  retryCondition: (error) => {
    if (!error.response) return true; // Network errors
    const status = error.response.status;
    return status >= 500 || status === 429; // Server errors or rate limiting
  },
  shouldResetTimeout: true,
};

/**
 * Default API client configuration
 */
export const DEFAULT_API_CONFIG: ApiClientConfig = {
  // Use validated environment configuration
  baseURL: config.apiUrl,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  withCredentials: true, // Send cookies for CSRF
  validateStatus: (status) => status < 500,
  maxContentLength: 50 * 1024 * 1024, // 50MB
  maxBodyLength: 50 * 1024 * 1024, // 50MB
  retry: DEFAULT_RETRY_CONFIG,
  enableLogging: config.enableDebugMode,
  cache: {
    enabled: true,
    ttl: 5 * 60 * 1000, // 5 minutes
    maxSize: 100,
    excludePaths: ['/auth', '/user/profile'],
  },
  performance: {
    enabled: true,
    slowRequestThreshold: 3000,
    sampleRate: 1.0,
  },
};

/**
 * WebSocket configuration
 */
export const WS_CONFIG = {
  url: import.meta.env.VITE_WS_URL || (
    config.isDevelopment
      ? 'ws://localhost:8000/ws'
      : config.apiUrl.replace(/^http/, 'ws').replace('/api/v1', '/ws')
  ),
  reconnectInterval: 5000,
  maxReconnectAttempts: 10,
  heartbeatInterval: 30000,
};

/**
 * Get environment-specific API configuration
 */
export function getApiConfig(): ApiClientConfig {
  const baseConfig = { ...DEFAULT_API_CONFIG };

  // Apply environment-specific overrides
  if (config.isProduction) {
    // Production optimizations
    baseConfig.retry.retries = 2; // Fewer retries in production
    baseConfig.cache.ttl = 10 * 60 * 1000; // 10 minutes cache
  }

  if (import.meta.env.MODE === 'test') {
    // Test environment configuration
    baseConfig.baseURL = 'http://localhost:3001/api/v1';
    baseConfig.timeout = 5000; // Shorter timeout for tests
    baseConfig.enableLogging = false;
  }

  return baseConfig;
}