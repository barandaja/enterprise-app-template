/**
 * Environment configuration with validation
 * Ensures all required environment variables are present and valid
 */

// Define required environment variables
const requiredEnvVars = [
  'VITE_API_URL',
  // Add other critical variables as needed
] as const;

// Define optional but recommended variables
const recommendedEnvVars = [
  'VITE_SESSION_TIMEOUT',
  'VITE_MAX_FILE_SIZE',
  'VITE_RATE_LIMIT_REQUESTS'
] as const;

// Validate URL format
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    // In production, enforce HTTPS (except for localhost)
    if (import.meta.env.PROD && parsed.protocol === 'http:' && parsed.hostname !== 'localhost') {
      console.error(`Invalid API URL: ${url}. HTTPS is required in production.`);
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// Environment configuration with defaults
export const config = {
  // API configuration
  apiUrl: import.meta.env.VITE_API_URL || (
    import.meta.env.DEV 
      ? 'http://localhost:8000/api/v1'  // Development default
      : 'https://api.example.com/api/v1' // Production default (should be overridden)
  ),
  
  // Feature flags
  enableAnalytics: import.meta.env.VITE_ENABLE_ANALYTICS === 'true',
  enableDebugMode: import.meta.env.VITE_DEBUG_MODE === 'true',
  
  // Security
  cspReportUri: import.meta.env.VITE_CSP_REPORT_URI || '/api/csp-report',
  
  // Authentication
  sessionTimeout: parseInt(import.meta.env.VITE_SESSION_TIMEOUT || '1800000', 10),
  tokenRefreshBuffer: parseInt(import.meta.env.VITE_TOKEN_REFRESH_BUFFER || '300000', 10),
  
  // File Upload
  maxFileSize: parseInt(import.meta.env.VITE_MAX_FILE_SIZE || '10485760', 10),
  allowedFileTypes: (import.meta.env.VITE_ALLOWED_FILE_TYPES || 'image/jpeg,image/png,image/gif,application/pdf').split(','),
  
  // Rate Limiting
  rateLimitRequests: parseInt(import.meta.env.VITE_RATE_LIMIT_REQUESTS || '100', 10),
  rateLimitWindow: parseInt(import.meta.env.VITE_RATE_LIMIT_WINDOW || '900000', 10),
  
  // Environment
  isDevelopment: import.meta.env.DEV,
  isProduction: import.meta.env.PROD,
  mode: import.meta.env.MODE,
} as const;

// Validate environment configuration
export function validateEnvironment(): void {
  const errors: string[] = [];

  // Check required variables
  requiredEnvVars.forEach(varName => {
    if (!import.meta.env[varName]) {
      // Only error in production, warn in development
      if (import.meta.env.PROD) {
        errors.push(`Missing required environment variable: ${varName}`);
      } else {
        console.warn(`Missing environment variable: ${varName}, using default value`);
      }
    }
  });

  // Validate API URL
  if (!isValidUrl(config.apiUrl)) {
    errors.push(`Invalid API URL format: ${config.apiUrl}`);
  }

  // In production, ensure HTTPS is used
  if (import.meta.env.PROD && config.apiUrl.startsWith('http://') && !config.apiUrl.includes('localhost')) {
    errors.push('API URL must use HTTPS in production');
  }

  // Warn about placeholder URL in production
  if (import.meta.env.PROD && config.apiUrl.includes('example.com')) {
    errors.push('Production API URL must be configured (currently using placeholder)');
  }

  // Check recommended variables
  recommendedEnvVars.forEach(varName => {
    if (!import.meta.env[varName] && import.meta.env.DEV) {
      console.warn(`Recommended environment variable ${varName} is not set, using default value`);
    }
  });

  // Throw if any errors in production
  if (errors.length > 0 && import.meta.env.PROD) {
    throw new Error(`Environment validation failed:\n${errors.join('\n')}`);
  }

  // Log warnings in development
  if (errors.length > 0 && import.meta.env.DEV) {
    console.warn('Environment validation warnings:', errors);
  }
}

// Type-safe environment variable getter
export function getEnvVar<T extends keyof typeof config>(key: T): typeof config[T] {
  return config[key];
}

// Export typed environment object
export type EnvironmentConfig = typeof config;