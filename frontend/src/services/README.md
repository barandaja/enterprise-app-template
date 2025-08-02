# API Service Layer Documentation

This document provides comprehensive information about the type-safe API service layer built for the React frontend application.

## 📁 Structure Overview

```
src/services/
├── api/
│   ├── types.ts          # Core API type definitions
│   ├── client.ts         # Axios-based API client
│   ├── auth.service.ts   # Authentication endpoints
│   ├── user.service.ts   # User management endpoints
│   └── index.ts          # Main API exports
└── utils/
    └── api-helpers.ts    # Utility functions
```

## 🚀 Quick Start

### Basic Usage

```typescript
import { api } from '../services/api';

// Login user
const loginResponse = await api.login({
  email: 'user@example.com',
  password: 'securePassword123!'
});

// Get current user
const userResponse = await api.getCurrentUser();

// Update profile
const updateResponse = await api.updateUserProfile({
  firstName: 'John',
  lastName: 'Doe'
});
```

### Direct Service Usage

```typescript
import { authService, userService } from '../services/api';

// Authentication
await authService.login(credentials);
await authService.register(userData);
await authService.logout();

// User management
await userService.getProfile();
await userService.updateProfile(data);
await userService.uploadAvatar(file);
```

## 🔧 Core Features

### Type Safety
- **Zero `any` types** - Complete type safety throughout
- **Discriminated unions** for success/error responses
- **Generic response wrappers** with proper typing
- **Zod validation** for request/response schemas

### Authentication Integration
- **Automatic token management** with refresh logic
- **Seamless Zustand integration** with authStore
- **JWT token parsing** and expiration handling
- **Multi-session support** with session management

### Error Handling
- **Custom error classes** with detailed information
- **User-friendly error messages** with fallbacks
- **Field-level validation errors** for forms
- **Automatic retry logic** with exponential backoff

### Request Management
- **Request deduplication** to prevent duplicate calls
- **Request cancellation** with AbortController
- **Progress tracking** for file uploads
- **Automatic retries** with configurable policies

### File Upload Support
- **Multipart form data** handling
- **Upload progress tracking** with callbacks
- **File validation** (size, type, dimensions)
- **Thumbnail generation** support

## 📘 API Client Configuration

### Default Configuration

```typescript
const DEFAULT_API_CONFIG: ApiClientConfig = {
  baseURL: 'http://localhost:3000/api/v1',
  timeout: 30000,
  retryConfig: {
    attempts: 3,
    delay: 1000,
    backoff: 'exponential',
    maxDelay: 10000,
  },
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  },
  withCredentials: true,
  enableLogging: import.meta.env.DEV,
  enableCaching: false,
  cacheTTL: 5 * 60 * 1000, // 5 minutes
};
```

### Custom Configuration

```typescript
import { ApiService } from '../services/api';

const customApi = new ApiService({
  baseURL: 'https://api.myapp.com/v2',
  timeout: 60000,
  retryConfig: {
    attempts: 5,
    delay: 2000,
    backoff: 'linear',
  },
  enableLogging: true,
});
```

## 🔐 Authentication Service

### Available Methods

```typescript
// Core authentication
await authService.login(credentials);
await authService.register(userData);
await authService.logout();
await authService.refreshToken(refreshToken);

// Password management
await authService.requestPasswordReset({ email });
await authService.confirmPasswordReset({ token, password, confirmPassword });
await authService.changePassword({ currentPassword, newPassword, confirmPassword });

// Email verification
await authService.requestEmailVerification({ email });
await authService.confirmEmailVerification({ token });

// Two-factor authentication
await authService.setupTwoFactor({ method: 'totp' });
await authService.verifyTwoFactor({ token, code, method });
await authService.disableTwoFactor(password);

// Social authentication
await authService.socialLogin({ provider: 'google', accessToken });
await authService.getSocialLoginUrl('github', redirectUrl);

// Session management
await authService.getSession();
await authService.validateToken();
await authService.getActiveSessions();
await authService.revokeSession(sessionId);
await authService.revokeAllSessions();
```

### Usage Examples

```typescript
// Login with error handling
try {
  const response = await authService.login({
    email: 'user@example.com',
    password: 'password123'
  });
  
  if (response.success) {
    console.log('User:', response.data.user);
    console.log('Access Token:', response.data.tokens.accessToken);
  }
} catch (error) {
  const errorInfo = extractErrorMessage(error);
  console.error('Login failed:', errorInfo.message);
  
  // Handle field-specific errors
  if (errorInfo.fieldErrors.email) {
    console.error('Email error:', errorInfo.fieldErrors.email);
  }
}

// Password reset flow
await authService.requestPasswordReset({
  email: 'user@example.com',
  redirectUrl: 'https://app.example.com/reset-password'
});

// Later, with token from email
await authService.confirmPasswordReset({
  token: 'reset_token_from_email',
  password: 'newSecurePassword123!',
  confirmPassword: 'newSecurePassword123!'
});
```

## 👤 User Service

### Available Methods

```typescript
// Profile management
await userService.getProfile();
await userService.updateProfile(data);
await userService.uploadAvatar(file);
await userService.removeAvatar();

// Preferences and settings
await userService.getPreferences();
await userService.updatePreferences(preferences);
await userService.resetPreferences();

// Security and activity
await userService.getSecurityStatus();
await userService.getActivityHistory();
await userService.getStats();

// Phone number management
await userService.updatePhoneNumber(phoneNumber);
await userService.verifyPhoneNumber(code);
await userService.removePhoneNumber();

// Email management
await userService.updateEmail(email, password);
await userService.verifyEmail(token);

// Data export
await userService.requestDataExport(request);
await userService.getDataExportStatus(exportId);
await userService.downloadDataExport(exportId);

// Account deletion
await userService.deleteAccount({ password, confirmation: 'DELETE', reason });
await userService.cancelAccountDeletion();

// Public profiles
await userService.searchUsers(query, params);
await userService.getPublicProfile(userId);
```

### Usage Examples

```typescript
// Upload avatar with progress tracking
const fileInput = document.getElementById('avatar') as HTMLInputElement;
const file = fileInput.files?.[0];

if (file) {
  try {
    const response = await userService.uploadAvatar(file, {
      onUploadProgress: (progress) => {
        console.log(`Upload progress: ${progress.progress}%`);
        updateProgressBar(progress.progress);
      }
    });
    
    if (response.success) {
      console.log('Avatar uploaded:', response.data.url);
    }
  } catch (error) {
    console.error('Upload failed:', createUserFriendlyError(error));
  }
}

// Update user preferences
await userService.updatePreferences({
  theme: 'dark',
  notifications: {
    email: true,
    push: false,
    sms: false,
    marketing: false
  },
  privacy: {
    profileVisible: true,
    showEmail: false,
    allowMessaging: true
  }
});

// Request data export
const exportRequest = await userService.requestDataExport({
  format: 'json',
  includePersonalData: true,
  includeActivityLogs: true,
  includePreferences: true,
  dateRange: {
    start: '2023-01-01T00:00:00Z',
    end: '2024-01-01T00:00:00Z'
  }
});

// Check export status periodically
const checkExportStatus = async (exportId: string) => {
  const status = await userService.getDataExportStatus(exportId);
  
  if (status.success && status.data.status === 'completed') {
    const blob = await userService.downloadDataExport(exportId);
    downloadFile(blob, 'user-data.json');
  }
};
```

## 🛠 Utility Functions

### Query Building

```typescript
import { buildQueryParams, buildValidatedQueryParams } from '../services/utils/api-helpers';

// Basic query building
const params = buildQueryParams({
  page: 1,
  limit: 20,
  search: 'typescript',
  filters: { category: 'tech', active: true }
});

// Validated query building
const schema = z.object({
  page: z.number().min(1),
  limit: z.number().min(1).max(100),
  search: z.string().optional()
});

const validatedParams = buildValidatedQueryParams({
  page: 2,
  limit: 50,
  search: 'react'
}, schema);
```

### Response Validation

```typescript
import { validateApiResponse, createResponseValidator } from '../services/utils/api-helpers';

// One-time validation
const userSchema = z.object({
  id: z.string(),
  name: z.string(),
  email: z.string().email()
});

const response = await apiClient.get('/users/123');
const validatedResponse = validateApiResponse(response, userSchema);

// Reusable validator
const validateUser = createResponseValidator(userSchema);
const validatedResponse2 = validateUser(response);
```

### Error Handling

```typescript
import { extractErrorMessage, createUserFriendlyError } from '../services/utils/api-helpers';

try {
  await apiClient.post('/users', userData);
} catch (error) {
  // Extract detailed error information
  const errorInfo = extractErrorMessage(error);
  console.log('Error message:', errorInfo.message);
  console.log('Error code:', errorInfo.code);
  console.log('Status code:', errorInfo.statusCode);
  console.log('Field errors:', errorInfo.fieldErrors);
  
  // Create user-friendly message
  const friendlyMessage = createUserFriendlyError(error);
  showToast(friendlyMessage);
}
```

### File Handling

```typescript
import { validateFile, createMultipartFormData, formatFileSize } from '../services/utils/api-helpers';

// File validation
const validationResult = await validateFile(file, {
  maxSize: 5 * 1024 * 1024, // 5MB
  allowedTypes: ['image/jpeg', 'image/png'],
  requireImageDimensions: {
    minWidth: 100,
    minHeight: 100,
    maxWidth: 2000,
    maxHeight: 2000
  }
});

if (!validationResult.valid) {
  console.error('Validation errors:', validationResult.errors);
  return;
}

// Create form data for upload
const formData = createMultipartFormData({
  files: [{ file, field: 'avatar' }],
  fields: { userId: '123', category: 'profile' }
});

// Format file size for display
const sizeText = formatFileSize(file.size); // "2.5 MB"
```

## 🔄 Request Management

### Request Cancellation

```typescript
import { api } from '../services/api';

// Cancel specific request
api.cancelRequest('user.profile');

// Cancel all requests
api.cancelAllRequests('Component unmounted');

// Get cancellation controller
const controller = api.client.getCancellationController('my-request');
controller.cancel('User cancelled');
```

### Request Deduplication

```typescript
// Automatic deduplication (default behavior)
const response1 = api.getCurrentUser(); // Makes HTTP request
const response2 = api.getCurrentUser(); // Returns same promise (deduplicated)

// Disable deduplication for specific request
const response = await api.client.get('/users/profile', {
  deduplication: false
});
```

### Retry Configuration

```typescript
// Custom retry for specific request
const response = await api.client.get('/users', {
  retryConfig: {
    attempts: 5,
    delay: 2000,
    backoff: 'exponential',
    maxDelay: 30000,
    retryCondition: (error) => error.statusCode >= 500,
    onRetry: (attempt, error) => {
      console.log(`Retry attempt ${attempt} after error:`, error.message);
    }
  }
});
```

## 📊 Pagination Support

### Basic Pagination

```typescript
import { extractPaginationParams, generatePaginationUrls } from '../services/utils/api-helpers';

// Extract pagination from URL
const queryParams = new URLSearchParams(window.location.search);
const { page, limit, offset } = extractPaginationParams(Object.fromEntries(queryParams));

// Generate navigation URLs
const paginationUrls = generatePaginationUrls(
  '/api/users',
  { page: 2, limit: 20, total: 100, totalPages: 5, hasNext: true, hasPrev: true },
  { search: 'john', category: 'admin' }
);

console.log('First page:', paginationUrls.first);
console.log('Previous page:', paginationUrls.prev);
console.log('Next page:', paginationUrls.next);
console.log('Last page:', paginationUrls.last);
```

## 🔒 Security Features

### Token Management

- **Automatic token refresh** before expiration
- **Refresh token rotation** for enhanced security
- **Token validation** and expiration checking
- **Secure token storage** with Zustand persistence

### Request Security

- **CSRF protection** with proper headers
- **Request signing** for sensitive operations
- **Rate limiting** awareness and handling
- **Secure cookie handling** for authentication

### Data Protection

- **Request/response encryption** support
- **Sensitive data masking** in logs
- **PII handling** with proper validation
- **Data export/import** with security controls

## 🐛 Debugging and Logging

### Development Logging

```typescript
// Automatic logging in development
const api = new ApiService({
  enableLogging: true // Shows detailed request/response logs
});
```

### Custom Error Tracking

```typescript
import { ApiError } from '../services/api';

try {
  await api.getCurrentUser();
} catch (error) {
  if (error instanceof ApiError) {
    // Log to external service
    analytics.track('API Error', {
      code: error.code,
      statusCode: error.statusCode,
      endpoint: error.response?.config?.url,
      message: error.message
    });
  }
}
```

## 🧪 Testing Support

### Mock API Responses

```typescript
// Create test API instance
const testApi = new ApiService({
  baseURL: 'http://localhost:3001/api/test'
});

// Mock responses for testing
jest.mock('../services/api', () => ({
  api: {
    login: jest.fn().mockResolvedValue({
      success: true,
      data: { user: mockUser, tokens: mockTokens }
    }),
    getCurrentUser: jest.fn().mockResolvedValue({
      success: true,
      data: mockUser
    })
  }
}));
```

### Integration Testing

```typescript
import { render, screen, waitFor } from '@testing-library/react';
import { api } from '../services/api';

test('should handle API errors gracefully', async () => {
  // Mock API error
  jest.spyOn(api, 'login').mockRejectedValue(
    new ApiError('Invalid credentials', 'UNAUTHORIZED', 401)
  );

  render(<LoginForm />);
  
  // Trigger login
  fireEvent.click(screen.getByRole('button', { name: /login/i }));
  
  // Check error handling
  await waitFor(() => {
    expect(screen.getByText(/invalid credentials/i)).toBeInTheDocument();
  });
});
```

## 📈 Performance Optimization

### Request Optimization

- **Request deduplication** prevents duplicate API calls
- **Response caching** for frequently accessed data
- **Compression support** with gzip/brotli
- **Connection pooling** for better performance

### Bundle Optimization

- **Tree shaking** support for unused code elimination
- **Lazy loading** of service modules
- **Code splitting** at service boundaries
- **Type-only imports** to reduce bundle size

### Memory Management

- **Automatic cleanup** of cancelled requests
- **Weak references** for cached responses
- **Memory leak prevention** in long-running apps
- **Garbage collection** friendly patterns

## 🤝 Integration Examples

### React Hook Integration

```typescript
import { useQuery } from '@tanstack/react-query';
import { api } from '../services/api';

export const useCurrentUser = () => {
  return useQuery({
    queryKey: ['user', 'current'],
    queryFn: async () => {
      const response = await api.getCurrentUser();
      if (!response.success) {
        throw new Error(response.message);
      }
      return response.data;
    },
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
};
```

### Form Integration

```typescript
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { loginCredentialsSchema } from '../services/api/auth.service';

const LoginForm = () => {
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting }
  } = useForm({
    resolver: zodResolver(loginCredentialsSchema)
  });

  const onSubmit = async (data) => {
    try {
      await api.login(data);
      // Handle success
    } catch (error) {
      // Handle error with user-friendly message
      const message = createUserFriendlyError(error);
      toast.error(message);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)}>
      {/* Form fields */}
    </form>
  );
};
```

## 📚 Additional Resources

- **TypeScript Documentation**: For advanced type usage
- **Axios Documentation**: For HTTP client configuration
- **Zod Documentation**: For schema validation
- **Zustand Documentation**: For state management integration

## 🆘 Troubleshooting

### Common Issues

1. **Token Refresh Loops**
   - Check token expiration logic
   - Verify refresh endpoint configuration
   - Ensure proper error handling

2. **Request Cancellation**
   - Use unique cancel keys
   - Clean up controllers on unmount
   - Handle cancellation in error boundaries

3. **Type Errors**
   - Update schemas when API changes
   - Use proper generic constraints
   - Validate response structures

4. **Network Errors**
   - Check base URL configuration
   - Verify CORS settings
   - Test retry logic behavior

### Debug Checklist

- [ ] API base URL is correct
- [ ] Authentication tokens are valid
- [ ] Request/response schemas match API
- [ ] Error handling is implemented
- [ ] Network connectivity is stable
- [ ] CORS headers are configured
- [ ] Rate limiting is respected

---

This API service layer provides a robust, type-safe foundation for all API communications in your React application. The comprehensive error handling, authentication integration, and utility functions ensure reliable and maintainable code.