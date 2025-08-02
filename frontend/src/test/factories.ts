import { faker } from '@faker-js/faker'
import type { User, LoginCredentials, RegisterData } from '../types'

// Configure faker for consistent test data
faker.seed(123)

// User factory
export const userFactory = {
  build: (overrides: Partial<User> = {}): User => ({
    id: faker.string.uuid(),
    email: faker.internet.email(),
    name: faker.person.fullName(),
    role: 'user',
    isEmailVerified: true,
    createdAt: faker.date.past().toISOString(),
    updatedAt: faker.date.recent().toISOString(),
    ...overrides,
  }),

  buildAdmin: (overrides: Partial<User> = {}): User => 
    userFactory.build({ role: 'admin', ...overrides }),

  buildUnverified: (overrides: Partial<User> = {}): User => 
    userFactory.build({ isEmailVerified: false, ...overrides }),

  buildMany: (count: number, overrides: Partial<User> = {}): User[] => 
    Array.from({ length: count }, () => userFactory.build(overrides)),
}

// Authentication data factories
export const authFactory = {
  buildLoginCredentials: (overrides: Partial<LoginCredentials> = {}): LoginCredentials => ({
    email: faker.internet.email(),
    password: faker.internet.password({ length: 12 }),
    ...overrides,
  }),

  buildRegisterData: (overrides: Partial<RegisterData> = {}): RegisterData => ({
    name: faker.person.fullName(),
    email: faker.internet.email(),
    password: faker.internet.password({ 
      length: 12, 
      memorable: false,
      pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
    }),
    ...overrides,
  }),

  buildTokens: (overrides = {}) => ({
    accessToken: faker.string.alphanumeric(40),
    refreshToken: faker.string.alphanumeric(40),
    expiresIn: 3600,
    tokenType: 'Bearer' as const,
    ...overrides,
  }),

  buildValidCredentials: (): LoginCredentials => ({
    email: 'test@example.com',
    password: 'SecurePassword123!',
  }),

  buildInvalidCredentials: (): LoginCredentials => ({
    email: 'invalid@example.com',
    password: 'wrongpassword',
  }),
}

// Security event factory
export const securityEventFactory = {
  build: (overrides = {}) => ({
    id: faker.string.uuid(),
    type: faker.helpers.arrayElement([
      'LOGIN_SUCCESS',
      'LOGIN_FAILURE',
      'LOGOUT',
      'TOKEN_REFRESH_SUCCESS',
      'TOKEN_REFRESH_FAILURE',
      'UNAUTHORIZED_ACCESS',
      'SUSPICIOUS_ACTIVITY',
    ]),
    severity: faker.helpers.arrayElement(['INFO', 'WARNING', 'ERROR', 'CRITICAL']),
    message: faker.lorem.sentence(),
    timestamp: faker.date.recent().toISOString(),
    userId: faker.string.uuid(),
    sessionId: faker.string.uuid(),
    ipAddress: faker.internet.ip(),
    userAgent: faker.internet.userAgent(),
    details: {},
    ...overrides,
  }),

  buildLoginSuccess: (userId?: string) => 
    securityEventFactory.build({
      type: 'LOGIN_SUCCESS',
      severity: 'INFO',
      message: 'User logged in successfully',
      userId,
    }),

  buildLoginFailure: (details = {}) => 
    securityEventFactory.build({
      type: 'LOGIN_FAILURE',
      severity: 'WARNING',
      message: 'Login attempt failed',
      details,
    }),

  buildSuspiciousActivity: (details = {}) => 
    securityEventFactory.build({
      type: 'SUSPICIOUS_ACTIVITY',
      severity: 'CRITICAL',
      message: 'Suspicious activity detected',
      details,
    }),
}

// API response factory
export const apiResponseFactory = {
  buildSuccess: <T>(data: T, meta = {}) => ({
    success: true as const,
    data,
    message: 'Success',
    code: 200,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: faker.string.uuid(),
      ...meta,
    },
  }),

  buildError: (message = 'Error', code = 400, data = null) => ({
    success: false as const,
    data,
    message,
    code,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: faker.string.uuid(),
    },
  }),

  buildPaginated: <T>(items: T[], page = 1, limit = 10, total?: number) => ({
    success: true as const,
    data: items,
    meta: {
      pagination: {
        page,
        limit,
        total: total ?? items.length,
        pages: Math.ceil((total ?? items.length) / limit),
        hasNext: page * limit < (total ?? items.length),
        hasPrev: page > 1,
      },
      timestamp: new Date().toISOString(),
      requestId: faker.string.uuid(),
    },
  }),
}

// Form data factory
export const formFactory = {
  buildContactForm: (overrides = {}) => ({
    name: faker.person.fullName(),
    email: faker.internet.email(),
    subject: faker.lorem.words(5),
    message: faker.lorem.paragraphs(2),
    ...overrides,
  }),

  buildProfileForm: (overrides = {}) => ({
    name: faker.person.fullName(),
    email: faker.internet.email(),
    bio: faker.lorem.paragraph(),
    location: faker.location.city(),
    website: faker.internet.url(),
    ...overrides,
  }),

  buildPasswordChangeForm: (overrides = {}) => ({
    currentPassword: 'OldPassword123!',
    newPassword: faker.internet.password({ 
      length: 12, 
      memorable: false,
      pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/
    }),
    confirmPassword: '', // Will be set to newPassword by default
    ...overrides,
  }),
}

// File factory for upload testing
export const fileFactory = {
  buildImage: (name = 'test-image.jpg', size = 1024 * 100) => { // 100KB
    const content = new Uint8Array(size).fill(65) // Fill with 'A'
    return new File([content], name, { type: 'image/jpeg' })
  },

  buildPDF: (name = 'test-document.pdf', size = 1024 * 500) => { // 500KB
    const content = new Uint8Array(size).fill(80) // Fill with 'P'
    return new File([content], name, { type: 'application/pdf' })
  },

  buildLargeFile: (name = 'large-file.zip', size = 1024 * 1024 * 10) => { // 10MB
    const content = new Uint8Array(size).fill(90) // Fill with 'Z'
    return new File([content], name, { type: 'application/zip' })
  },

  buildMaliciousFile: (name = 'virus.exe') => {
    const content = new TextEncoder().encode('MZ\x90\x00') // PE header signature
    return new File([content], name, { type: 'application/octet-stream' })
  },

  buildInvalidImage: (name = 'not-an-image.jpg') => {
    const content = new TextEncoder().encode('This is not an image file')
    return new File([content], name, { type: 'image/jpeg' })
  },
}

// Notification factory
export const notificationFactory = {
  build: (overrides = {}) => ({
    id: faker.string.uuid(),
    type: faker.helpers.arrayElement(['info', 'success', 'warning', 'error']),
    title: faker.lorem.words(3),
    message: faker.lorem.sentence(),
    timestamp: faker.date.recent().toISOString(),
    read: faker.datatype.boolean(),
    actions: [],
    ...overrides,
  }),

  buildSuccess: (message?: string) => 
    notificationFactory.build({
      type: 'success',
      title: 'Success',
      message: message || 'Operation completed successfully',
    }),

  buildError: (message?: string) => 
    notificationFactory.build({
      type: 'error',
      title: 'Error',
      message: message || 'An error occurred',
    }),

  buildMany: (count: number, overrides = {}) =>
    Array.from({ length: count }, () => notificationFactory.build(overrides)),
}

// Test scenario factories
export const scenarioFactory = {
  // Authentication scenarios
  buildLoginScenario: (variant: 'success' | 'failure' | 'locked' = 'success') => {
    switch (variant) {
      case 'success':
        return {
          credentials: authFactory.buildValidCredentials(),
          expectedResult: 'redirect_to_dashboard',
          user: userFactory.build({ email: 'test@example.com' }),
        }
      case 'failure':
        return {
          credentials: authFactory.buildInvalidCredentials(),
          expectedResult: 'show_error_message',
          error: 'Invalid credentials',
        }
      case 'locked':
        return {
          credentials: authFactory.buildValidCredentials(),
          expectedResult: 'show_locked_message',
          error: 'Account temporarily locked',
        }
    }
  },

  // Security test scenarios
  buildSecurityScenario: (type: 'xss' | 'injection' | 'csrf' | 'brute_force') => {
    switch (type) {
      case 'xss':
        return {
          maliciousInput: '<script>alert("XSS")</script>',
          inputField: 'name',
          expectedBehavior: 'sanitized_and_safe',
        }
      case 'injection':
        return {
          maliciousInput: "'; DROP TABLE users; --",
          inputField: 'email',
          expectedBehavior: 'rejected_or_escaped',
        }
      case 'csrf':
        return {
          action: 'profile_update',
          withToken: faker.datatype.boolean(),
          expectedBehavior: 'requires_valid_token',
        }
      case 'brute_force':
        return {
          attempts: 10,
          credentials: Array.from({ length: 10 }, () => 
            authFactory.buildInvalidCredentials()
          ),
          expectedBehavior: 'rate_limited_after_attempts',
        }
    }
  },

  // Accessibility test scenarios
  buildA11yScenario: (component: string) => ({
    component,
    tests: [
      'keyboard_navigation',
      'screen_reader_compatibility', 
      'color_contrast',
      'focus_management',
      'aria_labels',
    ],
    expectedCompliance: 'WCAG_2.1_AA',
  }),

  // Performance test scenarios
  buildPerformanceScenario: (page: string) => ({
    page,
    metrics: {
      expectedLoadTime: 2000, // ms
      expectedFCP: 1500, // ms
      expectedLCP: 2500, // ms
      expectedCLS: 0.1,
      expectedFID: 100, // ms
    },
    testConditions: {
      network: '3G',
      device: 'mobile',
      cacheEnabled: true,
    },
  }),
}

// Mock data generators for complex scenarios
export const mockDataFactory = {
  buildLargeDataset: (size: number) => 
    Array.from({ length: size }, (_, index) => ({
      id: index + 1,
      name: faker.person.fullName(),
      email: faker.internet.email(),
      status: faker.helpers.arrayElement(['active', 'inactive', 'pending']),
      createdAt: faker.date.past().toISOString(),
      lastActivity: faker.date.recent().toISOString(),
    })),

  buildNestedData: (depth: number, breadth: number): any => {
    if (depth === 0) {
      return {
        id: faker.string.uuid(),
        value: faker.lorem.word(),
      }
    }
    
    return {
      id: faker.string.uuid(),
      value: faker.lorem.word(),
      children: Array.from({ length: breadth }, () => 
        mockDataFactory.buildNestedData(depth - 1, breadth)
      ),
    }
  },

  buildTimeSeriesData: (points: number, startDate?: Date) => {
    const start = startDate || faker.date.past()
    return Array.from({ length: points }, (_, index) => ({
      timestamp: new Date(start.getTime() + index * 60000).toISOString(), // 1 minute intervals
      value: faker.number.float({ min: 0, max: 100, fractionDigits: 2 }),
      label: faker.lorem.word(),
    }))
  },
}

// Export convenience function to build all factories
export const buildTestData = {
  user: userFactory.build,
  users: userFactory.buildMany,
  loginCredentials: authFactory.buildLoginCredentials,
  registerData: authFactory.buildRegisterData,
  tokens: authFactory.buildTokens,
  securityEvent: securityEventFactory.build,
  apiSuccess: apiResponseFactory.buildSuccess,
  apiError: apiResponseFactory.buildError,
  notification: notificationFactory.build,
  file: fileFactory.buildImage,
  scenario: scenarioFactory.buildLoginScenario,
}