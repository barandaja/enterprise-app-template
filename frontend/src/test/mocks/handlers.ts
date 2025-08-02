import { http, HttpResponse } from 'msw'
import { testDataFactories } from '../utils'
import type { User, LoginCredentials, RegisterData } from '../../types'

// Mock data
const mockUser: User = testDataFactories.user({
  id: 'test-user-123',
  email: 'test@example.com',
  name: 'Test User',
  role: 'user'
})

const mockTokens = testDataFactories.tokens({
  accessToken: 'mock-access-token-123',
  refreshToken: 'mock-refresh-token-456'
})

// Auth handlers
export const authHandlers = [
  // Login
  http.post('/api/auth/login', async ({ request }) => {
    const body = await request.json() as LoginCredentials
    
    // Simulate validation
    if (!body.email || !body.password) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 400 }
      )
    }
    
    // Simulate invalid credentials
    if (body.email === 'invalid@example.com') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    // Simulate network error
    if (body.email === 'network-error@example.com') {
      return HttpResponse.error()
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        user: mockUser,
        tokens: mockTokens
      })
    )
  }),

  // Register
  http.post('/api/auth/register', async ({ request }) => {
    const body = await request.json() as RegisterData
    
    // Simulate validation
    if (!body.email || !body.password || !body.name) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 400 }
      )
    }
    
    // Simulate email already exists
    if (body.email === 'existing@example.com') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 409 }
      )
    }
    
    const newUser = testDataFactories.user({
      ...body,
      id: 'new-user-' + Date.now()
    })
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        user: newUser,
        tokens: mockTokens
      })
    )
  }),

  // Refresh token
  http.post('/api/auth/refresh', async ({ request }) => {
    const body = await request.json() as { refreshToken: string }
    
    if (!body.refreshToken || body.refreshToken === 'invalid-refresh-token') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        accessToken: 'new-access-token-' + Date.now(),
        refreshToken: 'new-refresh-token-' + Date.now()
      })
    )
  }),

  // Logout
  http.post('/api/auth/logout', () => {
    return HttpResponse.json(
      testDataFactories.apiResponse({ message: 'Logged out successfully' })
    )
  }),

  // Get current user
  http.get('/api/auth/me', ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse(mockUser)
    )
  }),
]

// User handlers
export const userHandlers = [
  // Get user profile
  http.get('/api/users/:id', ({ params, request }) => {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    const userId = params.id as string
    
    if (userId === 'non-existent') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 404 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        ...mockUser,
        id: userId
      })
    )
  }),

  // Update user profile
  http.put('/api/users/:id', async ({ params, request }) => {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    const userId = params.id as string
    const body = await request.json() as Partial<User>
    
    const updatedUser = {
      ...mockUser,
      ...body,
      id: userId,
      updatedAt: new Date().toISOString()
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse(updatedUser)
    )
  }),

  // Delete user
  http.delete('/api/users/:id', ({ params, request }) => {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({ message: 'User deleted successfully' })
    )
  }),
]

// Security handlers
export const securityHandlers = [
  // CSRF token
  http.get('/api/csrf-token', () => {
    return HttpResponse.json(
      testDataFactories.apiResponse({
        token: 'mock-csrf-token-' + Date.now()
      })
    )
  }),

  // Security events
  http.post('/api/security/events', async ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    
    if (!authHeader) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 401 }
      )
    }
    
    const body = await request.json()
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        id: 'event-' + Date.now(),
        ...body,
        timestamp: new Date().toISOString()
      })
    )
  }),

  // Rate limiting check
  http.get('/api/rate-limit/:identifier', ({ params }) => {
    const identifier = params.identifier as string
    
    // Simulate rate limit exceeded
    if (identifier === 'rate-limited') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { 
          status: 429,
          headers: {
            'X-RateLimit-Limit': '100',
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': String(Date.now() + 60000)
          }
        }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        allowed: true,
        remaining: 95,
        resetTime: Date.now() + 60000
      })
    )
  }),
]

// Error simulation handlers
export const errorHandlers = [
  // Simulate server error
  http.get('/api/error/500', () => {
    return HttpResponse.json(
      testDataFactories.apiResponse(null, false),
      { status: 500 }
    )
  }),

  // Simulate network timeout
  http.get('/api/error/timeout', () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(HttpResponse.error())
      }, 30000) // 30 second timeout
    })
  }),

  // Simulate bad request
  http.post('/api/error/400', () => {
    return HttpResponse.json(
      testDataFactories.apiResponse(null, false),
      { status: 400 }
    )
  }),

  // Simulate forbidden
  http.get('/api/error/403', () => {
    return HttpResponse.json(
      testDataFactories.apiResponse(null, false),
      { status: 403 }
    )
  }),
]

// File upload handlers
export const fileHandlers = [
  // Upload file
  http.post('/api/files/upload', async ({ request }) => {
    const formData = await request.formData()
    const file = formData.get('file') as File
    
    if (!file) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 400 }
      )
    }
    
    // Simulate file size validation
    if (file.size > 5 * 1024 * 1024) { // 5MB
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 413 }
      )
    }
    
    // Simulate file type validation
    if (!file.type.startsWith('image/')) {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 415 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({
        id: 'file-' + Date.now(),
        name: file.name,
        size: file.size,
        type: file.type,
        url: 'https://example.com/files/' + file.name
      })
    )
  }),

  // Delete file
  http.delete('/api/files/:id', ({ params }) => {
    const fileId = params.id as string
    
    if (fileId === 'non-existent') {
      return HttpResponse.json(
        testDataFactories.apiResponse(null, false),
        { status: 404 }
      )
    }
    
    return HttpResponse.json(
      testDataFactories.apiResponse({ message: 'File deleted successfully' })
    )
  }),
]

// Combine all handlers
export const handlers = [
  ...authHandlers,
  ...userHandlers,
  ...securityHandlers,
  ...errorHandlers,
  ...fileHandlers,
]