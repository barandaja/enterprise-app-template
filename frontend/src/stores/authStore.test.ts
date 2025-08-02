import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act } from '@testing-library/react'
import { useAuthStore } from './authStore'
import { testStoreAction, createMockAuthStore, testStoreErrorHandling } from '../test/store-utils'
import { buildTestData } from '../test/factories'
import { server, http, HttpResponse } from '../test/mocks/server'

// Mock dependencies
vi.mock('../services/auth/tokenManager', () => ({
  tokenManager: {
    initialize: vi.fn().mockResolvedValue(undefined),
    setTokens: vi.fn().mockResolvedValue(undefined),
    clearTokens: vi.fn().mockResolvedValue(undefined),
    getCurrentTokens: vi.fn().mockResolvedValue(null),
    getValidToken: vi.fn().mockResolvedValue('valid-token'),
    forceRefresh: vi.fn().mockResolvedValue({
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token'
    }),
    onTokenChange: vi.fn()
  }
}))

vi.mock('../security/monitoring', () => ({
  logSecurityEvent: vi.fn(),
  SecurityEventType: {
    LOGIN_SUCCESS: 'LOGIN_SUCCESS',
    LOGIN_FAILURE: 'LOGIN_FAILURE',
    LOGOUT: 'LOGOUT',
    TOKEN_REFRESH_SUCCESS: 'TOKEN_REFRESH_SUCCESS',
    TOKEN_REFRESH_FAILURE: 'TOKEN_REFRESH_FAILURE'
  },
  SecuritySeverity: {
    INFO: 'INFO',
    WARNING: 'WARNING',
    ERROR: 'ERROR'
  }
}))

describe('AuthStore', () => {
  beforeEach(() => {
    // Reset store state before each test
    useAuthStore.setState({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      isInitializing: false,
      error: null,
      isRefreshing: false,
    }, true)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('Initial State', () => {
    it('should have correct initial state', () => {
      const state = useAuthStore.getState()
      
      expect(state.user).toBeNull()
      expect(state.token).toBeNull()
      expect(state.refreshToken).toBeNull()
      expect(state.isAuthenticated).toBe(false)
      expect(state.isLoading).toBe(false)
      expect(state.isInitializing).toBe(true)
      expect(state.error).toBeNull()
      expect(state.isRefreshing).toBe(false)
    })
  })

  describe('Login Action', () => {
    it('should handle successful login', async () => {
      const credentials = buildTestData.loginCredentials()
      const mockUser = buildTestData.user()
      const mockTokens = buildTestData.tokens()

      // Mock successful API response
      server.use(
        http.post('/api/auth/login', () => {
          return HttpResponse.json({
            success: true,
            data: { user: mockUser, tokens: mockTokens }
          })
        })
      )

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().login(credentials),
        {
          user: mockUser,
          token: mockTokens.accessToken,
          refreshToken: mockTokens.refreshToken,
          isAuthenticated: true,
          isLoading: false,
          error: null
        }
      )
    })

    it('should handle login failure', async () => {
      const credentials = buildTestData.loginCredentials()

      // Mock failed API response
      server.use(
        http.post('/api/auth/login', () => {
          return HttpResponse.json(
            { success: false, message: 'Invalid credentials' },
            { status: 401 }
          )
        })
      )

      await testStoreErrorHandling(
        useAuthStore,
        () => useAuthStore.getState().login(credentials),
        'Invalid credentials'
      )

      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.user).toBeNull()
      expect(state.token).toBeNull()
    })

    it('should set loading state during login', async () => {
      const credentials = buildTestData.loginCredentials()
      let loadingStatesDuringLogin: boolean[] = []

      // Subscribe to loading state changes
      const unsubscribe = useAuthStore.subscribe((state) => {
        loadingStatesDuringLogin.push(state.isLoading)
      })

      // Mock delayed API response
      server.use(
        http.post('/api/auth/login', async () => {
          await new Promise(resolve => setTimeout(resolve, 100))
          return HttpResponse.json({
            success: true,
            data: { user: buildTestData.user(), tokens: buildTestData.tokens() }
          })
        })
      )

      await act(async () => {
        await useAuthStore.getState().login(credentials)
      })

      unsubscribe()

      // Should have loading states: false (initial) -> true (during) -> false (after)
      expect(loadingStatesDuringLogin).toContain(true)
      expect(loadingStatesDuringLogin[loadingStatesDuringLogin.length - 1]).toBe(false)
    })

    it('should handle network errors during login', async () => {
      const credentials = buildTestData.loginCredentials()

      // Mock network error
      server.use(
        http.post('/api/auth/login', () => {
          return HttpResponse.error()
        })
      )

      await expect(
        useAuthStore.getState().login(credentials)
      ).rejects.toThrow()

      const state = useAuthStore.getState()
      expect(state.isLoading).toBe(false)
      expect(state.error).toBeTruthy()
      expect(state.isAuthenticated).toBe(false)
    })
  })

  describe('Registration Action', () => {
    it('should handle successful registration', async () => {
      const registerData = buildTestData.registerData()
      const mockUser = buildTestData.user()
      const mockTokens = buildTestData.tokens()

      server.use(
        http.post('/api/auth/register', () => {
          return HttpResponse.json({
            success: true,
            data: { user: mockUser, tokens: mockTokens }
          })
        })
      )

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().register(registerData),
        {
          user: mockUser,
          token: mockTokens.accessToken,
          refreshToken: mockTokens.refreshToken,
          isAuthenticated: true,
          isLoading: false,
          error: null
        }
      )
    })

    it('should handle registration failure', async () => {
      const registerData = buildTestData.registerData()

      server.use(
        http.post('/api/auth/register', () => {
          return HttpResponse.json(
            { success: false, message: 'Email already exists' },
            { status: 409 }
          )
        })
      )

      await testStoreErrorHandling(
        useAuthStore,
        () => useAuthStore.getState().register(registerData),
        'Email already exists'
      )
    })
  })

  describe('Logout Action', () => {
    it('should clear auth state on logout', async () => {
      // Set initial authenticated state
      const user = buildTestData.user()
      const tokens = buildTestData.tokens()
      
      useAuthStore.setState({
        user,
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        isAuthenticated: true
      })

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().logout(),
        {
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          error: null,
          isLoading: false,
          isRefreshing: false
        }
      )
    })

    it('should call tokenManager.clearTokens on logout', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      
      await useAuthStore.getState().logout()
      
      expect(tokenManager.clearTokens).toHaveBeenCalled()
    })
  })

  describe('Token Refresh', () => {
    it('should refresh tokens successfully', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      const newTokens = {
        accessToken: 'new-access-token',
        refreshToken: 'new-refresh-token'
      }
      
      vi.mocked(tokenManager.forceRefresh).mockResolvedValueOnce(newTokens)

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().refreshAccessToken(),
        {
          token: newTokens.accessToken,
          refreshToken: newTokens.refreshToken,
          isRefreshing: false
        }
      )
    })

    it('should handle token refresh failure', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      
      vi.mocked(tokenManager.forceRefresh).mockRejectedValueOnce(
        new Error('Token refresh failed')
      )

      await testStoreErrorHandling(
        useAuthStore,
        () => useAuthStore.getState().refreshAccessToken(),
        'Token refresh failed'
      )

      // Should logout user on refresh failure
      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(false)
      expect(state.user).toBeNull()
    })

    it('should set refreshing state during token refresh', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      let refreshingStates: boolean[] = []

      const unsubscribe = useAuthStore.subscribe((state) => {
        refreshingStates.push(state.isRefreshing)
      })

      vi.mocked(tokenManager.forceRefresh).mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 50))
        return { accessToken: 'new-token', refreshToken: 'new-refresh' }
      })

      await act(async () => {
        await useAuthStore.getState().refreshAccessToken()
      })

      unsubscribe()

      expect(refreshingStates).toContain(true)
      expect(refreshingStates[refreshingStates.length - 1]).toBe(false)
    })
  })

  describe('Profile Update', () => {
    it('should update user profile successfully', async () => {
      const updatedUserData = { name: 'Updated Name' }
      const currentUser = buildTestData.user()
      const updatedUser = { ...currentUser, ...updatedUserData }

      // Set initial user
      useAuthStore.setState({ user: currentUser, isAuthenticated: true })

      server.use(
        http.put('/api/users/:id', () => {
          return HttpResponse.json({
            success: true,
            data: updatedUser
          })
        })
      )

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().updateProfile(updatedUserData),
        {
          user: updatedUser,
          isLoading: false,
          error: null
        }
      )
    })

    it('should handle profile update failure', async () => {
      const updatedUserData = { name: 'Updated Name' }
      
      useAuthStore.setState({ 
        user: buildTestData.user(), 
        isAuthenticated: true 
      })

      server.use(
        http.put('/api/users/:id', () => {
          return HttpResponse.json(
            { success: false, message: 'Update failed' },
            { status: 400 }
          )
        })
      )

      await testStoreErrorHandling(
        useAuthStore,
        () => useAuthStore.getState().updateProfile(updatedUserData),
        'Update failed'
      )
    })
  })

  describe('State Management', () => {
    it('should clear error when clearError is called', async () => {
      useAuthStore.setState({ error: 'Some error' })

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().clearError(),
        { error: null }
      )
    })

    it('should set loading state', async () => {
      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().setLoading(true),
        { isLoading: true }
      )

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().setLoading(false),
        { isLoading: false }
      )
    })

    it('should set user data', async () => {
      const user = buildTestData.user()

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().setUser(user),
        { user }
      )
    })
  })

  describe('Initialization', () => {
    it('should initialize with existing tokens', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      const mockTokens = buildTestData.tokens()

      vi.mocked(tokenManager.getCurrentTokens).mockResolvedValueOnce(mockTokens)
      vi.mocked(tokenManager.getValidToken).mockResolvedValueOnce(mockTokens.accessToken)

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().initialize(),
        {
          token: mockTokens.accessToken,
          refreshToken: mockTokens.refreshToken,
          isAuthenticated: true,
          isInitializing: false
        }
      )
    })

    it('should initialize without tokens', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')

      vi.mocked(tokenManager.getCurrentTokens).mockResolvedValueOnce(null)

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().initialize(),
        {
          isInitializing: false,
          isAuthenticated: false
        }
      )
    })

    it('should handle initialization errors', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')

      vi.mocked(tokenManager.initialize).mockRejectedValueOnce(
        new Error('Initialization failed')
      )

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().initialize(),
        {
          isInitializing: false,
          error: 'Failed to initialize authentication'
        }
      )
    })
  })

  describe('Token Management', () => {
    it('should set tokens correctly', async () => {
      const tokens = buildTestData.tokens()

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().setTokens(tokens.accessToken, tokens.refreshToken),
        {
          token: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          isAuthenticated: true
        }
      )
    })

    it('should clear tokens correctly', async () => {
      // Set initial tokens
      const tokens = buildTestData.tokens()
      useAuthStore.setState({
        token: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        isAuthenticated: true
      })

      await testStoreAction(
        useAuthStore,
        () => useAuthStore.getState().clearTokens(),
        {
          token: null,
          refreshToken: null,
          isAuthenticated: false
        }
      )
    })

    it('should validate token expiration correctly', () => {
      const store = useAuthStore.getState()
      
      // Create expired token
      const expiredPayload = {
        exp: Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
      }
      const expiredToken = btoa(JSON.stringify({})) + '.' + 
                          btoa(JSON.stringify(expiredPayload)) + '.' +
                          'signature'

      // Create valid token
      const validPayload = {
        exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
      }
      const validToken = btoa(JSON.stringify({})) + '.' + 
                        btoa(JSON.stringify(validPayload)) + '.' +
                        'signature'

      expect(store.isTokenExpired(expiredToken)).toBe(true)
      expect(store.isTokenExpired(validToken)).toBe(false)
    })
  })

  describe('Security Events', () => {
    it('should log security events for login success', async () => {
      const { logSecurityEvent } = await import('../security/monitoring')
      const credentials = buildTestData.loginCredentials()
      const mockUser = buildTestData.user()

      server.use(
        http.post('/api/auth/login', () => {
          return HttpResponse.json({
            success: true,
            data: { user: mockUser, tokens: buildTestData.tokens() }
          })
        })
      )

      await useAuthStore.getState().login(credentials)

      expect(logSecurityEvent).toHaveBeenCalledWith({
        type: 'LOGIN_SUCCESS',
        severity: 'INFO',
        message: 'User logged in successfully',
        userId: mockUser.id
      })
    })

    it('should log security events for login failure', async () => {
      const { logSecurityEvent } = await import('../security/monitoring')
      const credentials = buildTestData.loginCredentials()

      server.use(
        http.post('/api/auth/login', () => {
          return HttpResponse.json(
            { success: false, message: 'Invalid credentials' },
            { status: 401 }
          )
        })
      )

      try {
        await useAuthStore.getState().login(credentials)
      } catch (error) {
        // Expected to throw
      }

      expect(logSecurityEvent).toHaveBeenCalledWith({
        type: 'LOGIN_FAILURE',
        severity: 'WARNING',
        message: 'Login attempt failed',
        details: { error: expect.any(String) }
      })
    })

    it('should log security events for logout', async () => {
      const { logSecurityEvent } = await import('../security/monitoring')

      await useAuthStore.getState().logout()

      expect(logSecurityEvent).toHaveBeenCalledWith({
        type: 'LOGOUT',
        severity: 'INFO',
        message: 'User logged out'
      })
    })
  })

  describe('Concurrent Actions', () => {
    it('should handle concurrent login attempts', async () => {
      const credentials = buildTestData.loginCredentials()
      const mockUser = buildTestData.user()
      const mockTokens = buildTestData.tokens()

      server.use(
        http.post('/api/auth/login', async () => {
          await new Promise(resolve => setTimeout(resolve, 100))
          return HttpResponse.json({
            success: true,
            data: { user: mockUser, tokens: mockTokens }
          })
        })
      )

      const loginPromises = [
        useAuthStore.getState().login(credentials),
        useAuthStore.getState().login(credentials)
      ]

      // Both should resolve, but only one should succeed due to loading state
      const results = await Promise.allSettled(loginPromises)
      
      const state = useAuthStore.getState()
      expect(state.isAuthenticated).toBe(true)
      expect(state.user).toEqual(mockUser)
    })

    it('should handle concurrent token refresh attempts', async () => {
      const { tokenManager } = await import('../services/auth/tokenManager')
      
      vi.mocked(tokenManager.forceRefresh).mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return { accessToken: 'new-token', refreshToken: 'new-refresh' }
      })

      const refreshPromises = [
        useAuthStore.getState().refreshAccessToken(),
        useAuthStore.getState().refreshAccessToken()
      ]

      await Promise.allSettled(refreshPromises)

      const state = useAuthStore.getState()
      expect(state.isRefreshing).toBe(false)
    })
  })

  describe('Selectors', () => {
    it('should provide working selectors', () => {
      const user = buildTestData.user()
      const tokens = buildTestData.tokens()

      useAuthStore.setState({
        user,
        token: tokens.accessToken,
        isAuthenticated: true,
        isLoading: false,
        error: null,
        isInitializing: false
      })

      // Test individual selectors
      expect(useAuthStore.getState().user).toEqual(user)
      expect(useAuthStore.getState().token).toBe(tokens.accessToken)
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
      expect(useAuthStore.getState().isLoading).toBe(false)
      expect(useAuthStore.getState().error).toBeNull()
      expect(useAuthStore.getState().isInitializing).toBe(false)
    })
  })
})