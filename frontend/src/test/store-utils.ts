import { act, renderHook } from '@testing-library/react'
import { vi } from 'vitest'
import type { UseBoundStore, StoreApi } from 'zustand'

// Utility to reset Zustand store state
export const resetStore = <T>(store: UseBoundStore<StoreApi<T>>) => {
  // Get the initial state by creating a fresh store
  const initialState = store.getState()
  store.setState(initialState, true)
}

// Utility to mock Zustand store
export const createMockStore = <T extends object>(initialState: T) => {
  let state = { ...initialState }
  
  const setState = vi.fn((partial: Partial<T> | ((state: T) => Partial<T>), replace?: boolean) => {
    const newState = typeof partial === 'function' ? partial(state) : partial
    state = replace ? (newState as T) : { ...state, ...newState }
  })
  
  const getState = vi.fn(() => state)
  
  const subscribe = vi.fn()
  const destroy = vi.fn()
  
  return {
    setState,
    getState,
    subscribe,
    destroy,
    // Helper to update state in tests
    __setState: (newState: Partial<T>) => {
      state = { ...state, ...newState }
    },
    // Helper to get current state in tests
    __getState: () => state
  }
}

// Test utilities for auth store
export const createMockAuthStore = () => {
  const initialState = {
    user: null,
    token: null,
    refreshToken: null,
    isAuthenticated: false,
    isLoading: false,
    isInitializing: false,
    error: null,
    isRefreshing: false,
  }
  
  const actions = {
    login: vi.fn(),
    register: vi.fn(),
    logout: vi.fn(),
    refreshAccessToken: vi.fn(),
    setTokens: vi.fn(),
    clearTokens: vi.fn(),
    updateProfile: vi.fn(),
    setUser: vi.fn(),
    clearError: vi.fn(),
    setLoading: vi.fn(),
    initialize: vi.fn(),
    isTokenExpired: vi.fn(),
    scheduleRefresh: vi.fn(),
  }
  
  return createMockStore({ ...initialState, ...actions })
}

// Test utilities for consent store
export const createMockConsentStore = () => {
  const initialState = {
    hasConsented: false,
    consentTimestamp: null,
    consentVersion: null,
    preferences: {
      analytics: false,
      marketing: false,
      functional: true,
      necessary: true,
    },
    isLoading: false,
    error: null,
  }
  
  const actions = {
    grantConsent: vi.fn(),
    revokeConsent: vi.fn(),
    updatePreferences: vi.fn(),
    loadConsent: vi.fn(),
    clearError: vi.fn(),
  }
  
  return createMockStore({ ...initialState, ...actions })
}

// Test utilities for theme store
export const createMockThemeStore = () => {
  const initialState = {
    theme: 'light' as const,
    systemPreference: 'light' as const,
  }
  
  const actions = {
    setTheme: vi.fn(),
    toggleTheme: vi.fn(),
    resetTheme: vi.fn(),
  }
  
  return createMockStore({ ...initialState, ...actions })
}

// Test utilities for UI store
export const createMockUIStore = () => {
  const initialState = {
    sidebarOpen: false,
    notifications: [],
    modals: {},
    loading: {},
  }
  
  const actions = {
    toggleSidebar: vi.fn(),
    setSidebarOpen: vi.fn(),
    addNotification: vi.fn(),
    removeNotification: vi.fn(),
    clearNotifications: vi.fn(),
    openModal: vi.fn(),
    closeModal: vi.fn(),
    setLoading: vi.fn(),
    clearLoading: vi.fn(),
  }
  
  return createMockStore({ ...initialState, ...actions })
}

// Generic store testing utilities
export const testStoreAction = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  action: () => Promise<void> | void,
  expectedStateChanges: Partial<T>
) => {
  const initialState = store.getState()
  
  await act(async () => {
    await action()
  })
  
  const finalState = store.getState()
  
  Object.entries(expectedStateChanges).forEach(([key, expectedValue]) => {
    expect(finalState[key as keyof T]).toEqual(expectedValue)
  })
  
  return { initialState, finalState }
}

// Store subscription testing
export const testStoreSubscription = <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  selector: (state: T) => any
) => {
  const { result } = renderHook(() => store(selector))
  
  return {
    current: result.current,
    rerender: () => {
      // Force re-render to test subscription updates
      act(() => {
        store.setState({} as Partial<T>)
      })
    }
  }
}

// Test store persistence
export const testStorePersistence = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  key: string,
  testState: Partial<T>
) => {
  // Set state
  act(() => {
    store.setState(testState)
  })
  
  // Check if state is persisted
  const persistedData = localStorage.getItem(key)
  expect(persistedData).toBeTruthy()
  
  // Check if persisted data matches state
  const parsedData = JSON.parse(persistedData || '{}')
  Object.entries(testState).forEach(([key, value]) => {
    expect(parsedData.state[key]).toEqual(value)
  })
}

// Store error handling testing
export const testStoreErrorHandling = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  action: () => Promise<void>,
  expectedError: string
) => {
  await act(async () => {
    try {
      await action()
    } catch (error) {
      // Error is expected
    }
  })
  
  const state = store.getState()
  expect((state as any).error).toBe(expectedError)
}

// Store loading state testing
export const testStoreLoadingState = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  action: () => Promise<void>
) => {
  const loadingStates: boolean[] = []
  
  // Subscribe to loading state changes
  const unsubscribe = store.subscribe((state) => {
    loadingStates.push((state as any).isLoading || false)
  })
  
  await act(async () => {
    await action()
  })
  
  unsubscribe()
  
  // Should start with loading = true and end with loading = false
  expect(loadingStates).toContain(true)
  expect(loadingStates[loadingStates.length - 1]).toBe(false)
}

// Store concurrent action testing
export const testStoreConcurrentActions = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  actions: (() => Promise<void>)[]
) => {
  const initialState = store.getState()
  
  await act(async () => {
    await Promise.all(actions.map(action => action()))
  })
  
  const finalState = store.getState()
  
  return { initialState, finalState }
}

// Store state validation testing
export const validateStoreState = <T extends object>(
  state: T,
  schema: Record<string, (value: any) => boolean>
) => {
  Object.entries(schema).forEach(([key, validator]) => {
    const value = state[key as keyof T]
    expect(validator(value)).toBe(true)
  })
}

// Store performance testing
export const testStorePerformance = async <T extends object>(
  store: UseBoundStore<StoreApi<T>>,
  action: () => Promise<void> | void,
  maxTime: number
) => {
  const start = performance.now()
  
  await act(async () => {
    await action()
  })
  
  const end = performance.now()
  const duration = end - start
  
  expect(duration).toBeLessThan(maxTime)
  
  return duration
}