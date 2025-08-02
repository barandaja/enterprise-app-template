import React, { ReactElement, ReactNode } from 'react'
import { render, RenderOptions } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'
// Note: Add @tanstack/react-query to dependencies if using query features
// import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import userEvent from '@testing-library/user-event'
import { axe, toHaveNoViolations } from 'jest-axe'

// Extend Jest matchers
expect.extend(toHaveNoViolations)

// Custom render function with providers
interface AllTheProvidersProps {
  children: ReactNode
}

const AllTheProviders = ({ children }: AllTheProvidersProps) => {
  // Note: Uncomment and install @tanstack/react-query if using query features
  // const queryClient = new QueryClient({
  //   defaultOptions: {
  //     queries: {
  //       retry: false,
  //       gcTime: 0,
  //     },
  //     mutations: {
  //       retry: false,
  //     },
  //   },
  // })

  return (
    // <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        {children}
      </BrowserRouter>
    // </QueryClientProvider>
  )
}

const customRender = (
  ui: ReactElement,
  options?: Omit<RenderOptions, 'wrapper'>
) => {
  return {
    user: userEvent.setup(),
    ...render(ui, { wrapper: AllTheProviders, ...options }),
  }
}

// Re-export everything
export * from '@testing-library/react'
export { customRender as render }

// Utility functions for testing
export const waitForLoadingToFinish = () =>
  new Promise((resolve) => setTimeout(resolve, 0))

export const createMockUser = (overrides = {}) => ({
  id: 'test-user-id',
  email: 'test@example.com',
  name: 'Test User',
  role: 'user' as const,
  isEmailVerified: true,
  createdAt: new Date().toISOString(),
  updatedAt: new Date().toISOString(),
  ...overrides,
})

export const createMockTokens = (overrides = {}) => ({
  accessToken: 'mock-access-token',
  refreshToken: 'mock-refresh-token',
  expiresIn: 3600,
  tokenType: 'Bearer',
  ...overrides,
})

// Security testing utilities
export const createMockSecurityEvent = (overrides = {}) => ({
  type: 'LOGIN_SUCCESS' as const,
  severity: 'INFO' as const,
  message: 'Test security event',
  timestamp: new Date().toISOString(),
  userId: 'test-user-id',
  sessionId: 'test-session-id',
  ipAddress: '127.0.0.1',
  userAgent: 'Test User Agent',
  ...overrides,
})

// Mock crypto operations for testing
export const mockCryptoOperations = {
  generateKey: () => Promise.resolve({
    type: 'secret' as const,
    extractable: false,
    algorithm: { name: 'AES-GCM', length: 256 },
    usages: ['encrypt', 'decrypt'] as KeyUsage[]
  }),
  
  encrypt: (data: string) => Promise.resolve(new ArrayBuffer(data.length + 16)),
  
  decrypt: () => Promise.resolve(new TextEncoder().encode('decrypted-data').buffer),
  
  hash: (data: string) => Promise.resolve(new ArrayBuffer(32)),
  
  sign: () => Promise.resolve(new ArrayBuffer(64)),
  
  verify: () => Promise.resolve(true)
}

// Form testing utilities
export const fillForm = async (
  fields: Record<string, string>,
  getByLabelText: (text: string) => HTMLElement
) => {
  const user = userEvent.setup()
  
  for (const [label, value] of Object.entries(fields)) {
    const field = getByLabelText(label)
    await user.clear(field)
    await user.type(field, value)
  }
}

// Accessibility testing helper
export const checkA11y = async (container: Element) => {
  const results = await axe(container)
  expect(results).toHaveNoViolations()
}

// Mock API responses
export const createMockApiResponse = <T>(data: T, success = true) => ({
  success,
  data,
  message: success ? 'Success' : 'Error',
  code: success ? 200 : 400,
  meta: {
    timestamp: new Date().toISOString(),
    requestId: 'test-request-id'
  }
})

// Error simulation utilities
export const simulateNetworkError = () => {
  throw new Error('Network Error')
}

export const simulateServerError = (status = 500) => {
  const error = new Error('Server Error')
  ;(error as any).status = status
  throw error
}

// Local storage mocking utilities
export const mockLocalStorage = () => {
  const store: Record<string, string> = {}
  
  return {
    getItem: (key: string) => store[key] || null,
    setItem: (key: string, value: string) => {
      store[key] = value
    },
    removeItem: (key: string) => {
      delete store[key]
    },
    clear: () => {
      Object.keys(store).forEach(key => delete store[key])
    },
    length: Object.keys(store).length,
    key: (index: number) => Object.keys(store)[index] || null
  }
}

// Session storage mocking utilities
export const mockSessionStorage = mockLocalStorage

// Cookie utilities for testing
export const mockCookies = {
  set: (name: string, value: string, options?: any) => {
    document.cookie = `${name}=${value}${options ? '; ' + Object.entries(options).map(([k, v]) => `${k}=${v}`).join('; ') : ''}`
  },
  
  get: (name: string) => {
    const value = `; ${document.cookie}`
    const parts = value.split(`; ${name}=`)
    if (parts.length === 2) return parts.pop()?.split(';').shift()
    return null
  },
  
  remove: (name: string) => {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`
  }
}

// Test data factories
export const testDataFactories = {
  user: (overrides = {}) => createMockUser(overrides),
  tokens: (overrides = {}) => createMockTokens(overrides),
  securityEvent: (overrides = {}) => createMockSecurityEvent(overrides),
  apiResponse: <T>(data: T, success = true) => createMockApiResponse(data, success)
}

// Custom hooks testing utilities
export const renderHook = async <T extends any[], R>(
  hook: (...args: T) => R,
  options?: {
    initialProps?: T
    wrapper?: React.ComponentType<any>
  }
) => {
  let result: R
  let error: Error | undefined
  
  const TestComponent = (props: { args: T }) => {
    try {
      result = hook(...props.args)
      error = undefined
    } catch (e) {
      error = e as Error
    }
    return null
  }
  
  const initialProps = options?.initialProps || ([] as unknown as T)
  const Wrapper = options?.wrapper || React.Fragment
  
  const { rerender } = render(
    <Wrapper>
      <TestComponent args={initialProps} />
    </Wrapper>
  )
  
  return {
    result: () => {
      if (error) throw error
      return result!
    },
    rerender: (newArgs: T) => {
      rerender(
        <Wrapper>
          <TestComponent args={newArgs} />
        </Wrapper>
      )
    }
  }
}

// Performance testing utilities
export const measurePerformance = async (fn: () => Promise<void> | void) => {
  const start = performance.now()
  await fn()
  const end = performance.now()
  return end - start
}

// Snapshot testing utilities
export const createSnapshot = (component: ReactElement) => {
  const { container } = render(component)
  return container.firstChild
}