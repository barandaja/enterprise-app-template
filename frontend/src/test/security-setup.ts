import { vi } from 'vitest'

// Enhanced Web Crypto API mock for security testing
const createMockCrypto = () => {
  const mockSubtle = {
    digest: vi.fn().mockImplementation(async (algorithm: string, data: BufferSource) => {
      // Return a consistent hash for testing
      const encoder = new TextEncoder()
      const dataString = typeof data === 'string' ? data : encoder.decode(data as ArrayBuffer)
      return new ArrayBuffer(32) // Mock SHA-256 hash
    }),

    generateKey: vi.fn().mockImplementation(async (algorithm: any, extractable: boolean, keyUsages: string[]) => {
      return {
        type: 'secret',
        extractable,
        algorithm,
        usages: keyUsages,
        [Symbol.toStringTag]: 'CryptoKey'
      }
    }),

    importKey: vi.fn().mockImplementation(async (format: string, keyData: any, algorithm: any, extractable: boolean, keyUsages: string[]) => {
      return {
        type: 'secret',
        extractable,
        algorithm,
        usages: keyUsages,
        [Symbol.toStringTag]: 'CryptoKey'
      }
    }),

    exportKey: vi.fn().mockImplementation(async (format: string, key: any) => {
      if (format === 'raw') {
        return new ArrayBuffer(32)
      }
      return { kty: 'oct', k: 'mock-key-data' }
    }),

    encrypt: vi.fn().mockImplementation(async (algorithm: any, key: any, data: BufferSource) => {
      // Return mock encrypted data
      const mockEncrypted = new ArrayBuffer(48) // 32 bytes data + 16 bytes IV
      return mockEncrypted
    }),

    decrypt: vi.fn().mockImplementation(async (algorithm: any, key: any, data: BufferSource) => {
      // Return mock decrypted data
      const encoder = new TextEncoder()
      return encoder.encode('decrypted-data').buffer
    }),

    sign: vi.fn().mockImplementation(async (algorithm: any, key: any, data: BufferSource) => {
      return new ArrayBuffer(64) // Mock signature
    }),

    verify: vi.fn().mockImplementation(async (algorithm: any, key: any, signature: BufferSource, data: BufferSource) => {
      return true // Mock successful verification
    }),

    deriveBits: vi.fn().mockImplementation(async (algorithm: any, baseKey: any, length: number) => {
      return new ArrayBuffer(length / 8)
    }),

    deriveKey: vi.fn().mockImplementation(async (algorithm: any, baseKey: any, derivedKeyAlgo: any, extractable: boolean, keyUsages: string[]) => {
      return {
        type: 'secret',
        extractable,
        algorithm: derivedKeyAlgo,
        usages: keyUsages,
        [Symbol.toStringTag]: 'CryptoKey'
      }
    }),

    wrapKey: vi.fn().mockImplementation(async (format: string, key: any, wrappingKey: any, wrapAlgorithm: any) => {
      return new ArrayBuffer(48)
    }),

    unwrapKey: vi.fn().mockImplementation(async (format: string, wrappedKey: BufferSource, unwrappingKey: any, unwrapAlgorithm: any, unwrappedKeyAlgorithm: any, extractable: boolean, keyUsages: string[]) => {
      return {
        type: 'secret',
        extractable,
        algorithm: unwrappedKeyAlgorithm,
        usages: keyUsages,
        [Symbol.toStringTag]: 'CryptoKey'
      }
    })
  }

  return {
    getRandomValues: vi.fn((arr: any) => {
      // Generate predictable "random" values for testing
      const seed = 123456789
      let random = seed
      for (let i = 0; i < arr.length; i++) {
        random = (random * 9301 + 49297) % 233280
        arr[i] = Math.floor((random / 233280) * 256)
      }
      return arr
    }),

    randomUUID: vi.fn(() => {
      // Generate predictable UUIDs for testing
      return 'test-uuid-12345678-1234-4234-8234-123456789012'
    }),

    subtle: mockSubtle
  }
}

// Replace the global crypto object with our enhanced mock
vi.stubGlobal('crypto', createMockCrypto())

// Mock IndexedDB for secure storage testing
const mockIndexedDB = {
  open: vi.fn().mockImplementation((name: string, version?: number) => {
    const mockRequest = {
      result: {
        transaction: vi.fn().mockReturnValue({
          objectStore: vi.fn().mockReturnValue({
            get: vi.fn().mockReturnValue({ result: null }),
            put: vi.fn().mockReturnValue({ result: undefined }),
            delete: vi.fn().mockReturnValue({ result: undefined }),
            clear: vi.fn().mockReturnValue({ result: undefined })
          })
        }),
        createObjectStore: vi.fn(),
        deleteObjectStore: vi.fn(),
        close: vi.fn()
      },
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null
    }

    // Simulate async behavior
    setTimeout(() => {
      if (mockRequest.onsuccess) {
        mockRequest.onsuccess({ target: mockRequest } as any)
      }
    }, 0)

    return mockRequest
  }),
  deleteDatabase: vi.fn().mockImplementation((name: string) => {
    const mockRequest = {
      result: undefined,
      onsuccess: null,
      onerror: null
    }

    setTimeout(() => {
      if (mockRequest.onsuccess) {
        mockRequest.onsuccess({ target: mockRequest } as any)
      }
    }, 0)

    return mockRequest
  })
}

vi.stubGlobal('indexedDB', mockIndexedDB)

// Mock atob and btoa for base64 operations
vi.stubGlobal('atob', vi.fn((str: string) => {
  try {
    return Buffer.from(str, 'base64').toString('binary')
  } catch {
    throw new Error('Invalid base64 string')
  }
}))

vi.stubGlobal('btoa', vi.fn((str: string) => {
  try {
    return Buffer.from(str, 'binary').toString('base64')
  } catch {
    throw new Error('Invalid string for base64 encoding')
  }
}))

// Mock TextEncoder and TextDecoder if not available
if (typeof global.TextEncoder === 'undefined') {
  vi.stubGlobal('TextEncoder', class TextEncoder {
    encode(input: string = '') {
      return new Uint8Array(Buffer.from(input, 'utf-8'))
    }
  })
}

if (typeof global.TextDecoder === 'undefined') {
  vi.stubGlobal('TextDecoder', class TextDecoder {
    decode(input?: BufferSource) {
      if (!input) return ''
      return Buffer.from(input as ArrayBuffer).toString('utf-8')
    }
  })
}

// Mock Blob constructor for file operations
if (typeof global.Blob === 'undefined') {
  class MockBlob {
    constructor(public parts: any[], public options: any = {}) {}
    get size() { return this.parts.join('').length }
    get type() { return this.options.type || '' }
    
    text() {
      return Promise.resolve(this.parts.join(''))
    }
    
    arrayBuffer() {
      const str = this.parts.join('')
      const buffer = new ArrayBuffer(str.length)
      const view = new Uint8Array(buffer)
      for (let i = 0; i < str.length; i++) {
        view[i] = str.charCodeAt(i)
      }
      return Promise.resolve(buffer)
    }
  }
  
  vi.stubGlobal('Blob', MockBlob)
}

// Mock File API for secure file upload testing
if (typeof global.File === 'undefined') {
  class MockFile extends (global.Blob as any) {
    constructor(public parts: any[], public name: string, public options: any = {}) {
      super(parts, options)
    }
    
    get lastModified() { return Date.now() }
    get webkitRelativePath() { return '' }
  }
  
  vi.stubGlobal('File', MockFile)
}

// Enhanced security event simulation
global.dispatchEvent = vi.fn()
global.addEventListener = vi.fn()
global.removeEventListener = vi.fn()

// Mock security headers for CSP testing
const mockHeaders = {
  'Content-Security-Policy': "default-src 'self'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
}

// Mock fetch for security header testing
const originalFetch = global.fetch
global.fetch = vi.fn().mockImplementation(async (url: any, options: any) => {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Map(Object.entries(mockHeaders)),
    json: async () => ({ success: true }),
    text: async () => 'mock response',
    blob: async () => new Blob(['mock data']),
    arrayBuffer: async () => new ArrayBuffer(8)
  }
})

// Restore original fetch after tests if needed
global.restoreOriginalFetch = () => {
  global.fetch = originalFetch
}