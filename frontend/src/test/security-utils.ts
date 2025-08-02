import { vi } from 'vitest'

// Security testing utilities for Web Crypto API operations
export const createSecurityTestUtils = () => {
  
  // Mock crypto operations with predictable results for testing
  const mockCrypto = {
    getRandomValues: vi.fn((array: Uint8Array) => {
      // Generate predictable "random" values for testing
      for (let i = 0; i < array.length; i++) {
        array[i] = (i * 123 + 456) % 256
      }
      return array
    }),

    randomUUID: vi.fn(() => 'test-uuid-12345678-1234-4567-8901-123456789012'),

    subtle: {
      generateKey: vi.fn(async (algorithm: any, extractable: boolean, keyUsages: KeyUsage[]) => {
        return {
          type: 'secret' as const,
          extractable,
          algorithm: {
            name: algorithm.name || algorithm,
            length: algorithm.length || 256
          },
          usages: keyUsages
        }
      }),

      importKey: vi.fn(async (format: string, keyData: any, algorithm: any, extractable: boolean, keyUsages: KeyUsage[]) => {
        return {
          type: 'secret' as const,
          extractable,
          algorithm: {
            name: algorithm.name || algorithm,
            length: algorithm.length || 256
          },
          usages: keyUsages
        }
      }),

      exportKey: vi.fn(async (format: string, key: any) => {
        if (format === 'raw') {
          return new ArrayBuffer(32) // Mock 256-bit key
        }
        return {
          kty: 'oct',
          k: 'dGVzdC1rZXktZGF0YS0xMjM0NTY3ODkw', // base64url encoded test data
          alg: 'A256GCM'
        }
      }),

      encrypt: vi.fn(async (algorithm: any, key: any, data: BufferSource) => {
        // Mock encryption - return data with mock IV prepended
        const mockIV = new Uint8Array(12) // GCM IV size
        mockIV.fill(42) // Predictable IV for testing
        
        const dataArray = new Uint8Array(data as ArrayBuffer)
        const encrypted = new Uint8Array(mockIV.length + dataArray.length + 16) // + 16 for auth tag
        
        encrypted.set(mockIV, 0)
        encrypted.set(dataArray, mockIV.length)
        // Mock auth tag
        encrypted.fill(123, mockIV.length + dataArray.length)
        
        return encrypted.buffer
      }),

      decrypt: vi.fn(async (algorithm: any, key: any, data: BufferSource) => {
        // Mock decryption - extract original data (remove IV and auth tag)
        const encrypted = new Uint8Array(data as ArrayBuffer)
        const ivLength = 12
        const authTagLength = 16
        
        const originalLength = encrypted.length - ivLength - authTagLength
        const decrypted = new Uint8Array(originalLength)
        
        decrypted.set(encrypted.slice(ivLength, ivLength + originalLength))
        
        return decrypted.buffer
      }),

      sign: vi.fn(async (algorithm: any, key: any, data: BufferSource) => {
        // Mock signature - return predictable signature
        const signature = new Uint8Array(64) // Mock 512-bit signature
        signature.fill(200)
        return signature.buffer
      }),

      verify: vi.fn(async (algorithm: any, key: any, signature: BufferSource, data: BufferSource) => {
        // Mock verification - return true for test signatures
        const sig = new Uint8Array(signature as ArrayBuffer)
        return sig[0] === 200 // Check our mock signature pattern
      }),

      digest: vi.fn(async (algorithm: string, data: BufferSource) => {
        // Mock hash - return predictable hash based on input
        const input = new Uint8Array(data as ArrayBuffer)
        const hashLength = algorithm === 'SHA-256' ? 32 : algorithm === 'SHA-512' ? 64 : 20
        const hash = new Uint8Array(hashLength)
        
        // Create deterministic hash based on input
        let seed = 0
        for (let i = 0; i < input.length; i++) {
          seed = (seed + input[i]) % 256
        }
        
        for (let i = 0; i < hashLength; i++) {
          hash[i] = (seed + i) % 256
        }
        
        return hash.buffer
      }),

      deriveBits: vi.fn(async (algorithm: any, baseKey: any, length: number) => {
        const bits = new Uint8Array(length / 8)
        bits.fill(150) // Predictable derived bits
        return bits.buffer
      }),

      deriveKey: vi.fn(async (algorithm: any, baseKey: any, derivedKeyAlgo: any, extractable: boolean, keyUsages: KeyUsage[]) => {
        return {
          type: 'secret' as const,
          extractable,
          algorithm: derivedKeyAlgo,
          usages: keyUsages
        }
      }),

      wrapKey: vi.fn(async (format: string, key: any, wrappingKey: any, wrapAlgorithm: any) => {
        // Mock wrapped key
        const wrapped = new Uint8Array(48) // Mock wrapped key size
        wrapped.fill(180)
        return wrapped.buffer
      }),

      unwrapKey: vi.fn(async (format: string, wrappedKey: BufferSource, unwrappingKey: any, unwrapAlgorithm: any, unwrappedKeyAlgorithm: any, extractable: boolean, keyUsages: KeyUsage[]) => {
        return {
          type: 'secret' as const,
          extractable,
          algorithm: unwrappedKeyAlgorithm,
          usages: keyUsages
        }
      })
    }
  }

  return {
    mockCrypto,
    
    // Security test data generators
    generateTestKey: () => ({
      type: 'secret' as const,
      extractable: false,
      algorithm: { name: 'AES-GCM', length: 256 },
      usages: ['encrypt', 'decrypt'] as KeyUsage[]
    }),

    generateTestData: (size: number = 32) => {
      const data = new Uint8Array(size)
      for (let i = 0; i < size; i++) {
        data[i] = i % 256
      }
      return data.buffer
    },

    generateTestToken: (payload: any = {}) => {
      const header = { alg: 'HS256', typ: 'JWT' }
      const testPayload = {
        sub: 'test-user-id',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 3600,
        ...payload
      }
      
      const encodedHeader = btoa(JSON.stringify(header))
      const encodedPayload = btoa(JSON.stringify(testPayload))
      const signature = 'test-signature-' + Math.random().toString(36).substr(2, 9)
      
      return `${encodedHeader}.${encodedPayload}.${signature}`
    },

    // Security event testing
    createSecurityEvent: (type: string, severity: string = 'INFO', details: any = {}) => ({
      id: 'event-' + Date.now(),
      type,
      severity,
      timestamp: new Date().toISOString(),
      userId: 'test-user-id',
      sessionId: 'test-session-id',
      ipAddress: '127.0.0.1',
      userAgent: 'Test User Agent',
      details,
      ...details
    }),

    // Input validation testing
    generateMaliciousInputs: () => [
      // XSS payloads
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")',
      '"><script>alert("XSS")</script>',
      '\';alert("XSS");//',
      
      // SQL injection payloads
      '\' OR 1=1 --',
      '\'; DROP TABLE users; --',
      '\' UNION SELECT password FROM users --',
      '1\' OR \'1\'=\'1',
      
      // NoSQL injection
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"$where": "function() { return true; }"}',
      
      // Command injection
      '; cat /etc/passwd',
      '| cat /etc/passwd',
      '`cat /etc/passwd`',
      '$(cat /etc/passwd)',
      
      // Path traversal
      '../../../etc/passwd',
      '..\\..\\..\\windows\\system32\\config\\sam',
      '....//....//....//etc/passwd',
      
      // Template injection
      '{{7*7}}',
      '${7*7}',
      '#{7*7}',
      
      // LDAP injection
      '*)(&',
      '*)(uid=*',
      '*))%00',
      
      // Header injection
      '\r\nSet-Cookie: admin=true',
      '\nLocation: http://evil.com',
      
      // Null bytes
      '%00',
      '\x00',
      
      // Unicode bypass attempts
      '\u003cscript\u003e',
      '\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E'
    ],

    // CSRF testing utilities
    createCSRFTest: () => ({
      token: 'test-csrf-token-' + Math.random().toString(36).substr(2, 9),
      validateToken: vi.fn((token: string) => token.startsWith('test-csrf-token')),
      generateToken: vi.fn(() => 'test-csrf-token-' + Math.random().toString(36).substr(2, 9))
    }),

    // Session testing utilities
    createSessionTest: () => ({
      sessionId: 'test-session-' + Math.random().toString(36).substr(2, 9),
      isValid: vi.fn(() => true),
      isExpired: vi.fn(() => false),
      refresh: vi.fn(),
      invalidate: vi.fn()
    }),

    // Rate limiting testing
    createRateLimitTest: () => {
      let requestCount = 0
      const resetTime = Date.now() + 60000 // 1 minute from now
      
      return {
        checkLimit: vi.fn((identifier: string, limit: number = 100) => {
          requestCount++
          return {
            allowed: requestCount <= limit,
            remaining: Math.max(0, limit - requestCount),
            resetTime,
            total: limit
          }
        }),
        reset: vi.fn(() => { requestCount = 0 }),
        getCount: () => requestCount
      }
    },

    // File upload security testing
    createFileSecurityTest: () => ({
      validateFileType: vi.fn((file: File, allowedTypes: string[]) => {
        return allowedTypes.some(type => file.type.startsWith(type))
      }),
      
      validateFileSize: vi.fn((file: File, maxSize: number) => {
        return file.size <= maxSize
      }),
      
      scanFile: vi.fn(async (file: File) => {
        // Mock virus scan
        return {
          safe: !file.name.includes('virus'),
          threats: file.name.includes('virus') ? ['test-threat'] : []
        }
      }),
      
      generateTestFile: (name: string, size: number, type: string) => {
        const content = new Uint8Array(size).fill(65) // Fill with 'A'
        return new File([content], name, { type })
      }
    }),

    // Authentication testing utilities
    createAuthTest: () => ({
      user: {
        id: 'test-user-id',
        email: 'test@example.com',
        name: 'Test User',
        role: 'user',
        isEmailVerified: true,
        lastLoginAt: new Date().toISOString(),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      },
      
      tokens: {
        accessToken: 'test-access-token',
        refreshToken: 'test-refresh-token',
        expiresIn: 3600,
        tokenType: 'Bearer'
      },
      
      validatePassword: vi.fn((password: string) => {
        return {
          valid: password.length >= 8,
          strength: password.length >= 12 ? 'strong' : password.length >= 8 ? 'medium' : 'weak',
          errors: password.length < 8 ? ['Password too short'] : []
        }
      })
    }),

    // Encryption testing utilities
    createEncryptionTest: () => ({
      encrypt: vi.fn(async (data: string, key?: any) => {
        return btoa(data) // Simple base64 for testing
      }),
      
      decrypt: vi.fn(async (encryptedData: string, key?: any) => {
        return atob(encryptedData) // Simple base64 decode for testing
      }),
      
      hash: vi.fn(async (data: string) => {
        // Simple hash for testing
        let hash = 0
        for (let i = 0; i < data.length; i++) {
          const char = data.charCodeAt(i)
          hash = ((hash << 5) - hash) + char
          hash = hash & hash // Convert to 32-bit integer
        }
        return hash.toString(16)
      })
    })
  }
}

// Security assertion helpers
export const securityAssertions = {
  expectNoXSS: (content: string) => {
    const xssPatterns = [
      /<script/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /expression\s*\(/i,
      /vbscript:/i
    ]
    
    for (const pattern of xssPatterns) {
      expect(content).not.toMatch(pattern)
    }
  },

  expectNoSQLInjection: (query: string) => {
    const sqlPatterns = [
      /'\s*or\s*'?\d/i,
      /'\s*or\s*'?\w/i,
      /union\s+select/i,
      /drop\s+table/i,
      /delete\s+from/i,
      /insert\s+into/i,
      /update\s+\w+\s+set/i
    ]
    
    for (const pattern of sqlPatterns) {
      expect(query).not.toMatch(pattern)
    }
  },

  expectValidCSRFToken: (token: string) => {
    expect(token).toBeTruthy()
    expect(token).toMatch(/^[a-zA-Z0-9+/=_-]+$/)
    expect(token.length).toBeGreaterThan(16)
  },

  expectSecurePassword: (password: string) => {
    expect(password.length).toBeGreaterThanOrEqual(8)
    expect(password).toMatch(/[a-z]/) // lowercase
    expect(password).toMatch(/[A-Z]/) // uppercase
    expect(password).toMatch(/[0-9]/) // number
    expect(password).toMatch(/[^a-zA-Z0-9]/) // special character
  },

  expectValidJWT: (token: string) => {
    const parts = token.split('.')
    expect(parts).toHaveLength(3)
    
    // Validate header
    const header = JSON.parse(atob(parts[0]))
    expect(header.alg).toBeTruthy()
    expect(header.typ).toBe('JWT')
    
    // Validate payload
    const payload = JSON.parse(atob(parts[1]))
    expect(payload.exp).toBeGreaterThan(Date.now() / 1000)
    expect(payload.iat).toBeLessThanOrEqual(Date.now() / 1000)
  },

  expectSecureHeaders: (headers: Record<string, string>) => {
    expect(headers['x-frame-options']).toBeTruthy()
    expect(headers['x-content-type-options']).toBe('nosniff')
    expect(headers['content-security-policy']).toBeTruthy()
    expect(headers['referrer-policy']).toBeTruthy()
  },

  expectSanitizedInput: (input: string, sanitized: string) => {
    // Common sanitization checks
    expect(sanitized).not.toContain('<script')
    expect(sanitized).not.toContain('javascript:')
    expect(sanitized).not.toContain('on' + 'load=')
    expect(sanitized).not.toContain('on' + 'error=')
    
    // Should preserve safe content
    const safeContent = input.replace(/<[^>]*>/g, '').replace(/javascript:/gi, '')
    expect(sanitized).toContain(safeContent.slice(0, 10)) // Check first 10 chars preserved
  }
}

// Security test scenarios
export const securityScenarios = {
  bruteForceAttack: async (loginFunction: (email: string, password: string) => Promise<any>) => {
    const attempts = []
    const passwords = ['123456', 'password', 'admin', 'test', 'qwerty']
    
    for (const password of passwords) {
      try {
        const result = await loginFunction('test@example.com', password)
        attempts.push({ password, success: result.success, blocked: false })
      } catch (error: any) {
        attempts.push({ 
          password, 
          success: false, 
          blocked: error.message.includes('rate limit') || error.message.includes('locked')
        })
      }
    }
    
    return attempts
  },

  sessionFixation: async (loginFunction: (credentials: any) => Promise<any>) => {
    // Get initial session
    const initialSession = 'fixed-session-id'
    
    // Login with fixed session
    const result = await loginFunction({
      email: 'test@example.com',
      password: 'password123',
      sessionId: initialSession
    })
    
    // Check if session was regenerated (should not be the same)
    return {
      initialSession,
      newSession: result.sessionId,
      wasRegenerated: result.sessionId !== initialSession
    }
  },

  privilegeEscalation: async (updateFunction: (data: any) => Promise<any>) => {
    try {
      // Attempt to escalate privileges
      const result = await updateFunction({
        role: 'admin',
        permissions: ['all']
      })
      
      return {
        allowed: result.success,
        newRole: result.data?.role,
        escalated: result.data?.role === 'admin'
      }
    } catch (error) {
      return {
        allowed: false,
        blocked: true,
        error: error.message
      }
    }
  }
}