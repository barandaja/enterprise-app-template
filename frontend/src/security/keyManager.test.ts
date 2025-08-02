import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { KeyManager } from './keyManager'
import { createSecurityTestUtils, securityAssertions } from '../test/security-utils'

// Mock IndexedDB for testing
global.indexedDB = {
  open: vi.fn(),
  deleteDatabase: vi.fn(),
  cmp: vi.fn()
} as any

describe('KeyManager Security Tests', () => {
  let keyManager: KeyManager
  let securityUtils: ReturnType<typeof createSecurityTestUtils>

  beforeEach(async () => {
    securityUtils = createSecurityTestUtils()
    
    // Mock crypto with our security test utils
    vi.stubGlobal('crypto', securityUtils.mockCrypto)
    
    // Mock IndexedDB operations
    const mockDB = {
      transaction: vi.fn().mockReturnValue({
        objectStore: vi.fn().mockReturnValue({
          get: vi.fn().mockReturnValue({
            onsuccess: null,
            result: null
          }),
          put: vi.fn().mockReturnValue({
            onsuccess: null,
            result: undefined
          }),
          delete: vi.fn().mockReturnValue({
            onsuccess: null,
            result: undefined
          })
        })
      }),
      close: vi.fn()
    }

    global.indexedDB.open = vi.fn().mockImplementation(() => {
      const request = {
        result: mockDB,
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null
      }
      
      setTimeout(() => {
        if (request.onsuccess) {
          request.onsuccess({ target: request } as any)
        }
      }, 0)
      
      return request
    })

    keyManager = new KeyManager()
    await keyManager.initialize()
  })

  afterEach(async () => {
    await keyManager.cleanup()
    vi.restoreAllMocks()
  })

  describe('Key Generation Security', () => {
    it('should generate cryptographically secure keys', async () => {
      const key = await keyManager.generateEncryptionKey()
      
      expect(key).toBeDefined()
      expect(key.type).toBe('secret')
      expect(key.algorithm.name).toBe('AES-GCM')
      expect(key.algorithm.length).toBe(256)
      expect(key.extractable).toBe(false) // Keys should not be extractable
      expect(key.usages).toContain('encrypt')
      expect(key.usages).toContain('decrypt')
    })

    it('should generate unique keys on each call', async () => {
      const key1 = await keyManager.generateEncryptionKey()
      const key2 = await keyManager.generateEncryptionKey()
      
      // Keys should be different objects
      expect(key1).not.toBe(key2)
    })

    it('should use secure random values for key generation', () => {
      const randomArray = new Uint8Array(32)
      securityUtils.mockCrypto.getRandomValues(randomArray)
      
      // Verify that getRandomValues was called and filled the array
      expect(securityUtils.mockCrypto.getRandomValues).toHaveBeenCalled()
      expect(randomArray.every(byte => byte === 0)).toBe(false)
    })

    it('should handle key generation failures gracefully', async () => {
      // Mock crypto.subtle.generateKey to throw an error
      securityUtils.mockCrypto.subtle.generateKey.mockRejectedValueOnce(
        new Error('Key generation failed')
      )

      await expect(keyManager.generateEncryptionKey()).rejects.toThrow('Key generation failed')
    })
  })

  describe('Key Storage Security', () => {
    it('should store keys securely in IndexedDB', async () => {
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'test-key-id'
      
      await keyManager.storeKey(keyId, key)
      
      // Verify that IndexedDB was used for storage
      expect(global.indexedDB.open).toHaveBeenCalled()
    })

    it('should not store extractable keys', async () => {
      const extractableKey = {
        ...securityUtils.generateTestKey(),
        extractable: true
      }
      
      await expect(keyManager.storeKey('test-key', extractableKey as any))
        .rejects.toThrow('Cannot store extractable keys')
    })

    it('should encrypt key metadata before storage', async () => {
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'test-key-with-metadata'
      const metadata = {
        purpose: 'user-data-encryption',
        created: new Date().toISOString(),
        algorithm: 'AES-GCM'
      }
      
      await keyManager.storeKey(keyId, key, metadata)
      
      // Verify encryption was called for metadata
      expect(securityUtils.mockCrypto.subtle.encrypt).toHaveBeenCalled()
    })

    it('should validate key IDs to prevent injection attacks', async () => {
      const key = await keyManager.generateEncryptionKey()
      const maliciousKeyIds = [
        '../../../etc/passwd',
        '<script>alert("xss")</script>',
        'key"; DROP TABLE keys; --',
        null,
        undefined,
        ''
      ]
      
      for (const keyId of maliciousKeyIds) {
        await expect(keyManager.storeKey(keyId as any, key))
          .rejects.toThrow(/Invalid key ID/)
      }
    })
  })

  describe('Key Retrieval Security', () => {
    it('should retrieve stored keys securely', async () => {
      const originalKey = await keyManager.generateEncryptionKey()
      const keyId = 'test-retrieval-key'
      
      await keyManager.storeKey(keyId, originalKey)
      const retrievedKey = await keyManager.getKey(keyId)
      
      expect(retrievedKey).toBeDefined()
      expect(retrievedKey?.type).toBe('secret')
      expect(retrievedKey?.algorithm.name).toBe('AES-GCM')
    })

    it('should return null for non-existent keys', async () => {
      const key = await keyManager.getKey('non-existent-key')
      expect(key).toBeNull()
    })

    it('should handle database errors during retrieval', async () => {
      // Mock database error
      const mockTransaction = {
        objectStore: vi.fn().mockReturnValue({
          get: vi.fn().mockImplementation(() => {
            const request = {
              onsuccess: null,
              onerror: null,
              result: null
            }
            
            setTimeout(() => {
              if (request.onerror) {
                request.onerror(new Error('Database error'))
              }
            }, 0)
            
            return request
          })
        })
      }
      
      const mockDB = { transaction: vi.fn().mockReturnValue(mockTransaction) }
      global.indexedDB.open = vi.fn().mockImplementation(() => {
        const request = {
          result: mockDB,
          onsuccess: null,
          onerror: null
        }
        
        setTimeout(() => {
          if (request.onsuccess) {
            request.onsuccess({ target: request } as any)
          }
        }, 0)
        
        return request
      })
      
      // Reinitialize with mocked database
      const newKeyManager = new KeyManager()
      await newKeyManager.initialize()
      
      await expect(newKeyManager.getKey('test-key')).rejects.toThrow()
    })
  })

  describe('Key Deletion Security', () => {
    it('should securely delete keys', async () => {
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'test-deletion-key'
      
      await keyManager.storeKey(keyId, key)
      await keyManager.deleteKey(keyId)
      
      const deletedKey = await keyManager.getKey(keyId)
      expect(deletedKey).toBeNull()
    })

    it('should handle deletion of non-existent keys gracefully', async () => {
      await expect(keyManager.deleteKey('non-existent-key')).resolves.not.toThrow()
    })

    it('should prevent deletion with malicious key IDs', async () => {
      const maliciousKeyIds = [
        '../../../etc/passwd',
        '<script>alert("xss")</script>',
        'key"; DROP TABLE keys; --'
      ]
      
      for (const keyId of maliciousKeyIds) {
        await expect(keyManager.deleteKey(keyId))
          .rejects.toThrow(/Invalid key ID/)
      }
    })
  })

  describe('Key Rotation Security', () => {
    it('should rotate keys securely', async () => {
      const oldKey = await keyManager.generateEncryptionKey()
      const keyId = 'rotation-test-key'
      
      await keyManager.storeKey(keyId, oldKey)
      await keyManager.rotateKey(keyId)
      
      const newKey = await keyManager.getKey(keyId)
      expect(newKey).toBeDefined()
      expect(newKey).not.toBe(oldKey)
    })

    it('should maintain key history during rotation', async () => {
      const keyId = 'history-test-key'
      const originalKey = await keyManager.generateEncryptionKey()
      
      await keyManager.storeKey(keyId, originalKey)
      await keyManager.rotateKey(keyId)
      
      const keyHistory = await keyManager.getKeyHistory(keyId)
      expect(keyHistory).toHaveLength(2) // original + rotated
      expect(keyHistory[0].version).toBe(1)
      expect(keyHistory[1].version).toBe(2)
    })

    it('should limit key history to prevent storage bloat', async () => {
      const keyId = 'history-limit-test'
      const key = await keyManager.generateEncryptionKey()
      
      await keyManager.storeKey(keyId, key)
      
      // Rotate multiple times
      for (let i = 0; i < 10; i++) {
        await keyManager.rotateKey(keyId)
      }
      
      const keyHistory = await keyManager.getKeyHistory(keyId)
      expect(keyHistory.length).toBeLessThanOrEqual(5) // Should limit history
    })
  })

  describe('Encryption/Decryption Security', () => {
    it('should encrypt data with proper authentication', async () => {
      const key = await keyManager.generateEncryptionKey()
      const plaintext = 'sensitive user data'
      
      const encrypted = await keyManager.encrypt(key, plaintext)
      
      expect(encrypted).toBeDefined()
      expect(encrypted).not.toBe(plaintext)
      expect(encrypted).not.toContain(plaintext)
      
      // Verify encryption was called with correct parameters
      expect(securityUtils.mockCrypto.subtle.encrypt).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'AES-GCM' }),
        key,
        expect.any(ArrayBuffer)
      )
    })

    it('should decrypt data correctly', async () => {
      const key = await keyManager.generateEncryptionKey()
      const plaintext = 'sensitive user data'
      
      const encrypted = await keyManager.encrypt(key, plaintext)
      const decrypted = await keyManager.decrypt(key, encrypted)
      
      expect(decrypted).toBe(plaintext)
    })

    it('should use unique IVs for each encryption', async () => {
      const key = await keyManager.generateEncryptionKey()
      const plaintext = 'test data'
      
      const encrypted1 = await keyManager.encrypt(key, plaintext)
      const encrypted2 = await keyManager.encrypt(key, plaintext)
      
      expect(encrypted1).not.toBe(encrypted2) // Should be different due to unique IVs
    })

    it('should reject tampered ciphertext', async () => {
      const key = await keyManager.generateEncryptionKey()
      const plaintext = 'sensitive data'
      
      const encrypted = await keyManager.encrypt(key, plaintext)
      
      // Tamper with the encrypted data
      const tamperedData = encrypted.slice(0, -1) + '0'
      
      // Mock decrypt to throw error for tampered data
      securityUtils.mockCrypto.subtle.decrypt.mockRejectedValueOnce(
        new Error('Authentication tag verification failed')
      )
      
      await expect(keyManager.decrypt(key, tamperedData))
        .rejects.toThrow('Authentication tag verification failed')
    })

    it('should handle large data encryption efficiently', async () => {
      const key = await keyManager.generateEncryptionKey()
      const largeData = 'x'.repeat(10000) // 10KB of data
      
      const startTime = Date.now()
      const encrypted = await keyManager.encrypt(key, largeData)
      const decrypted = await keyManager.decrypt(key, encrypted)
      const endTime = Date.now()
      
      expect(decrypted).toBe(largeData)
      expect(endTime - startTime).toBeLessThan(1000) // Should complete within 1 second
    })
  })

  describe('Access Control Security', () => {
    it('should enforce key access permissions', async () => {
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'protected-key'
      const permissions = {
        read: ['user-123'],
        write: ['admin-456'],
        delete: ['admin-456']
      }
      
      await keyManager.storeKey(keyId, key, { permissions })
      
      // Mock current user context
      const mockUser = { id: 'user-789', role: 'user' }
      
      await expect(keyManager.getKeyWithPermissions(keyId, mockUser))
        .rejects.toThrow('Access denied')
    })

    it('should validate user permissions before key operations', async () => {
      const adminUser = { id: 'admin-123', role: 'admin' }
      const regularUser = { id: 'user-456', role: 'user' }
      
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'admin-only-key'
      
      // Store key with admin-only permissions
      await keyManager.storeKeyWithPermissions(keyId, key, adminUser, {
        adminOnly: true
      })
      
      // Admin should be able to access
      const adminAccess = await keyManager.getKeyWithPermissions(keyId, adminUser)
      expect(adminAccess).toBeDefined()
      
      // Regular user should be denied
      await expect(keyManager.getKeyWithPermissions(keyId, regularUser))
        .rejects.toThrow('Insufficient permissions')
    })
  })

  describe('Key Backup and Recovery Security', () => {
    it('should create secure key backups', async () => {
      const keys = []
      for (let i = 0; i < 3; i++) {
        const key = await keyManager.generateEncryptionKey()
        await keyManager.storeKey(`backup-key-${i}`, key)
        keys.push(key)
      }
      
      const backup = await keyManager.createSecureBackup('backup-password-123')
      
      expect(backup).toBeDefined()
      expect(backup.encrypted).toBe(true)
      expect(backup.keyCount).toBe(3)
      expect(backup.timestamp).toBeDefined()
      
      // Backup should be encrypted
      expect(securityUtils.mockCrypto.subtle.encrypt).toHaveBeenCalled()
    })

    it('should restore keys from secure backup', async () => {
      // Create and backup keys
      const originalKeys = []
      for (let i = 0; i < 2; i++) {
        const key = await keyManager.generateEncryptionKey()
        await keyManager.storeKey(`restore-key-${i}`, key)
        originalKeys.push(key)
      }
      
      const backup = await keyManager.createSecureBackup('restore-password-456')
      
      // Clear keystore
      await keyManager.clearAllKeys()
      
      // Restore from backup
      const restored = await keyManager.restoreFromBackup(backup, 'restore-password-456')
      
      expect(restored.success).toBe(true)
      expect(restored.keyCount).toBe(2)
      
      // Verify keys are restored
      const restoredKey0 = await keyManager.getKey('restore-key-0')
      const restoredKey1 = await keyManager.getKey('restore-key-1')
      
      expect(restoredKey0).toBeDefined()
      expect(restoredKey1).toBeDefined()
    })

    it('should reject backup restoration with wrong password', async () => {
      const key = await keyManager.generateEncryptionKey()
      await keyManager.storeKey('password-test-key', key)
      
      const backup = await keyManager.createSecureBackup('correct-password')
      
      // Mock decryption failure for wrong password
      securityUtils.mockCrypto.subtle.decrypt.mockRejectedValueOnce(
        new Error('Authentication tag verification failed')
      )
      
      await expect(keyManager.restoreFromBackup(backup, 'wrong-password'))
        .rejects.toThrow('Invalid backup password')
    })
  })

  describe('Error Handling and Security', () => {
    it('should not leak sensitive information in error messages', async () => {
      const key = await keyManager.generateEncryptionKey()
      
      // Mock an internal error
      securityUtils.mockCrypto.subtle.encrypt.mockRejectedValueOnce(
        new Error('Internal crypto error with sensitive data: key=abc123')
      )
      
      try {
        await keyManager.encrypt(key, 'test data')
      } catch (error: any) {
        expect(error.message).not.toContain('abc123')
        expect(error.message).toMatch(/encryption (failed|error)/i)
      }
    })

    it('should handle memory cleanup on errors', async () => {
      const cleanupSpy = vi.spyOn(keyManager, 'cleanup')
      
      // Simulate a critical error
      securityUtils.mockCrypto.subtle.generateKey.mockRejectedValueOnce(
        new Error('Critical crypto failure')
      )
      
      try {
        await keyManager.generateEncryptionKey()
      } catch (error) {
        // Error should not leak sensitive info
        expect(error.message).not.toContain('crypto')
      }
      
      // Cleanup should be called on critical errors
      await keyManager.handleCriticalError(new Error('Test error'))
      expect(cleanupSpy).toHaveBeenCalled()
    })

    it('should rate limit key operations to prevent abuse', async () => {
      const rateLimitTest = securityUtils.createRateLimitTest()
      keyManager.setRateLimit(rateLimitTest.checkLimit)
      
      // Generate keys rapidly
      const results = []
      for (let i = 0; i < 105; i++) { // Exceed default limit of 100
        try {
          await keyManager.generateEncryptionKey()
          results.push({ success: true })
        } catch (error: any) {
          results.push({ success: false, rateLimited: error.message.includes('rate limit') })
          break
        }
      }
      
      // Should be rate limited before 105 operations
      const rateLimited = results.some(result => result.rateLimited)
      expect(rateLimited).toBe(true)
    })
  })

  describe('Audit and Logging Security', () => {
    it('should log security-relevant key operations', async () => {
      const auditSpy = vi.fn()
      keyManager.setAuditLogger(auditSpy)
      
      const key = await keyManager.generateEncryptionKey()
      const keyId = 'audit-test-key'
      
      await keyManager.storeKey(keyId, key)
      await keyManager.getKey(keyId)
      await keyManager.deleteKey(keyId)
      
      expect(auditSpy).toHaveBeenCalledTimes(3)
      expect(auditSpy).toHaveBeenCalledWith(expect.objectContaining({
        operation: 'store_key',
        keyId,
        timestamp: expect.any(String)
      }))
    })

    it('should not log sensitive data in audit logs', async () => {
      const auditSpy = vi.fn()
      keyManager.setAuditLogger(auditSpy)
      
      const key = await keyManager.generateEncryptionKey()
      const sensitiveData = 'secret password 123'
      
      await keyManager.encrypt(key, sensitiveData)
      
      // Check that audit logs don't contain sensitive data
      const auditCalls = auditSpy.mock.calls
      auditCalls.forEach(call => {
        const logEntry = call[0]
        expect(JSON.stringify(logEntry)).not.toContain(sensitiveData)
        expect(JSON.stringify(logEntry)).not.toContain('secret')
        expect(JSON.stringify(logEntry)).not.toContain('password')
      })
    })
  })
})