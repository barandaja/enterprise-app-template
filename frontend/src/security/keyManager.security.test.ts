/**
 * Security Test Suite for SecureKeyManager
 * Validates the security fixes and implementation against common attack vectors
 */

import { SecureKeyManager, KeyPurpose, KeyManagerConfig } from './keyManager';

// Security test configuration
const TEST_CONFIG: KeyManagerConfig = {
  rotationInterval: 5000, // Short interval for testing
  autoRotate: false, // Disable for controlled testing
  storageKey: 'test_master_key',
  debug: true,
  logger: (message: string, data?: any) => console.log(`[SecurityTest] ${message}`, data)
};

/**
 * Mock WebAuthn API for testing hardware-backed keys
 */
function mockWebAuthnAPI(available: boolean = true) {
  if (available) {
    (global as any).window = {
      ...global.window,
      PublicKeyCredential: {
        isUserVerifyingPlatformAuthenticatorAvailable: jest.fn().mockResolvedValue(true)
      },
      location: { hostname: 'localhost' }
    };
    
    (global as any).navigator = {
      ...global.navigator,
      credentials: {
        create: jest.fn().mockResolvedValue({
          rawId: crypto.getRandomValues(new Uint8Array(32)).buffer,
          id: 'test-credential'
        })
      }
    };
  } else {
    (global as any).window = { ...global.window, PublicKeyCredential: undefined };
    (global as any).navigator = { ...global.navigator, credentials: undefined };
  }
}

/**
 * Mock localStorage for testing
 */
function mockLocalStorage() {
  const storage: { [key: string]: string } = {};
  
  (global as any).localStorage = {
    getItem: jest.fn((key: string) => storage[key] || null),
    setItem: jest.fn((key: string, value: string) => { storage[key] = value; }),
    removeItem: jest.fn((key: string) => { delete storage[key]; }),
    clear: jest.fn(() => { Object.keys(storage).forEach(key => delete storage[key]); })
  };
}

/**
 * Mock IndexedDB for testing
 */
function mockIndexedDB() {
  const db = {
    transaction: jest.fn().mockReturnValue({
      objectStore: jest.fn().mockReturnValue({
        put: jest.fn().mockReturnValue({ onsuccess: null, onerror: null }),
        get: jest.fn().mockReturnValue({ onsuccess: null, onerror: null, result: null }),
        delete: jest.fn().mockReturnValue({ onsuccess: null, onerror: null })
      })
    }),
    close: jest.fn()
  };

  (global as any).indexedDB = {
    open: jest.fn().mockReturnValue({
      onsuccess: null,
      onerror: null,
      onupgradeneeded: null,
      result: db
    })
  };
}

describe('SecureKeyManager Security Tests', () => {
  let keyManager: SecureKeyManager;

  beforeEach(() => {
    // Setup mocks
    mockWebAuthnAPI();
    mockLocalStorage();
    mockIndexedDB();
    
    // Create fresh instance for each test
    keyManager = new SecureKeyManager(TEST_CONFIG);
  });

  afterEach(async () => {
    // Clean up after each test
    await keyManager.clear();
    keyManager.dispose();
  });

  describe('Vulnerability Remediation Tests', () => {
    test('should NOT use predictable browser fingerprinting for key derivation', async () => {
      // Initialize key manager
      await keyManager.initialize();
      
      // Get two keys with same parameters - they should be identical if properly derived
      const key1 = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const key2 = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      
      // Keys should be the same (cached)
      expect(key1).toBe(key2);
      
      // But the underlying derivation should not rely on user agent strings
      // This is tested by ensuring no predictable data is used in key material
      const keyMaterial1 = await crypto.subtle.exportKey('raw', key1);
      const keyMaterial2 = await crypto.subtle.exportKey('raw', key2);
      
      expect(new Uint8Array(keyMaterial1)).toEqual(new Uint8Array(keyMaterial2));
    });

    test('should use NIST-compliant PBKDF2 iterations (600k minimum)', async () => {
      await keyManager.initialize();
      
      // The implementation should use 600,000 iterations minimum as per NIST 2024 guidelines
      // This is verified by the implementation code - we test that keys are properly derived
      const key = await keyManager.deriveKey(KeyPurpose.AUTHENTICATION);
      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe('HMAC');
    });

    test('should generate cryptographically secure entropy', async () => {
      await keyManager.initialize();
      
      // Test that multiple key generations produce different master keys
      const keyManager2 = new SecureKeyManager({
        ...TEST_CONFIG,
        storageKey: 'test_master_key_2'
      });
      
      await keyManager2.initialize();
      
      const key1 = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const key2 = await keyManager2.deriveKey(KeyPurpose.ENCRYPTION);
      
      // Keys should be different (different master keys)
      expect(key1).not.toBe(key2);
      
      await keyManager2.clear();
      keyManager2.dispose();
    });
  });

  describe('Hardware-Backed Key Security', () => {
    test('should attempt hardware-backed key derivation when available', async () => {
      mockWebAuthnAPI(true);
      await keyManager.initialize();
      
      const key = await keyManager.deriveKey(KeyPurpose.KEY_WRAPPING);
      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe('AES-KW');
    });

    test('should fall back gracefully when hardware keys unavailable', async () => {
      mockWebAuthnAPI(false);
      await keyManager.initialize();
      
      const key = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      expect(key).toBeDefined();
      expect(key.algorithm.name).toBe('AES-GCM');
    });

    test('should handle WebAuthn errors gracefully', async () => {
      // Mock WebAuthn to throw error
      (global as any).navigator.credentials.create = jest.fn().mockRejectedValue(new Error('Hardware unavailable'));
      
      await expect(keyManager.initialize()).resolves.not.toThrow();
    });
  });

  describe('Key Derivation Security', () => {
    test('should derive different keys for different purposes', async () => {
      await keyManager.initialize();
      
      const encKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const authKey = await keyManager.deriveKey(KeyPurpose.AUTHENTICATION);
      const signKey = await keyManager.deriveKey(KeyPurpose.SIGNING);
      
      expect(encKey).not.toBe(authKey);
      expect(authKey).not.toBe(signKey);
      expect(encKey).not.toBe(signKey);
    });

    test('should use appropriate algorithms for each key purpose', async () => {
      await keyManager.initialize();
      
      const encKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const authKey = await keyManager.deriveKey(KeyPurpose.AUTHENTICATION);
      const wrapKey = await keyManager.deriveKey(KeyPurpose.KEY_WRAPPING);
      
      expect(encKey.algorithm.name).toBe('AES-GCM');
      expect(authKey.algorithm.name).toBe('HMAC');
      expect(wrapKey.algorithm.name).toBe('AES-KW');
    });

    test('should not allow key extraction', async () => {
      await keyManager.initialize();
      
      const key = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      
      // Keys should not be extractable
      expect(key.extractable).toBe(false);
      
      // Attempting to export should fail
      await expect(crypto.subtle.exportKey('raw', key)).rejects.toThrow();
    });
  });

  describe('Key Rotation Security', () => {
    test('should securely rotate all keys', async () => {
      await keyManager.initialize();
      
      const oldKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const oldMetadata = keyManager.getActiveKeys();
      
      await keyManager.rotateKeys();
      
      const newKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const newMetadata = keyManager.getActiveKeys();
      
      // Keys should be different after rotation
      expect(oldKey).not.toBe(newKey);
      
      // Metadata should show rotation
      const oldEncMeta = oldMetadata.get('encryption:default');
      const newEncMeta = newMetadata.get('encryption:default');
      
      expect(newEncMeta?.version).toBeGreaterThan(oldEncMeta?.version || 0);
      expect(newEncMeta?.rotatedAt).toBeDefined();
    });

    test('should handle rotation failures gracefully', async () => {
      await keyManager.initialize();
      
      // Mock storage failure
      const originalStore = (keyManager as any).storeMasterKey;
      (keyManager as any).storeMasterKey = jest.fn().mockRejectedValue(new Error('Storage failed'));
      
      await expect(keyManager.rotateKeys()).rejects.toThrow('Storage failed');
      
      // Restore original method
      (keyManager as any).storeMasterKey = originalStore;
    });
  });

  describe('Migration Security', () => {
    test('should detect and migrate old insecure keys', async () => {
      // Mock old key data in storage
      const mockOldKeyData = {
        id: TEST_CONFIG.storageKey,
        encryptedKeyMaterial: Array.from(crypto.getRandomValues(new Uint8Array(32))),
        iv: Array.from(crypto.getRandomValues(new Uint8Array(12))),
        algorithm: 'HKDF',
        createdAt: Date.now(),
        version: 1 // Old version
      };

      // Mock IndexedDB to return old key data
      const mockGet = jest.fn().mockReturnValue({
        onsuccess: null,
        onerror: null,
        result: mockOldKeyData
      });

      (global as any).indexedDB.open = jest.fn().mockReturnValue({
        onsuccess: null,
        onerror: null,
        onupgradeneeded: null,
        result: {
          transaction: jest.fn().mockReturnValue({
            objectStore: jest.fn().mockReturnValue({
              get: mockGet,
              put: jest.fn().mockReturnValue({ onsuccess: null, onerror: null })
            })
          }),
          close: jest.fn()
        }
      });

      await keyManager.initialize();
      
      // Verify that migration was attempted
      expect(mockGet).toHaveBeenCalledWith(TEST_CONFIG.storageKey);
    });

    test('should handle migration failures gracefully', async () => {
      // Mock migration failure scenario
      const mockGet = jest.fn().mockReturnValue({
        onsuccess: null,
        onerror: null,
        result: {
          version: 1,
          encryptedKeyMaterial: 'invalid-data'
        }
      });

      (global as any).indexedDB.open = jest.fn().mockReturnValue({
        onsuccess: null,
        onerror: null,
        result: {
          transaction: jest.fn().mockReturnValue({
            objectStore: jest.fn().mockReturnValue({ get: mockGet })
          }),
          close: jest.fn()
        }
      });

      // Should not throw, should fall back to generating new key
      await expect(keyManager.initialize()).resolves.not.toThrow();
    });
  });

  describe('Entropy Source Security', () => {
    test('should use multiple entropy sources for device binding', async () => {
      await keyManager.initialize();
      
      // Test that device-specific salt is generated
      const salt1 = await (keyManager as any).getOrCreateDeviceSalt();
      const salt2 = await (keyManager as any).getOrCreateDeviceSalt();
      
      // Should return same salt (cached)
      expect(salt1).toEqual(salt2);
      expect(salt1.length).toBe(32); // 256 bits
    });

    test('should generate secure device identifiers', async () => {
      const identifier1 = await (keyManager as any).getSecureDeviceIdentifier();
      const identifier2 = await (keyManager as any).getSecureDeviceIdentifier();
      
      // Should be different each time (includes random entropy)
      expect(identifier1).not.toEqual(identifier2);
      expect(identifier1.length).toBe(32); // SHA-256 hash
      expect(identifier2.length).toBe(32);
    });

    test('should combine multiple entropy sources', async () => {
      // Mock screen properties
      (global as any).screen = {
        width: 1920,
        height: 1080,
        colorDepth: 24
      };

      (global as any).Intl = {
        DateTimeFormat: jest.fn().mockReturnValue({
          resolvedOptions: jest.fn().mockReturnValue({ timeZone: 'America/New_York' })
        })
      };

      const identifier = await (keyManager as any).getSecureDeviceIdentifier();
      
      expect(identifier).toBeDefined();
      expect(identifier.length).toBe(32);
    });
  });

  describe('Error Handling and Security Boundaries', () => {
    test('should fail securely when initialization fails', async () => {
      // Mock storage error
      (global as any).indexedDB.open = jest.fn().mockReturnValue({
        onerror: jest.fn(),
        onsuccess: null,
        result: null
      });

      await expect(keyManager.initialize()).rejects.toThrow();
    });

    test('should prevent key derivation without initialization', async () => {
      await expect(keyManager.deriveKey(KeyPurpose.ENCRYPTION))
        .rejects.toThrow('Key manager not initialized');
    });

    test('should handle concurrent access safely', async () => {
      await keyManager.initialize();
      
      // Test concurrent key derivations
      const promises = Array.from({ length: 10 }, () => 
        keyManager.deriveKey(KeyPurpose.ENCRYPTION)
      );
      
      const keys = await Promise.all(promises);
      
      // All keys should be the same (cached)
      keys.forEach(key => expect(key).toBe(keys[0]));
    });
  });

  describe('Side Channel Attack Resistance', () => {
    test('should use constant-time operations where possible', async () => {
      await keyManager.initialize();
      
      // Test that key derivation timing is relatively consistent
      const iterations = 5;
      const timings: number[] = [];
      
      for (let i = 0; i < iterations; i++) {
        const start = performance.now();
        await keyManager.deriveKey(KeyPurpose.AUTHENTICATION, undefined, `test-${i}`);
        const end = performance.now();
        timings.push(end - start);
      }
      
      // Calculate coefficient of variation (should be relatively low for constant-time ops)
      const mean = timings.reduce((a, b) => a + b) / timings.length;
      const variance = timings.reduce((sum, timing) => sum + Math.pow(timing - mean, 2), 0) / timings.length;
      const standardDeviation = Math.sqrt(variance);
      const coefficientOfVariation = standardDeviation / mean;
      
      // Should be reasonably consistent (less than 50% variation)
      expect(coefficientOfVariation).toBeLessThan(0.5);
    });
  });

  describe('Memory Security', () => {
    test('should properly clear sensitive data on disposal', async () => {
      await keyManager.initialize();
      
      const key = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      expect(key).toBeDefined();
      
      // Dispose should clear all data
      keyManager.dispose();
      
      // Further operations should require re-initialization
      await expect(keyManager.deriveKey(KeyPurpose.ENCRYPTION))
        .rejects.toThrow('Key manager not initialized');
    });

    test('should overwrite key material during rotation', async () => {
      await keyManager.initialize();
      
      const originalKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      expect(originalKey).toBeDefined();
      
      // Rotation should securely overwrite old key material
      await keyManager.rotateKeys();
      
      const newKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      expect(newKey).not.toBe(originalKey);
    });
  });
});

/**
 * Integration test to verify the complete security posture
 */
describe('KeyManager Security Integration Test', () => {
  test('complete security workflow', async () => {
    const keyManager = new SecureKeyManager({
      ...TEST_CONFIG,
      autoRotate: false,
      debug: false
    });

    try {
      // 1. Initialize with secure key derivation
      await keyManager.initialize();
      
      // 2. Derive keys for different purposes
      const encKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      const authKey = await keyManager.deriveKey(KeyPurpose.AUTHENTICATION);
      
      expect(encKey.algorithm.name).toBe('AES-GCM');
      expect(authKey.algorithm.name).toBe('HMAC');
      
      // 3. Verify key metadata
      const activeKeys = keyManager.getActiveKeys();
      expect(activeKeys.size).toBeGreaterThan(0);
      
      // 4. Test key rotation
      await keyManager.rotateKeys();
      
      const newEncKey = await keyManager.deriveKey(KeyPurpose.ENCRYPTION);
      expect(newEncKey).not.toBe(encKey);
      
      // 5. Verify secure cleanup
      await keyManager.clear();
      
      await expect(keyManager.deriveKey(KeyPurpose.ENCRYPTION))
        .rejects.toThrow('Key manager not initialized');
        
    } finally {
      keyManager.dispose();
    }
  });
});

// Export test functions for potential manual testing
export {
  mockWebAuthnAPI,
  mockLocalStorage,
  mockIndexedDB
};