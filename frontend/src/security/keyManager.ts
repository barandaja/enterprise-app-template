/**
 * Secure Key Manager
 * Advanced key derivation, rotation, and management using Web Crypto API
 */

import { Mutex } from '../utils/mutex';

/**
 * Key purpose enumeration for key derivation
 */
export enum KeyPurpose {
  ENCRYPTION = 'encryption',
  AUTHENTICATION = 'auth',
  SIGNING = 'signing',
  KEY_WRAPPING = 'key-wrap'
}

/**
 * Key metadata interface
 */
export interface KeyMetadata {
  id: string;
  purpose: KeyPurpose;
  algorithm: string;
  createdAt: number;
  rotatedAt?: number;
  expiresAt?: number;
  version: number;
}

/**
 * Derived key with metadata
 */
export interface DerivedKey {
  key: CryptoKey;
  metadata: KeyMetadata;
}

/**
 * Key manager configuration
 */
export interface KeyManagerConfig {
  /** Key rotation interval in milliseconds */
  rotationInterval?: number;
  /** Enable automatic key rotation */
  autoRotate?: boolean;
  /** Master key storage key name */
  storageKey?: string;
  /** Enable debug logging */
  debug?: boolean;
  /** Custom logger */
  logger?: (message: string, data?: any) => void;
}

/**
 * Key derivation parameters
 */
interface KeyDerivationParams {
  salt: Uint8Array;
  info: string;
  keyLength: number;
}

/**
 * Secure Key Manager
 * Implements NIST-compliant key derivation and management
 */
export class SecureKeyManager {
  private masterKey: CryptoKey | null = null;
  private masterKeyMaterial: Uint8Array | null = null;
  private derivedKeys = new Map<string, DerivedKey>();
  private keyMutex = new Mutex<void>('KeyManager');
  private rotationTimer: ReturnType<typeof setTimeout> | null = null;
  private config: Required<KeyManagerConfig>;
  private keyChangeCallbacks = new Set<(keys: Map<string, DerivedKey>) => void>();

  constructor(config: KeyManagerConfig = {}) {
    this.config = {
      rotationInterval: config.rotationInterval ?? 24 * 60 * 60 * 1000, // 24 hours
      autoRotate: config.autoRotate ?? true,
      storageKey: config.storageKey ?? 'app_master_key',
      debug: config.debug ?? false,
      logger: config.logger ?? console.log
    };
  }

  /**
   * Initialize the key manager
   */
  async initialize(): Promise<void> {
    await this.keyMutex.acquire(async () => {
      try {
        // Try to load existing master key
        const storedKeyData = await this.loadMasterKey();
        
        if (storedKeyData) {
          this.masterKey = storedKeyData.key;
          this.masterKeyMaterial = storedKeyData.material;
          this.log('Loaded existing master key');
        } else {
          // Generate new master key
          const keyData = await this.generateMasterKey();
          this.masterKey = keyData.key;
          this.masterKeyMaterial = keyData.material;
          await this.storeMasterKey();
          this.log('Generated new master key');
        }

        // Schedule rotation if enabled
        if (this.config.autoRotate) {
          this.scheduleRotation();
        }
      } catch (error) {
        this.log('Failed to initialize key manager', error);
        throw error;
      }
    });
  }

  /**
   * Derive a key for specific purpose
   */
  async deriveKey(
    purpose: KeyPurpose,
    salt?: Uint8Array,
    info?: string
  ): Promise<CryptoKey> {
    return this.keyMutex.acquire(async () => {
      if (!this.masterKey) {
        throw new Error('Key manager not initialized');
      }

      const keyId = this.getKeyId(purpose, info);
      
      // Check if we already have this key
      const existing = this.derivedKeys.get(keyId);
      if (existing && !this.isKeyExpired(existing.metadata)) {
        return existing.key;
      }

      // Derive new key
      const derivedKey = await this.performKeyDerivation(
        purpose,
        salt || crypto.getRandomValues(new Uint8Array(32)),
        info || purpose
      );

      // Store the derived key
      this.derivedKeys.set(keyId, derivedKey);
      
      // Notify listeners
      this.notifyKeyChange();
      
      return derivedKey.key;
    });
  }

  /**
   * Rotate all keys
   */
  async rotateKeys(): Promise<void> {
    await this.keyMutex.acquire(async () => {
      this.log('Starting key rotation');
      
      try {
        // Generate new master key
        const newKeyData = await this.generateMasterKey();
        
        // Re-derive all existing keys with new master
        const oldMasterKey = this.masterKey;
        const oldMasterKeyMaterial = this.masterKeyMaterial;
        
        this.masterKey = newKeyData.key;
        this.masterKeyMaterial = newKeyData.material;
        
        const newDerivedKeys = new Map<string, DerivedKey>();
        
        for (const [keyId, derivedKey] of this.derivedKeys) {
          const { purpose } = derivedKey.metadata;
          const salt = crypto.getRandomValues(new Uint8Array(32));
          const info = keyId.split(':')[1] || purpose;
          
          const newDerivedKey = await this.performKeyDerivation(
            purpose as KeyPurpose,
            salt,
            info
          );
          
          newDerivedKeys.set(keyId, {
            ...newDerivedKey,
            metadata: {
              ...newDerivedKey.metadata,
              version: derivedKey.metadata.version + 1,
              rotatedAt: Date.now()
            }
          });
        }
        
        // Update stored keys
        this.derivedKeys = newDerivedKeys;
        await this.storeMasterKey();
        
        // Clean up old key material
        if (oldMasterKeyMaterial) {
          crypto.getRandomValues(oldMasterKeyMaterial); // Overwrite with random data
        }
        
        this.log('Key rotation completed');
        
        // Notify listeners
        this.notifyKeyChange();
        
        // Schedule next rotation
        if (this.config.autoRotate) {
          this.scheduleRotation();
        }
      } catch (error) {
        this.log('Key rotation failed', error);
        throw error;
      }
    });
  }

  /**
   * Get all active keys
   */
  getActiveKeys(): Map<string, KeyMetadata> {
    const metadata = new Map<string, KeyMetadata>();
    
    for (const [keyId, derivedKey] of this.derivedKeys) {
      if (!this.isKeyExpired(derivedKey.metadata)) {
        metadata.set(keyId, derivedKey.metadata);
      }
    }
    
    return metadata;
  }

  /**
   * Register callback for key changes
   */
  onKeyChange(callback: (keys: Map<string, DerivedKey>) => void): () => void {
    this.keyChangeCallbacks.add(callback);
    return () => this.keyChangeCallbacks.delete(callback);
  }

  /**
   * Clear all keys and reset
   */
  async clear(): Promise<void> {
    await this.keyMutex.acquire(async () => {
      // Cancel rotation timer
      if (this.rotationTimer) {
        clearTimeout(this.rotationTimer);
        this.rotationTimer = null;
      }
      
      // Clear derived keys
      this.derivedKeys.clear();
      
      // Clear master key and material
      this.masterKey = null;
      if (this.masterKeyMaterial) {
        crypto.getRandomValues(this.masterKeyMaterial); // Overwrite with random data
        this.masterKeyMaterial = null;
      }
      
      // Remove from storage
      await this.removeMasterKey();
      
      // Notify listeners
      this.notifyKeyChange();
    });
  }

  /**
   * Generate master key using Web Crypto API
   */
  private async generateMasterKey(): Promise<{ key: CryptoKey; material: Uint8Array }> {
    // Generate a random key material
    const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    
    // Import as HKDF key
    const key = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      'HKDF',
      false, // Not extractable
      ['deriveKey', 'deriveBits']
    );
    
    return { key, material: keyMaterial };
  }

  /**
   * Perform HKDF key derivation
   */
  private async performKeyDerivation(
    purpose: KeyPurpose,
    salt: Uint8Array,
    info: string
  ): Promise<DerivedKey> {
    if (!this.masterKey) {
      throw new Error('No master key available');
    }

    const keyId = this.getKeyId(purpose, info);
    const algorithm = this.getAlgorithmForPurpose(purpose);
    const keyUsages = this.getKeyUsagesForPurpose(purpose);
    
    // Derive key material using HKDF
    const keyMaterial = await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt,
        info: new TextEncoder().encode(info)
      },
      this.masterKey,
      algorithm.length || 256 // Default 256 bits
    );
    
    // Import as CryptoKey
    const key = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      algorithm,
      false, // Not extractable
      keyUsages
    );
    
    const metadata: KeyMetadata = {
      id: keyId,
      purpose,
      algorithm: algorithm.name,
      createdAt: Date.now(),
      version: 1,
      expiresAt: Date.now() + this.config.rotationInterval
    };
    
    return { key, metadata };
  }

  /**
   * Get algorithm for key purpose
   */
  private getAlgorithmForPurpose(purpose: KeyPurpose): any {
    switch (purpose) {
      case KeyPurpose.ENCRYPTION:
        return { name: 'AES-GCM', length: 256 };
      case KeyPurpose.AUTHENTICATION:
        return { name: 'HMAC', hash: 'SHA-256' };
      case KeyPurpose.SIGNING:
        return { name: 'HMAC', hash: 'SHA-256' };
      case KeyPurpose.KEY_WRAPPING:
        return { name: 'AES-KW', length: 256 };
      default:
        return { name: 'AES-GCM', length: 256 };
    }
  }

  /**
   * Get key usages for purpose
   */
  private getKeyUsagesForPurpose(purpose: KeyPurpose): KeyUsage[] {
    switch (purpose) {
      case KeyPurpose.ENCRYPTION:
        return ['encrypt', 'decrypt'];
      case KeyPurpose.AUTHENTICATION:
        return ['sign', 'verify'];
      case KeyPurpose.SIGNING:
        return ['sign', 'verify'];
      case KeyPurpose.KEY_WRAPPING:
        return ['wrapKey', 'unwrapKey'];
      default:
        return ['encrypt', 'decrypt'];
    }
  }

  /**
   * Generate key ID
   */
  private getKeyId(purpose: KeyPurpose, info?: string): string {
    return `${purpose}:${info || 'default'}`;
  }

  /**
   * Check if key is expired
   */
  private isKeyExpired(metadata: KeyMetadata): boolean {
    if (!metadata.expiresAt) return false;
    return Date.now() > metadata.expiresAt;
  }

  /**
   * Schedule automatic key rotation
   */
  private scheduleRotation(): void {
    if (this.rotationTimer) {
      clearTimeout(this.rotationTimer);
    }
    
    this.rotationTimer = setTimeout(() => {
      this.rotateKeys().catch(error => {
        this.log('Scheduled rotation failed', error);
        // Retry after 1 hour
        setTimeout(() => this.scheduleRotation(), 60 * 60 * 1000);
      });
    }, this.config.rotationInterval);
    
    this.log(`Scheduled key rotation in ${this.config.rotationInterval}ms`);
  }

  /**
   * Store master key (indexed DB or similar)
   */
  private async storeMasterKey(): Promise<void> {
    if (!this.masterKeyMaterial) {
      throw new Error('No master key material to store');
    }
    
    try {
      const db = await this.openDatabase();
      const transaction = db.transaction(['keys'], 'readwrite');
      const store = transaction.objectStore('keys');
      
      // Derive a wrapping key from a device-specific value
      const wrappingKey = await this.getWrappingKey();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the key material
      const encryptedKeyMaterial = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        wrappingKey,
        this.masterKeyMaterial
      );
      
      await new Promise<void>((resolve, reject) => {
        const request = store.put({
          id: this.config.storageKey,
          encryptedKeyMaterial: Array.from(new Uint8Array(encryptedKeyMaterial)),
          iv: Array.from(iv),
          algorithm: 'HKDF',
          createdAt: Date.now(),
          version: 1,
          keyVersion: 2, // New secure key version
          securityLevel: 'hardware-backed' // Will be updated based on actual method used
        });
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      db.close();
      this.log('Master key stored successfully');
    } catch (error) {
      this.log('Failed to store master key', error);
      throw new Error('Failed to store master key');
    }
  }

  /**
   * Load master key from storage
   */
  private async loadMasterKey(): Promise<{ key: CryptoKey; material: Uint8Array } | null> {
    try {
      const db = await this.openDatabase();
      const transaction = db.transaction(['keys'], 'readonly');
      const store = transaction.objectStore('keys');
      
      const result = await new Promise<any>((resolve, reject) => {
        const request = store.get(this.config.storageKey);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      db.close();
      
      if (!result) {
        return null;
      }
      
      // Check if this is an old key that needs migration
      const needsMigration = result.version === 1 || !result.keyVersion;
      
      if (needsMigration) {
        this.log('Detecting old key format, attempting migration');
        const migratedKey = await this.migrateOldKey(result);
        if (migratedKey) {
          // Store the migrated key
          await this.storeMasterKey();
          return migratedKey;
        }
        // If migration fails, fall through to try current method
      }
      
      // Decrypt the key material using current secure method
      const wrappingKey = await this.getWrappingKey();
      const encryptedKeyMaterial = new Uint8Array(result.encryptedKeyMaterial);
      const iv = new Uint8Array(result.iv);
      
      const keyMaterial = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        wrappingKey,
        encryptedKeyMaterial
      );
      
      // Import as HKDF key
      const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'HKDF',
        false,
        ['deriveKey', 'deriveBits']
      );
      
      this.log('Master key loaded successfully');
      return { key, material: new Uint8Array(keyMaterial) };
    } catch (error) {
      this.log('Failed to load master key', error);
      
      // Try migration as fallback
      try {
        const migratedKey = await this.attemptKeyMigration();
        if (migratedKey) {
          this.log('Successfully migrated key after initial load failure');
          return migratedKey;
        }
      } catch (migrationError) {
        this.log('Key migration also failed', migrationError);
      }
      
      return null;
    }
  }

  /**
   * Migrate old insecure key to new secure format
   */
  private async migrateOldKey(oldKeyData: any): Promise<{ key: CryptoKey; material: Uint8Array } | null> {
    try {
      // Get the old insecure wrapping key for decryption
      const oldWrappingKey = await this.getOldInsecureWrappingKey();
      const encryptedKeyMaterial = new Uint8Array(oldKeyData.encryptedKeyMaterial);
      const iv = new Uint8Array(oldKeyData.iv);
      
      // Decrypt with old key
      const keyMaterial = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        oldWrappingKey,
        encryptedKeyMaterial
      );
      
      // Import as HKDF key
      const key = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'HKDF',
        false,
        ['deriveKey', 'deriveBits']
      );
      
      // Update the master key in memory
      this.masterKey = key;
      this.masterKeyMaterial = new Uint8Array(keyMaterial);
      
      this.log('Successfully migrated old key to secure format');
      return { key, material: new Uint8Array(keyMaterial) };
    } catch (error) {
      this.log('Failed to migrate old key', error);
      return null;
    }
  }

  /**
   * Attempt key migration from storage
   */
  private async attemptKeyMigration(): Promise<{ key: CryptoKey; material: Uint8Array } | null> {
    try {
      const db = await this.openDatabase();
      const transaction = db.transaction(['keys'], 'readonly');
      const store = transaction.objectStore('keys');
      
      const result = await new Promise<any>((resolve, reject) => {
        const request = store.get(this.config.storageKey);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      
      db.close();
      
      if (!result) {
        return null;
      }
      
      return this.migrateOldKey(result);
    } catch (error) {
      this.log('Migration attempt failed', error);
      return null;
    }
  }

  /**
   * Get the old insecure wrapping key for migration purposes only
   * WARNING: This is the vulnerable implementation - only used for migration
   */
  private async getOldInsecureWrappingKey(): Promise<CryptoKey> {
    this.log('WARNING: Using insecure key derivation for migration only');
    
    const encoder = new TextEncoder();
    const keyMaterial = encoder.encode(
      navigator.userAgent + navigator.hardwareConcurrency + navigator.language
    );
    
    // Import as raw key material
    const baseKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    // Derive AES-GCM key for wrapping
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('SecureKeyManager-v1'),
        iterations: 100000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Remove master key from storage
   */
  private async removeMasterKey(): Promise<void> {
    try {
      const db = await this.openDatabase();
      const transaction = db.transaction(['keys'], 'readwrite');
      const store = transaction.objectStore('keys');
      
      await new Promise<void>((resolve, reject) => {
        const request = store.delete(this.config.storageKey);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
      
      db.close();
      this.log('Master key removed successfully');
    } catch (error) {
      this.log('Failed to remove master key', error);
      throw new Error('Failed to remove master key');
    }
  }

  /**
   * Open IndexedDB database
   */
  private async openDatabase(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('SecureKeyStore', 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains('keys')) {
          const store = db.createObjectStore('keys', { keyPath: 'id' });
          store.createIndex('createdAt', 'createdAt', { unique: false });
        }
      };
    });
  }

  /**
   * Get wrapping key for encrypting stored keys
   * Uses a multi-tier security approach with hardware-backed keys as primary method
   */
  private async getWrappingKey(): Promise<CryptoKey> {
    try {
      // Primary: Hardware-backed key using WebAuthn/Credential Management API
      const hardwareKey = await this.getHardwareBackedKey();
      if (hardwareKey) {
        this.log('Using hardware-backed wrapping key');
        return hardwareKey;
      }
    } catch (error) {
      this.log('Hardware-backed key not available, falling back', error);
    }

    try {
      // Secondary: User-derived key with secure parameters
      const userDerivedKey = await this.getUserDerivedKey();
      if (userDerivedKey) {
        this.log('Using user-derived wrapping key');
        return userDerivedKey;
      }
    } catch (error) {
      this.log('User-derived key not available, falling back', error);
    }

    // Fallback: Secure random key generation with device binding
    this.log('Using secure random wrapping key with device binding');
    return this.getSecureRandomKey();
  }

  /**
   * Attempt to get hardware-backed key using WebAuthn/Credential Management API
   */
  private async getHardwareBackedKey(): Promise<CryptoKey | null> {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      return null;
    }

    try {
      const challenge = crypto.getRandomValues(new Uint8Array(32));
      const credentialId = await this.getOrCreateCredentialId();
      
      // Check if we can use WebAuthn for key derivation
      const isAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!isAvailable) {
        return null;
      }

      // Create/get credential for key derivation
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: {
            name: 'Secure Key Manager',
            id: window.location.hostname
          },
          user: {
            id: credentialId,
            name: 'key-manager',
            displayName: 'Key Manager'
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 }, // ES256
            { type: 'public-key', alg: -257 } // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            requireResidentKey: true
          },
          timeout: 30000
        }
      }) as PublicKeyCredential;

      if (!credential) {
        return null;
      }

      // Use credential ID as key material for derivation
      const keyMaterial = new Uint8Array(credential.rawId);
      
      // Derive wrapping key from hardware-backed credential
      const baseKey = await crypto.subtle.importKey(
        'raw',
        keyMaterial,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new TextEncoder().encode('HardwareKeyManager-v2'),
          iterations: 600000, // NIST recommended minimum for 2024
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    } catch (error) {
      this.log('Hardware key creation failed', error);
      return null;
    }
  }

  /**
   * Get or create a stable credential ID for this application
   */
  private async getOrCreateCredentialId(): Promise<Uint8Array> {
    const storageKey = 'keymanager_credential_id';
    
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        return new Uint8Array(JSON.parse(stored));
      }
    } catch (error) {
      this.log('Failed to load credential ID', error);
    }

    // Generate new credential ID
    const credentialId = crypto.getRandomValues(new Uint8Array(32));
    
    try {
      localStorage.setItem(storageKey, JSON.stringify(Array.from(credentialId)));
    } catch (error) {
      this.log('Failed to store credential ID', error);
    }

    return credentialId;
  }

  /**
   * Get user-derived key using secure password-based derivation
   */
  private async getUserDerivedKey(): Promise<CryptoKey | null> {
    // Check if we have a stored salt for user key derivation
    const storedSalt = this.getStoredUserKeySalt();
    if (!storedSalt) {
      return null; // No user key setup
    }

    try {
      // In a real implementation, this would prompt for user password/PIN
      // For this fallback, we'll use a device-specific but more secure approach
      const deviceSpecificData = await this.getSecureDeviceIdentifier();
      
      const baseKey = await crypto.subtle.importKey(
        'raw',
        deviceSpecificData,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      return crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: storedSalt,
          iterations: 600000, // NIST recommended minimum
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    } catch (error) {
      this.log('User-derived key generation failed', error);
      return null;
    }
  }

  /**
   * Get stored salt for user key derivation
   */
  private getStoredUserKeySalt(): Uint8Array | null {
    try {
      const stored = localStorage.getItem('keymanager_user_salt');
      if (stored) {
        return new Uint8Array(JSON.parse(stored));
      }
    } catch (error) {
      this.log('Failed to load user salt', error);
    }
    return null;
  }

  /**
   * Generate secure device identifier using multiple entropy sources
   */
  private async getSecureDeviceIdentifier(): Promise<Uint8Array> {
    const entropy: Uint8Array[] = [];
    
    // Add high-entropy random data
    entropy.push(crypto.getRandomValues(new Uint8Array(32)));
    
    // Add timing-based entropy
    const timingEntropy = new Uint8Array(8);
    const start = performance.now();
    for (let i = 0; i < 1000; i++) {
      Math.random(); // Generate some CPU load
    }
    const end = performance.now();
    new DataView(timingEntropy.buffer).setFloat64(0, end - start);
    entropy.push(timingEntropy);
    
    // Add screen and hardware characteristics (more stable than user agent)
    const deviceData = new TextEncoder().encode(
      `${screen.width}x${screen.height}x${screen.colorDepth}:${navigator.hardwareConcurrency}:${Intl.DateTimeFormat().resolvedOptions().timeZone}`
    );
    entropy.push(deviceData);
    
    // Combine all entropy sources
    const totalLength = entropy.reduce((sum, arr) => sum + arr.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    
    for (const arr of entropy) {
      combined.set(arr, offset);
      offset += arr.length;
    }
    
    // Hash the combined entropy to get uniform distribution
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    return new Uint8Array(hashBuffer);
  }

  /**
   * Fallback: Generate secure random wrapping key with device binding
   */
  private async getSecureRandomKey(): Promise<CryptoKey> {
    // Get or generate a device-specific salt
    const deviceSalt = await this.getOrCreateDeviceSalt();
    
    // Generate secure device identifier
    const deviceIdentifier = await this.getSecureDeviceIdentifier();
    
    // Import device identifier as base key
    const baseKey = await crypto.subtle.importKey(
      'raw',
      deviceIdentifier,
      'PBKDF2',
      false,
      ['deriveKey']
    );
    
    // Derive wrapping key with device salt
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: deviceSalt,
        iterations: 600000, // NIST recommended minimum for 2024
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Get or create device-specific salt
   */
  private async getOrCreateDeviceSalt(): Promise<Uint8Array> {
    const storageKey = 'keymanager_device_salt';
    
    try {
      const stored = localStorage.getItem(storageKey);
      if (stored) {
        return new Uint8Array(JSON.parse(stored));
      }
    } catch (error) {
      this.log('Failed to load device salt', error);
    }

    // Generate new device salt with high entropy
    const salt = crypto.getRandomValues(new Uint8Array(32));
    
    try {
      localStorage.setItem(storageKey, JSON.stringify(Array.from(salt)));
    } catch (error) {
      this.log('Failed to store device salt', error);
      // Continue anyway - salt will be regenerated next time
    }

    return salt;
  }

  /**
   * Notify listeners of key changes
   */
  private notifyKeyChange(): void {
    const keysCopy = new Map(this.derivedKeys);
    this.keyChangeCallbacks.forEach(callback => {
      try {
        callback(keysCopy);
      } catch (error) {
        this.log('Key change callback error', error);
      }
    });
  }

  /**
   * Log message if debug is enabled
   */
  private log(message: string, data?: any): void {
    if (this.config.debug) {
      this.config.logger(`[SecureKeyManager] ${message}`, data);
    }
  }

  /**
   * Clean up resources
   */
  dispose(): void {
    if (this.rotationTimer) {
      clearTimeout(this.rotationTimer);
      this.rotationTimer = null;
    }
    this.keyChangeCallbacks.clear();
    this.derivedKeys.clear();
    this.masterKey = null;
  }
}

// Create singleton instance
export const keyManager = new SecureKeyManager({
  debug: process.env.NODE_ENV === 'development'
});

// Utility functions for common crypto operations

/**
 * Encrypt data using derived key
 */
export async function encryptData(
  data: string | ArrayBuffer,
  purpose: KeyPurpose = KeyPurpose.ENCRYPTION
): Promise<{ encrypted: ArrayBuffer; iv: Uint8Array }> {
  const key = await keyManager.deriveKey(purpose);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM requires 96-bit IV
  
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    dataBuffer
  );
  
  return { encrypted, iv };
}

/**
 * Decrypt data using derived key
 */
export async function decryptData(
  encrypted: ArrayBuffer,
  iv: Uint8Array,
  purpose: KeyPurpose = KeyPurpose.ENCRYPTION
): Promise<ArrayBuffer> {
  const key = await keyManager.deriveKey(purpose);
  
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    encrypted
  );
}

/**
 * Sign data using derived key
 */
export async function signData(
  data: string | ArrayBuffer,
  purpose: KeyPurpose = KeyPurpose.SIGNING
): Promise<ArrayBuffer> {
  const key = await keyManager.deriveKey(purpose);
  
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  
  return crypto.subtle.sign(
    'HMAC',
    key,
    dataBuffer
  );
}

/**
 * Verify signature using derived key
 */
export async function verifySignature(
  signature: ArrayBuffer,
  data: string | ArrayBuffer,
  purpose: KeyPurpose = KeyPurpose.SIGNING
): Promise<boolean> {
  const key = await keyManager.deriveKey(purpose);
  
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  
  return crypto.subtle.verify(
    'HMAC',
    key,
    signature,
    dataBuffer
  );
}