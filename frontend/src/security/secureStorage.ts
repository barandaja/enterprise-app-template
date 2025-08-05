/**
 * Secure storage implementation for sensitive data
 * Provides encryption and secure storage mechanisms for tokens and sensitive information
 * Uses Web Crypto API for all cryptographic operations
 */

// Generate a unique encryption key per session using Web Crypto API
const generateSessionKey = async (): Promise<CryptoKey> => {
  return await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true,
    ['encrypt', 'decrypt']
  );
};

// Store the session key in memory only (not persisted)
let SESSION_KEY: CryptoKey | null = null;

const getSessionKey = async (): Promise<CryptoKey> => {
  if (!SESSION_KEY) {
    SESSION_KEY = await generateSessionKey();
  }
  return SESSION_KEY;
};

// Convert string to ArrayBuffer
const stringToArrayBuffer = (str: string): ArrayBuffer => {
  const encoder = new TextEncoder();
  return encoder.encode(str).buffer;
};

// Convert ArrayBuffer to string
const arrayBufferToString = (buffer: ArrayBuffer): string => {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
};

// Convert ArrayBuffer to base64
const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

// Convert base64 to ArrayBuffer
const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
};

export interface SecureStorageOptions {
  expirationMinutes?: number;
  useSessionStorage?: boolean;
}

interface StoredItem<T> {
  data: T;
  expiry?: number;
  checksum: string;
  iv: string; // Initialization vector for AES-GCM
}

/**
 * Secure storage class for handling sensitive data with encryption
 */
export class SecureStorage {
  private readonly prefix = 'sec_';
  private readonly storage: Storage;

  constructor(useSessionStorage = true) {
    this.storage = useSessionStorage ? sessionStorage : localStorage;
  }

  /**
   * Encrypt and store data
   */
  async setItem<T>(key: string, value: T, options: SecureStorageOptions = {}): Promise<void> {
    try {
      const dataStr = JSON.stringify(value);
      const sessionKey = await getSessionKey();
      
      // Generate a random initialization vector
      const iv = crypto.getRandomValues(new Uint8Array(12));
      
      // Encrypt the data
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
        },
        sessionKey,
        stringToArrayBuffer(dataStr)
      );
      
      const item: StoredItem<string> = {
        data: arrayBufferToBase64(encryptedBuffer),
        checksum: await this.generateChecksum(dataStr),
        iv: arrayBufferToBase64(iv.buffer),
      };

      if (options.expirationMinutes) {
        item.expiry = Date.now() + options.expirationMinutes * 60 * 1000;
      }

      this.storage.setItem(this.prefix + key, JSON.stringify(item));
    } catch (error) {
      console.error('SecureStorage: Failed to store item', error);
      throw new Error('Failed to securely store data');
    }
  }

  /**
   * Retrieve and decrypt data
   */
  async getItem<T>(key: string): Promise<T | null> {
    try {
      const itemStr = this.storage.getItem(this.prefix + key);
      if (!itemStr) return null;

      const item: StoredItem<string> = JSON.parse(itemStr);

      // Check expiration
      if (item.expiry && Date.now() > item.expiry) {
        this.removeItem(key);
        return null;
      }

      const sessionKey = await getSessionKey();
      
      // Decrypt data
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: base64ToArrayBuffer(item.iv),
        },
        sessionKey,
        base64ToArrayBuffer(item.data)
      );
      
      const decrypted = arrayBufferToString(decryptedBuffer);
      
      // Verify integrity
      const expectedChecksum = await this.generateChecksum(decrypted);
      if (expectedChecksum !== item.checksum) {
        console.error('SecureStorage: Data integrity check failed');
        this.removeItem(key);
        return null;
      }

      return JSON.parse(decrypted) as T;
    } catch (error) {
      // Only log errors that aren't related to missing items
      if (item && error instanceof Error && !error.message.includes('OperationError')) {
        console.error('SecureStorage: Failed to retrieve item', error);
      }
      return null;
    }
  }

  /**
   * Remove item from storage
   */
  removeItem(key: string): void {
    this.storage.removeItem(this.prefix + key);
  }

  /**
   * Clear all secure storage items
   */
  clear(): void {
    const keys = Object.keys(this.storage);
    keys.forEach(key => {
      if (key.startsWith(this.prefix)) {
        this.storage.removeItem(key);
      }
    });
  }

  /**
   * Generate checksum for data integrity using Web Crypto API
   */
  private async generateChecksum(data: string): Promise<string> {
    const sessionKey = await getSessionKey();
    const keyData = await crypto.subtle.exportKey('raw', sessionKey);
    const combined = new Uint8Array(stringToArrayBuffer(data).byteLength + keyData.byteLength);
    combined.set(new Uint8Array(stringToArrayBuffer(data)), 0);
    combined.set(new Uint8Array(keyData), stringToArrayBuffer(data).byteLength);
    
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    return arrayBufferToBase64(hashBuffer);
  }
}

/**
 * Token storage with additional security measures
 */
export class TokenStorage {
  private secureStorage: SecureStorage;
  private tokenRefreshCallbacks: Set<() => void> = new Set();

  constructor() {
    this.secureStorage = new SecureStorage(true); // Use sessionStorage
    this.setupActivityMonitoring();
  }

  /**
   * Store authentication tokens securely
   */
  async setTokens(accessToken: string, refreshToken?: string): Promise<void> {
    // Store tokens with expiration
    await this.secureStorage.setItem('access_token', accessToken, {
      expirationMinutes: 15, // Short-lived access token
    });

    if (refreshToken) {
      await this.secureStorage.setItem('refresh_token', refreshToken, {
        expirationMinutes: 60 * 24 * 7, // 7 days for refresh token
      });
    }

    // Reset activity timer
    this.resetActivityTimer();
  }

  /**
   * Get access token
   */
  async getAccessToken(): Promise<string | null> {
    return await this.secureStorage.getItem<string>('access_token');
  }

  /**
   * Get refresh token
   */
  async getRefreshToken(): Promise<string | null> {
    return await this.secureStorage.getItem<string>('refresh_token');
  }

  /**
   * Get both tokens
   */
  async getTokens(): Promise<{ accessToken: string | null; refreshToken: string | null }> {
    const accessToken = await this.getAccessToken();
    const refreshToken = await this.getRefreshToken();
    return { accessToken, refreshToken };
  }

  /**
   * Clear all tokens
   */
  clearTokens(): void {
    this.secureStorage.removeItem('access_token');
    this.secureStorage.removeItem('refresh_token');
    this.clearActivityTimer();
  }

  /**
   * Register callback for token refresh
   */
  onTokenRefresh(callback: () => void): () => void {
    this.tokenRefreshCallbacks.add(callback);
    return () => this.tokenRefreshCallbacks.delete(callback);
  }

  /**
   * Setup activity monitoring for session timeout
   */
  private activityTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes

  private setupActivityMonitoring(): void {
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    events.forEach(event => {
      document.addEventListener(event, () => this.resetActivityTimer(), { passive: true });
    });

    // Check for token expiration on visibility change
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.checkTokenExpiration();
      }
    });
  }

  private resetActivityTimer(): void {
    if (this.activityTimer) {
      clearTimeout(this.activityTimer);
    }

    this.activityTimer = setTimeout(() => {
      this.handleInactivity();
    }, this.INACTIVITY_TIMEOUT);
  }

  private clearActivityTimer(): void {
    if (this.activityTimer) {
      clearTimeout(this.activityTimer);
      this.activityTimer = null;
    }
  }

  private handleInactivity(): void {
    console.warn('Session timeout due to inactivity');
    this.clearTokens();
    // Trigger logout in auth store
    window.dispatchEvent(new CustomEvent('session-timeout'));
  }

  private async checkTokenExpiration(): Promise<void> {
    const token = await this.getAccessToken();
    if (!token) {
      // Trigger re-authentication if needed
      this.tokenRefreshCallbacks.forEach(callback => callback());
    }
  }
}

// Export singleton instances
export const secureStorage = new SecureStorage();
export const tokenStorage = new TokenStorage();

/**
 * Secure cookie utilities for production use
 */
export const secureCookie = {
  set(name: string, value: string, days: number = 7): void {
    const expires = new Date();
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000);
    
    const cookieOptions = [
      `${name}=${encodeURIComponent(value)}`,
      `expires=${expires.toUTCString()}`,
      'path=/',
      'SameSite=Strict',
    ];

    // Add Secure flag in production
    if (window.location.protocol === 'https:') {
      cookieOptions.push('Secure');
    }

    document.cookie = cookieOptions.join('; ');
  },

  get(name: string): string | null {
    const nameEQ = name + '=';
    const cookies = document.cookie.split(';');
    
    for (let cookie of cookies) {
      cookie = cookie.trim();
      if (cookie.indexOf(nameEQ) === 0) {
        return decodeURIComponent(cookie.substring(nameEQ.length));
      }
    }
    return null;
  },

  delete(name: string): void {
    this.set(name, '', -1);
  },
};

/**
 * Security utilities
 */
export const securityUtils = {
  /**
   * Generate cryptographically secure random string
   */
  generateSecureRandom(length: number = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  },

  /**
   * Hash sensitive data for comparison using Web Crypto API
   */
  async hashData(data: string): Promise<string> {
    const hashBuffer = await crypto.subtle.digest('SHA-256', stringToArrayBuffer(data));
    return arrayBufferToBase64(hashBuffer);
  },

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false;
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
  },

  /**
   * Sanitize user input to prevent XSS
   */
  sanitizeInput(input: string): string {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
  },
};