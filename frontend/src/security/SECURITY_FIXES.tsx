/**
 * Security Fixes for Critical Vulnerabilities
 * 
 * This file contains secure implementations to fix the vulnerabilities
 * identified in the security audit.
 */

import React from 'react';
import DOMPurify from 'dompurify';
import { InputSanitizer } from './inputValidation';

// =============================================================================
// FIX 1: Secure TextInput Component with XSS Protection
// =============================================================================

interface SecureSuggestionListProps {
  suggestions: string[];
  onSelect: (suggestion: string) => void;
  selectedIndex: number;
}

export const SecureSuggestionList: React.FC<SecureSuggestionListProps> = ({
  suggestions,
  onSelect,
  selectedIndex
}) => {
  return (
    <ul className="absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-lg max-h-60 overflow-auto">
      {suggestions.map((suggestion, index) => {
        // Sanitize suggestion text to prevent XSS
        const sanitizedSuggestion = DOMPurify.sanitize(suggestion, {
          ALLOWED_TAGS: [], // No HTML tags allowed
          ALLOWED_ATTR: []
        });
        
        return (
          <li
            key={`${index}-${sanitizedSuggestion}`}
            className={`px-3 py-2 cursor-pointer text-sm ${
              index === selectedIndex
                ? 'bg-primary-100 dark:bg-primary-900'
                : 'hover:bg-gray-100 dark:hover:bg-gray-700'
            }`}
            onClick={() => onSelect(sanitizedSuggestion)}
            role="option"
            aria-selected={index === selectedIndex}
          >
            {/* Use text content, not dangerouslySetInnerHTML */}
            {sanitizedSuggestion}
          </li>
        );
      })}
    </ul>
  );
};

// =============================================================================
// FIX 2: Enhanced Secure Storage with Non-Extractable Keys
// =============================================================================

export class EnhancedSecureStorage {
  private static instance: EnhancedSecureStorage;
  private encryptionKey: CryptoKey | null = null;
  private readonly dbName = 'SecureTokenStore';
  private readonly storeName = 'tokens';
  
  private constructor() {
    this.initializeDB();
  }
  
  static getInstance(): EnhancedSecureStorage {
    if (!EnhancedSecureStorage.instance) {
      EnhancedSecureStorage.instance = new EnhancedSecureStorage();
    }
    return EnhancedSecureStorage.instance;
  }
  
  private async initializeDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.dbName, 1);
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName, { keyPath: 'id' });
        }
      };
    });
  }
  
  private async getOrCreateKey(): Promise<CryptoKey> {
    if (this.encryptionKey) return this.encryptionKey;
    
    // Try to retrieve existing key from IndexedDB
    const db = await this.initializeDB();
    const transaction = db.transaction([this.storeName], 'readonly');
    const store = transaction.objectStore(this.storeName);
    const keyRequest = store.get('encryption-key');
    
    return new Promise(async (resolve, reject) => {
      keyRequest.onsuccess = async () => {
        if (keyRequest.result) {
          // Import existing key
          try {
            this.encryptionKey = await crypto.subtle.importKey(
              'jwk',
              keyRequest.result.key,
              { name: 'AES-GCM', length: 256 },
              false, // Non-extractable
              ['encrypt', 'decrypt']
            );
            resolve(this.encryptionKey);
          } catch (error) {
            reject(error);
          }
        } else {
          // Generate new key
          this.encryptionKey = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true, // Extractable only for storage
            ['encrypt', 'decrypt']
          );
          
          // Export and store the key
          const exportedKey = await crypto.subtle.exportKey('jwk', this.encryptionKey);
          const writeTransaction = db.transaction([this.storeName], 'readwrite');
          const writeStore = writeTransaction.objectStore(this.storeName);
          writeStore.put({ id: 'encryption-key', key: exportedKey });
          
          // Re-import as non-extractable
          this.encryptionKey = await crypto.subtle.importKey(
            'jwk',
            exportedKey,
            { name: 'AES-GCM', length: 256 },
            false, // Non-extractable
            ['encrypt', 'decrypt']
          );
          
          resolve(this.encryptionKey);
        }
      };
      
      keyRequest.onerror = () => reject(keyRequest.error);
    });
  }
  
  async storeToken(tokenType: 'access' | 'refresh', token: string): Promise<void> {
    const key = await this.getOrCreateKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    const encoder = new TextEncoder();
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoder.encode(token)
    );
    
    const db = await this.initializeDB();
    const transaction = db.transaction([this.storeName], 'readwrite');
    const store = transaction.objectStore(this.storeName);
    
    store.put({
      id: `token-${tokenType}`,
      data: Array.from(new Uint8Array(encrypted)),
      iv: Array.from(iv),
      timestamp: Date.now()
    });
  }
  
  async retrieveToken(tokenType: 'access' | 'refresh'): Promise<string | null> {
    const key = await this.getOrCreateKey();
    const db = await this.initializeDB();
    const transaction = db.transaction([this.storeName], 'readonly');
    const store = transaction.objectStore(this.storeName);
    const request = store.get(`token-${tokenType}`);
    
    return new Promise((resolve, reject) => {
      request.onsuccess = async () => {
        if (!request.result) {
          resolve(null);
          return;
        }
        
        try {
          const { data, iv } = request.result;
          const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: new Uint8Array(iv) },
            key,
            new Uint8Array(data)
          );
          
          const decoder = new TextDecoder();
          resolve(decoder.decode(decrypted));
        } catch (error) {
          console.error('Token decryption failed:', error);
          resolve(null);
        }
      };
      
      request.onerror = () => reject(request.error);
    });
  }
  
  async clearTokens(): Promise<void> {
    const db = await this.initializeDB();
    const transaction = db.transaction([this.storeName], 'readwrite');
    const store = transaction.objectStore(this.storeName);
    store.delete('token-access');
    store.delete('token-refresh');
  }
}

// =============================================================================
// FIX 3: Server-Side CSRF Token Validation Component
// =============================================================================

interface CSRFTokenProviderProps {
  children: React.ReactNode;
}

export const CSRFTokenProvider: React.FC<CSRFTokenProviderProps> = ({ children }) => {
  const [csrfToken, setCSRFToken] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  
  React.useEffect(() => {
    // Fetch CSRF token from server
    const fetchCSRFToken = async () => {
      try {
        const response = await fetch('/api/csrf-token', {
          credentials: 'include',
          headers: {
            'Accept': 'application/json',
          }
        });
        
        if (!response.ok) {
          throw new Error('Failed to fetch CSRF token');
        }
        
        const data = await response.json();
        setCSRFToken(data.token);
        
        // Store in meta tag for forms
        let meta = document.querySelector('meta[name="csrf-token"]');
        if (!meta) {
          meta = document.createElement('meta');
          meta.setAttribute('name', 'csrf-token');
          document.head.appendChild(meta);
        }
        meta.setAttribute('content', data.token);
        
      } catch (error) {
        console.error('CSRF token fetch failed:', error);
        // In production, this should redirect to error page
      } finally {
        setLoading(false);
      }
    };
    
    fetchCSRFToken();
    
    // Refresh token periodically
    const interval = setInterval(fetchCSRFToken, 30 * 60 * 1000); // 30 minutes
    
    return () => clearInterval(interval);
  }, []);
  
  if (loading) {
    return <div>Loading security context...</div>;
  }
  
  if (!csrfToken) {
    return <div>Security initialization failed. Please refresh the page.</div>;
  }
  
  return <>{children}</>;
};

// =============================================================================
// FIX 4: Content Security Policy Component
// =============================================================================

export const ContentSecurityPolicy: React.FC = () => {
  React.useEffect(() => {
    // Generate nonce for inline scripts
    const nonce = btoa(crypto.getRandomValues(new Uint8Array(16)).toString());
    
    // Apply nonce to all inline scripts
    document.querySelectorAll('script:not([src])').forEach(script => {
      script.setAttribute('nonce', nonce);
    });
    
    // Create CSP meta tag
    const cspContent = [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${nonce}'`,
      `style-src 'self' 'unsafe-inline'`, // Required for Tailwind
      `img-src 'self' data: https:`,
      `font-src 'self'`,
      `connect-src 'self' ${process.env.VITE_API_BASE_URL}`,
      `frame-ancestors 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
      `upgrade-insecure-requests`
    ].join('; ');
    
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = cspContent;
    document.head.appendChild(meta);
    
    // Report CSP violations
    window.addEventListener('securitypolicyviolation', (e) => {
      console.error('CSP Violation:', {
        blockedURI: e.blockedURI,
        violatedDirective: e.violatedDirective,
        originalPolicy: e.originalPolicy
      });
      
      // Send to monitoring service
      fetch('/api/security/csp-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          blockedURI: e.blockedURI,
          violatedDirective: e.violatedDirective,
          documentURI: e.documentURI,
          timestamp: new Date().toISOString()
        })
      });
    });
    
    return () => {
      // Cleanup
      document.head.removeChild(meta);
    };
  }, []);
  
  return null;
};

// =============================================================================
// FIX 5: Secure Form Wrapper with Input Validation
// =============================================================================

interface SecureFormProps extends React.FormHTMLAttributes<HTMLFormElement> {
  onSecureSubmit: (data: any) => Promise<void>;
  validationSchema?: any; // Zod schema
}

export const SecureForm: React.FC<SecureFormProps> = ({
  children,
  onSecureSubmit,
  validationSchema,
  ...props
}) => {
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    
    const formData = new FormData(e.currentTarget);
    const data: Record<string, any> = {};
    
    // Extract and sanitize form data
    for (const [key, value] of formData.entries()) {
      if (typeof value === 'string') {
        // Apply appropriate sanitization based on field type
        if (key.includes('email')) {
          data[key] = value.toLowerCase().trim();
        } else if (key.includes('url')) {
          data[key] = InputSanitizer.sanitizeURL(value);
        } else if (key.includes('html') || key.includes('description')) {
          data[key] = InputSanitizer.sanitizeHTML(value);
        } else {
          data[key] = InputSanitizer.sanitizeText(value);
        }
      } else {
        data[key] = value;
      }
    }
    
    // Validate if schema provided
    if (validationSchema) {
      try {
        const validated = validationSchema.parse(data);
        await onSecureSubmit(validated);
      } catch (error) {
        console.error('Validation failed:', error);
        // Handle validation errors
      }
    } else {
      await onSecureSubmit(data);
    }
  };
  
  return (
    <form {...props} onSubmit={handleSubmit}>
      {/* Inject CSRF token */}
      <input 
        type="hidden" 
        name="csrf_token" 
        value={document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || ''}
      />
      {children}
    </form>
  );
};

// =============================================================================
// FIX 6: Session Manager with Warning System
// =============================================================================

interface SessionWarningModalProps {
  timeRemaining: number;
  onExtend: () => void;
  onLogout: () => void;
}

export const SessionWarningModal: React.FC<SessionWarningModalProps> = ({
  timeRemaining,
  onExtend,
  onLogout
}) => {
  const [secondsLeft, setSecondsLeft] = React.useState(Math.floor(timeRemaining / 1000));
  
  React.useEffect(() => {
    const interval = setInterval(() => {
      setSecondsLeft(prev => {
        if (prev <= 1) {
          clearInterval(interval);
          onLogout();
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(interval);
  }, [onLogout]);
  
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };
  
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h2 className="text-xl font-bold mb-4">Session Expiring Soon</h2>
        <p className="mb-4">
          Your session will expire in {formatTime(secondsLeft)}. 
          Would you like to continue?
        </p>
        <div className="flex gap-4">
          <button
            onClick={onExtend}
            className="flex-1 bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark"
          >
            Continue Session
          </button>
          <button
            onClick={onLogout}
            className="flex-1 bg-gray-300 text-gray-700 px-4 py-2 rounded hover:bg-gray-400"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
};

// =============================================================================
// FIX 7: Security Headers Validator Hook
// =============================================================================

export const useSecurityHeaders = () => {
  const [headersValid, setHeadersValid] = React.useState(true);
  const [warnings, setWarnings] = React.useState<string[]>([]);
  
  React.useEffect(() => {
    // Check security headers on initial load
    const checkHeaders = async () => {
      try {
        const response = await fetch(window.location.origin, { method: 'HEAD' });
        const headers = response.headers;
        
        const requiredHeaders = [
          'X-Content-Type-Options',
          'X-Frame-Options',
          'X-XSS-Protection',
          'Strict-Transport-Security',
          'Content-Security-Policy'
        ];
        
        const missing = requiredHeaders.filter(header => !headers.has(header));
        const newWarnings: string[] = [];
        
        if (missing.length > 0) {
          newWarnings.push(`Missing security headers: ${missing.join(', ')}`);
        }
        
        // Check for weak CSP
        const csp = headers.get('Content-Security-Policy');
        if (csp?.includes('unsafe-inline') || csp?.includes('unsafe-eval')) {
          newWarnings.push('CSP contains unsafe directives');
        }
        
        // Check HSTS
        const hsts = headers.get('Strict-Transport-Security');
        if (hsts && !hsts.includes('includeSubDomains')) {
          newWarnings.push('HSTS should include subdomains');
        }
        
        setWarnings(newWarnings);
        setHeadersValid(newWarnings.length === 0);
        
        // Log to monitoring
        if (newWarnings.length > 0) {
          console.warn('Security header warnings:', newWarnings);
        }
      } catch (error) {
        console.error('Failed to check security headers:', error);
      }
    };
    
    checkHeaders();
  }, []);
  
  return { headersValid, warnings };
};

// Export all security components
export default {
  SecureSuggestionList,
  EnhancedSecureStorage,
  CSRFTokenProvider,
  ContentSecurityPolicy,
  SecureForm,
  SessionWarningModal,
  useSecurityHeaders
};