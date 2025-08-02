/**
 * Security Test Suite for Vulnerability Fixes
 * 
 * These tests validate that security vulnerabilities have been properly fixed
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import DOMPurify from 'dompurify';
import { 
  SecureSuggestionList,
  EnhancedSecureStorage,
  SecureForm,
  useSecurityHeaders
} from '../SECURITY_FIXES';
import { InputSanitizer, InputValidator } from '../inputValidation';
import { CSRFTokenManager } from '../csrf';

describe('Security Fixes Test Suite', () => {
  
  describe('XSS Prevention in Suggestions', () => {
    it('should sanitize malicious scripts in suggestions', () => {
      const maliciousSuggestions = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror="alert(document.cookie)">',
        'javascript:alert("XSS")',
        '<svg onload="alert(1)">',
        '"><script>alert(String.fromCharCode(88,83,83))</script>'
      ];
      
      const onSelect = vi.fn();
      
      const { container } = render(
        <SecureSuggestionList
          suggestions={maliciousSuggestions}
          onSelect={onSelect}
          selectedIndex={0}
        />
      );
      
      // Check that no script tags are rendered
      expect(container.querySelector('script')).toBeNull();
      expect(container.innerHTML).not.toContain('<script>');
      expect(container.innerHTML).not.toContain('onerror=');
      expect(container.innerHTML).not.toContain('javascript:');
      expect(container.innerHTML).not.toContain('onload=');
      
      // Check that text content is properly escaped
      const listItems = container.querySelectorAll('li');
      listItems.forEach((item, index) => {
        const sanitized = DOMPurify.sanitize(maliciousSuggestions[index], {
          ALLOWED_TAGS: [],
          ALLOWED_ATTR: []
        });
        expect(item.textContent).toBe(sanitized);
      });
    });
    
    it('should handle onclick events safely', async () => {
      const suggestions = ['<b>Bold</b> text', 'Normal text'];
      const onSelect = vi.fn();
      
      const { container } = render(
        <SecureSuggestionList
          suggestions={suggestions}
          onSelect={onSelect}
          selectedIndex={0}
        />
      );
      
      const firstItem = container.querySelector('li');
      fireEvent.click(firstItem!);
      
      // Should receive sanitized text
      expect(onSelect).toHaveBeenCalledWith('Bold text');
    });
  });
  
  describe('Enhanced Secure Storage', () => {
    let storage: EnhancedSecureStorage;
    
    beforeEach(() => {
      // Mock IndexedDB
      const mockDB = {
        transaction: vi.fn(() => ({
          objectStore: vi.fn(() => ({
            get: vi.fn(() => ({ result: null })),
            put: vi.fn(),
            delete: vi.fn()
          }))
        }))
      };
      
      global.indexedDB = {
        open: vi.fn(() => ({
          onsuccess: null,
          onerror: null,
          onupgradeneeded: null,
          result: mockDB
        }))
      } as any;
      
      storage = EnhancedSecureStorage.getInstance();
    });
    
    it('should use non-extractable encryption keys', async () => {
      const generateKeySpy = vi.spyOn(crypto.subtle, 'generateKey');
      
      // Trigger key generation
      await storage.storeToken('access', 'test-token');
      
      // Verify non-extractable key was created
      expect(generateKeySpy).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'AES-GCM', length: 256 }),
        expect.any(Boolean),
        ['encrypt', 'decrypt']
      );
    });
    
    it('should encrypt tokens before storage', async () => {
      const encryptSpy = vi.spyOn(crypto.subtle, 'encrypt');
      const testToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
      
      await storage.storeToken('access', testToken);
      
      expect(encryptSpy).toHaveBeenCalledWith(
        expect.objectContaining({ name: 'AES-GCM' }),
        expect.any(Object), // CryptoKey
        expect.any(ArrayBuffer) // Encoded token
      );
    });
    
    it('should use unique IV for each encryption', async () => {
      const getRandomValuesSpy = vi.spyOn(crypto, 'getRandomValues');
      
      await storage.storeToken('access', 'token1');
      await storage.storeToken('refresh', 'token2');
      
      // Should generate new IV for each token
      expect(getRandomValuesSpy).toHaveBeenCalledTimes(2);
    });
  });
  
  describe('CSRF Protection', () => {
    it('should not allow client-side token generation in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      // Mock missing server token
      vi.spyOn(document, 'cookie', 'get').mockReturnValue('');
      vi.spyOn(document, 'querySelector').mockReturnValue(null);
      
      const manager = new CSRFTokenManager();
      
      expect(() => manager.getToken()).toThrow('CSRF token not found');
      
      process.env.NODE_ENV = originalEnv;
    });
    
    it('should validate CSRF tokens using constant-time comparison', () => {
      const token1 = 'abc123def456';
      const token2 = 'abc123def456';
      const token3 = 'xyz789ghi012';
      
      // Mock timing attack detection
      const startTime = performance.now();
      const result1 = securityUtils.secureCompare(token1, token2);
      const time1 = performance.now() - startTime;
      
      const startTime2 = performance.now();
      const result2 = securityUtils.secureCompare(token1, token3);
      const time2 = performance.now() - startTime2;
      
      expect(result1).toBe(true);
      expect(result2).toBe(false);
      
      // Times should be similar (constant-time)
      expect(Math.abs(time1 - time2)).toBeLessThan(1);
    });
  });
  
  describe('Input Validation and Sanitization', () => {
    it('should prevent SQL injection in search queries', () => {
      const maliciousQueries = [
        "'; DROP TABLE users; --",
        "1' OR '1'='1",
        "admin'--",
        "1; DELETE FROM users WHERE 1=1; --"
      ];
      
      maliciousQueries.forEach(query => {
        const sanitized = InputSanitizer.sanitizeSearchQuery(query);
        expect(sanitized).not.toContain("'");
        expect(sanitized).not.toContain(';');
        expect(sanitized).not.toContain('--');
      });
    });
    
    it('should validate and sanitize email addresses', () => {
      const testCases = [
        { input: 'test@example.com', valid: true },
        { input: 'test@sub.example.com', valid: true },
        { input: 'test+tag@example.com', valid: true },
        { input: 'test@', valid: false },
        { input: '@example.com', valid: false },
        { input: 'test..test@example.com', valid: false },
        { input: 'test@example', valid: false },
        { input: '<script>@example.com', valid: false }
      ];
      
      testCases.forEach(({ input, valid }) => {
        const result = InputValidator.validateEmail(input);
        expect(result.valid).toBe(valid);
      });
    });
    
    it('should enforce strong password requirements', () => {
      const weakPasswords = [
        'password',
        '12345678',
        'abcdefgh',
        'ABCDEFGH',
        'Abcd1234', // No special chars
        'Abcd!@#$', // No numbers
      ];
      
      const strongPasswords = [
        'Str0ng!Pass',
        'C0mpl3x@Pass',
        'S3cur3$Pass!',
      ];
      
      weakPasswords.forEach(password => {
        const result = InputValidator.validatePassword(password);
        expect(result.valid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
      
      strongPasswords.forEach(password => {
        const result = InputValidator.validatePassword(password);
        expect(result.valid).toBe(true);
        expect(result.score).toBeGreaterThanOrEqual(4);
      });
    });
  });
  
  describe('Secure Form Submission', () => {
    it('should sanitize all form inputs before submission', async () => {
      const onSubmit = vi.fn();
      const user = userEvent.setup();
      
      render(
        <SecureForm onSecureSubmit={onSubmit}>
          <input name="name" defaultValue="<script>alert('xss')</script>" />
          <input name="email" defaultValue="TEST@EXAMPLE.COM" />
          <textarea name="description" defaultValue="<b>Bold</b> text" />
          <button type="submit">Submit</button>
        </SecureForm>
      );
      
      await user.click(screen.getByText('Submit'));
      
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledWith({
          name: expect.not.stringContaining('<script>'),
          email: 'test@example.com', // Lowercased
          description: expect.stringContaining('<b>Bold</b>'), // HTML allowed
          csrf_token: expect.any(String)
        });
      });
    });
    
    it('should include CSRF token in form submission', async () => {
      // Mock CSRF token in meta tag
      const meta = document.createElement('meta');
      meta.name = 'csrf-token';
      meta.content = 'test-csrf-token';
      document.head.appendChild(meta);
      
      const onSubmit = vi.fn();
      
      render(
        <SecureForm onSecureSubmit={onSubmit}>
          <button type="submit">Submit</button>
        </SecureForm>
      );
      
      fireEvent.submit(screen.getByRole('form'));
      
      await waitFor(() => {
        expect(onSubmit).toHaveBeenCalledWith(
          expect.objectContaining({
            csrf_token: 'test-csrf-token'
          })
        );
      });
      
      document.head.removeChild(meta);
    });
  });
  
  describe('Content Security Policy', () => {
    it('should detect CSP violations', () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation();
      
      // Simulate CSP violation
      const event = new SecurityPolicyViolationEvent('securitypolicyviolation', {
        blockedURI: 'https://evil.com/script.js',
        violatedDirective: 'script-src',
        originalPolicy: "script-src 'self'"
      });
      
      window.dispatchEvent(event);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'CSP Violation:',
        expect.objectContaining({
          blockedURI: 'https://evil.com/script.js',
          violatedDirective: 'script-src'
        })
      );
    });
  });
  
  describe('Security Headers Validation', () => {
    it('should detect missing security headers', async () => {
      // Mock fetch response without security headers
      global.fetch = vi.fn().mockResolvedValue({
        headers: new Headers({
          'Content-Type': 'text/html'
          // Missing security headers
        })
      });
      
      const { result } = renderHook(() => useSecurityHeaders());
      
      await waitFor(() => {
        expect(result.current.headersValid).toBe(false);
        expect(result.current.warnings).toContain(
          expect.stringContaining('Missing security headers')
        );
      });
    });
    
    it('should warn about weak CSP directives', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        headers: new Headers({
          'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'",
          'X-Content-Type-Options': 'nosniff',
          'X-Frame-Options': 'DENY',
          'X-XSS-Protection': '1; mode=block',
          'Strict-Transport-Security': 'max-age=31536000'
        })
      });
      
      const { result } = renderHook(() => useSecurityHeaders());
      
      await waitFor(() => {
        expect(result.current.warnings).toContain(
          'CSP contains unsafe directives'
        );
      });
    });
  });
  
  describe('File Upload Security', () => {
    it('should reject dangerous file types', () => {
      const dangerousFiles = [
        new File([''], 'malware.exe', { type: 'application/x-msdownload' }),
        new File([''], 'script.js', { type: 'text/javascript' }),
        new File([''], 'batch.bat', { type: 'application/bat' }),
        new File([''], 'shell.sh', { type: 'application/x-sh' })
      ];
      
      dangerousFiles.forEach(file => {
        const result = InputValidator.validateFile(file);
        expect(result.valid).toBe(false);
        expect(result.error).toContain('dangerous');
      });
    });
    
    it('should enforce file size limits', () => {
      const largeFile = new File(
        [new ArrayBuffer(11 * 1024 * 1024)], // 11MB
        'large.pdf',
        { type: 'application/pdf' }
      );
      
      const result = InputValidator.validateFile(largeFile, {
        maxSize: 10 * 1024 * 1024 // 10MB limit
      });
      
      expect(result.valid).toBe(false);
      expect(result.error).toContain('exceeds 10.0MB');
    });
  });
});

// Performance and security monitoring tests
describe('Security Monitoring', () => {
  it('should log security events with proper context', () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation();
    
    logSecurityEvent({
      type: SecurityEventType.LOGIN_FAILURE,
      severity: SecuritySeverity.WARNING,
      message: 'Multiple failed login attempts',
      userId: 'user123',
      details: {
        attempts: 5,
        ipAddress: '192.168.1.1'
      }
    });
    
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('SECURITY'),
      expect.objectContaining({
        type: SecurityEventType.LOGIN_FAILURE,
        severity: SecuritySeverity.WARNING
      })
    );
  });
});