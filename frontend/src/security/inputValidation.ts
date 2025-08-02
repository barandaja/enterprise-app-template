/**
 * Comprehensive input validation and sanitization utilities
 * Prevents XSS, SQL injection, and other input-based attacks
 */

import DOMPurify from 'dompurify';
import { z } from 'zod';

/**
 * Input validation rules for different data types
 */
export const ValidationPatterns = {
  // Personal Information
  NAME: /^[a-zA-Z\s\-']{1,50}$/,
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  PHONE: /^[+]?[(]?[0-9]{3}[)]?[-\s.]?[0-9]{3}[-\s.]?[0-9]{4,6}$/,
  
  // Security
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  USERNAME: /^[a-zA-Z0-9_-]{3,20}$/,
  
  // Identifiers
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  ALPHANUMERIC: /^[a-zA-Z0-9]+$/,
  
  // URLs and Paths
  URL: /^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_+.~#?&//=]*)$/,
  PATH: /^[a-zA-Z0-9/_-]+$/,
  
  // Financial
  CREDIT_CARD: /^[0-9]{13,19}$/,
  CVV: /^[0-9]{3,4}$/,
  
  // Medical (HIPAA)
  SSN: /^(?!000|666)[0-9]{3}(?!00)[0-9]{2}(?!0000)[0-9]{4}$/,
  MRN: /^[A-Z0-9]{6,12}$/,
} as const;

/**
 * Sanitizer class for different types of content
 */
export class InputSanitizer {
  private static domPurifyConfig = {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br'],
    ALLOWED_ATTR: ['href', 'target'],
    ALLOW_DATA_ATTR: false,
  };

  /**
   * Sanitize HTML content (for rich text inputs)
   */
  static sanitizeHTML(input: string): string {
    return DOMPurify.sanitize(input, this.domPurifyConfig);
  }

  /**
   * Sanitize plain text (removes all HTML)
   */
  static sanitizeText(input: string): string {
    return DOMPurify.sanitize(input, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  }

  /**
   * Sanitize filename
   */
  static sanitizeFilename(filename: string): string {
    // Remove path traversal attempts
    let safe = filename.replace(/[\/\\]/g, '');
    // Remove special characters except dots and hyphens
    safe = safe.replace(/[^a-zA-Z0-9.-]/g, '_');
    // Ensure it doesn't start with a dot
    safe = safe.replace(/^\.+/, '');
    // Limit length
    return safe.substring(0, 255);
  }

  /**
   * Sanitize URL
   */
  static sanitizeURL(url: string): string | null {
    try {
      const parsed = new URL(url);
      // Only allow http and https protocols
      if (!['http:', 'https:'].includes(parsed.protocol)) {
        return null;
      }
      return parsed.toString();
    } catch {
      return null;
    }
  }

  /**
   * Sanitize SQL-like input (for search queries)
   */
  static sanitizeSearchQuery(query: string): string {
    // Remove SQL special characters
    return query
      .replace(/[';\\]/g, '')
      .replace(/--/g, '')
      .replace(/\/\*/g, '')
      .replace(/\*\//g, '')
      .trim();
  }

  /**
   * Sanitize JSON string
   */
  static sanitizeJSON(jsonString: string): object | null {
    try {
      const parsed = JSON.parse(jsonString);
      // Recursively sanitize string values
      return this.sanitizeObject(parsed);
    } catch {
      return null;
    }
  }

  /**
   * Recursively sanitize object values
   */
  private static sanitizeObject(obj: any): any {
    if (typeof obj === 'string') {
      return this.sanitizeText(obj);
    }
    if (Array.isArray(obj)) {
      return obj.map(item => this.sanitizeObject(item));
    }
    if (obj && typeof obj === 'object') {
      const sanitized: any = {};
      for (const [key, value] of Object.entries(obj)) {
        sanitized[this.sanitizeText(key)] = this.sanitizeObject(value);
      }
      return sanitized;
    }
    return obj;
  }
}

/**
 * Validator class for input validation
 */
export class InputValidator {
  /**
   * Validate email with additional checks
   */
  static validateEmail(email: string): { valid: boolean; error?: string } {
    if (!email) {
      return { valid: false, error: 'Email is required' };
    }

    if (!ValidationPatterns.EMAIL.test(email)) {
      return { valid: false, error: 'Invalid email format' };
    }

    // Additional checks
    const [localPart, domain] = email.split('@');
    
    // Check for consecutive dots
    if (email.includes('..')) {
      return { valid: false, error: 'Email cannot contain consecutive dots' };
    }

    // Check local part length
    if (localPart.length > 64) {
      return { valid: false, error: 'Email local part too long' };
    }

    // Check domain length
    if (domain.length > 255) {
      return { valid: false, error: 'Email domain too long' };
    }

    return { valid: true };
  }

  /**
   * Validate password strength
   */
  static validatePassword(password: string): { 
    valid: boolean; 
    score: number; 
    errors: string[] 
  } {
    const errors: string[] = [];
    let score = 0;

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters');
    } else {
      score += 1;
    }

    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain lowercase letters');
    } else {
      score += 1;
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain uppercase letters');
    } else {
      score += 1;
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain numbers');
    } else {
      score += 1;
    }

    if (!/[@$!%*?&]/.test(password)) {
      errors.push('Password must contain special characters (@$!%*?&)');
    } else {
      score += 1;
    }

    // Check for common patterns
    const commonPatterns = ['123', 'abc', 'password', 'qwerty'];
    for (const pattern of commonPatterns) {
      if (password.toLowerCase().includes(pattern)) {
        errors.push('Password contains common patterns');
        score = Math.max(0, score - 1);
        break;
      }
    }

    return {
      valid: errors.length === 0,
      score: Math.min(5, score),
      errors,
    };
  }

  /**
   * Validate credit card number using Luhn algorithm
   */
  static validateCreditCard(cardNumber: string): { valid: boolean; type?: string } {
    const cleaned = cardNumber.replace(/\s/g, '');
    
    if (!ValidationPatterns.CREDIT_CARD.test(cleaned)) {
      return { valid: false };
    }

    // Luhn algorithm
    let sum = 0;
    let isEven = false;
    
    for (let i = cleaned.length - 1; i >= 0; i--) {
      let digit = parseInt(cleaned[i], 10);
      
      if (isEven) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
      isEven = !isEven;
    }

    if (sum % 10 !== 0) {
      return { valid: false };
    }

    // Detect card type
    let type = 'unknown';
    if (/^4/.test(cleaned)) type = 'visa';
    else if (/^5[1-5]/.test(cleaned)) type = 'mastercard';
    else if (/^3[47]/.test(cleaned)) type = 'amex';
    else if (/^6(?:011|5)/.test(cleaned)) type = 'discover';

    return { valid: true, type };
  }

  /**
   * Validate file upload
   */
  static validateFile(file: File, options: {
    maxSize?: number;
    allowedTypes?: string[];
    allowedExtensions?: string[];
  } = {}): { valid: boolean; error?: string } {
    const {
      maxSize = 10 * 1024 * 1024, // 10MB default
      allowedTypes = [],
      allowedExtensions = [],
    } = options;

    // Check file size
    if (file.size > maxSize) {
      return { 
        valid: false, 
        error: `File size exceeds ${(maxSize / 1024 / 1024).toFixed(1)}MB` 
      };
    }

    // Check MIME type
    if (allowedTypes.length > 0 && !allowedTypes.includes(file.type)) {
      return { 
        valid: false, 
        error: `File type ${file.type} is not allowed` 
      };
    }

    // Check extension
    const extension = file.name.split('.').pop()?.toLowerCase();
    if (allowedExtensions.length > 0 && (!extension || !allowedExtensions.includes(extension))) {
      return { 
        valid: false, 
        error: `File extension .${extension} is not allowed` 
      };
    }

    // Check for potentially dangerous extensions
    const dangerousExtensions = ['exe', 'bat', 'cmd', 'sh', 'ps1', 'vbs', 'js', 'jar'];
    if (extension && dangerousExtensions.includes(extension)) {
      return { 
        valid: false, 
        error: 'Potentially dangerous file type' 
      };
    }

    return { valid: true };
  }
}

/**
 * Form validation schemas using Zod
 */
export const FormSchemas = {
  // User registration
  registration: z.object({
    email: z.string()
      .email('Invalid email address')
      .refine(email => InputValidator.validateEmail(email).valid, {
        message: 'Invalid email format',
      }),
    password: z.string()
      .min(8, 'Password must be at least 8 characters')
      .refine(password => InputValidator.validatePassword(password).valid, {
        message: 'Password does not meet security requirements',
      }),
    confirmPassword: z.string(),
    firstName: z.string()
      .min(1, 'First name is required')
      .max(50, 'First name too long')
      .regex(ValidationPatterns.NAME, 'Invalid characters in name'),
    lastName: z.string()
      .min(1, 'Last name is required')
      .max(50, 'Last name too long')
      .regex(ValidationPatterns.NAME, 'Invalid characters in name'),
    acceptTerms: z.boolean().refine(val => val === true, {
      message: 'You must accept the terms and conditions',
    }),
  }).refine(data => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }),

  // Profile update
  profileUpdate: z.object({
    firstName: z.string()
      .min(1, 'First name is required')
      .max(50, 'First name too long')
      .transform(val => InputSanitizer.sanitizeText(val)),
    lastName: z.string()
      .min(1, 'Last name is required')
      .max(50, 'Last name too long')
      .transform(val => InputSanitizer.sanitizeText(val)),
    bio: z.string()
      .max(500, 'Bio too long')
      .transform(val => InputSanitizer.sanitizeHTML(val))
      .optional(),
    phone: z.string()
      .regex(ValidationPatterns.PHONE, 'Invalid phone number')
      .optional()
      .or(z.literal('')),
    location: z.string()
      .max(100, 'Location too long')
      .transform(val => InputSanitizer.sanitizeText(val))
      .optional(),
  }),

  // Payment information (PCI compliance)
  payment: z.object({
    cardNumber: z.string()
      .refine(card => InputValidator.validateCreditCard(card).valid, {
        message: 'Invalid credit card number',
      }),
    cvv: z.string()
      .regex(ValidationPatterns.CVV, 'Invalid CVV'),
    expiryMonth: z.number().min(1).max(12),
    expiryYear: z.number().min(new Date().getFullYear()),
    cardholderName: z.string()
      .min(1, 'Cardholder name is required')
      .regex(ValidationPatterns.NAME, 'Invalid characters in name'),
  }),
};

/**
 * React hook for form validation
 */
export function useSecureForm<T extends z.ZodType>(
  schema: T,
  options: {
    sanitize?: boolean;
    validateOnChange?: boolean;
    validateOnBlur?: boolean;
  } = {}
) {
  const {
    sanitize = true,
    validateOnChange = false,
    validateOnBlur = true,
  } = options;

  // Implementation would integrate with react-hook-form
  // This is a placeholder for the actual implementation
  return {
    register: (name: string) => ({
      onChange: (e: React.ChangeEvent<HTMLInputElement>) => {
        let value = e.target.value;
        if (sanitize) {
          value = InputSanitizer.sanitizeText(value);
        }
        if (validateOnChange) {
          // Validate field
        }
      },
      onBlur: (e: React.FocusEvent<HTMLInputElement>) => {
        if (validateOnBlur) {
          // Validate field
        }
      },
    }),
    errors: {},
    isValid: true,
  };
}

/**
 * Security headers validator
 */
export function validateSecurityHeaders(headers: Headers): {
  missing: string[];
  warnings: string[];
} {
  const requiredHeaders = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Content-Security-Policy',
  ];

  const missing: string[] = [];
  const warnings: string[] = [];

  for (const header of requiredHeaders) {
    if (!headers.has(header)) {
      missing.push(header);
    }
  }

  // Check for weak CSP
  const csp = headers.get('Content-Security-Policy');
  if (csp && csp.includes('unsafe-inline')) {
    warnings.push('CSP contains unsafe-inline directive');
  }

  return { missing, warnings };
}