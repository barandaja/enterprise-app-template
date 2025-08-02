/**
 * Password validation and strength checking utilities
 * Enforces strong password requirements for enhanced security
 */

export interface PasswordStrength {
  score: number; // 0-5
  feedback: string[];
  strength: 'very-weak' | 'weak' | 'fair' | 'strong' | 'very-strong';
  isAcceptable: boolean;
}

export interface PasswordRequirements {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  preventCommonPasswords: boolean;
  preventUserInfo: boolean;
  customBannedWords?: string[];
}

// Default password requirements
export const DEFAULT_PASSWORD_REQUIREMENTS: PasswordRequirements = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  preventCommonPasswords: true,
  preventUserInfo: true,
};

// Common weak passwords to block
const COMMON_PASSWORDS = [
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  'qwerty', 'abc123', '111111', '1234567', 'monkey', '1234567890',
  'password!', 'iloveyou', 'trustno1', 'dragon', 'baseball', 'football',
  'letmein', 'monkey123', '696969', 'shadow', 'master', '666666',
  'qwertyuiop', '123321', 'mustang', '1234567890', 'michael', '654321',
  'superman', '1qaz2wsx', '7777777', '121212', '000000', 'qazwsx',
  '123qwe', 'killer', 'trustno1', 'jordan', 'jennifer', 'zxcvbnm',
  'asdfgh', 'hunter', 'buster', 'soccer', 'harley', 'batman',
  'andrew', 'tigger', 'sunshine', 'iloveyou', '2000', 'charlie',
  'robert', 'thomas', 'hockey', 'ranger', 'daniel', 'starwars',
  'klaster', '112233', 'george', 'computer', 'michelle', 'jessica',
  'pepper', '1111', 'zxcvbn', '555555', '11111111', '131313',
  'freedom', '777777', 'pass', 'maggie', '159753', 'aaaaaa',
  'ginger', 'princess', 'joshua', 'cheese', 'amanda', 'summer',
  'love', 'ashley', 'nicole', 'chelsea', 'biteme', 'matthew',
  'access', 'yankees', '987654321', 'dallas', 'austin', 'thunder',
  'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'monitoring',
  'montana', 'moon', 'moscow', 'admin', 'adminadmin', 'root',
  'toor', 'pass', 'pass123', 'password1!', 'Password1', 'Password123',
  'Admin123', 'admin123', 'Root123', 'root123', 'letmein123',
  'welcome', 'welcome123', 'Welcome123', 'changeme', 'changeme123',
];

/**
 * Validates a password against specified requirements
 */
export function validatePassword(
  password: string,
  requirements: PasswordRequirements = DEFAULT_PASSWORD_REQUIREMENTS,
  userInfo?: { email?: string; username?: string; firstName?: string; lastName?: string }
): PasswordStrength {
  const feedback: string[] = [];
  let score = 0;

  // Check minimum length
  if (password.length < requirements.minLength) {
    feedback.push(`Password must be at least ${requirements.minLength} characters long`);
  } else {
    score += 1;
    // Bonus points for extra length
    if (password.length >= 16) score += 0.5;
    if (password.length >= 20) score += 0.5;
  }

  // Check character requirements
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  if (requirements.requireUppercase && !hasUppercase) {
    feedback.push('Password must contain at least one uppercase letter');
  } else if (hasUppercase) {
    score += 0.5;
  }

  if (requirements.requireLowercase && !hasLowercase) {
    feedback.push('Password must contain at least one lowercase letter');
  } else if (hasLowercase) {
    score += 0.5;
  }

  if (requirements.requireNumbers && !hasNumbers) {
    feedback.push('Password must contain at least one number');
  } else if (hasNumbers) {
    score += 0.5;
  }

  if (requirements.requireSpecialChars && !hasSpecialChars) {
    feedback.push('Password must contain at least one special character (!@#$%^&*...)');
  } else if (hasSpecialChars) {
    score += 0.5;
  }

  // Check for common passwords
  if (requirements.preventCommonPasswords) {
    const lowerPassword = password.toLowerCase();
    if (COMMON_PASSWORDS.includes(lowerPassword)) {
      feedback.push('This password is too common. Please choose a more unique password');
      score = Math.max(0, score - 2);
    }
  }

  // Check for user information in password
  if (requirements.preventUserInfo && userInfo) {
    const lowerPassword = password.toLowerCase();
    const userInfoValues = Object.values(userInfo)
      .filter(Boolean)
      .map(v => v!.toLowerCase());

    for (const info of userInfoValues) {
      if (info.length > 2 && lowerPassword.includes(info)) {
        feedback.push('Password should not contain personal information');
        score = Math.max(0, score - 1);
        break;
      }
    }
  }

  // Check custom banned words
  if (requirements.customBannedWords) {
    const lowerPassword = password.toLowerCase();
    for (const word of requirements.customBannedWords) {
      if (lowerPassword.includes(word.toLowerCase())) {
        feedback.push(`Password should not contain "${word}"`);
        score = Math.max(0, score - 0.5);
      }
    }
  }

  // Check for patterns
  if (hasRepeatingCharacters(password)) {
    feedback.push('Avoid repeating characters (e.g., "aaa", "111")');
    score = Math.max(0, score - 0.5);
  }

  if (hasSequentialCharacters(password)) {
    feedback.push('Avoid sequential characters (e.g., "abc", "123")');
    score = Math.max(0, score - 0.5);
  }

  if (hasKeyboardPatterns(password)) {
    feedback.push('Avoid keyboard patterns (e.g., "qwerty", "asdf")');
    score = Math.max(0, score - 0.5);
  }

  // Calculate entropy bonus
  const entropy = calculateEntropy(password);
  if (entropy > 50) score += 0.5;
  if (entropy > 70) score += 0.5;

  // Determine strength level
  let strength: PasswordStrength['strength'];
  if (score < 1) strength = 'very-weak';
  else if (score < 2) strength = 'weak';
  else if (score < 3) strength = 'fair';
  else if (score < 4) strength = 'strong';
  else strength = 'very-strong';

  // Password is acceptable if it meets all requirements and has at least fair strength
  const isAcceptable = feedback.length === 0 && score >= 2.5;

  return {
    score: Math.min(5, Math.max(0, score)),
    feedback,
    strength,
    isAcceptable,
  };
}

/**
 * Checks for repeating characters (e.g., "aaa", "111")
 */
function hasRepeatingCharacters(password: string): boolean {
  return /(.)\1{2,}/.test(password);
}

/**
 * Checks for sequential characters (e.g., "abc", "123")
 */
function hasSequentialCharacters(password: string): boolean {
  const sequences = [
    'abcdefghijklmnopqrstuvwxyz',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '0123456789',
    '9876543210',
  ];

  const lowerPassword = password.toLowerCase();
  for (const seq of sequences) {
    for (let i = 0; i < lowerPassword.length - 2; i++) {
      const substring = lowerPassword.substring(i, i + 3);
      if (seq.includes(substring)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Checks for keyboard patterns (e.g., "qwerty", "asdf")
 */
function hasKeyboardPatterns(password: string): boolean {
  const patterns = [
    'qwerty', 'asdfgh', 'zxcvbn', 'qazwsx', 'qwertyuiop',
    'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qweasd', '!@#$%^',
  ];

  const lowerPassword = password.toLowerCase();
  for (const pattern of patterns) {
    if (lowerPassword.includes(pattern) || lowerPassword.includes(pattern.split('').reverse().join(''))) {
      return true;
    }
  }
  return false;
}

/**
 * Calculates password entropy (bits)
 */
function calculateEntropy(password: string): number {
  let charsetSize = 0;

  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/\d/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

  return password.length * Math.log2(charsetSize);
}

/**
 * Password strength meter component props
 */
export interface PasswordStrengthMeterProps {
  password: string;
  requirements?: PasswordRequirements;
  userInfo?: { email?: string; username?: string; firstName?: string; lastName?: string };
  showFeedback?: boolean;
  className?: string;
}

/**
 * Generates a secure random password
 */
export function generateSecurePassword(
  length: number = 16,
  options: {
    includeUppercase?: boolean;
    includeLowercase?: boolean;
    includeNumbers?: boolean;
    includeSpecialChars?: boolean;
    excludeAmbiguous?: boolean;
  } = {}
): string {
  const {
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSpecialChars = true,
    excludeAmbiguous = true,
  } = options;

  let charset = '';
  let password = '';

  // Build character set
  if (includeLowercase) charset += excludeAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  if (includeUppercase) charset += excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeNumbers) charset += excludeAmbiguous ? '23456789' : '0123456789';
  if (includeSpecialChars) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  // Ensure at least one character from each required set
  const requiredChars: string[] = [];
  if (includeLowercase) requiredChars.push(getRandomChar(excludeAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz'));
  if (includeUppercase) requiredChars.push(getRandomChar(excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
  if (includeNumbers) requiredChars.push(getRandomChar(excludeAmbiguous ? '23456789' : '0123456789'));
  if (includeSpecialChars) requiredChars.push(getRandomChar('!@#$%^&*()_+-=[]{}|;:,.<>?'));

  // Generate remaining characters
  for (let i = requiredChars.length; i < length; i++) {
    password += getRandomChar(charset);
  }

  // Add required characters at random positions
  for (const char of requiredChars) {
    const position = Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / (0xffffffff + 1) * (password.length + 1));
    password = password.slice(0, position) + char + password.slice(position);
  }

  return password;
}

/**
 * Gets a random character from a string using crypto.getRandomValues
 */
function getRandomChar(str: string): string {
  const randomIndex = crypto.getRandomValues(new Uint32Array(1))[0] % str.length;
  return str[randomIndex];
}

/**
 * Password validation rules for form validation
 */
export const passwordValidationRules = (requirements: PasswordRequirements = DEFAULT_PASSWORD_REQUIREMENTS) => ({
  required: 'Password is required',
  minLength: {
    value: requirements.minLength,
    message: `Password must be at least ${requirements.minLength} characters`,
  },
  validate: (value: string) => {
    const result = validatePassword(value, requirements);
    return result.isAcceptable || result.feedback.join('. ');
  },
});

/**
 * Hook for password strength validation
 */
export function usePasswordStrength(
  password: string,
  requirements?: PasswordRequirements,
  userInfo?: { email?: string; username?: string; firstName?: string; lastName?: string }
): PasswordStrength {
  return validatePassword(password, requirements, userInfo);
}