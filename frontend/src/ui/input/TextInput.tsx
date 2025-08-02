import React from 'react';
import { Input, InputProps } from './Input';
import { cn } from '../../utils';

// Enhanced TextInput with additional features
export interface TextInputProps extends Omit<InputProps, 'type'> {
  mask?: string;
  transform?: 'none' | 'uppercase' | 'lowercase' | 'capitalize';
  maxLength?: number;
  showCharacterCount?: boolean;
  autoComplete?: 'name' | 'given-name' | 'family-name' | 'organization' | 'street-address' | 'address-line1' | 'address-line2' | 'postal-code' | 'country' | 'username' | 'off';
  pattern?: string;
  suggestions?: string[];
  onSuggestionSelect?: (suggestion: string) => void;
}

export const TextInput = React.forwardRef<HTMLInputElement, TextInputProps>(
  ({
    mask,
    transform = 'none',
    maxLength,
    showCharacterCount = false,
    autoComplete,
    pattern,
    suggestions = [],
    onSuggestionSelect,
    value = '',
    onChange,
    onFocus,
    onBlur,
    className,
    helperText,
    ...props
  }, ref) => {
    const [isFocused, setIsFocused] = React.useState(false);
    const [showSuggestions, setShowSuggestions] = React.useState(false);
    const [filteredSuggestions, setFilteredSuggestions] = React.useState<string[]>([]);
    const [selectedSuggestionIndex, setSelectedSuggestionIndex] = React.useState(-1);
    const inputRef = React.useRef<HTMLInputElement>(null);
    const suggestionsRef = React.useRef<HTMLUListElement>(null);

    // Combine refs
    React.useImperativeHandle(ref, () => inputRef.current!, []);

    // Apply text transformation
    const transformText = (text: string): string => {
      switch (transform) {
        case 'uppercase':
          return text.toUpperCase();
        case 'lowercase':
          return text.toLowerCase();
        case 'capitalize':
          return text
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
            .join(' ');
        default:
          return text;
      }
    };

    // Apply input mask
    const applyMask = (value: string, mask: string): string => {
      if (!mask) return value;
      
      let result = '';
      let maskIndex = 0;
      let valueIndex = 0;
      
      while (maskIndex < mask.length && valueIndex < value.length) {
        const maskChar = mask[maskIndex];
        const valueChar = value[valueIndex];
        
        if (maskChar === '9') {
          // Numeric character
          if (/\d/.test(valueChar)) {
            result += valueChar;
            valueIndex++;
          } else {
            break;
          }
        } else if (maskChar === 'A') {
          // Alphabetic character
          if (/[a-zA-Z]/.test(valueChar)) {
            result += valueChar;
            valueIndex++;
          } else {
            break;
          }
        } else if (maskChar === '*') {
          // Any character
          result += valueChar;
          valueIndex++;
        } else {
          // Literal character
          result += maskChar;
          if (valueChar === maskChar) {
            valueIndex++;
          }
        }
        maskIndex++;
      }
      
      return result;
    };

    // Sanitize suggestion to prevent XSS
    const sanitizeSuggestion = (text: string): string => {
      // Remove any HTML tags and encode special characters
      return String(text)
        .replace(/[<>]/g, '') // Remove angle brackets
        .replace(/javascript:/gi, '') // Remove javascript: protocol
        .replace(/on\w+\s*=/gi, ''); // Remove event handlers
    };

    // Filter suggestions based on input value
    React.useEffect(() => {
      if (suggestions.length > 0 && typeof value === 'string' && value.length > 0) {
        const filtered = suggestions
          .map(sanitizeSuggestion) // Sanitize all suggestions
          .filter(suggestion =>
            suggestion.toLowerCase().includes(value.toLowerCase())
          );
        setFilteredSuggestions(filtered);
        setShowSuggestions(isFocused && filtered.length > 0);
      } else {
        setShowSuggestions(false);
        setFilteredSuggestions([]);
      }
      setSelectedSuggestionIndex(-1);
    }, [value, suggestions, isFocused]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      let newValue = e.target.value;
      
      // Apply mask if provided
      if (mask) {
        newValue = applyMask(newValue, mask);
      }
      
      // Apply text transformation
      if (transform !== 'none') {
        newValue = transformText(newValue);
      }
      
      // Create new event with transformed value
      const newEvent = {
        ...e,
        target: {
          ...e.target,
          value: newValue
        }
      };
      
      onChange?.(newEvent);
    };

    const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(true);
      onFocus?.(e);
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      // Delay blur to allow suggestion click
      setTimeout(() => {
        setIsFocused(false);
        setShowSuggestions(false);
        setSelectedSuggestionIndex(-1);
      }, 150);
      onBlur?.(e);
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (showSuggestions && filteredSuggestions.length > 0) {
        switch (e.key) {
          case 'ArrowDown':
            e.preventDefault();
            setSelectedSuggestionIndex(prev => 
              prev < filteredSuggestions.length - 1 ? prev + 1 : 0
            );
            break;
          case 'ArrowUp':
            e.preventDefault();
            setSelectedSuggestionIndex(prev => 
              prev > 0 ? prev - 1 : filteredSuggestions.length - 1
            );
            break;
          case 'Enter':
            e.preventDefault();
            if (selectedSuggestionIndex >= 0) {
              handleSuggestionSelect(filteredSuggestions[selectedSuggestionIndex]);
            }
            break;
          case 'Escape':
            setShowSuggestions(false);
            setSelectedSuggestionIndex(-1);
            break;
        }
      }
      
      props.onKeyDown?.(e);
    };

    const handleSuggestionSelect = (suggestion: string) => {
      onSuggestionSelect?.(suggestion);
      setShowSuggestions(false);
      setSelectedSuggestionIndex(-1);
      
      // Create synthetic change event
      if (onChange) {
        const syntheticEvent = {
          target: { value: suggestion },
          currentTarget: { value: suggestion }
        } as React.ChangeEvent<HTMLInputElement>;
        onChange(syntheticEvent);
      }
    };

    // Character count
    const characterCount = typeof value === 'string' ? value.length : 0;
    const showCount = showCharacterCount && (maxLength || characterCount > 0);
    const countText = maxLength ? `${characterCount}/${maxLength}` : `${characterCount}`;
    const isOverLimit = maxLength && characterCount > maxLength;

    // Helper text with character count
    const enhancedHelperText = showCount 
      ? `${helperText || ''}${helperText ? ' ' : ''}${countText}`
      : helperText;

    return (
      <div className="relative">
        <Input
          ref={inputRef}
          type="text"
          value={value}
          onChange={handleChange}
          onFocus={handleFocus}
          onBlur={handleBlur}
          onKeyDown={handleKeyDown}
          maxLength={maxLength}
          autoComplete={autoComplete}
          pattern={pattern}
          helperText={enhancedHelperText}
          className={cn(
            isOverLimit && 'border-red-500 focus:border-red-500 focus:ring-red-500',
            className
          )}
          {...props}
        />

        {/* Suggestions Dropdown */}
        {showSuggestions && filteredSuggestions.length > 0 && (
          <ul
            ref={suggestionsRef}
            className="absolute z-50 w-full mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-lg max-h-60 overflow-auto"
            role="listbox"
          >
            {filteredSuggestions.map((suggestion, index) => (
              <li
                key={index}
                className={cn(
                  'px-3 py-2 cursor-pointer text-sm',
                  index === selectedSuggestionIndex
                    ? 'bg-primary-100 dark:bg-primary-900 text-primary-900 dark:text-primary-100'
                    : 'text-gray-900 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-700'
                )}
                onClick={() => handleSuggestionSelect(suggestion)}
                role="option"
                aria-selected={index === selectedSuggestionIndex}
                dangerouslySetInnerHTML={undefined} // Explicitly prevent dangerous HTML
              >
                {/* Safely render text content only */}
                {String(suggestion)}
              </li>
            ))}
          </ul>
        )}
      </div>
    );
  }
);

TextInput.displayName = 'TextInput';

// Email Input Component
export interface EmailInputProps extends Omit<TextInputProps, 'type' | 'autoComplete' | 'pattern'> {
  suggestions?: string[];
  domains?: string[];
  validateOnBlur?: boolean;
}

export const EmailInput = React.forwardRef<HTMLInputElement, EmailInputProps>(
  ({
    suggestions = [],
    domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'],
    validateOnBlur = true,
    value = '',
    onChange,
    onBlur,
    ...props
  }, ref) => {
    const [emailError, setEmailError] = React.useState<string>('');

    // Generate email suggestions based on domains
    const generateEmailSuggestions = (inputValue: string): string[] => {
      if (!inputValue.includes('@') && inputValue.length > 0) {
        return domains.map(domain => `${inputValue}@${domain}`);
      }
      return suggestions;
    };

    const validateEmail = (email: string): string => {
      if (!email) return '';
      
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(email)) {
        return 'Please enter a valid email address';
      }
      
      return '';
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      if (validateOnBlur && value) {
        const error = validateEmail(String(value));
        setEmailError(error);
      }
      onBlur?.(e);
    };

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      if (emailError) {
        setEmailError('');
      }
      onChange?.(e);
    };

    return (
      <TextInput
        ref={ref}
        value={value}
        onChange={handleChange}
        onBlur={handleBlur}
        autoComplete="email"
        suggestions={generateEmailSuggestions(String(value))}
        error={emailError || props.error}
        transform="lowercase"
        {...props}
      />
    );
  }
);

EmailInput.displayName = 'EmailInput';

// Password Input Component
export interface PasswordInputProps extends Omit<TextInputProps, 'type' | 'autoComplete'> {
  showStrengthMeter?: boolean;
  strengthRules?: {
    minLength?: number;
    requireUppercase?: boolean;
    requireLowercase?: boolean;
    requireNumbers?: boolean;
    requireSpecialChars?: boolean;
  };
  showToggle?: boolean;
  confirmPassword?: string;
  showConfirmation?: boolean;
  onStrengthChange?: (strength: number) => void;
}

export const PasswordInput = React.forwardRef<HTMLInputElement, PasswordInputProps>(
  ({
    showStrengthMeter = false,
    strengthRules = {
      minLength: 8,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true
    },
    showToggle = true,
    confirmPassword,
    showConfirmation = false,
    onStrengthChange,
    value = '',
    ...props
  }, ref) => {
    const [showPassword, setShowPassword] = React.useState(false);
    const [strength, setStrength] = React.useState(0);

    // Calculate password strength
    React.useEffect(() => {
      if (typeof value !== 'string') return;

      let score = 0;
      const rules = strengthRules;

      if (rules.minLength && value.length >= rules.minLength) score++;
      if (rules.requireUppercase && /[A-Z]/.test(value)) score++;
      if (rules.requireLowercase && /[a-z]/.test(value)) score++;
      if (rules.requireNumbers && /\d/.test(value)) score++;
      if (rules.requireSpecialChars && /[!@#$%^&*(),.?":{}|<>]/.test(value)) score++;

      const totalRules = Object.values(rules).filter(Boolean).length;
      const strengthPercentage = totalRules > 0 ? (score / totalRules) * 100 : 0;

      setStrength(strengthPercentage);
      onStrengthChange?.(strengthPercentage);
    }, [value, strengthRules, onStrengthChange]);

    const getStrengthColor = () => {
      if (strength < 25) return 'bg-red-500';
      if (strength < 50) return 'bg-orange-500';
      if (strength < 75) return 'bg-yellow-500';
      return 'bg-green-500';
    };

    const getStrengthText = () => {
      if (strength < 25) return 'Weak';
      if (strength < 50) return 'Fair';
      if (strength < 75) return 'Good';
      return 'Strong';
    };

    const togglePasswordVisibility = () => {
      setShowPassword(!showPassword);
    };

    return (
      <div className="space-y-2">
        <TextInput
          ref={ref}
          type={showPassword ? 'text' : 'password'}
          value={value}
          autoComplete="new-password"
          rightElement={
            showToggle ? (
              <button
                type="button"
                onClick={togglePasswordVisibility}
                className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 focus:outline-none"
                tabIndex={-1}
              >
                {showPassword ? (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.878 9.878L3 3m6.878 6.878L21 21" />
                  </svg>
                ) : (
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                )}
              </button>
            ) : undefined
          }
          {...props}
        />

        {/* Password Strength Meter */}
        {showStrengthMeter && value && (
          <div className="space-y-1">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Password strength</span>
              <span className={cn(
                'font-medium',
                strength < 25 && 'text-red-600',
                strength >= 25 && strength < 50 && 'text-orange-600',
                strength >= 50 && strength < 75 && 'text-yellow-600',
                strength >= 75 && 'text-green-600'
              )}>
                {getStrengthText()}
              </span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2 dark:bg-gray-700">
              <div
                className={cn('h-2 rounded-full transition-all duration-300', getStrengthColor())}
                style={{ width: `${strength}%` }}
              />
            </div>
          </div>
        )}

        {/* Password Confirmation */}
        {showConfirmation && (
          <TextInput
            type={showPassword ? 'text' : 'password'}
            label="Confirm Password"
            placeholder="Confirm your password"
            autoComplete="new-password"
            error={
              confirmPassword && value !== confirmPassword
                ? "Passwords don't match"
                : undefined
            }
          />
        )}
      </div>
    );
  }
);

PasswordInput.displayName = 'PasswordInput';

export type { TextInputProps, EmailInputProps, PasswordInputProps };

/*
Usage Examples:

// Basic TextInput with mask
<TextInput
  label="Phone Number"
  mask="(999) 999-9999"
  placeholder="(123) 456-7890"
/>

// TextInput with text transformation
<TextInput
  label="Full Name"
  transform="capitalize"
  showCharacterCount
  maxLength={50}
/>

// TextInput with suggestions
<TextInput
  label="City"
  suggestions={['New York', 'Los Angeles', 'Chicago', 'Houston']}
  onSuggestionSelect={(city) => console.log('Selected:', city)}
/>

// Email Input
<EmailInput
  label="Email Address"
  validateOnBlur
  domains={['company.com', 'gmail.com', 'outlook.com']}
/>

// Password Input with strength meter
<PasswordInput
  label="Password"
  showStrengthMeter
  showToggle
  strengthRules={{
    minLength: 12,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true
  }}
  onStrengthChange={(strength) => console.log('Strength:', strength)}
/>

// Password with confirmation
<PasswordInput
  label="New Password"
  showConfirmation
  confirmPassword={confirmPasswordValue}
  showStrengthMeter
/>
*/