import React from 'react';
import { Input, InputProps } from './Input';
import { cn } from '../../utils';

// Number Input Component
export interface NumberInputProps extends Omit<InputProps, 'type' | 'value' | 'onChange'> {
  value?: number | string;
  onChange?: (value: number | undefined, event: React.ChangeEvent<HTMLInputElement>) => void;
  min?: number;
  max?: number;
  step?: number;
  precision?: number;
  allowNegative?: boolean;
  allowDecimal?: boolean;
  format?: 'standard' | 'currency' | 'percentage';
  currency?: string;
  locale?: string;
  showControls?: boolean;
  controlsPosition?: 'right' | 'left';
  onIncrement?: (value: number) => void;
  onDecrement?: (value: number) => void;
  clampValueOnBlur?: boolean;
  keepWithinRange?: boolean;
  thousandSeparator?: string;
  decimalSeparator?: string;
}

export const NumberInput = React.forwardRef<HTMLInputElement, NumberInputProps>(
  ({
    value = '',
    onChange,
    min,
    max,
    step = 1,
    precision,
    allowNegative = true,
    allowDecimal = true,
    format = 'standard',
    currency = 'USD',
    locale = 'en-US',
    showControls = false,
    controlsPosition = 'right',
    onIncrement,
    onDecrement,
    clampValueOnBlur = true,
    keepWithinRange = true,
    thousandSeparator = ',',
    decimalSeparator = '.',
    onFocus,
    onBlur,
    className,
    ...props
  }, ref) => {
    const [displayValue, setDisplayValue] = React.useState<string>('');
    const [isFocused, setIsFocused] = React.useState(false);
    const inputRef = React.useRef<HTMLInputElement>(null);

    // Combine refs
    React.useImperativeHandle(ref, () => inputRef.current!, []);

    // Convert value to number
    const parseValue = (val: string | number): number | undefined => {
      if (val === '' || val === null || val === undefined) return undefined;
      
      const num = typeof val === 'string' 
        ? parseFloat(val.replace(/[^\d.-]/g, ''))
        : val;
      
      return isNaN(num) ? undefined : num;
    };

    // Format number for display
    const formatNumber = (num: number | undefined, focused: boolean = false): string => {
      if (num === undefined || num === null || isNaN(num)) return '';
      
      // When focused, show raw number for editing
      if (focused) {
        return String(num);
      }

      try {
        switch (format) {
          case 'currency':
            return new Intl.NumberFormat(locale, {
              style: 'currency',
              currency,
              minimumFractionDigits: precision ?? 2,
              maximumFractionDigits: precision ?? 2
            }).format(num);
          
          case 'percentage':
            return new Intl.NumberFormat(locale, {
              style: 'percent',
              minimumFractionDigits: precision ?? 2,
              maximumFractionDigits: precision ?? 2
            }).format(num / 100);
          
          default:
            return new Intl.NumberFormat(locale, {
              minimumFractionDigits: precision,
              maximumFractionDigits: precision ?? (allowDecimal ? 10 : 0)
            }).format(num);
        }
      } catch (error) {
        return String(num);
      }
    };

    // Clamp value within range
    const clampValue = (val: number): number => {
      if (!keepWithinRange) return val;
      
      let clampedValue = val;
      if (min !== undefined && clampedValue < min) clampedValue = min;
      if (max !== undefined && clampedValue > max) clampedValue = max;
      
      return clampedValue;
    };

    // Apply precision
    const applyPrecision = (val: number): number => {
      if (precision === undefined) return val;
      return parseFloat(val.toFixed(precision));
    };

    // Validate input character
    const isValidInput = (char: string, currentValue: string): boolean => {
      // Allow control characters
      if (char.length !== 1) return true;
      
      // Allow digits
      if (/\d/.test(char)) return true;
      
      // Allow decimal separator
      if (allowDecimal && char === decimalSeparator && !currentValue.includes(decimalSeparator)) {
        return true;
      }
      
      // Allow negative sign at the beginning
      if (allowNegative && char === '-' && currentValue.length === 0) {
        return true;
      }
      
      return false;
    };

    // Update display value when value prop changes
    React.useEffect(() => {
      const numValue = parseValue(value);
      setDisplayValue(formatNumber(numValue, isFocused));
    }, [value, format, precision, currency, locale, isFocused]);

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const inputValue = e.target.value;
      
      // Allow empty value
      if (inputValue === '') {
        setDisplayValue('');
        onChange?.(undefined, e);
        return;
      }

      // Remove formatting for parsing
      const cleanValue = inputValue.replace(/[^\d.-]/g, '');
      const numValue = parseValue(cleanValue);
      
      if (numValue !== undefined) {
        // Apply constraints
        let finalValue = numValue;
        
        if (!allowNegative && finalValue < 0) {
          finalValue = Math.abs(finalValue);
        }
        
        if (!allowDecimal) {
          finalValue = Math.floor(finalValue);
        }
        
        if (keepWithinRange) {
          finalValue = clampValue(finalValue);
        }
        
        finalValue = applyPrecision(finalValue);
        
        setDisplayValue(isFocused ? String(finalValue) : formatNumber(finalValue));
        onChange?.(finalValue, e);
      }
    };

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      // Handle arrow keys for increment/decrement
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        handleIncrement();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        handleDecrement();
      }
      
      props.onKeyDown?.(e);
    };

    const handleFocus = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(true);
      const numValue = parseValue(value);
      setDisplayValue(numValue !== undefined ? String(numValue) : '');
      onFocus?.(e);
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      setIsFocused(false);
      
      const numValue = parseValue(displayValue);
      if (numValue !== undefined) {
        let finalValue = numValue;
        
        if (clampValueOnBlur) {
          finalValue = clampValue(finalValue);
        }
        
        finalValue = applyPrecision(finalValue);
        setDisplayValue(formatNumber(finalValue));
        
        // Trigger onChange if value changed due to clamping
        if (finalValue !== numValue) {
          onChange?.(finalValue, e as any);
        }
      }
      
      onBlur?.(e);
    };

    const handleIncrement = () => {
      const currentValue = parseValue(value) || 0;
      const newValue = applyPrecision(currentValue + step);
      const finalValue = keepWithinRange ? clampValue(newValue) : newValue;
      
      onIncrement?.(finalValue);
      onChange?.(finalValue, {} as React.ChangeEvent<HTMLInputElement>);
    };

    const handleDecrement = () => {
      const currentValue = parseValue(value) || 0;
      const newValue = applyPrecision(currentValue - step);
      const finalValue = keepWithinRange ? clampValue(newValue) : newValue;
      
      onDecrement?.(finalValue);
      onChange?.(finalValue, {} as React.ChangeEvent<HTMLInputElement>);
    };

    // Render controls
    const renderControls = () => (
      <div className="flex flex-col">
        <button
          type="button"
          onClick={handleIncrement}
          disabled={props.disabled || (max !== undefined && parseValue(value) >= max)}
          className="px-2 py-1 text-xs text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
          tabIndex={-1}
        >
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 15l7-7 7 7" />
          </svg>
        </button>
        <button
          type="button"
          onClick={handleDecrement}
          disabled={props.disabled || (min !== undefined && parseValue(value) <= min)}
          className="px-2 py-1 text-xs text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200 disabled:opacity-50 disabled:cursor-not-allowed"
          tabIndex={-1}
        >
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>
      </div>
    );

    return (
      <Input
        ref={inputRef}
        type="text"
        inputMode="numeric"
        value={displayValue}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onFocus={handleFocus}
        onBlur={handleBlur}
        leftElement={showControls && controlsPosition === 'left' ? renderControls() : undefined}
        rightElement={showControls && controlsPosition === 'right' ? renderControls() : undefined}
        className={cn(
          'text-right',
          className
        )}
        {...props}
      />
    );
  }
);

NumberInput.displayName = 'NumberInput';

// Phone Input Component
export interface PhoneInputProps extends Omit<InputProps, 'type' | 'value' | 'onChange'> {
  value?: string;
  onChange?: (value: string, event: React.ChangeEvent<HTMLInputElement>) => void;
  countryCode?: string;
  showCountryCode?: boolean;
  countries?: Array<{
    code: string;
    name: string;
    dialCode: string;
    flag?: string;
  }>;
  onCountryChange?: (country: string) => void;
  format?: 'national' | 'international' | 'e164';
  validateOnBlur?: boolean;
}

const defaultCountries = [
  { code: 'US', name: 'United States', dialCode: '+1', flag: '🇺🇸' },
  { code: 'CA', name: 'Canada', dialCode: '+1', flag: '🇨🇦' },
  { code: 'GB', name: 'United Kingdom', dialCode: '+44', flag: '🇬🇧' },
  { code: 'DE', name: 'Germany', dialCode: '+49', flag: '🇩🇪' },
  { code: 'FR', name: 'France', dialCode: '+33', flag: '🇫🇷' },
  { code: 'ES', name: 'Spain', dialCode: '+34', flag: '🇪🇸' },
  { code: 'IT', name: 'Italy', dialCode: '+39', flag: '🇮🇹' },
  { code: 'AU', name: 'Australia', dialCode: '+61', flag: '🇦🇺' },
  { code: 'JP', name: 'Japan', dialCode: '+81', flag: '🇯🇵' },
  { code: 'CN', name: 'China', dialCode: '+86', flag: '🇨🇳' },
];

export const PhoneInput = React.forwardRef<HTMLInputElement, PhoneInputProps>(
  ({
    value = '',
    onChange,
    countryCode = 'US',
    showCountryCode = true,
    countries = defaultCountries,
    onCountryChange,
    format = 'national',
    validateOnBlur = false,
    onBlur,
    ...props
  }, ref) => {
    const [selectedCountry, setSelectedCountry] = React.useState(
      countries.find(c => c.code === countryCode) || countries[0]
    );
    const [showCountryDropdown, setShowCountryDropdown] = React.useState(false);
    const [phoneError, setPhoneError] = React.useState<string>('');

    // Format phone number based on country and format
    const formatPhoneNumber = (phone: string, country: typeof selectedCountry): string => {
      if (!phone) return '';
      
      // Remove all non-digit characters
      const digits = phone.replace(/\D/g, '');
      
      switch (format) {
        case 'international':
          return `${country.dialCode} ${digits}`;
        case 'e164':
          return `${country.dialCode}${digits}`;
        case 'national':
        default:
          // Apply country-specific formatting
          if (country.code === 'US' || country.code === 'CA') {
            if (digits.length >= 10) {
              return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6, 10)}`;
            } else if (digits.length >= 6) {
              return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
            } else if (digits.length >= 3) {
              return `(${digits.slice(0, 3)}) ${digits.slice(3)}`;
            }
          }
          return digits;
      }
    };

    // Validate phone number
    const validatePhone = (phone: string): string => {
      if (!phone) return '';
      
      const digits = phone.replace(/\D/g, '');
      
      // Basic validation - at least 7 digits for most countries
      if (digits.length < 7) {
        return 'Phone number is too short';
      }
      
      // Country-specific validation
      if (selectedCountry.code === 'US' || selectedCountry.code === 'CA') {
        if (digits.length !== 10) {
          return 'Please enter a valid 10-digit phone number';
        }
      }
      
      return '';
    };

    const handlePhoneChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const inputValue = e.target.value;
      const formattedValue = formatPhoneNumber(inputValue, selectedCountry);
      
      if (phoneError) {
        setPhoneError('');
      }
      
      const syntheticEvent = {
        ...e,
        target: {
          ...e.target,
          value: formattedValue
        }
      };
      
      onChange?.(formattedValue, syntheticEvent);
    };

    const handleCountrySelect = (country: typeof selectedCountry) => {
      setSelectedCountry(country);
      setShowCountryDropdown(false);
      onCountryChange?.(country.code);
      
      // Reformat existing phone number with new country
      if (value) {
        const formattedValue = formatPhoneNumber(value, country);
        onChange?.(formattedValue, {} as React.ChangeEvent<HTMLInputElement>);
      }
    };

    const handleBlur = (e: React.FocusEvent<HTMLInputElement>) => {
      if (validateOnBlur && value) {
        const error = validatePhone(value);
        setPhoneError(error);
      }
      onBlur?.(e);
    };

    // Country selector component
    const CountrySelector = () => (
      <div className="relative">
        <button
          type="button"
          onClick={() => setShowCountryDropdown(!showCountryDropdown)}
          className="flex items-center px-3 py-2 text-sm border-r border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700 focus:outline-none"
          disabled={props.disabled}
        >
          <span className="mr-2">{selectedCountry.flag}</span>
          <span className="text-gray-600 dark:text-gray-400">{selectedCountry.dialCode}</span>
          <svg className="w-4 h-4 ml-1 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </button>

        {showCountryDropdown && (
          <div className="absolute z-50 left-0 top-full mt-1 w-64 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md shadow-lg max-h-60 overflow-auto">
            {countries.map((country) => (
              <button
                key={country.code}
                type="button"
                onClick={() => handleCountrySelect(country)}
                className="w-full flex items-center px-3 py-2 text-sm text-left hover:bg-gray-100 dark:hover:bg-gray-700 focus:outline-none focus:bg-gray-100 dark:focus:bg-gray-700"
              >
                <span className="mr-3">{country.flag}</span>
                <span className="flex-1">{country.name}</span>
                <span className="text-gray-500 dark:text-gray-400">{country.dialCode}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    );

    return (
      <div className="relative">
        <Input
          ref={ref}
          type="tel"
          value={value}
          onChange={handlePhoneChange}
          onBlur={handleBlur}
          leftElement={showCountryCode ? <CountrySelector /> : undefined}
          error={phoneError || props.error}
          {...props}
        />
        
        {/* Click outside handler for dropdown */}
        {showCountryDropdown && (
          <div
            className="fixed inset-0 z-40"
            onClick={() => setShowCountryDropdown(false)}
          />
        )}
      </div>
    );
  }
);

PhoneInput.displayName = 'PhoneInput';

export type { NumberInputProps, PhoneInputProps };

/*
Usage Examples:

// Basic NumberInput
<NumberInput
  label="Age"
  min={0}
  max={120}
  showControls
/>

// Currency NumberInput
<NumberInput
  label="Price"
  format="currency"
  currency="USD"
  precision={2}
  min={0}
  showControls
  controlsPosition="right"
/>

// Percentage NumberInput
<NumberInput
  label="Discount"
  format="percentage"
  min={0}
  max={100}
  step={5}
/>

// NumberInput with custom formatting
<NumberInput
  label="Quantity"
  allowDecimal={false}
  showControls
  min={1}
  step={1}
  onIncrement={(value) => console.log('Incremented to:', value)}
  onDecrement={(value) => console.log('Decremented to:', value)}
/>

// Basic PhoneInput
<PhoneInput
  label="Phone Number"
  countryCode="US"
  validateOnBlur
/>

// PhoneInput with custom countries
<PhoneInput
  label="Contact Number"
  showCountryCode={true}
  format="international"
  countries={[
    { code: 'US', name: 'United States', dialCode: '+1', flag: '🇺🇸' },
    { code: 'UK', name: 'United Kingdom', dialCode: '+44', flag: '🇬🇧' },
    { code: 'DE', name: 'Germany', dialCode: '+49', flag: '🇩🇪' }
  ]}
  onCountryChange={(country) => console.log('Country changed to:', country)}
/>

// PhoneInput with E164 format
<PhoneInput
  label="Mobile Number"
  format="e164"
  validateOnBlur
  helperText="Enter your mobile number for SMS notifications"
/>
*/