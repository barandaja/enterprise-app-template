import React from 'react';
import { cn } from '../../utils';

// Input variant and size types
export type InputVariant = 'default' | 'filled' | 'flushed' | 'unstyled';
export type InputSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

export interface InputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  variant?: InputVariant;
  size?: InputSize;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  leftElement?: React.ReactNode;
  rightElement?: React.ReactNode;
  error?: string;
  helperText?: string;
  label?: string;
  required?: boolean;
  invalid?: boolean;
  focusBorderColor?: string;
  errorBorderColor?: string;
  isReadOnly?: boolean;
  isDisabled?: boolean;
  clearable?: boolean;
  onClear?: () => void;
  loading?: boolean;
  showRequiredIndicator?: boolean;
}

const inputVariants = {
  default: 'border border-gray-300 bg-white focus:border-primary-500 focus:ring-primary-500 dark:border-gray-600 dark:bg-gray-800 dark:focus:border-primary-400',
  filled: 'border-0 bg-gray-100 focus:bg-white focus:ring-2 focus:ring-primary-500 dark:bg-gray-700 dark:focus:bg-gray-800',
  flushed: 'border-0 border-b-2 border-gray-300 rounded-none bg-transparent focus:border-primary-500 focus:ring-0 dark:border-gray-600',
  unstyled: 'border-0 bg-transparent focus:ring-0 focus:outline-none'
};

const inputSizes = {
  xs: 'h-6 px-2 text-xs',
  sm: 'h-8 px-3 text-sm',
  md: 'h-10 px-3 text-sm',
  lg: 'h-11 px-4 text-base',
  xl: 'h-12 px-4 text-lg'
};

const LoadingSpinner = ({ size = 16 }: { size?: number }) => (
  <svg
    className="animate-spin text-gray-400"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <circle
      cx="12"
      cy="12"
      r="10"
      stroke="currentColor"
      strokeWidth="4"
      className="opacity-25"
    />
    <path
      fill="currentColor"
      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      className="opacity-75"
    />
  </svg>
);

const ClearButton = ({ onClear, size }: { onClear?: () => void; size: InputSize }) => {
  const iconSizes = {
    xs: 12,
    sm: 14,
    md: 16,
    lg: 18,
    xl: 20
  };

  return (
    <button
      type="button"
      onClick={onClear}
      className="text-gray-400 hover:text-gray-600 focus:outline-none focus:text-gray-600 dark:hover:text-gray-300 dark:focus:text-gray-300"
      aria-label="Clear input"
    >
      <svg
        width={iconSizes[size]}
        height={iconSizes[size]}
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <line x1="18" y1="6" x2="6" y2="18"></line>
        <line x1="6" y1="6" x2="18" y2="18"></line>
      </svg>
    </button>
  );
};

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({
    className,
    variant = 'default',
    size = 'md',
    leftIcon,
    rightIcon,
    leftElement,
    rightElement,
    error,
    helperText,
    label,
    required = false,
    invalid = false,
    isReadOnly = false,
    isDisabled = false,
    clearable = false,
    onClear,
    loading = false,
    showRequiredIndicator = true,
    id,
    ...props
  }, ref) => {
    const inputId = id || `input-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = invalid || !!error;
    const showClearButton = clearable && !isDisabled && !isReadOnly && props.value && !loading;
    
    // Calculate icon sizes based on input size
    const iconSizes = {
      xs: 12,
      sm: 14,
      md: 16,
      lg: 18,
      xl: 20
    };

    return (
      <div className="w-full">
        {/* Label */}
        {label && (
          <label
            htmlFor={inputId}
            className={cn(
              'block text-sm font-medium mb-1',
              hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
              isDisabled && 'opacity-50'
            )}
          >
            {label}
            {required && showRequiredIndicator && (
              <span className="text-red-500 ml-1" aria-label="required">
                *
              </span>
            )}
          </label>
        )}

        {/* Input Container */}
        <div className="relative">
          {/* Left Element/Icon */}
          {(leftIcon || leftElement) && (
            <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
              {leftElement || (
                <span 
                  className={cn(
                    'text-gray-400 dark:text-gray-500',
                    hasError && 'text-red-400'
                  )}
                  style={{ width: iconSizes[size], height: iconSizes[size] }}
                >
                  {leftIcon}
                </span>
              )}
            </div>
          )}

          {/* Input Field */}
          <input
            ref={ref}
            id={inputId}
            className={cn(
              // Base styles
              'w-full rounded-md transition-colors duration-200 focus:outline-none',
              // Variant styles
              inputVariants[variant],
              // Size styles
              inputSizes[size],
              // Padding adjustments for icons/elements
              (leftIcon || leftElement) && 'pl-10',
              (rightIcon || rightElement || showClearButton || loading) && 'pr-10',
              // Error styles
              hasError && variant !== 'unstyled' && 'border-red-500 focus:border-red-500 focus:ring-red-500 dark:border-red-400',
              // Disabled styles
              isDisabled && 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-900',
              // ReadOnly styles
              isReadOnly && 'bg-gray-50 focus:bg-gray-50 dark:bg-gray-900 dark:focus:bg-gray-900',
              className
            )}
            disabled={isDisabled}
            readOnly={isReadOnly}
            aria-invalid={hasError}
            aria-describedby={
              error ? `${inputId}-error` : helperText ? `${inputId}-helper` : undefined
            }
            {...props}
          />

          {/* Right Element/Icon/Clear/Loading */}
          {(rightIcon || rightElement || showClearButton || loading) && (
            <div className="absolute inset-y-0 right-0 flex items-center pr-3">
              {loading && <LoadingSpinner size={iconSizes[size]} />}
              {!loading && showClearButton && (
                <ClearButton onClear={onClear} size={size} />
              )}
              {!loading && !showClearButton && (rightElement || rightIcon) && (
                <span 
                  className={cn(
                    'text-gray-400 dark:text-gray-500',
                    hasError && 'text-red-400'
                  )}
                  style={{ width: iconSizes[size], height: iconSizes[size] }}
                >
                  {rightElement || rightIcon}
                </span>
              )}
            </div>
          )}
        </div>

        {/* Error Message */}
        {error && (
          <p
            id={`${inputId}-error`}
            className="mt-1 text-sm text-red-600 dark:text-red-400"
            role="alert"
          >
            {error}
          </p>
        )}

        {/* Helper Text */}
        {helperText && !error && (
          <p
            id={`${inputId}-helper`}
            className="mt-1 text-sm text-gray-500 dark:text-gray-400"
          >
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

// Textarea Component
export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  variant?: InputVariant;
  error?: string;
  helperText?: string;
  label?: string;
  required?: boolean;
  invalid?: boolean;
  isReadOnly?: boolean;
  isDisabled?: boolean;
  resize?: 'none' | 'both' | 'horizontal' | 'vertical';
  showRequiredIndicator?: boolean;
}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({
    className,
    variant = 'default',
    error,
    helperText,
    label,
    required = false,
    invalid = false,
    isReadOnly = false,
    isDisabled = false,
    resize = 'vertical',
    showRequiredIndicator = true,
    id,
    ...props
  }, ref) => {
    const textareaId = id || `textarea-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = invalid || !!error;

    const resizeClasses = {
      none: 'resize-none',
      both: 'resize',
      horizontal: 'resize-x',
      vertical: 'resize-y'
    };

    return (
      <div className="w-full">
        {/* Label */}
        {label && (
          <label
            htmlFor={textareaId}
            className={cn(
              'block text-sm font-medium mb-1',
              hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
              isDisabled && 'opacity-50'
            )}
          >
            {label}
            {required && showRequiredIndicator && (
              <span className="text-red-500 ml-1" aria-label="required">
                *
              </span>
            )}
          </label>
        )}

        {/* Textarea Field */}
        <textarea
          ref={ref}
          id={textareaId}
          className={cn(
            // Base styles
            'w-full px-3 py-2 rounded-md transition-colors duration-200 focus:outline-none min-h-[80px]',
            // Variant styles
            inputVariants[variant],
            // Resize styles
            resizeClasses[resize],
            // Error styles
            hasError && variant !== 'unstyled' && 'border-red-500 focus:border-red-500 focus:ring-red-500 dark:border-red-400',
            // Disabled styles
            isDisabled && 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-900',
            // ReadOnly styles
            isReadOnly && 'bg-gray-50 focus:bg-gray-50 dark:bg-gray-900 dark:focus:bg-gray-900',
            className
          )}
          disabled={isDisabled}
          readOnly={isReadOnly}
          aria-invalid={hasError}
          aria-describedby={
            error ? `${textareaId}-error` : helperText ? `${textareaId}-helper` : undefined
          }
          {...props}
        />

        {/* Error Message */}
        {error && (
          <p
            id={`${textareaId}-error`}
            className="mt-1 text-sm text-red-600 dark:text-red-400"
            role="alert"
          >
            {error}
          </p>
        )}

        {/* Helper Text */}
        {helperText && !error && (
          <p
            id={`${textareaId}-helper`}
            className="mt-1 text-sm text-gray-500 dark:text-gray-400"
          >
            {helperText}
          </p>
        )}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';

// Input Group Component for composite inputs
export interface InputGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  size?: InputSize;
}

export const InputGroup = React.forwardRef<HTMLDivElement, InputGroupProps>(
  ({ className, children, size = 'md', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'flex w-full',
          '[&>*:not(:first-child):not(:last-child)]:rounded-none',
          '[&>*:first-child]:rounded-r-none',
          '[&>*:last-child]:rounded-l-none',
          '[&>*:not(:first-child)]:border-l-0',
          className
        )}
        {...props}
      >
        {React.Children.map(children, (child) => {
          if (React.isValidElement(child) && (child.type === Input || child.type === Textarea)) {
            return React.cloneElement(child, {
              size: size || child.props.size,
            });
          }
          return child;
        })}
      </div>
    );
  }
);

InputGroup.displayName = 'InputGroup';

// Input Addon Components
export interface InputAddonProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  size?: InputSize;
}

export const InputLeftAddon = React.forwardRef<HTMLDivElement, InputAddonProps>(
  ({ className, children, size = 'md', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'flex items-center px-3 bg-gray-50 border border-r-0 border-gray-300 rounded-l-md text-gray-500 dark:bg-gray-700 dark:border-gray-600 dark:text-gray-400',
          inputSizes[size].split(' ')[0], // Get height from inputSizes
          className
        )}
        {...props}
      >
        {children}
      </div>
    );
  }
);

InputLeftAddon.displayName = 'InputLeftAddon';

export const InputRightAddon = React.forwardRef<HTMLDivElement, InputAddonProps>(
  ({ className, children, size = 'md', ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'flex items-center px-3 bg-gray-50 border border-l-0 border-gray-300 rounded-r-md text-gray-500 dark:bg-gray-700 dark:border-gray-600 dark:text-gray-400',
          inputSizes[size].split(' ')[0], // Get height from inputSizes
          className
        )}
        {...props}
      >
        {children}
      </div>
    );
  }
);

InputRightAddon.displayName = 'InputRightAddon';

export type { InputProps, TextareaProps, InputGroupProps, InputAddonProps };

/*
Usage Examples:

// Basic Input
<Input placeholder="Enter your name" />

// With label and helper text
<Input 
  label="Email" 
  placeholder="john@example.com"
  helperText="We'll never share your email."
/>

// With error
<Input 
  label="Password"
  type="password"
  error="Password must be at least 8 characters"
  invalid
/>

// With icons
<Input 
  leftIcon={<SearchIcon />}
  placeholder="Search..."
/>

// Clearable input
<Input 
  value={value}
  onChange={(e) => setValue(e.target.value)}
  clearable
  onClear={() => setValue('')}
/>

// Textarea
<Textarea 
  label="Description"
  placeholder="Enter description..."
  rows={4}
/>

// Input Group with addons
<InputGroup>
  <InputLeftAddon>https://</InputLeftAddon>
  <Input placeholder="example.com" />
  <InputRightAddon>.com</InputRightAddon>
</InputGroup>

// Different variants
<Input variant="filled" placeholder="Filled variant" />
<Input variant="flushed" placeholder="Flushed variant" />
<Input variant="unstyled" placeholder="Unstyled variant" />
*/