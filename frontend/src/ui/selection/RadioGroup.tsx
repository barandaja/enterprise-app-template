import React from 'react';
import { cn } from '../../utils';

// Radio Option interface
export interface RadioOption {
  value: string | number;
  label: string;
  description?: string;
  disabled?: boolean;
  icon?: React.ReactNode;
}

// RadioGroup Props
export interface RadioGroupProps extends Omit<React.HTMLAttributes<HTMLFieldSetElement>, 'onChange'> {
  options: RadioOption[];
  value?: string | number;
  onChange?: (value: string | number, option: RadioOption) => void;
  name?: string;
  label?: string;
  description?: string;
  error?: string;
  helperText?: string;
  required?: boolean;
  disabled?: boolean;
  orientation?: 'horizontal' | 'vertical';
  size?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'card' | 'button';
  colorScheme?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger';
  spacing?: 'sm' | 'md' | 'lg';
  renderOption?: (option: RadioOption, isSelected: boolean, isDisabled: boolean) => React.ReactNode;
}

export const RadioGroup = React.forwardRef<HTMLFieldSetElement, RadioGroupProps>(
  ({
    options = [],
    value,
    onChange,
    name,
    label,
    description,
    error,
    helperText,
    required = false,
    disabled = false,
    orientation = 'vertical',
    size = 'md',
    variant = 'default',
    colorScheme = 'primary',
    spacing = 'md',
    renderOption,
    className,
    ...props
  }, ref) => {
    const groupId = name || `radio-group-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = !!error;

    const handleOptionChange = (option: RadioOption) => {
      if (option.disabled || disabled) return;
      onChange?.(option.value, option);
    };

    const sizeClasses = {
      sm: {
        radio: 'h-3 w-3',
        text: 'text-sm',
        spacing: 'space-y-2'
      },
      md: {
        radio: 'h-4 w-4',
        text: 'text-sm',
        spacing: 'space-y-3'
      },
      lg: {
        radio: 'h-5 w-5',
        text: 'text-base',
        spacing: 'space-y-4'
      }
    };

    const spacingClasses = {
      sm: orientation === 'vertical' ? 'space-y-2' : 'space-x-3',
      md: orientation === 'vertical' ? 'space-y-3' : 'space-x-4',
      lg: orientation === 'vertical' ? 'space-y-4' : 'space-x-6'
    };

    const colorSchemeClasses = {
      primary: {
        radio: 'text-primary-600 focus:ring-primary-500',
        button: 'checked:bg-primary-600 checked:border-primary-600 checked:text-white'
      },
      secondary: {
        radio: 'text-gray-600 focus:ring-gray-500',
        button: 'checked:bg-gray-600 checked:border-gray-600 checked:text-white'
      },
      success: {
        radio: 'text-green-600 focus:ring-green-500',
        button: 'checked:bg-green-600 checked:border-green-600 checked:text-white'
      },
      warning: {
        radio: 'text-yellow-600 focus:ring-yellow-500',
        button: 'checked:bg-yellow-600 checked:border-yellow-600 checked:text-white'
      },
      danger: {
        radio: 'text-red-600 focus:ring-red-500',
        button: 'checked:bg-red-600 checked:border-red-600 checked:text-white'
      }
    };

    const renderRadioOption = (option: RadioOption, index: number) => {
      const isSelected = option.value === value;
      const isDisabled = option.disabled || disabled;
      const optionId = `${groupId}-${index}`;

      if (renderOption) {
        return (
          <div key={option.value} className="relative">
            {renderOption(option, isSelected, isDisabled)}
            <input
              type="radio"
              id={optionId}
              name={groupId}
              value={option.value}
              checked={isSelected}
              onChange={() => handleOptionChange(option)}
              disabled={isDisabled}
              className="absolute opacity-0 inset-0 w-full h-full cursor-pointer disabled:cursor-not-allowed"
              aria-describedby={option.description ? `${optionId}-description` : undefined}
            />
          </div>
        );
      }

      switch (variant) {
        case 'card':
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative flex items-start p-4 border rounded-lg cursor-pointer focus-within:ring-2 focus-within:ring-offset-2',
                isSelected 
                  ? 'border-primary-300 bg-primary-50 dark:border-primary-600 dark:bg-primary-900/20'
                  : 'border-gray-300 bg-white hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:hover:bg-gray-700',
                isDisabled && 'opacity-50 cursor-not-allowed bg-gray-50 dark:bg-gray-900',
                hasError && 'border-red-300 dark:border-red-600',
                `focus-within:ring-${colorScheme}-500`
              )}
            >
              <input
                type="radio"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className={cn(
                  'mt-1 border-gray-300 focus:ring-2 focus:ring-offset-0',
                  sizeClasses[size].radio,
                  colorSchemeClasses[colorScheme].radio,
                  'dark:border-gray-600 dark:bg-gray-700'
                )}
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              <div className="ml-3 flex-1 min-w-0">
                <div className={cn(
                  'font-medium',
                  sizeClasses[size].text,
                  isSelected ? 'text-primary-900 dark:text-primary-100' : 'text-gray-900 dark:text-gray-100'
                )}>
                  {option.icon && <span className="mr-2">{option.icon}</span>}
                  {option.label}
                </div>
                {option.description && (
                  <p
                    id={`${optionId}-description`}
                    className="text-sm text-gray-500 dark:text-gray-400 mt-1"
                  >
                    {option.description}
                  </p>
                )}
              </div>
            </label>
          );

        case 'button':
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative inline-flex items-center justify-center px-4 py-2 border font-medium rounded-md cursor-pointer focus-within:ring-2 focus-within:ring-offset-2 transition-colors',
                isSelected
                  ? colorSchemeClasses[colorScheme].button
                  : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50 dark:border-gray-600 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700',
                isDisabled && 'opacity-50 cursor-not-allowed',
                hasError && !isSelected && 'border-red-300 dark:border-red-600',
                sizeClasses[size].text,
                `focus-within:ring-${colorScheme}-500`
              )}
            >
              <input
                type="radio"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className="sr-only"
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              {option.icon && <span className="mr-2">{option.icon}</span>}
              {option.label}
            </label>
          );

        default:
          return (
            <label
              key={option.value}
              htmlFor={optionId}
              className={cn(
                'relative flex items-start cursor-pointer',
                isDisabled && 'opacity-50 cursor-not-allowed'
              )}
            >
              <input
                type="radio"
                id={optionId}
                name={groupId}
                value={option.value}
                checked={isSelected}
                onChange={() => handleOptionChange(option)}
                disabled={isDisabled}
                className={cn(
                  'mt-1 border-gray-300 focus:ring-2 focus:ring-offset-2',
                  sizeClasses[size].radio,
                  colorSchemeClasses[colorScheme].radio,
                  'dark:border-gray-600 dark:bg-gray-700'
                )}
                aria-describedby={option.description ? `${optionId}-description` : undefined}
              />
              <div className="ml-3 flex-1 min-w-0">
                <div className={cn(
                  'font-medium',
                  sizeClasses[size].text,
                  'text-gray-900 dark:text-gray-100'
                )}>
                  {option.icon && <span className="mr-2">{option.icon}</span>}
                  {option.label}
                </div>
                {option.description && (
                  <p
                    id={`${optionId}-description`}
                    className="text-sm text-gray-500 dark:text-gray-400 mt-1"
                  >
                    {option.description}
                  </p>
                )}
              </div>
            </label>
          );
      }
    };

    return (
      <fieldset
        ref={ref}
        className={cn('space-y-2', className)}
        disabled={disabled}
        {...props}
      >
        {/* Legend/Label */}
        {label && (
          <legend className={cn(
            'text-sm font-medium mb-2',
            hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300'
          )}>
            {label}
            {required && <span className="text-red-500 ml-1">*</span>}
          </legend>
        )}

        {/* Description */}
        {description && (
          <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
            {description}
          </p>
        )}

        {/* Options */}
        <div
          className={cn(
            orientation === 'vertical' ? 'space-y-0' : 'flex flex-wrap',
            spacingClasses[spacing]
          )}
          role="radiogroup"
          aria-labelledby={label ? `${groupId}-legend` : undefined}
        >
          {options.map((option, index) => renderRadioOption(option, index))}
        </div>

        {/* Helper Text */}
        {helperText && !error && (
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            {helperText}
          </p>
        )}

        {/* Error Message */}
        {error && (
          <p className="text-sm text-red-600 dark:text-red-400 mt-2" role="alert">
            {error}
          </p>
        )}
      </fieldset>
    );
  }
);

RadioGroup.displayName = 'RadioGroup';

// Individual Radio Component
export interface RadioProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string;
  description?: string;
  size?: 'sm' | 'md' | 'lg';
  colorScheme?: 'primary' | 'secondary' | 'success' | 'warning' | 'danger';
  error?: boolean;
}

export const Radio = React.forwardRef<HTMLInputElement, RadioProps>(
  ({
    label,
    description,
    size = 'md',
    colorScheme = 'primary',
    error = false,
    className,
    disabled,
    id,
    ...props
  }, ref) => {
    const radioId = id || `radio-${Math.random().toString(36).substr(2, 9)}`;

    const sizeClasses = {
      sm: { radio: 'h-3 w-3', text: 'text-sm' },
      md: { radio: 'h-4 w-4', text: 'text-sm' },
      lg: { radio: 'h-5 w-5', text: 'text-base' }
    };

    const colorSchemeClasses = {
      primary: 'text-primary-600 focus:ring-primary-500',
      secondary: 'text-gray-600 focus:ring-gray-500',
      success: 'text-green-600 focus:ring-green-500',
      warning: 'text-yellow-600 focus:ring-yellow-500',
      danger: 'text-red-600 focus:ring-red-500'
    };

    return (
      <label
        htmlFor={radioId}
        className={cn(
          'relative flex items-start cursor-pointer',
          disabled && 'opacity-50 cursor-not-allowed',
          className
        )}
      >
        <input
          ref={ref}
          type="radio"
          id={radioId}
          className={cn(
            'mt-1 border-gray-300 focus:ring-2 focus:ring-offset-2',
            sizeClasses[size].radio,
            colorSchemeClasses[colorScheme],
            error && 'border-red-500 focus:ring-red-500',
            'dark:border-gray-600 dark:bg-gray-700'
          )}
          disabled={disabled}
          aria-describedby={description ? `${radioId}-description` : undefined}
          {...props}
        />
        {(label || description) && (
          <div className="ml-3 flex-1 min-w-0">
            {label && (
              <div className={cn(
                'font-medium',
                sizeClasses[size].text,
                error ? 'text-red-700 dark:text-red-400' : 'text-gray-900 dark:text-gray-100'
              )}>
                {label}
              </div>
            )}
            {description && (
              <p
                id={`${radioId}-description`}
                className="text-sm text-gray-500 dark:text-gray-400 mt-1"
              >
                {description}
              </p>
            )}
          </div>
        )}
      </label>
    );
  }
);

Radio.displayName = 'Radio';

export type { RadioGroupProps, RadioProps, RadioOption };

/*
Usage Examples:

// Basic RadioGroup
<RadioGroup
  label="Notification Preference"
  name="notifications"
  value={notificationPref}
  onChange={(value, option) => setNotificationPref(value)}
  options={[
    { value: 'email', label: 'Email notifications' },
    { value: 'sms', label: 'SMS notifications' },
    { value: 'push', label: 'Push notifications' },
    { value: 'none', label: 'No notifications' }
  ]}
/>

// Card variant with descriptions
<RadioGroup
  label="Subscription Plan"
  variant="card"
  colorScheme="primary"
  value={selectedPlan}
  onChange={(value) => setSelectedPlan(value)}
  options={[
    {
      value: 'basic',
      label: 'Basic Plan',
      description: 'Perfect for individuals. Includes 10GB storage and basic features.',
      icon: '📦'
    },
    {
      value: 'pro',
      label: 'Pro Plan',
      description: 'Great for teams. Includes 100GB storage and advanced features.',
      icon: '🚀'
    },
    {
      value: 'enterprise',
      label: 'Enterprise Plan',
      description: 'For large organizations. Unlimited storage and premium support.',
      icon: '🏢'
    }
  ]}
/>

// Button variant horizontal
<RadioGroup
  label="Size"
  variant="button"
  orientation="horizontal"
  spacing="sm"
  value={selectedSize}
  onChange={(value) => setSelectedSize(value)}
  options={[
    { value: 'xs', label: 'XS' },
    { value: 's', label: 'S' },
    { value: 'm', label: 'M' },
    { value: 'l', label: 'L' },
    { value: 'xl', label: 'XL' }
  ]}
/>

// Custom rendering
<RadioGroup
  label="Payment Method"
  value={paymentMethod}
  onChange={setPaymentMethod}
  renderOption={(option, isSelected, isDisabled) => (
    <div className={cn(
      'flex items-center p-3 border rounded-lg',
      isSelected ? 'border-blue-500 bg-blue-50' : 'border-gray-200',
      isDisabled && 'opacity-50'
    )}>
      <div className="flex-1">
        <div className="font-medium">{option.label}</div>
        <div className="text-sm text-gray-500">{option.description}</div>
      </div>
      {option.icon}
    </div>
  )}
  options={[
    {
      value: 'credit',
      label: 'Credit Card',
      description: '**** **** **** 1234',
      icon: '💳'
    },
    {
      value: 'paypal',
      label: 'PayPal',
      description: 'user@example.com',
      icon: '🅿️'
    }
  ]}
/>

// Individual Radio
<Radio
  label="I agree to the terms and conditions"
  description="By checking this, you agree to our Terms of Service and Privacy Policy"
  required
  colorScheme="success"
/>

// Different sizes and colors
<RadioGroup size="lg" colorScheme="success" options={options} />
<RadioGroup size="sm" colorScheme="warning" variant="button" options={options} />
*/