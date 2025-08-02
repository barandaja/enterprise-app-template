import React from 'react';
import { cn } from '../../utils';

export interface FormFieldProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  label?: string;
  error?: string;
  helperText?: string;
  required?: boolean;
  showRequiredIndicator?: boolean;
  isInvalid?: boolean;
  isDisabled?: boolean;
  orientation?: 'vertical' | 'horizontal';
  labelWidth?: string;
}

export const FormField = React.forwardRef<HTMLDivElement, FormFieldProps>(
  ({
    children,
    label,
    error,
    helperText,
    required = false,
    showRequiredIndicator = true,
    isInvalid = false,
    isDisabled = false,
    orientation = 'vertical',
    labelWidth = '150px',
    className,
    ...props
  }, ref) => {
    const fieldId = `field-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = isInvalid || !!error;

    return (
      <div
        ref={ref}
        className={cn(
          'space-y-1',
          orientation === 'horizontal' && 'flex items-start space-y-0 space-x-4',
          isDisabled && 'opacity-50',
          className
        )}
        {...props}
      >
        {/* Label */}
        {label && (
          <label
            htmlFor={fieldId}
            className={cn(
              'block text-sm font-medium',
              hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
              orientation === 'horizontal' && 'flex-shrink-0 pt-2',
              orientation === 'horizontal' && `w-[${labelWidth}]`
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

        {/* Field Content */}
        <div className={cn('flex-1', orientation === 'vertical' && 'space-y-1')}>
          {/* Clone children to pass down field props */}
          {React.Children.map(children, (child) => {
            if (React.isValidElement(child)) {
              return React.cloneElement(child, {
                id: fieldId,
                'aria-invalid': hasError,
                'aria-describedby': error ? `${fieldId}-error` : helperText ? `${fieldId}-helper` : undefined,
                disabled: isDisabled || child.props.disabled,
                ...child.props
              });
            }
            return child;
          })}

          {/* Helper Text */}
          {helperText && !error && (
            <p
              id={`${fieldId}-helper`}
              className="text-sm text-gray-500 dark:text-gray-400"
            >
              {helperText}
            </p>
          )}

          {/* Error Message */}
          {error && (
            <p
              id={`${fieldId}-error`}
              className="text-sm text-red-600 dark:text-red-400"
              role="alert"
            >
              {error}
            </p>
          )}
        </div>
      </div>
    );
  }
);

FormField.displayName = 'FormField';

// Form Group Component for related fields
export interface FormGroupProps extends React.HTMLAttributes<HTMLFieldSetElement> {
  children: React.ReactNode;
  legend?: string;
  description?: string;
  error?: string;
  isInvalid?: boolean;
  isDisabled?: boolean;
  spacing?: 'sm' | 'md' | 'lg';
}

export const FormGroup = React.forwardRef<HTMLFieldSetElement, FormGroupProps>(
  ({
    children,
    legend,
    description,
    error,
    isInvalid = false,
    isDisabled = false,
    spacing = 'md',
    className,
    ...props
  }, ref) => {
    const groupId = `group-${Math.random().toString(36).substr(2, 9)}`;
    const hasError = isInvalid || !!error;

    const spacingClasses = {
      sm: 'space-y-3',
      md: 'space-y-4',
      lg: 'space-y-6'
    };

    return (
      <fieldset
        ref={ref}
        className={cn(
          'border-0 p-0 m-0',
          spacingClasses[spacing],
          isDisabled && 'opacity-50',
          className
        )}
        disabled={isDisabled}
        aria-describedby={
          error ? `${groupId}-error` : description ? `${groupId}-description` : undefined
        }
        {...props}
      >
        {/* Legend */}
        {legend && (
          <legend className={cn(
            'text-lg font-semibold mb-2',
            hasError ? 'text-red-700 dark:text-red-400' : 'text-gray-900 dark:text-gray-100'
          )}>
            {legend}
          </legend>
        )}

        {/* Description */}
        {description && (
          <p
            id={`${groupId}-description`}
            className="text-sm text-gray-600 dark:text-gray-400 mb-4"
          >
            {description}
          </p>
        )}

        {/* Fields */}
        <div className={spacingClasses[spacing]}>
          {children}
        </div>

        {/* Group Error */}
        {error && (
          <p
            id={`${groupId}-error`}
            className="text-sm text-red-600 dark:text-red-400"
            role="alert"
          >
            {error}
          </p>
        )}
      </fieldset>
    );
  }
);

FormGroup.displayName = 'FormGroup';

// Form Section Component for logical form sections
export interface FormSectionProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  title?: string;
  description?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  separator?: boolean;
}

export const FormSection = React.forwardRef<HTMLDivElement, FormSectionProps>(
  ({
    children,
    title,
    description,
    collapsible = false,
    defaultCollapsed = false,
    separator = true,
    className,
    ...props
  }, ref) => {
    const [isCollapsed, setIsCollapsed] = React.useState(defaultCollapsed);
    const sectionId = `section-${Math.random().toString(36).substr(2, 9)}`;

    return (
      <div
        ref={ref}
        className={cn(
          'space-y-6',
          separator && 'border-b border-gray-200 dark:border-gray-700 pb-6',
          className
        )}
        {...props}
      >
        {/* Section Header */}
        {(title || description) && (
          <div className="space-y-1">
            {title && (
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                  {title}
                </h3>
                {collapsible && (
                  <button
                    type="button"
                    onClick={() => setIsCollapsed(!isCollapsed)}
                    className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 transition-colors"
                    aria-expanded={!isCollapsed}
                    aria-controls={sectionId}
                  >
                    <svg
                      className={cn(
                        'h-5 w-5 transition-transform',
                        isCollapsed && 'rotate-180'
                      )}
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                    >
                      <path
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        strokeWidth={2}
                        d="M19 9l-7 7-7-7"
                      />
                    </svg>
                  </button>
                )}
              </div>
            )}
            {description && (
              <p className="text-sm text-gray-600 dark:text-gray-400">
                {description}
              </p>
            )}
          </div>
        )}

        {/* Section Content */}
        {(!collapsible || !isCollapsed) && (
          <div id={sectionId} className="space-y-6">
            {children}
          </div>
        )}
      </div>
    );
  }
);

FormSection.displayName = 'FormSection';

// Form Label Component for standalone labels
export interface FormLabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  children: React.ReactNode;
  required?: boolean;
  showRequiredIndicator?: boolean;
  isInvalid?: boolean;
  size?: 'sm' | 'md' | 'lg';
}

export const FormLabel = React.forwardRef<HTMLLabelElement, FormLabelProps>(
  ({
    children,
    required = false,
    showRequiredIndicator = true,
    isInvalid = false,
    size = 'md',
    className,
    ...props
  }, ref) => {
    const sizeClasses = {
      sm: 'text-xs',
      md: 'text-sm',
      lg: 'text-base'
    };

    return (
      <label
        ref={ref}
        className={cn(
          'block font-medium',
          sizeClasses[size],
          isInvalid ? 'text-red-700 dark:text-red-400' : 'text-gray-700 dark:text-gray-300',
          className
        )}
        {...props}
      >
        {children}
        {required && showRequiredIndicator && (
          <span className="text-red-500 ml-1" aria-label="required">
            *
          </span>
        )}
      </label>
    );
  }
);

FormLabel.displayName = 'FormLabel';

// Form Error Message Component
export interface FormErrorMessageProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode;
}

export const FormErrorMessage = React.forwardRef<HTMLParagraphElement, FormErrorMessageProps>(
  ({ children, className, ...props }, ref) => {
    return (
      <p
        ref={ref}
        className={cn('text-sm text-red-600 dark:text-red-400', className)}
        role="alert"
        {...props}
      >
        {children}
      </p>
    );
  }
);

FormErrorMessage.displayName = 'FormErrorMessage';

// Form Helper Text Component
export interface FormHelperTextProps extends React.HTMLAttributes<HTMLParagraphElement> {
  children: React.ReactNode;
}

export const FormHelperText = React.forwardRef<HTMLParagraphElement, FormHelperTextProps>(
  ({ children, className, ...props }, ref) => {
    return (
      <p
        ref={ref}
        className={cn('text-sm text-gray-500 dark:text-gray-400', className)}
        {...props}
      >
        {children}
      </p>
    );
  }
);

FormHelperText.displayName = 'FormHelperText';

export type {
  FormFieldProps,
  FormGroupProps,
  FormSectionProps,
  FormLabelProps,
  FormErrorMessageProps,
  FormHelperTextProps
};

/*
Usage Examples:

// Basic Form Field
<FormField label="Email" error={errors.email}>
  <Input type="email" placeholder="john@example.com" />
</FormField>

// Form Group for related fields
<FormGroup legend="Personal Information" description="Please provide your basic details">
  <FormField label="First Name" required>
    <Input placeholder="John" />
  </FormField>
  <FormField label="Last Name" required>
    <Input placeholder="Doe" />
  </FormField>
</FormGroup>

// Form Section for logical grouping
<FormSection 
  title="Account Settings" 
  description="Manage your account preferences"
  collapsible
>
  <FormField label="Username">
    <Input placeholder="johndoe" />
  </FormField>
  <FormField label="Email">
    <Input type="email" placeholder="john@example.com" />
  </FormField>
</FormSection>

// Horizontal layout
<FormField 
  label="Website" 
  orientation="horizontal"
  labelWidth="120px"
>
  <Input placeholder="https://example.com" />
</FormField>

// Standalone components
<FormLabel required>Email Address</FormLabel>
<Input type="email" />
<FormHelperText>We'll never share your email.</FormHelperText>
<FormErrorMessage>Please enter a valid email address.</FormErrorMessage>
*/