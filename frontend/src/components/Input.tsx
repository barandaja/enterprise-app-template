import React from 'react';
import { cn } from '../utils';

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  helperText?: string;
  error?: string | boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  containerClassName?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ 
    className,
    containerClassName,
    type = 'text',
    label,
    helperText,
    error,
    leftIcon,
    rightIcon,
    id,
    ...props 
  }, ref) => {
    const inputId = id || `input-${Math.random().toString(36).substring(2, 11)}`;
    const hasError = Boolean(error);
    const errorMessage = typeof error === 'string' ? error : '';

    return (
      <div className={cn('w-full', containerClassName)}>
        {label && (
          <label 
            htmlFor={inputId}
            className={cn(
              'label block mb-2',
              hasError && 'text-destructive'
            )}
          >
            {label}
            {props.required && <span className="text-destructive ml-1">*</span>}
          </label>
        )}
        
        <div className="relative">
          {leftIcon && (
            <div className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground pointer-events-none z-10">
              {leftIcon}
            </div>
          )}
          
          <input
            type={type}
            id={inputId}
            className={cn(
              'input',
              leftIcon && 'pl-10',
              rightIcon && 'pr-10',
              hasError && 'border-destructive focus-visible:ring-destructive',
              className
            )}
            ref={ref}
            aria-invalid={hasError}
            aria-describedby={
              helperText || errorMessage 
                ? `${inputId}-description` 
                : undefined
            }
            {...props}
          />
          
          {rightIcon && (
            <div className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground pointer-events-none">
              {rightIcon}
            </div>
          )}
        </div>

        {(helperText || errorMessage) && (
          <p 
            id={`${inputId}-description`}
            className={cn(
              'text-sm mt-1',
              hasError ? 'text-destructive' : 'text-muted-foreground'
            )}
          >
            {errorMessage || helperText}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

// Textarea component
export interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  helperText?: string;
  error?: string | boolean;
  containerClassName?: string;
}

export const Textarea = React.forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ 
    className,
    containerClassName,
    label,
    helperText,
    error,
    id,
    ...props 
  }, ref) => {
    const textareaId = id || `textarea-${Math.random().toString(36).substring(2, 11)}`;
    const hasError = Boolean(error);
    const errorMessage = typeof error === 'string' ? error : '';

    return (
      <div className={cn('w-full', containerClassName)}>
        {label && (
          <label 
            htmlFor={textareaId}
            className={cn(
              'label block mb-2',
              hasError && 'text-destructive'
            )}
          >
            {label}
            {props.required && <span className="text-destructive ml-1">*</span>}
          </label>
        )}
        
        <textarea
          id={textareaId}
          className={cn(
            'textarea',
            hasError && 'border-destructive focus-visible:ring-destructive',
            className
          )}
          ref={ref}
          aria-invalid={hasError}
          aria-describedby={
            helperText || errorMessage 
              ? `${textareaId}-description` 
              : undefined
          }
          {...props}
        />

        {(helperText || errorMessage) && (
          <p 
            id={`${textareaId}-description`}
            className={cn(
              'text-sm mt-1',
              hasError ? 'text-destructive' : 'text-muted-foreground'
            )}
          >
            {errorMessage || helperText}
          </p>
        )}
      </div>
    );
  }
);

Textarea.displayName = 'Textarea';

// Form field wrapper for React Hook Form integration
export interface FormFieldProps {
  children: React.ReactNode;
  label?: string;
  error?: string;
  helperText?: string;
  required?: boolean;
  className?: string;
}

export const FormField: React.FC<FormFieldProps> = ({
  children,
  label,
  error,
  helperText,
  required = false,
  className
}) => {
  const hasError = Boolean(error);
  
  return (
    <div className={cn('w-full', className)}>
      {label && (
        <label className={cn(
          'label block mb-2',
          hasError && 'text-destructive'
        )}>
          {label}
          {required && <span className="text-destructive ml-1">*</span>}
        </label>
      )}
      
      {children}
      
      {(helperText || error) && (
        <p className={cn(
          'text-sm mt-1',
          hasError ? 'text-destructive' : 'text-muted-foreground'
        )}>
          {error || helperText}
        </p>
      )}
    </div>
  );
};

// Usage examples:
/*
// Basic input
<Input placeholder="Enter your name" />

// With label and helper text
<Input 
  label="Email"
  placeholder="john@example.com"
  helperText="We'll never share your email"
  type="email"
/>

// With error state
<Input 
  label="Password"
  type="password"
  error="Password must be at least 8 characters"
  placeholder="Enter password"
/>

// With left icon
<Input 
  label="Search"
  leftIcon={<SearchIcon className="w-4 h-4" />}
  placeholder="Search..."
/>

// Textarea
<Textarea 
  label="Message"
  placeholder="Enter your message"
  rows={4}
/>

// With React Hook Form (example)
import { useForm } from 'react-hook-form';

const MyForm = () => {
  const { register, formState: { errors } } = useForm();
  
  return (
    <Input
      {...register('email', { required: 'Email is required' })}
      label="Email"
      error={errors.email?.message}
      type="email"
    />
  );
};
*/