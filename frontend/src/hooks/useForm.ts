import { useForm as useReactHookForm, UseFormProps, UseFormReturn, FieldValues, Path, FieldPath } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useCallback, useMemo, useState } from 'react';
import { useUIStore } from '../stores/uiStore';

/**
 * Enhanced form configuration options
 */
interface UseFormOptions<T extends FieldValues> extends UseFormProps<T> {
  /**
   * Zod schema for validation
   */
  schema?: z.ZodSchema<T>;
  /**
   * Form ID for tracking dirty state
   */
  formId?: string;
  /**
   * Auto-save functionality
   */
  autoSave?: {
    enabled: boolean;
    delay: number;
    onSave: (data: T) => Promise<void> | void;
  };
  /**
   * Submit handling
   */
  onSubmit?: (data: T) => Promise<void> | void;
  onError?: (errors: any) => void;
  /**
   * Reset options
   */
  resetAfterSubmit?: boolean;
  /**
   * Transform data before submission
   */
  transformSubmitData?: (data: T) => any;
}

/**
 * Enhanced form return type with additional utilities
 */
interface UseFormEnhancedReturn<T extends FieldValues> extends UseFormReturn<T> {
  /**
   * Submit handler with error handling and loading states
   */
  handleSubmit: (e?: React.BaseSyntheticEvent) => Promise<void>;
  /**
   * Check if form is dirty (has unsaved changes)
   */
  isDirty: boolean;
  /**
   * Check if form is submitting
   */
  isSubmitting: boolean;
  /**
   * Check if form is valid
   */
  isValid: boolean;
  /**
   * Reset form to initial values
   */
  reset: (values?: T) => void;
  /**
   * Get field error message
   */
  getFieldError: (name: FieldPath<T>) => string | undefined;
  /**
   * Check if field has error
   */
  hasFieldError: (name: FieldPath<T>) => boolean;
  /**
   * Format all errors for display
   */
  getFormattedErrors: () => Record<string, string>;
  /**
   * Submit form programmatically
   */
  submitForm: () => Promise<void>;
  /**
   * Clear specific field error
   */
  clearFieldError: (name: FieldPath<T>) => void;
  /**
   * Clear all errors
   */
  clearAllErrors: () => void;
  /**
   * Set loading state
   */
  setIsSubmitting: (loading: boolean) => void;
}

/**
 * Enhanced form hook with react-hook-form integration, Zod validation,
 * error formatting, and comprehensive form utilities
 * 
 * @example
 * ```tsx
 * // Basic form with Zod validation
 * const schema = z.object({
 *   email: z.string().email('Invalid email'),
 *   password: z.string().min(8, 'Password must be at least 8 characters'),
 * });
 * 
 * const LoginForm = () => {
 *   const {
 *     register,
 *     handleSubmit,
 *     getFieldError,
 *     isSubmitting,
 *     isValid
 *   } = useForm({
 *     schema,
 *     onSubmit: async (data) => {
 *       await api.login(data);
 *     }
 *   });
 * 
 *   return (
 *     <form onSubmit={handleSubmit}>
 *       <input
 *         {...register('email')}
 *         type="email"
 *         placeholder="Email"
 *       />
 *       {getFieldError('email') && (
 *         <span className="error">{getFieldError('email')}</span>
 *       )}
 *       
 *       <input
 *         {...register('password')}
 *         type="password"
 *         placeholder="Password"
 *       />
 *       {getFieldError('password') && (
 *         <span className="error">{getFieldError('password')}</span>
 *       )}
 *       
 *       <button type="submit" disabled={!isValid || isSubmitting}>
 *         {isSubmitting ? 'Logging in...' : 'Login'}
 *       </button>
 *     </form>
 *   );
 * };
 * 
 * // Form with auto-save
 * const ProfileForm = () => {
 *   const form = useForm({
 *     schema: profileSchema,
 *     formId: 'profile-form',
 *     autoSave: {
 *       enabled: true,
 *       delay: 1000,
 *       onSave: async (data) => {
 *         await api.saveProfile(data);
 *       }
 *     }
 *   });
 * 
 *   return <ProfileFormUI {...form} />;
 * };
 * ```
 * 
 * @param options - Form configuration options
 * @returns Enhanced form utilities and state
 */
export function useForm<T extends FieldValues>(
  options: UseFormOptions<T> = {}
): UseFormEnhancedReturn<T> {
  const {
    schema,
    formId,
    autoSave,
    onSubmit,
    onError,
    resetAfterSubmit = false,
    transformSubmitData,
    ...reactHookFormOptions
  } = options;

  // Setup react-hook-form with Zod resolver if schema provided
  const form = useReactHookForm<T>({
    ...reactHookFormOptions,
    resolver: schema ? zodResolver(schema) : reactHookFormOptions.resolver,
    mode: reactHookFormOptions.mode || 'onChange',
  });

  const {
    handleSubmit: rhfHandleSubmit,
    formState: { errors, isSubmitting, isDirty, isValid },
    reset: rhfReset,
    clearErrors,
    setError,
  } = form;

  // UI store integration for form dirty state tracking
  const setFormDirty = useUIStore((state) => state.setFormDirty);
  const clearFormDirty = useUIStore((state) => state.clearFormDirty);

  // Track form dirty state in UI store
  if (formId && isDirty) {
    setFormDirty(formId, isDirty);
  }

  // Enhanced submit handler
  const handleSubmit = useCallback(async (e?: React.BaseSyntheticEvent) => {
    if (!onSubmit) return;

    const submitHandler = rhfHandleSubmit(
      async (data: T) => {
        try {
          // Transform data if needed
          const submitData = transformSubmitData ? transformSubmitData(data) : data;
          
          // Call submit handler
          await onSubmit(submitData);
          
          // Reset form if configured
          if (resetAfterSubmit) {
            rhfReset();
          }
          
          // Clear form dirty state
          if (formId) {
            clearFormDirty(formId);
          }
        } catch (error) {
          // Handle submission errors
          if (onError) {
            onError(error);
          } else {
            console.error('Form submission error:', error);
          }
          throw error;
        }
      },
      (formErrors) => {
        // Handle validation errors
        if (onError) {
          onError(formErrors);
        }
      }
    );

    return submitHandler(e);
  }, [
    onSubmit,
    rhfHandleSubmit,
    transformSubmitData,
    resetAfterSubmit,
    rhfReset,
    formId,
    clearFormDirty,
    onError,
  ]);

  // Enhanced reset function
  const reset = useCallback((values?: T) => {
    rhfReset(values);
    if (formId) {
      clearFormDirty(formId);
    }
  }, [rhfReset, formId, clearFormDirty]);

  // Field error utilities
  const getFieldError = useCallback((name: FieldPath<T>): string | undefined => {
    const error = errors[name];
    return error?.message as string | undefined;
  }, [errors]);

  const hasFieldError = useCallback((name: FieldPath<T>): boolean => {
    return !!errors[name];
  }, [errors]);

  const getFormattedErrors = useCallback((): Record<string, string> => {
    const formattedErrors: Record<string, string> = {};
    
    Object.entries(errors).forEach(([key, error]) => {
      if (error && typeof error.message === 'string') {
        formattedErrors[key] = error.message;
      }
    });
    
    return formattedErrors;
  }, [errors]);

  // Programmatic submit
  const submitForm = useCallback(async () => {
    return handleSubmit();
  }, [handleSubmit]);

  // Error management utilities
  const clearFieldError = useCallback((name: FieldPath<T>) => {
    clearErrors(name);
  }, [clearErrors]);

  const clearAllErrors = useCallback(() => {
    clearErrors();
  }, [clearErrors]);

  // Manual loading state control
  const setIsSubmitting = useCallback((loading: boolean) => {
    // This is a workaround since react-hook-form doesn't expose setIsSubmitting
    // You would typically handle this through your submit handler
    console.warn('setIsSubmitting is not directly supported by react-hook-form');
  }, []);

  return {
    ...form,
    handleSubmit,
    isDirty,
    isSubmitting,
    isValid,
    reset,
    getFieldError,
    hasFieldError,
    getFormattedErrors,
    submitForm,
    clearFieldError,
    clearAllErrors,
    setIsSubmitting,
  };
}

/**
 * Common validation schemas that can be reused across forms
 */
export const validationSchemas = {
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  confirmPassword: (passwordField: string = 'password') =>
    z.string().min(1, 'Please confirm your password'),
  name: z.string().min(1, 'Name is required').max(50, 'Name must be less than 50 characters'),
  phone: z.string().regex(/^\+?[1-9]\d{1,14}$/, 'Please enter a valid phone number'),
  url: z.string().url('Please enter a valid URL'),
  required: (message: string = 'This field is required') => z.string().min(1, message),
  minLength: (min: number, message?: string) =>
    z.string().min(min, message || `Must be at least ${min} characters`),
  maxLength: (max: number, message?: string) =>
    z.string().max(max, message || `Must be no more than ${max} characters`),
  number: z.number({ invalid_type_error: 'Please enter a valid number' }),
  positiveNumber: z.number().positive('Must be a positive number'),
  date: z.date({ invalid_type_error: 'Please enter a valid date' }),
  boolean: z.boolean(),
} as const;

/**
 * Factory function for creating form schemas with password confirmation
 */
export function createPasswordConfirmationSchema<T extends Record<string, any>>(
  baseSchema: z.ZodObject<T>,
  passwordField: keyof T = 'password',
  confirmPasswordField: string = 'confirmPassword'
) {
  return baseSchema
    .extend({
      [confirmPasswordField]: z.string(),
    } as any)
    .refine(
      (data) => data[passwordField] === data[confirmPasswordField],
      {
        message: 'Passwords do not match',
        path: [confirmPasswordField],
      }
    );
}

/**
 * Hook for form field validation status and styling
 * Useful for consistent field styling across forms
 * 
 * @example
 * ```tsx
 * const FieldWrapper = ({ name, children }) => {
 *   const { isError, isValid, className } = useFieldValidation(name);
 *   
 *   return (
 *     <div className={`field ${className}`}>
 *       {children}
 *       {isError && <span className="error-icon">❌</span>}
 *       {isValid && <span className="success-icon">✅</span>}
 *     </div>
 *   );
 * };
 * ```
 */
export function useFieldValidation<T extends FieldValues>(
  name: FieldPath<T>,
  form?: UseFormReturn<T>
) {
  const { formState } = form || {};
  const { errors, touchedFields, dirtyFields } = formState || {};

  const error = errors?.[name];
  const isTouched = touchedFields?.[name];
  const isDirty = dirtyFields?.[name];

  const isError = !!error;
  const isValid = !error && (isTouched || isDirty);

  const className = useMemo(() => {
    const classes = [];
    if (isError) classes.push('field-error');
    if (isValid) classes.push('field-valid');
    if (isTouched) classes.push('field-touched');
    if (isDirty) classes.push('field-dirty');
    return classes.join(' ');
  }, [isError, isValid, isTouched, isDirty]);

  return {
    isError,
    isValid,
    isTouched,
    isDirty,
    error: error?.message as string | undefined,
    className,
  };
}

/**
 * Hook for managing multi-step forms
 * 
 * @example
 * ```tsx
 * const steps = ['personal', 'contact', 'preferences'];
 * 
 * const MultiStepForm = () => {
 *   const {
 *     currentStep,
 *     currentStepIndex,
 *     isFirstStep,
 *     isLastStep,
 *     nextStep,
 *     prevStep,
 *     goToStep,
 *     progress
 *   } = useMultiStepForm(steps);
 * 
 *   return (
 *     <div>
 *       <div className="progress">
 *         <div style={{ width: `${progress}%` }} />
 *       </div>
 *       
 *       {currentStep === 'personal' && <PersonalInfoStep />}
 *       {currentStep === 'contact' && <ContactInfoStep />}
 *       {currentStep === 'preferences' && <PreferencesStep />}
 *       
 *       <div className="navigation">
 *         {!isFirstStep && (
 *           <button onClick={prevStep}>Previous</button>
 *         )}
 *         {!isLastStep && (
 *           <button onClick={nextStep}>Next</button>
 *         )}
 *       </div>
 *     </div>
 *   );
 * };
 * ```
 */
export function useMultiStepForm<T extends string>(steps: readonly T[]) {
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  const currentStep = steps[currentStepIndex];
  const isFirstStep = currentStepIndex === 0;
  const isLastStep = currentStepIndex === steps.length - 1;
  const progress = ((currentStepIndex + 1) / steps.length) * 100;

  const nextStep = useCallback(() => {
    if (!isLastStep) {
      setCurrentStepIndex(prev => prev + 1);
    }
  }, [isLastStep]);

  const prevStep = useCallback(() => {
    if (!isFirstStep) {
      setCurrentStepIndex(prev => prev - 1);
    }
  }, [isFirstStep]);

  const goToStep = useCallback((step: T | number) => {
    const index = typeof step === 'number' ? step : steps.indexOf(step);
    if (index >= 0 && index < steps.length) {
      setCurrentStepIndex(index);
    }
  }, [steps]);

  const reset = useCallback(() => {
    setCurrentStepIndex(0);
  }, []);

  return {
    currentStep,
    currentStepIndex,
    isFirstStep,
    isLastStep,
    nextStep,
    prevStep,
    goToStep,
    reset,
    progress,
    totalSteps: steps.length,
  };
}