import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Mail, User, ArrowRight, ArrowLeft, CheckCircle, AlertCircle, Shield, Github } from 'lucide-react';
import { 
  Input, 
  SecurePasswordInput, 
  PasswordConfirmationInput,
  RateLimitedButton,
  Alert,
  AlertContent,
  AgeVerification,
  Button,
  Spinner
} from '../components';
import { passwordValidationRules } from '../security/passwordValidation';
import { validateEmail, sanitizeInput } from '../security/inputValidation';
import { CSRFToken } from '../components/CSRFToken';
import { useAuthActions, useAuthError, useAuthLoading } from '../stores/authStore';
import { useConsent } from '../hooks/useConsent';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

// Multi-step form validation schemas
const personalInfoSchema = z.object({
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Only letters, spaces, hyphens and apostrophes allowed'),
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters')
    .regex(/^[a-zA-Z\s'-]+$/, 'Only letters, spaces, hyphens and apostrophes allowed'),
  email: z.string()
    .min(1, 'Email is required')
    .email('Invalid email address')
    .max(254, 'Email address too long'),
});

const passwordSchema = z.object({
  password: z.string().min(12, 'Password must be at least 12 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

const termsSchema = z.object({
  agreeToTerms: z.boolean().refine(val => val === true, {
    message: 'You must agree to the terms and conditions',
  }),
  agreeToPrivacy: z.boolean().refine(val => val === true, {
    message: 'You must agree to the privacy policy',
  }),
  agreeToMarketing: z.boolean().default(false),
});

// Combined schema for final validation
const registerSchema = personalInfoSchema
  .merge(passwordSchema)
  .merge(termsSchema);

type RegisterFormData = z.infer<typeof registerSchema>;
type PersonalInfoData = z.infer<typeof personalInfoSchema>;
type PasswordData = z.infer<typeof passwordSchema>;
type TermsData = z.infer<typeof termsSchema>;

type RegistrationStep = 'personal' | 'password' | 'terms' | 'age-verification' | 'confirmation';

interface StepData {
  personal: PersonalInfoData;
  password: PasswordData;
  terms: TermsData;
}

// Storage key for persisting form data
const FORM_STORAGE_KEY = 'register-form-data';
const STEP_STORAGE_KEY = 'register-current-step';

function Register({ className }: PageProps) {
  const navigate = useNavigate();
  const { register: registerUser } = useAuthActions();
  const authError = useAuthError();
  const isLoading = useAuthLoading();
  const { hasConsent, requestConsent } = useConsent();
  
  // Storage availability check
  const isStorageAvailable = React.useMemo(() => {
    try {
      const test = '__storage_test__';
      localStorage.setItem(test, test);
      localStorage.removeItem(test);
      return true;
    } catch {
      return false;
    }
  }, []);

  // Safe localStorage getter with validation
  const getSafeStorageItem = React.useCallback((key: string, fallback: any = null) => {
    if (!isStorageAvailable) return fallback;
    
    try {
      const item = localStorage.getItem(key);
      if (!item) return fallback;
      
      // Validate JSON before parsing
      if (key === FORM_STORAGE_KEY) {
        const parsed = JSON.parse(item);
        // Ensure parsed data is an object and doesn't contain sensitive fields
        if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
          // Remove any password fields if they exist (security fix)
          const { password, confirmPassword, ...safeData } = parsed as any;
          return safeData;
        }
        return fallback;
      }
      
      // For step storage, validate it's a valid step
      if (key === STEP_STORAGE_KEY) {
        const validSteps: RegistrationStep[] = ['personal', 'password', 'terms', 'age-verification', 'confirmation'];
        // The step is stored as a plain string, not JSON
        console.log('Retrieved step from storage:', item);
        return validSteps.includes(item as RegistrationStep) ? item : fallback;
      }
      
      return item;
    } catch (error) {
      console.warn(`Failed to parse localStorage item ${key}:`, error);
      return fallback;
    }
  }, [isStorageAvailable]);

  // Safe localStorage setter with quota handling
  const setSafeStorageItem = React.useCallback((key: string, value: any) => {
    if (!isStorageAvailable) return false;
    
    try {
      let dataToStore = value;
      
      // Security fix: Exclude password fields from storage
      if (key === FORM_STORAGE_KEY && typeof value === 'object' && value !== null) {
        const { password, confirmPassword, ...safeData } = value;
        dataToStore = safeData;
      }
      
      // For step storage, save as plain string without JSON.stringify
      if (key === STEP_STORAGE_KEY && typeof dataToStore === 'string') {
        localStorage.setItem(key, dataToStore);
        console.log('Saved step to localStorage as plain string:', dataToStore);
      } else {
        const serialized = typeof dataToStore === 'string' ? dataToStore : JSON.stringify(dataToStore);
        localStorage.setItem(key, serialized);
      }
      return true;
    } catch (error) {
      if (error instanceof DOMException && error.code === 22) {
        // Quota exceeded error
        console.warn('localStorage quota exceeded, clearing old data');
        try {
          localStorage.removeItem(FORM_STORAGE_KEY);
          localStorage.removeItem(STEP_STORAGE_KEY);
          // Try again after clearing
          const serialized = typeof dataToStore === 'string' ? dataToStore : JSON.stringify(dataToStore);
          localStorage.setItem(key, serialized);
          return true;
        } catch {
          console.error('Failed to store data even after clearing localStorage');
        }
      } else {
        console.warn(`Failed to store localStorage item ${key}:`, error);
      }
      return false;
    }
  }, [isStorageAvailable]);

  // State with secure localStorage persistence
  const [currentStep, setCurrentStep] = React.useState<RegistrationStep>(() => {
    const savedStep = getSafeStorageItem(STEP_STORAGE_KEY, 'personal');
    console.log('Initial currentStep from storage:', savedStep);
    return savedStep;
  });
  const [stepData, setStepData] = React.useState<Partial<StepData>>(() => {
    return getSafeStorageItem(FORM_STORAGE_KEY, {});
  });
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [ageVerified, setAgeVerified] = React.useState(false);
  const [userAge, setUserAge] = React.useState<number | null>(null);
  // Use useRef for isMounted to avoid state issues
  const isMountedRef = React.useRef(true);
  const isMounted = isMountedRef.current;
  const [isRedirecting, setIsRedirecting] = React.useState(false);
  
  // Age verification step state - moved to top level to fix hooks error
  const [birthDate, setBirthDate] = React.useState('');
  const [ageError, setAgeError] = React.useState('');
  const [isVerifying, setIsVerifying] = React.useState(false);
  const [requiresParentalConsent, setRequiresParentalConsent] = React.useState(false);
  
  // Timeout ref for cleanup
  const timeoutRef = React.useRef<NodeJS.Timeout | null>(null);
  
  // Get the appropriate schema based on current step
  const getCurrentSchema = () => {
    switch (currentStep) {
      case 'personal':
        return personalInfoSchema;
      case 'password':
        return passwordSchema;
      case 'terms':
        return termsSchema;
      default:
        return registerSchema;
    }
  };
  
  const {
    register,
    handleSubmit,
    formState: { errors, isValid },
    watch,
    setValue,
    reset,
    trigger,
    clearErrors,
  } = useForm({
    resolver: zodResolver(registerSchema),
    mode: 'onChange',
    defaultValues: {
      firstName: stepData.personal?.firstName || '',
      lastName: stepData.personal?.lastName || '',
      email: stepData.personal?.email || '',
      // SECURITY FIX: Never populate password fields from storage
      password: '',
      confirmPassword: '',
      agreeToTerms: stepData.terms?.agreeToTerms || false,
      agreeToPrivacy: stepData.terms?.agreeToPrivacy || false,
      agreeToMarketing: stepData.terms?.agreeToMarketing || false,
    },
  });

  const watchedPassword = watch('password');
  const watchedEmail = watch('email');
  const watchedFirstName = watch('firstName');
  const watchedLastName = watch('lastName');
  
  // Clear errors when step changes to avoid validation conflicts
  React.useEffect(() => {
    console.log('=== STEP CHANGED TO:', currentStep, '===');
    clearErrors();
    
    // Clear age verification state when leaving that step
    if (currentStep !== 'age-verification') {
      setBirthDate('');
      setAgeError('');
      setIsVerifying(false);
      setRequiresParentalConsent(false);
    }
  }, [currentStep, clearErrors]);
  
  // Persist form data to localStorage whenever it changes (SECURITY: passwords excluded)
  React.useEffect(() => {
    const subscription = watch((data) => {
      if (isMounted) {
        const currentStepData = {
          personal: {
            firstName: data.firstName || '',
            lastName: data.lastName || '',
            email: data.email || '',
          },
          // SECURITY FIX: Never store password fields in localStorage
          terms: {
            agreeToTerms: data.agreeToTerms || false,
            agreeToPrivacy: data.agreeToPrivacy || false,
            agreeToMarketing: data.agreeToMarketing || false,
          },
        };
        setSafeStorageItem(FORM_STORAGE_KEY, currentStepData);
      }
    });
    return () => subscription.unsubscribe();
  }, [watch, isMounted, setSafeStorageItem]);
  
  // Persist current step to localStorage
  React.useEffect(() => {
    console.log('Persisting step to localStorage:', currentStep);
    if (isMounted) {
      setSafeStorageItem(STEP_STORAGE_KEY, currentStep);
    }
  }, [currentStep, isMounted, setSafeStorageItem]);
  
  // Cleanup effect for component unmount and timeout
  React.useEffect(() => {
    // Set mounted on mount
    isMountedRef.current = true;
    console.log('Register component mounted, isMounted:', isMountedRef.current);
    
    return () => {
      // Only runs on actual unmount
      console.log('Register component unmounting, clearing timeout');
      isMountedRef.current = false;
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current);
        timeoutRef.current = null;
      }
      // SECURITY FIX: Always clear storage on unmount to prevent data persistence
      try {
        localStorage.removeItem(FORM_STORAGE_KEY);
        localStorage.removeItem(STEP_STORAGE_KEY);
      } catch (error) {
        console.warn('Failed to clear localStorage on unmount:', error);
      }
    };
  }, []); // Empty dependency array - only run on mount/unmount
  
  // Debug effect to track redirect state
  React.useEffect(() => {
    if (currentStep === 'confirmation') {
      console.log('Confirmation step rendered, isRedirecting:', isRedirecting);
      console.log('isMounted:', isMountedRef.current);
      console.log('timeoutRef.current:', timeoutRef.current);
    }
  }, [currentStep, isRedirecting]);
  
  // Progress calculation
  const getProgressPercentage = () => {
    const steps = ['personal', 'password', 'terms', 'age-verification', 'confirmation'];
    const currentIndex = steps.indexOf(currentStep);
    return ((currentIndex + 1) / steps.length) * 100;
  };
  
  // Simplified validation for current step - only check if required fields have values
  const isCurrentStepValid = () => {
    const fieldsToCheck = getFieldsForCurrentStep();
    
    // Check that all required fields have values
    const hasValues = fieldsToCheck.every(field => {
      const value = watch(field as any);
      
      // Special handling for checkbox fields (terms/privacy)
      if (field === 'agreeToTerms' || field === 'agreeToPrivacy') {
        return value === true;
      }
      
      // Optional marketing checkbox doesn't need to be checked
      if (field === 'agreeToMarketing') {
        return true; // Always valid since it's optional
      }
      
      // For password fields - just check they exist, full validation happens on submit
      if (field === 'password' || field === 'confirmPassword') {
        return value && typeof value === 'string' && value.length > 0;
      }
      
      // For text fields (firstName, lastName, email)
      if (field === 'firstName' || field === 'lastName' || field === 'email') {
        return value && typeof value === 'string' && value.trim().length > 0;
      }
      
      return Boolean(value);
    });
    
    // For debugging
    const values = fieldsToCheck.map(field => ({ field, value: watch(field as any) }));
    console.log('Step validation result:', { currentStep, fieldsToCheck, values, hasValues });
    
    return hasValues;
  };
  
  const getFieldsForCurrentStep = () => {
    switch (currentStep) {
      case 'personal':
        return ['firstName', 'lastName', 'email'];
      case 'password':
        return ['password', 'confirmPassword'];
      case 'terms':
        return ['agreeToTerms', 'agreeToPrivacy'];
      default:
        return [];
    }
  };
  
  // Navigation helpers with improved error handling
  const goToNextStep = async (data: any) => {
    console.log('goToNextStep called with:', { currentStep, data });
    
    if (!isMounted) return;
    
    // Store current step data
    const updatedStepData = { ...stepData, [currentStep]: data };
    setStepData(updatedStepData);
    
    // Clear any previous errors
    setSubmitError(null);
    
    try {
      switch (currentStep) {
        case 'personal':
          console.log('Moving from personal to password step');
          // Additional email validation
          const emailValidation = validateEmail(data.email);
          if (!emailValidation.valid) {
            console.log('Email validation failed:', emailValidation);
            setSubmitError(emailValidation.error || 'Invalid email address');
            return;
          }
          console.log('Email validation passed, setting step to password');
          setCurrentStep('password');
          console.log('Called setCurrentStep("password"), current step should now be:', currentStep);
          // Force a re-render to ensure the step change is reflected
          setTimeout(() => {
            console.log('After timeout, current step is:', currentStep);
          }, 100);
          break;
        case 'password':
          console.log('Moving from password to terms step');
          setCurrentStep('terms');
          console.log('Set current step to terms');
          break;
        case 'terms':
          console.log('Moving from terms step');
          // Check if user needs age verification
          if (!ageVerified) {
            setCurrentStep('age-verification');
            console.log('Set current step to age-verification');
          } else {
            await submitRegistration();
          }
          break;
        case 'age-verification':
          console.log('Moving from age-verification step');
          await submitRegistration();
          break;
      }
    } catch (error) {
      console.error('Navigation error:', error);
      setSubmitError('An error occurred. Please try again.');
    }
  };
  
  const goToPrevStep = () => {
    switch (currentStep) {
      case 'password':
        setCurrentStep('personal');
        break;
      case 'terms':
        setCurrentStep('password');
        break;
      case 'age-verification':
        setCurrentStep('terms');
        break;
    }
  };
  
  const handleAgeVerification = async (age: number) => {
    setAgeVerified(true);
    setUserAge(age);
    // Proceed directly to registration submission
    await submitRegistration();
  };
  
  const handleAgeVerificationFailed = () => {
    toast.error('Age verification is required to create an account.');
    setCurrentStep('terms');
  };

  const submitRegistration = async () => {
    try {
      // Combine all step data
      const completeData = {
        ...stepData.personal,
        ...stepData.password,
        ...stepData.terms,
      } as RegisterFormData;
      
      // Sanitize inputs
      const sanitizedData = {
        firstName: sanitizeInput(completeData.firstName),
        lastName: sanitizeInput(completeData.lastName),
        email: completeData.email.toLowerCase().trim(),
        password: completeData.password,
      };
      
      await registerUser(sanitizedData);
      
      // Set confirmation step
      setCurrentStep('confirmation');
      
      toast.success('Account created successfully!');
      
      // Clear form data on success
      if (isStorageAvailable) {
        try {
          localStorage.removeItem(FORM_STORAGE_KEY);
          localStorage.removeItem(STEP_STORAGE_KEY);
        } catch (error) {
          console.warn('Failed to clear localStorage on success:', error);
        }
      }
      
      // Navigate to dashboard after a delay with cleanup
      setIsRedirecting(true);
      timeoutRef.current = setTimeout(() => {
        if (isMountedRef.current) {
          console.log('Navigating to dashboard...');
          navigate('/dashboard', { replace: true });
        } else {
          console.log('Component unmounted, skipping navigation');
        }
      }, 2000);
    } catch (error) {
      console.error('Registration error:', error);
      const errorMessage = authError || 'Registration failed. Please try again.';
      setSubmitError(errorMessage);
      
      // Better error recovery - stay on terms step instead of going back to step 1
      if (currentStep !== 'terms') {
        setCurrentStep('terms');
      }
      
      toast.error(errorMessage);
    }
  };
  
  const onSubmit = async (data: any) => {
    console.log('====== FORM SUBMITTED ======');
    console.log('onSubmit called with data:', data);
    console.log('Current step:', currentStep);
    console.log('Is mounted:', isMounted);
    
    if (!isMounted) {
      console.log('Component not mounted, returning');
      return;
    }
    
    setSubmitError(null);
    
    // Get current step fields and validate them using step-specific schema
    const fieldsToValidate = getFieldsForCurrentStep();
    const currentStepSchema = getCurrentSchema();
    
    console.log('Fields to validate:', fieldsToValidate);
    console.log('Current step schema:', currentStepSchema);
    
    try {
      // Extract only the data for current step
      const currentStepData = fieldsToValidate.reduce((acc, field) => {
        acc[field] = data[field];
        return acc;
      }, {} as any);
      
      console.log('Current step data to validate:', currentStepData);
      
      // Validate using the current step's schema
      const validationResult = currentStepSchema.safeParse(currentStepData);
      
      if (!validationResult.success) {
        console.log('Validation failed for step:', currentStep, 'Fields:', fieldsToValidate, 'Errors:', validationResult.error.issues);
        
        // Show specific error message from Zod validation
        const firstError = validationResult.error.issues[0];
        if (firstError) {
          toast.error(firstError.message);
          
          // Focus on first error field
          setTimeout(() => {
            const element = document.querySelector(`[name="${firstError.path[0]}"]`) as HTMLElement;
            element?.focus();
          }, 100);
        }
        return;
      }
      
      console.log('Validation passed! Moving to next step with data:', currentStepData);
      await goToNextStep(currentStepData);
    } catch (error) {
      console.error('Form submission error:', error);
      setSubmitError('An error occurred during validation. Please try again.');
    }
  };
  
  const handleSocialRegister = (provider: 'google' | 'github') => {
    // In production, implement OAuth flow
    toast.info(`${provider} registration coming soon!`);
    console.log(`${provider} registration clicked`);
  };

  // Render different steps
  const renderPersonalInfoStep = () => (
    <>
      <div className="mb-6">
        <h2 id="step-heading" className="text-xl font-semibold mb-2">Personal Information</h2>
        <p className="text-sm text-muted-foreground">
          Let's start with some basic information about you.
        </p>
      </div>
      
      {/* Name fields */}
      <fieldset className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <legend className="sr-only">Name information</legend>
        <Input
          label="First name"
          type="text"
          autoComplete="given-name"
          placeholder="Enter your first name"
          error={errors.firstName?.message}
          data-testid="first-name-input"
          aria-describedby={errors.firstName ? 'firstName-error' : undefined}
          aria-required="true"
          {...register('firstName')}
        />
        
        <Input
          label="Last name"
          type="text"
          autoComplete="family-name"
          placeholder="Enter your last name"
          error={errors.lastName?.message}
          data-testid="last-name-input"
          aria-describedby={errors.lastName ? 'lastName-error' : undefined}
          aria-required="true"
          {...register('lastName')}
        />
      </fieldset>

      {/* Email field */}
      <Input
        label="Email address"
        type="email"
        autoComplete="email"
        placeholder="Enter your email address"
        error={errors.email?.message}
        data-testid="email-input"
        aria-describedby={errors.email ? 'email-error' : 'email-description'}
        aria-required="true"
        {...register('email')}
      />
      <div id="email-description" className="sr-only">
        We'll use this email to send you important account updates
      </div>
    </>
  );
  
  const renderPasswordStep = () => (
    <>
      <div className="mb-6">
        <h2 id="step-heading" className="text-xl font-semibold mb-2">Create Password</h2>
        <p className="text-sm text-muted-foreground">
          Choose a strong password to protect your account.
        </p>
      </div>
      
      {/* Password field */}
      <fieldset>
        <legend className="sr-only">Password creation</legend>
        <SecurePasswordInput
          label="Password"
          autoComplete="new-password"
          placeholder="Create a strong password"
          showGenerator={true}
          showStrengthMeter={true}
          showRequirements={true}
          userInfo={{
            email: watchedEmail,
            firstName: watchedFirstName,
            lastName: watchedLastName,
          }}
          error={errors.password?.message}
          data-testid="password-input"
          aria-describedby="password-requirements"
          aria-required="true"
          {...register('password', passwordValidationRules())}
        />

        {/* Confirm Password field */}
        <div className="space-y-2">
          <label htmlFor="confirmPassword" className="label">
            Confirm password
          </label>
          <PasswordConfirmationInput
            password={watchedPassword}
            confirmPassword={watch('confirmPassword')}
            onConfirmPasswordChange={(e) => setValue('confirmPassword', e.target.value)}
            autoComplete="new-password"
            placeholder="Confirm your password"
            data-testid="confirm-password-input"
            aria-describedby={errors.confirmPassword ? 'confirmPassword-error' : 'confirmPassword-description'}
            aria-required="true"
            {...register('confirmPassword')}
          />
          <div id="confirmPassword-description" className="sr-only">
            Re-enter your password to confirm it matches
          </div>
          {errors.confirmPassword && (
            <p id="confirmPassword-error" className="text-sm text-destructive mt-1" role="alert">
              {errors.confirmPassword.message}
            </p>
          )}
        </div>
      </fieldset>
    </>
  );
  
  const renderTermsStep = () => (
    <>
      <div className="mb-6">
        <h2 id="step-heading" className="text-xl font-semibold mb-2">Terms & Privacy</h2>
        <p className="text-sm text-muted-foreground">
          Please review and accept our terms to continue.
        </p>
      </div>
      
      {/* Terms agreement */}
      <fieldset className="space-y-4">
        <legend className="sr-only">Agreement to terms and policies</legend>
        <div className="flex items-start space-x-3">
          <input
            id="agreeToTerms"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="terms-checkbox"
            aria-describedby={errors.agreeToTerms ? 'agreeToTerms-error' : 'agreeToTerms-description'}
            aria-required="true"
            {...register('agreeToTerms')}
          />
          <div>
            <label htmlFor="agreeToTerms" className="text-sm text-muted-foreground select-none">
              I agree to the{' '}
              <Link 
                to="/terms" 
                className="text-primary hover:text-primary/80 font-medium" 
                target="_blank"
                aria-describedby="terms-link-description"
              >
                Terms of Service
              </Link>
            </label>
            <div id="agreeToTerms-description" className="sr-only">
              Required: You must agree to our terms of service to create an account
            </div>
            <div id="terms-link-description" className="sr-only">
              Opens in a new tab
            </div>
          </div>
        </div>
        {errors.agreeToTerms && (
          <p id="agreeToTerms-error" className="text-sm text-destructive ml-7" role="alert">
            {errors.agreeToTerms.message}
          </p>
        )}
        
        <div className="flex items-start space-x-3">
          <input
            id="agreeToPrivacy"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="privacy-checkbox"
            aria-describedby={errors.agreeToPrivacy ? 'agreeToPrivacy-error' : 'agreeToPrivacy-description'}
            aria-required="true"
            {...register('agreeToPrivacy')}
          />
          <div>
            <label htmlFor="agreeToPrivacy" className="text-sm text-muted-foreground select-none">
              I agree to the{' '}
              <Link 
                to="/privacy" 
                className="text-primary hover:text-primary/80 font-medium" 
                target="_blank"
                aria-describedby="privacy-link-description"
              >
                Privacy Policy
              </Link>
            </label>
            <div id="agreeToPrivacy-description" className="sr-only">
              Required: You must agree to our privacy policy to create an account
            </div>
            <div id="privacy-link-description" className="sr-only">
              Opens in a new tab
            </div>
          </div>
        </div>
        {errors.agreeToPrivacy && (
          <p id="agreeToPrivacy-error" className="text-sm text-destructive ml-7" role="alert">
            {errors.agreeToPrivacy.message}
          </p>
        )}
        
        <div className="flex items-start space-x-3">
          <input
            id="agreeToMarketing"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="marketing-checkbox"
            aria-describedby="agreeToMarketing-description"
            {...register('agreeToMarketing')}
          />
          <div>
            <label htmlFor="agreeToMarketing" className="text-sm text-muted-foreground select-none">
              I would like to receive marketing emails and updates (optional)
            </label>
            <div id="agreeToMarketing-description" className="sr-only">
              Optional: Receive promotional emails and product updates
            </div>
          </div>
        </div>
      </fieldset>
    </>
  );
  
  const renderAgeVerificationStep = () => {
    const handleDateChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      setBirthDate(e.target.value);
      setAgeError('');
    };
    
    const calculateAge = (birthDate: Date): number => {
      const today = new Date();
      let age = today.getFullYear() - birthDate.getFullYear();
      const monthDiff = today.getMonth() - birthDate.getMonth();
      
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        age--;
      }
      
      return age;
    };
    
    const handleVerifyAge = () => {
      if (!birthDate) {
        setAgeError('Please enter your date of birth');
        return;
      }
      
      setIsVerifying(true);
      setAgeError('');
      
      try {
        const birth = new Date(birthDate);
        
        // Validate date
        if (isNaN(birth.getTime())) {
          setAgeError('Please enter a valid date');
          setIsVerifying(false);
          return;
        }

        // Check if date is in the future
        if (birth > new Date()) {
          setAgeError('Birth date cannot be in the future');
          setIsVerifying(false);
          return;
        }
        
        const age = calculateAge(birth);
        
        if (age >= 16) {
          // Age verified - GDPR compliant
          handleAgeVerification(age);
        } else if (age >= 13) {
          // Requires parental consent (COPPA compliance)
          setRequiresParentalConsent(true);
        } else {
          // Too young
          setAgeError('You must be at least 13 years old to use this service');
          handleAgeVerificationFailed();
        }
      } catch (error) {
        setAgeError('An error occurred. Please try again.');
      } finally {
        setIsVerifying(false);
      }
    };
    
    const handleParentalConsent = () => {
      // In production, implement proper parental consent flow
      const birth = new Date(birthDate);
      const age = calculateAge(birth);
      handleAgeVerification(age);
    };
    
    if (requiresParentalConsent) {
      return (
        <div className="max-w-md mx-auto py-8">
          <div className="text-center mb-6">
            <Shield className="h-16 w-16 text-primary mx-auto mb-4" aria-hidden="true" />
            <h2 id="step-heading" className="text-xl font-semibold mb-2">Parental Consent Required</h2>
            <p className="text-sm text-muted-foreground">
              Users under 16 require parental consent to comply with privacy regulations.
            </p>
          </div>
          
          <Alert type="warning" className="mb-6">
            <AlertCircle className="h-4 w-4" />
            <AlertContent>
              <h4 className="font-medium">For Parents/Guardians:</h4>
              <ul className="text-sm mt-2 space-y-1 text-left">
                <li>• We collect minimal data from users under 16</li>
                <li>• No marketing or analytics cookies will be used</li>
                <li>• You can request data deletion at any time</li>
                <li>• Review our Children's Privacy Policy for details</li>
              </ul>
            </AlertContent>
          </Alert>
          
          <div className="flex gap-3">
            <Button
              variant="outline"
              onClick={() => {
                setRequiresParentalConsent(false);
                setBirthDate('');
                setAgeError('');
              }}
              className="flex-1"
            >
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
            <Button
              onClick={handleParentalConsent}
              className="flex-1"
            >
              I'm a Parent/Guardian
            </Button>
          </div>
        </div>
      );
    }
    
    return (
      <div className="max-w-md mx-auto py-8">
        <div className="text-center mb-6">
          <Shield className="h-16 w-16 text-primary mx-auto mb-4" aria-hidden="true" />
          <h2 id="step-heading" className="text-xl font-semibold mb-2">Age Verification</h2>
          <p className="text-sm text-muted-foreground">
            We need to verify your age to comply with privacy regulations (GDPR/COPPA).
          </p>
        </div>
        
        <div className="space-y-4">
          <div>
            <label htmlFor="birthdate" className="block text-sm font-medium mb-2">
              Date of Birth
            </label>
            <div className="relative">
              <input
                type="date"
                id="birthdate"
                value={birthDate}
                onChange={handleDateChange}
                max={new Date().toISOString().split('T')[0]}
                className="input w-full pl-10"
                required
                aria-describedby={ageError ? 'age-error' : 'age-description'}
                aria-invalid={ageError ? 'true' : 'false'}
              />
              <svg
                className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                aria-hidden="true"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </div>
            {ageError && (
              <p id="age-error" className="text-sm text-destructive mt-2" role="alert">
                {ageError}
              </p>
            )}
            <div id="age-description" className="sr-only">
              Enter your date of birth for age verification
            </div>
          </div>
          
          <Alert type="info" className="text-left">
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <AlertContent>
              <h4 className="font-medium">Why we need your age</h4>
              <ul className="text-sm mt-2 space-y-1">
                <li>• To comply with GDPR and COPPA regulations</li>
                <li>• To provide age-appropriate content and features</li>
                <li>• To protect children's privacy online</li>
              </ul>
            </AlertContent>
          </Alert>
          
          <Button
            onClick={handleVerifyAge}
            className="w-full"
            disabled={!birthDate || isVerifying}
            loading={isVerifying}
          >
            {isVerifying ? 'Verifying Age...' : 'Verify Age'}
          </Button>
          
          <div className="text-center">
            <p className="text-xs text-muted-foreground">
              Your date of birth is used only for age verification and will not be stored.
            </p>
            <div className="text-xs text-muted-foreground mt-2">
              By verifying your age, you agree to our{' '}
              <Link to="/privacy" className="text-primary hover:underline" target="_blank">
                Privacy Policy
              </Link>{' '}
              and{' '}
              <Link to="/terms" className="text-primary hover:underline" target="_blank">
                Terms of Service
              </Link>.
            </div>
          </div>
        </div>
      </div>
    );
  };
  
  const renderConfirmationStep = () => (
    <div className="text-center py-8" role="region" aria-live="polite">
      <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" aria-hidden="true" />
      <h2 id="step-heading" className="text-2xl font-semibold mb-2">Welcome to Enterprise App!</h2>
      <p className="text-muted-foreground mb-6">
        Your account has been created successfully and you're now signed in!
      </p>
      <div className="bg-muted p-4 rounded-lg mb-6">
        <h3 className="font-medium mb-2">You're all set!</h3>
        <ul className="text-sm text-muted-foreground text-left space-y-1" role="list">
          <li role="listitem">• Your account is active and ready to use</li>
          <li role="listitem">• You can start exploring the dashboard</li>
          <li role="listitem">• Update your profile settings anytime</li>
        </ul>
      </div>
      {isRedirecting ? (
        <div className="flex justify-center" aria-live="polite">
          <Spinner size="sm" className="mr-2" aria-hidden="true" />
          <span className="text-sm text-muted-foreground">Redirecting to dashboard...</span>
        </div>
      ) : (
        <div className="space-y-3">
          <Button 
            onClick={() => {
              console.log('Manual navigation triggered');
              navigate('/dashboard', { replace: true });
            }}
            className="w-full"
          >
            Go to Dashboard
          </Button>
          <p className="text-xs text-muted-foreground">
            Automatic redirect didn't work? Click the button above.
          </p>
        </div>
      )}
    </div>
  );
  
  return (
    <div className={className}>
      {/* Progress bar */}
      {currentStep !== 'confirmation' && (
        <div className="mb-8" role="region" aria-label="Registration progress">
          <div className="flex justify-between text-xs text-muted-foreground mb-2">
            <span>Step {['personal', 'password', 'terms', 'age-verification'].indexOf(currentStep) + 1} of 4</span>
            <span>{Math.round(getProgressPercentage())}% complete</span>
          </div>
          <div className="w-full bg-muted rounded-full h-2" role="progressbar" 
               aria-valuenow={getProgressPercentage()} 
               aria-valuemin={0} 
               aria-valuemax={100}
               aria-label={`Registration progress: ${Math.round(getProgressPercentage())}% complete`}>
            <div 
              className="bg-primary h-2 rounded-full transition-all duration-300 ease-in-out"
              style={{ width: `${getProgressPercentage()}%` }}
            />
          </div>
        </div>
      )}
      
      <form 
        onSubmit={(e) => {
          e.preventDefault();
          console.log('====== FORM onSubmit EVENT FIRED ======');
          console.log('Form event:', e);
          console.log('Current step:', currentStep);
          
          // Get the form data directly
          const formData = new FormData(e.currentTarget);
          const data = {
            firstName: formData.get('firstName') as string,
            lastName: formData.get('lastName') as string,
            email: formData.get('email') as string,
            password: formData.get('password') as string,
            confirmPassword: formData.get('confirmPassword') as string,
            agreeToTerms: formData.get('agreeToTerms') === 'on',
            agreeToPrivacy: formData.get('agreeToPrivacy') === 'on',
            agreeToMarketing: formData.get('agreeToMarketing') === 'on',
          };
          
          console.log('Form data:', data);
          console.log('Calling onSubmit directly...');
          onSubmit(data);
        }}
        className="space-y-6" 
        data-testid="register-form" 
        noValidate 
        aria-labelledby="step-heading"
      >
        <CSRFToken />
        
        {/* Error Alert */}
        {submitError && (
          <Alert 
            type="error" 
            title="Registration failed" 
            description={submitError}
            dismissible
            onDismiss={() => setSubmitError(null)}
            role="alert"
            aria-live="assertive"
          />
        )}
        
        {/* Render current step */}
        {currentStep === 'personal' && renderPersonalInfoStep()}
        {currentStep === 'password' && renderPasswordStep()}
        {currentStep === 'terms' && renderTermsStep()}
        {currentStep === 'age-verification' && renderAgeVerificationStep()}
        {currentStep === 'confirmation' && renderConfirmationStep()}
        
        {/* Navigation buttons */}
        {currentStep !== 'age-verification' && currentStep !== 'confirmation' && (
          <div className="flex gap-3">
            {currentStep !== 'personal' && (
              <Button
                type="button"
                variant="outline"
                onClick={goToPrevStep}
                className="flex-1"
                disabled={isLoading}
                data-testid="back-button"
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Button>
            )}
            
            <button
              type="submit"
              disabled={isLoading || !isCurrentStepValid()}
              className={`btn btn-primary ${currentStep === 'personal' ? 'w-full' : 'flex-1'}`}
              data-testid="next-button"
            >
              {currentStep === 'terms' && isLoading ? (
                'Creating account...'
              ) : currentStep === 'terms' ? (
                'Create account'
              ) : (
                <>
                  Continue
                  <ArrowRight className="h-4 w-4 ml-2 inline" />
                </>
              )}
            </button>
          </div>
        )}

        {/* Social registration buttons - only show on first step */}
        {currentStep === 'personal' && (
          <>
            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="separator-horizontal" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-muted-foreground">
                  Or continue with
                </span>
              </div>
            </div>
            
            {/* Social registration buttons */}
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                className="btn-outline transition-all duration-200 hover:scale-[1.02] focus:scale-[1.02]"
                onClick={() => handleSocialRegister('google')}
                disabled={isLoading}
                data-testid="google-register-button"
                aria-label="Sign up with Google"
              >
                <svg className="h-4 w-4" viewBox="0 0 24 24" aria-hidden="true">
                  <path
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                    fill="#4285F4"
                  />
                  <path
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                    fill="#34A853"
                  />
                  <path
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                    fill="#FBBC05"
                  />
                  <path
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                    fill="#EA4335"
                  />
                </svg>
                Google
              </button>
              
              <button
                type="button"
                className="btn-outline transition-all duration-200 hover:scale-[1.02] focus:scale-[1.02]"
                onClick={() => handleSocialRegister('github')}
                disabled={isLoading}
                data-testid="github-register-button"
                aria-label="Sign up with GitHub"
              >
                <Github className="h-4 w-4" aria-hidden="true" />
                GitHub
              </button>
            </div>
          </>
        )}
      </form>

      {/* Removed sign in link - users are already on register page */}
    </div>
  );
}

// Wrap with AuthLayout in the router
Register.displayName = 'Register';

export default Register;