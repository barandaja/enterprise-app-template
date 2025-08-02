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

function Register({ className }: PageProps) {
  const navigate = useNavigate();
  const { register: registerUser } = useAuthActions();
  const authError = useAuthError();
  const isLoading = useAuthLoading();
  const { hasConsent, requestConsent } = useConsent();
  
  const [currentStep, setCurrentStep] = React.useState<RegistrationStep>('personal');
  const [stepData, setStepData] = React.useState<Partial<StepData>>({});
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [ageVerified, setAgeVerified] = React.useState(false);
  const [userAge, setUserAge] = React.useState<number | null>(null);
  
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
  } = useForm({
    resolver: zodResolver(getCurrentSchema()),
    mode: 'onChange',
    defaultValues: {
      firstName: '',
      lastName: '',
      email: '',
      password: '',
      confirmPassword: '',
      agreeToTerms: false,
      agreeToPrivacy: false,
      agreeToMarketing: false,
    },
  });

  const watchedPassword = watch('password');
  const watchedEmail = watch('email');
  const watchedFirstName = watch('firstName');
  const watchedLastName = watch('lastName');
  
  // Progress calculation
  const getProgressPercentage = () => {
    const steps = ['personal', 'password', 'terms', 'age-verification', 'confirmation'];
    const currentIndex = steps.indexOf(currentStep);
    return ((currentIndex + 1) / steps.length) * 100;
  };
  
  // Navigation helpers
  const goToNextStep = async (data: any) => {
    // Store current step data
    setStepData(prev => ({ ...prev, [currentStep]: data }));
    
    switch (currentStep) {
      case 'personal':
        // Additional email validation
        const emailValidation = validateEmail(data.email);
        if (!emailValidation.isValid) {
          setSubmitError(emailValidation.error);
          return;
        }
        setCurrentStep('password');
        break;
      case 'password':
        setCurrentStep('terms');
        break;
      case 'terms':
        // Check if user needs age verification
        if (!ageVerified) {
          setCurrentStep('age-verification');
        } else {
          await submitRegistration();
        }
        break;
      case 'age-verification':
        await submitRegistration();
        break;
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
  
  const handleAgeVerification = (age: number) => {
    setAgeVerified(true);
    setUserAge(age);
    setCurrentStep('confirmation');
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
      
      // Navigate to login after a delay
      setTimeout(() => {
        navigate('/login', { 
          state: { message: 'Account created successfully! Please check your email to verify your account.' }
        });
      }, 3000);
    } catch (error) {
      console.error('Registration error:', error);
      setSubmitError(authError || 'Registration failed. Please try again.');
      setCurrentStep('personal'); // Go back to first step
      toast.error('Registration failed. Please try again.');
    }
  };
  
  const onSubmit = async (data: any) => {
    setSubmitError(null);
    await goToNextStep(data);
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
        <h2 className="text-xl font-semibold mb-2">Personal Information</h2>
        <p className="text-sm text-muted-foreground">
          Let's start with some basic information about you.
        </p>
      </div>
      
      {/* Name fields */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <Input
          label="First name"
          type="text"
          autoComplete="given-name"
          leftIcon={<User className="h-4 w-4" />}
          error={errors.firstName?.message}
          data-testid="first-name-input"
          {...register('firstName')}
        />
        
        <Input
          label="Last name"
          type="text"
          autoComplete="family-name"
          leftIcon={<User className="h-4 w-4" />}
          error={errors.lastName?.message}
          data-testid="last-name-input"
          {...register('lastName')}
        />
      </div>

      {/* Email field */}
      <Input
        label="Email address"
        type="email"
        autoComplete="email"
        leftIcon={<Mail className="h-4 w-4" />}
        error={errors.email?.message}
        data-testid="email-input"
        {...register('email')}
      />
    </>
  );
  
  const renderPasswordStep = () => (
    <>
      <div className="mb-6">
        <h2 className="text-xl font-semibold mb-2">Create Password</h2>
        <p className="text-sm text-muted-foreground">
          Choose a strong password to protect your account.
        </p>
      </div>
      
      {/* Password field */}
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
          {...register('confirmPassword')}
        />
        {errors.confirmPassword && (
          <p className="text-sm text-destructive mt-1" role="alert">{errors.confirmPassword.message}</p>
        )}
      </div>
    </>
  );
  
  const renderTermsStep = () => (
    <>
      <div className="mb-6">
        <h2 className="text-xl font-semibold mb-2">Terms & Privacy</h2>
        <p className="text-sm text-muted-foreground">
          Please review and accept our terms to continue.
        </p>
      </div>
      
      {/* Terms agreement */}
      <div className="space-y-4">
        <div className="flex items-start space-x-3">
          <input
            id="agreeToTerms"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="terms-checkbox"
            {...register('agreeToTerms')}
          />
          <label htmlFor="agreeToTerms" className="text-sm text-muted-foreground select-none">
            I agree to the{' '}
            <Link to="/terms" className="text-primary hover:text-primary/80 font-medium" target="_blank">
              Terms of Service
            </Link>
          </label>
        </div>
        {errors.agreeToTerms && (
          <p className="text-sm text-destructive ml-7" role="alert">{errors.agreeToTerms.message}</p>
        )}
        
        <div className="flex items-start space-x-3">
          <input
            id="agreeToPrivacy"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="privacy-checkbox"
            {...register('agreeToPrivacy')}
          />
          <label htmlFor="agreeToPrivacy" className="text-sm text-muted-foreground select-none">
            I agree to the{' '}
            <Link to="/privacy" className="text-primary hover:text-primary/80 font-medium" target="_blank">
              Privacy Policy
            </Link>
          </label>
        </div>
        {errors.agreeToPrivacy && (
          <p className="text-sm text-destructive ml-7" role="alert">{errors.agreeToPrivacy.message}</p>
        )}
        
        <div className="flex items-start space-x-3">
          <input
            id="agreeToMarketing"
            type="checkbox"
            className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-1"
            data-testid="marketing-checkbox"
            {...register('agreeToMarketing')}
          />
          <label htmlFor="agreeToMarketing" className="text-sm text-muted-foreground select-none">
            I would like to receive marketing emails and updates (optional)
          </label>
        </div>
      </div>
    </>
  );
  
  const renderAgeVerificationStep = () => (
    <div className="text-center py-8">
      <Shield className="h-16 w-16 text-primary mx-auto mb-4" />
      <h2 className="text-xl font-semibold mb-2">Age Verification</h2>
      <p className="text-sm text-muted-foreground mb-6">
        We need to verify your age to comply with privacy regulations.
      </p>
      <AgeVerification
        minAge={16}
        onVerified={handleAgeVerification}
        onFailed={handleAgeVerificationFailed}
        showParentalConsent={true}
      />
    </div>
  );
  
  const renderConfirmationStep = () => (
    <div className="text-center py-8">
      <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
      <h2 className="text-2xl font-semibold mb-2">Welcome to Enterprise App!</h2>
      <p className="text-muted-foreground mb-6">
        Your account has been created successfully. We've sent a verification email to{' '}
        <span className="font-medium">{stepData.personal?.email}</span>.
      </p>
      <div className="bg-muted p-4 rounded-lg mb-6">
        <h3 className="font-medium mb-2">Next steps:</h3>
        <ul className="text-sm text-muted-foreground text-left space-y-1">
          <li>• Check your email for a verification link</li>
          <li>• Click the link to activate your account</li>
          <li>• Sign in to start using the platform</li>
        </ul>
      </div>
      <div className="flex justify-center">
        <Spinner size="sm" className="mr-2" />
        <span className="text-sm text-muted-foreground">Redirecting to login...</span>
      </div>
    </div>
  );
  
  return (
    <div className={className}>
      {/* Progress bar */}
      {currentStep !== 'confirmation' && (
        <div className="mb-8">
          <div className="flex justify-between text-xs text-muted-foreground mb-2">
            <span>Step {['personal', 'password', 'terms', 'age-verification'].indexOf(currentStep) + 1} of 4</span>
            <span>{Math.round(getProgressPercentage())}% complete</span>
          </div>
          <div className="w-full bg-muted rounded-full h-2">
            <div 
              className="bg-primary h-2 rounded-full transition-all duration-300 ease-in-out"
              style={{ width: `${getProgressPercentage()}%` }}
            />
          </div>
        </div>
      )}
      
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" data-testid="register-form">
        <CSRFToken />
        
        {/* Error Alert */}
        {submitError && (
          <Alert 
            type="error" 
            title="Registration failed" 
            description={submitError}
            dismissible
            onDismiss={() => setSubmitError(null)}
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
            
            <RateLimitedButton
              type="submit"
              disabled={isLoading || !isValid}
              loading={isLoading && currentStep === 'terms'}
              className={currentStep === 'personal' ? 'w-full' : 'flex-1'}
              onRateLimitExceeded={(seconds) => {
                toast.error(`Too many attempts. Please try again in ${seconds} seconds.`);
              }}
              data-testid="next-button"
            >
              {currentStep === 'terms' && isLoading ? (
                'Creating account...'
              ) : currentStep === 'terms' ? (
                'Create account'
              ) : (
                <>
                  Continue
                  <ArrowRight className="h-4 w-4 ml-2" />
                </>
              )}
            </RateLimitedButton>
          </div>
        )}

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

      {/* Sign in link - only show when not in confirmation step */}
      {currentStep !== 'confirmation' && (
        <div className="mt-8 text-center">
          <p className="text-sm text-muted-foreground">
            Already have an account?{' '}
            <Link
              to="/login"
              className="font-medium text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-1"
              data-testid="login-link"
            >
              Sign in
            </Link>
          </p>
        </div>
      )}
    </div>
  );
}

// Wrap with AuthLayout in the router
Register.displayName = 'Register';

export default Register;