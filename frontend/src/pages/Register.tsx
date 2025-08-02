import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Mail, User } from 'lucide-react';
import { 
  Input, 
  SecurePasswordInput, 
  PasswordConfirmationInput,
  RateLimitedButton,
  Alert
} from '../components';
import { passwordValidationRules } from '../security/passwordValidation';
import { CSRFToken } from '../components/CSRFToken';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

// Form validation schema with strong password requirements
const registerSchema = z.object({
  firstName: z.string().min(1, 'First name is required').max(50),
  lastName: z.string().min(1, 'Last name is required').max(50),
  email: z.string().email('Invalid email address'),
  password: z.string().min(12, 'Password must be at least 12 characters'),
  confirmPassword: z.string(),
  agreeToTerms: z.boolean().refine(val => val === true, {
    message: 'You must agree to the terms and conditions',
  }),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

type RegisterFormData = z.infer<typeof registerSchema>;

function Register({ className }: PageProps) {
  const navigate = useNavigate();
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
    setValue,
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      firstName: '',
      lastName: '',
      email: '',
      password: '',
      confirmPassword: '',
      agreeToTerms: false,
    },
  });

  const watchedPassword = watch('password');
  const watchedEmail = watch('email');
  const watchedFirstName = watch('firstName');
  const watchedLastName = watch('lastName');

  const onSubmit = async (data: RegisterFormData) => {
    setIsSubmitting(true);
    setSubmitError(null);
    
    try {
      // Simulate API call - In production, use your auth service
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      console.log('Registration data:', data);
      
      toast.success('Account created successfully!');
      
      // Navigate to login page with success message
      navigate('/login', { 
        state: { message: 'Account created successfully! Please sign in.' }
      });
    } catch (error) {
      console.error('Registration error:', error);
      setSubmitError('An account with this email already exists');
      toast.error('Registration failed. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className={className}>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
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
        {/* Name fields */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Input
            label="First name"
            type="text"
            autoComplete="given-name"
            leftIcon={<User className="h-4 w-4" />}
            error={errors.firstName?.message}
            {...register('firstName')}
          />
          
          <Input
            label="Last name"
            type="text"
            autoComplete="family-name"
            leftIcon={<User className="h-4 w-4" />}
            error={errors.lastName?.message}
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
          {...register('email')}
        />

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
            {...register('confirmPassword')}
          />
          {errors.confirmPassword && (
            <p className="text-sm text-destructive mt-1">{errors.confirmPassword.message}</p>
          )}
        </div>

        {/* Terms agreement */}
        <div className="space-y-2">
          <div className="flex items-start">
            <input
              id="agreeToTerms"
              type="checkbox"
              className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded mt-0.5"
              {...register('agreeToTerms')}
            />
            <label htmlFor="agreeToTerms" className="ml-2 block text-sm text-muted-foreground">
              I agree to the{' '}
              <Link to="/terms" className="text-primary hover:text-primary/80 font-medium">
                Terms of Service
              </Link>{' '}
              and{' '}
              <Link to="/privacy" className="text-primary hover:text-primary/80 font-medium">
                Privacy Policy
              </Link>
            </label>
          </div>
          {errors.agreeToTerms && (
            <p className="text-sm text-destructive">{errors.agreeToTerms}</p>
          )}
        </div>

        {/* Submit button */}
        <RateLimitedButton
          type="submit"
          disabled={isSubmitting}
          loading={isSubmitting}
          className="w-full"
          onRateLimitExceeded={(seconds) => {
            toast.error(`Too many registration attempts. Please try again in ${seconds} seconds.`);
          }}
        >
          {isSubmitting ? 'Creating account...' : 'Create account'}
        </RateLimitedButton>

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

        {/* Social login buttons */}
        <div className="grid grid-cols-2 gap-3">
          <button
            type="button"
            className="btn-outline"
            onClick={() => console.log('Google signup')}
          >
            <svg className="h-4 w-4" viewBox="0 0 24 24">
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
            className="btn-outline"
            onClick={() => console.log('GitHub signup')}
          >
            <svg className="h-4 w-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            GitHub
          </button>
        </div>
      </form>

      {/* Sign in link */}
      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Already have an account?{' '}
          <Link
            to="/login"
            className="font-medium text-primary hover:text-primary/80"
          >
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}

export default Register;