import React from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Lock, CheckCircle, AlertCircle, Shield, Eye, EyeOff, ArrowLeft } from 'lucide-react';
import { 
  SecurePasswordInput,
  PasswordConfirmationInput,
  RateLimitedButton, 
  Alert, 
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
  Spinner
} from '../components';
import { CSRFToken } from '../components/CSRFToken';
import { passwordValidationRules } from '../security/passwordValidation';
import { authService } from '../services/api/auth.service';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

// Form validation schema with strong password requirements
const resetPasswordSchema = z.object({
  password: z.string().min(12, 'Password must be at least 12 characters'),
  confirmPassword: z.string(),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

type ResetPasswordFormData = z.infer<typeof resetPasswordSchema>;

type ResetPasswordState = 'loading' | 'form' | 'success' | 'expired' | 'invalid';

function ResetPassword({ className }: PageProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const email = searchParams.get('email');
  
  const [state, setState] = React.useState<ResetPasswordState>('loading');
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [tokenValid, setTokenValid] = React.useState(false);
  
  const {
    register,
    handleSubmit,
    formState: { errors, isValid },
    watch,
    setValue,
  } = useForm<ResetPasswordFormData>({
    resolver: zodResolver(resetPasswordSchema),
    mode: 'onChange',
    defaultValues: {
      password: '',
      confirmPassword: '',
    },
  });

  const watchedPassword = watch('password');

  // Validate token on component mount
  React.useEffect(() => {
    if (!token || !email) {
      setState('invalid');
      return;
    }

    const validateToken = async () => {
      try {
        const response = await authService.validateResetToken(token, email);
        if (response.success) {
          setTokenValid(true);
          setState('form');
        } else {
          setState('expired');
        }
      } catch (error) {
        console.error('Token validation error:', error);
        setState('expired');
      }
    };

    validateToken();
  }, [token, email]);

  const onSubmit = async (data: ResetPasswordFormData) => {
    if (!token || !email || !tokenValid) {
      toast.error('Invalid reset token');
      return;
    }

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const response = await authService.resetPassword({
        token,
        email,
        password: data.password,
      });

      if (response.success) {
        setState('success');
        toast.success('Password reset successfully!');
        
        // Navigate to login after a delay
        setTimeout(() => {
          navigate('/login', {
            state: { message: 'Password reset successfully! Please sign in with your new password.' }
          });
        }, 3000);
      } else {
        setSubmitError(response.message || 'Failed to reset password');
        toast.error('Failed to reset password');
      }
    } catch (error) {
      console.error('Reset password error:', error);
      setSubmitError('An error occurred. Please try again.');
      toast.error('Failed to reset password');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderLoading = () => (
    <Card>
      <CardContent className="text-center py-12">
        <Spinner size="lg" className="mx-auto mb-4" />
        <h2 className="text-xl font-semibold mb-2">Validating reset token...</h2>
        <p className="text-muted-foreground">Please wait while we verify your reset link.</p>
      </CardContent>
    </Card>
  );

  const renderForm = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-4">
          <Lock className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl">Reset your password</CardTitle>
        <CardDescription>
          {email && (
            <>
              Creating a new password for{' '}
              <span className="font-medium text-foreground">{email}</span>
            </>
          )}
        </CardDescription>
      </CardHeader>
      
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" data-testid="reset-password-form">
          <CSRFToken />
          
          {/* Error Alert */}
          {submitError && (
            <Alert type="error" dismissible onDismiss={() => setSubmitError(null)}>
              <AlertCircle className="h-4 w-4" />
              <div className="ml-2">
                <p className="font-medium">Reset failed</p>
                <p className="text-sm opacity-90">{submitError}</p>
              </div>
            </Alert>
          )}

          {/* Password field with strength meter */}
          <SecurePasswordInput
            label="New password"
            autoComplete="new-password"
            placeholder="Create a strong password"
            showGenerator={true}
            showStrengthMeter={true}
            showRequirements={true}
            userInfo={{ email: email || undefined }}
            error={errors.password?.message}
            data-testid="password-input"
            {...register('password', passwordValidationRules())}
          />

          {/* Confirm Password field */}
          <div className="space-y-2">
            <label htmlFor="confirmPassword" className="label">
              Confirm new password
            </label>
            <PasswordConfirmationInput
              password={watchedPassword}
              confirmPassword={watch('confirmPassword')}
              onConfirmPasswordChange={(e) => setValue('confirmPassword', e.target.value)}
              autoComplete="new-password"
              placeholder="Confirm your new password"
              data-testid="confirm-password-input"
              {...register('confirmPassword')}
            />
            {errors.confirmPassword && (
              <p className="text-sm text-destructive mt-1" role="alert">{errors.confirmPassword.message}</p>
            )}
          </div>

          {/* Security guidelines */}
          <div className="bg-muted p-4 rounded-lg">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
              <div className="text-sm">
                <h4 className="font-medium mb-1">Password Security Tips</h4>
                <ul className="text-muted-foreground space-y-1">
                  <li>• Use a unique password you haven't used before</li>
                  <li>• Include a mix of letters, numbers, and symbols</li>
                  <li>• Avoid personal information or common words</li>
                  <li>• Consider using a password manager</li>
                </ul>
              </div>
            </div>
          </div>

          {/* Submit button */}
          <RateLimitedButton
            type="submit"
            disabled={!isValid || isSubmitting}
            loading={isSubmitting}
            className="w-full"
            onRateLimitExceeded={(seconds) => {
              toast.error(`Too many attempts. Please try again in ${seconds} seconds.`);
            }}
            data-testid="reset-password-button"
          >
            {isSubmitting ? 'Resetting password...' : 'Reset password'}
          </RateLimitedButton>

          {/* Back to login */}
          <div className="text-center">
            <Link
              to="/login"
              className="inline-flex items-center text-sm text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
              data-testid="back-to-login-link"
            >
              <ArrowLeft className="h-4 w-4 mr-1" />
              Back to login
            </Link>
          </div>
        </form>
      </CardContent>
    </Card>
  );

  const renderSuccess = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-4">
          <CheckCircle className="h-6 w-6 text-green-600" />
        </div>
        <CardTitle className="text-2xl">Password reset successful!</CardTitle>
        <CardDescription>
          Your password has been updated successfully. You can now sign in with your new password.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="text-center space-y-6">
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="font-medium text-green-800 mb-2">What's next?</h4>
          <ul className="text-sm text-green-700 space-y-1">
            <li>• Your new password is now active</li>
            <li>• You'll be redirected to the login page shortly</li>
            <li>• Sign in with your email and new password</li>
          </ul>
        </div>

        <div className="flex justify-center items-center space-x-2 text-sm text-muted-foreground">
          <Spinner size="sm" />
          <span>Redirecting to login...</span>
        </div>

        <Link
          to="/login"
          className="inline-flex items-center text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
          data-testid="continue-to-login-link"
        >
          Continue to login
        </Link>
      </CardContent>
    </Card>
  );

  const renderExpired = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mb-4">
          <AlertCircle className="h-6 w-6 text-orange-600" />
        </div>
        <CardTitle className="text-2xl">Reset link expired</CardTitle>
        <CardDescription>
          This password reset link has expired or has already been used.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="text-center space-y-6">
        <div className="bg-orange-50 p-4 rounded-lg">
          <h4 className="font-medium text-orange-800 mb-2">Why did this happen?</h4>
          <ul className="text-sm text-orange-700 space-y-1 text-left">
            <li>• Reset links expire after 1 hour for security</li>
            <li>• Links can only be used once</li>
            <li>• Multiple reset requests invalidate previous links</li>
          </ul>
        </div>

        <div className="space-y-3">
          <Link
            to="/forgot-password"
            className="inline-flex items-center justify-center w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            data-testid="request-new-reset-link"
          >
            Request a new reset link
          </Link>
          
          <Link
            to="/login"
            className="block text-center text-sm text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
            data-testid="back-to-login-link"
          >
            Back to login
          </Link>
        </div>
      </CardContent>
    </Card>
  );

  const renderInvalid = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-red-100 rounded-full flex items-center justify-center mb-4">
          <AlertCircle className="h-6 w-6 text-red-600" />
        </div>
        <CardTitle className="text-2xl">Invalid reset link</CardTitle>
        <CardDescription>
          This password reset link is invalid or malformed.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="text-center space-y-6">
        <Alert type="error">
          <AlertCircle className="h-4 w-4" />
          <div className="ml-2">
            <p className="font-medium">Link Error</p>
            <p className="text-sm opacity-90">
              The reset link you followed is not valid. Please request a new password reset.
            </p>
          </div>
        </Alert>

        <div className="space-y-3">
          <Link
            to="/forgot-password"
            className="inline-flex items-center justify-center w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            data-testid="request-new-reset-button"
          >
            Request password reset
          </Link>
          
          <Link
            to="/login"
            className="block text-center text-sm text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
            data-testid="back-to-login-link"
          >
            Back to login
          </Link>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className={className}>
      {state === 'loading' && renderLoading()}
      {state === 'form' && renderForm()}
      {state === 'success' && renderSuccess()}
      {state === 'expired' && renderExpired()}
      {state === 'invalid' && renderInvalid()}
      
      {/* Support information */}
      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Having trouble?{' '}
          <Link
            to="/contact"
            className="text-primary hover:text-primary/80 font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-1"
            data-testid="contact-support-link"
          >
            Contact support
          </Link>
        </p>
      </div>
    </div>
  );
}

// Wrap with AuthLayout in the router
ResetPassword.displayName = 'ResetPassword';

export default ResetPassword;