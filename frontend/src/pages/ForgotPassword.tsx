import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Mail, ArrowLeft, CheckCircle, AlertCircle, Clock, Shield } from 'lucide-react';
import { 
  Input, 
  RateLimitedButton, 
  Alert, 
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription
} from '../components';
import { CSRFToken } from '../components/CSRFToken';
import { validateEmail } from '../security/inputValidation';
import { authService } from '../services/api/auth.service';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

// Form validation schema
const forgotPasswordSchema = z.object({
  email: z.string()
    .min(1, 'Email is required')
    .email('Invalid email address')
    .max(254, 'Email address too long'),
});

type ForgotPasswordFormData = z.infer<typeof forgotPasswordSchema>;

type ForgotPasswordState = 'form' | 'sent' | 'error';

function ForgotPassword({ className }: PageProps) {
  const navigate = useNavigate();
  const [state, setState] = React.useState<ForgotPasswordState>('form');
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [sentEmail, setSentEmail] = React.useState<string>('');
  const [resendCooldown, setResendCooldown] = React.useState(0);
  
  const {
    register,
    handleSubmit,
    formState: { errors, isValid },
    watch,
  } = useForm<ForgotPasswordFormData>({
    resolver: zodResolver(forgotPasswordSchema),
    mode: 'onChange',
    defaultValues: {
      email: '',
    },
  });

  const watchedEmail = watch('email');

  // Cooldown timer effect
  React.useEffect(() => {
    let interval: NodeJS.Timeout;
    if (resendCooldown > 0) {
      interval = setInterval(() => {
        setResendCooldown((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [resendCooldown]);

  const onSubmit = async (data: ForgotPasswordFormData) => {
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      // Additional client-side email validation
      const emailValidation = validateEmail(data.email);
      if (!emailValidation.isValid) {
        setSubmitError(emailValidation.error);
        setIsSubmitting(false);
        return;
      }

      const email = data.email.toLowerCase().trim();

      // Call the forgot password API
      const response = await authService.forgotPassword(email);
      
      if (response.success) {
        setSentEmail(email);
        setState('sent');
        setResendCooldown(60); // 60 second cooldown
        toast.success('Reset instructions sent to your email');
      } else {
        // For security, don't reveal if email exists or not
        setSentEmail(email);
        setState('sent');
        setResendCooldown(60);
        toast.success('If that email exists, reset instructions have been sent');
      }
    } catch (error) {
      console.error('Forgot password error:', error);
      
      // For security, don't reveal specific errors
      setSentEmail(data.email.toLowerCase().trim());
      setState('sent');
      setResendCooldown(60);
      toast.success('If that email exists, reset instructions have been sent');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResend = async () => {
    if (resendCooldown > 0) return;
    
    setIsSubmitting(true);
    
    try {
      await authService.forgotPassword(sentEmail);
      setResendCooldown(60);
      toast.success('Reset instructions sent again');
    } catch (error) {
      console.error('Resend error:', error);
      toast.error('Failed to resend. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const renderForm = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-4">
          <Mail className="h-6 w-6 text-primary" />
        </div>
        <CardTitle className="text-2xl">Forgot your password?</CardTitle>
        <CardDescription>
          Enter your email address and we'll send you a link to reset your password.
        </CardDescription>
      </CardHeader>
      
      <CardContent>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" data-testid="forgot-password-form">
          <CSRFToken />
          
          {/* Error Alert */}
          {submitError && (
            <Alert type="error" dismissible onDismiss={() => setSubmitError(null)}>
              <AlertCircle className="h-4 w-4" />
              <div className="ml-2">
                <p className="font-medium">Invalid email</p>
                <p className="text-sm opacity-90">{submitError}</p>
              </div>
            </Alert>
          )}

          {/* Email field */}
          <Input
            label="Email address"
            type="email"
            autoComplete="email"
            placeholder="Enter your email address"
            leftIcon={<Mail className="h-4 w-4" />}
            error={errors.email?.message}
            data-testid="email-input"
            {...register('email')}
          />

          {/* Security notice */}
          <div className="bg-muted p-4 rounded-lg">
            <div className="flex items-start space-x-3">
              <Shield className="h-5 w-5 text-muted-foreground mt-0.5 flex-shrink-0" />
              <div className="text-sm">
                <h4 className="font-medium mb-1">Security Notice</h4>
                <ul className="text-muted-foreground space-y-1">
                  <li>• Reset links expire after 1 hour</li>
                  <li>• Links can only be used once</li>
                  <li>• Check your spam folder if you don't see the email</li>
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
            data-testid="send-reset-button"
          >
            {isSubmitting ? 'Sending...' : 'Send reset instructions'}
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

  const renderSent = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-4">
          <CheckCircle className="h-6 w-6 text-green-600" />
        </div>
        <CardTitle className="text-2xl">Check your email</CardTitle>
        <CardDescription>
          We've sent password reset instructions to{' '}
          <span className="font-medium text-foreground">{sentEmail}</span>
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <div className="bg-muted p-4 rounded-lg">
          <h4 className="font-medium mb-2">Next steps:</h4>
          <ul className="text-sm text-muted-foreground space-y-1">
            <li>1. Check your email inbox (and spam folder)</li>
            <li>2. Click the reset link in the email</li>
            <li>3. Follow the instructions to set a new password</li>
          </ul>
        </div>

        <Alert>
          <Clock className="h-4 w-4" />
          <div className="ml-2">
            <p className="font-medium">Didn't receive the email?</p>
            <p className="text-sm opacity-90 mt-1">
              The email may take a few minutes to arrive. If you still don't see it, 
              check your spam folder or try resending.
            </p>
          </div>
        </Alert>

        {/* Resend button */}
        <RateLimitedButton
          type="button"
          variant="outline"
          onClick={handleResend}
          disabled={resendCooldown > 0 || isSubmitting}
          loading={isSubmitting}
          className="w-full"
          onRateLimitExceeded={(seconds) => {
            toast.error(`Too many attempts. Please try again in ${seconds} seconds.`);
          }}
          data-testid="resend-button"
        >
          {resendCooldown > 0 
            ? `Resend in ${resendCooldown}s` 
            : isSubmitting 
              ? 'Sending...' 
              : 'Resend email'
          }
        </RateLimitedButton>

        {/* Alternative actions */}
        <div className="space-y-3 pt-4 border-t">
          <Link
            to="/login"
            className="block text-center text-sm text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
            data-testid="back-to-login-link"
          >
            Back to login
          </Link>
          
          <button
            type="button"
            onClick={() => {
              setState('form');
              setSubmitError(null);
              setSentEmail('');
              setResendCooldown(0);
            }}
            className="block w-full text-center text-sm text-muted-foreground hover:text-foreground transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
            data-testid="try-different-email-button"
          >
            Try a different email address
          </button>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className={className}>
      {state === 'form' && renderForm()}
      {state === 'sent' && renderSent()}
      
      {/* Support information */}
      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Need help?{' '}
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
ForgotPassword.displayName = 'ForgotPassword';

export default ForgotPassword;