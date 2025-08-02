import React from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { Mail, CheckCircle, AlertCircle, Clock, RefreshCw, ArrowLeft } from 'lucide-react';
import { 
  RateLimitedButton, 
  Alert, 
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
  Spinner
} from '../components';
import { authService } from '../services/api/auth.service';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

type VerificationState = 'loading' | 'success' | 'expired' | 'invalid' | 'already-verified' | 'resend';

function EmailVerification({ className }: PageProps) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');
  const email = searchParams.get('email');
  
  const [state, setState] = React.useState<VerificationState>('loading');
  const [isResending, setIsResending] = React.useState(false);
  const [resendCooldown, setResendCooldown] = React.useState(0);
  const [verifiedEmail, setVerifiedEmail] = React.useState<string>('');

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

  // Verify token on component mount
  React.useEffect(() => {
    if (!token) {
      setState('invalid');
      return;
    }

    const verifyEmail = async () => {
      try {
        const response = await authService.verifyEmail(token, email);
        
        if (response.success) {
          if (response.data?.alreadyVerified) {
            setState('already-verified');
            setVerifiedEmail(response.data.email || email || '');
          } else {
            setState('success');
            setVerifiedEmail(response.data?.email || email || '');
            toast.success('Email verified successfully!');
          }
        } else {
          if (response.message?.includes('expired')) {
            setState('expired');
          } else {
            setState('invalid');
          }
        }
      } catch (error) {
        console.error('Email verification error:', error);
        setState('expired');
      }
    };

    verifyEmail();
  }, [token, email]);

  const handleResendVerification = async () => {
    if (!email) {
      toast.error('Email address is required to resend verification');
      return;
    }

    setIsResending(true);
    
    try {
      const response = await authService.resendEmailVerification(email);
      
      if (response.success) {
        setResendCooldown(60);
        toast.success('Verification email sent! Check your inbox.');
      } else {
        toast.error(response.message || 'Failed to resend verification email');
      }
    } catch (error) {
      console.error('Resend verification error:', error);
      toast.error('Failed to resend verification email');
    } finally {
      setIsResending(false);
    }
  };

  const renderLoading = () => (
    <Card>
      <CardContent className="text-center py-12">
        <Spinner size="lg" className="mx-auto mb-4" />
        <h2 className="text-xl font-semibold mb-2">Verifying your email...</h2>
        <p className="text-muted-foreground">Please wait while we verify your email address.</p>
      </CardContent>
    </Card>
  );

  const renderSuccess = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mb-4">
          <CheckCircle className="h-8 w-8 text-green-600" />
        </div>
        <CardTitle className="text-2xl">Email verified successfully!</CardTitle>
        <CardDescription>
          {verifiedEmail && (
            <>
              <span className="font-medium text-foreground">{verifiedEmail}</span> has been verified.
            </>
          )}
        </CardDescription>
      </CardHeader>
      
      <CardContent className="text-center space-y-6">
        <div className="bg-green-50 p-4 rounded-lg">
          <h4 className="font-medium text-green-800 mb-2">Welcome to Enterprise App!</h4>
          <ul className="text-sm text-green-700 space-y-1">
            <li>• Your email address is now verified</li>
            <li>• You can access all platform features</li>
            <li>• You'll receive important account notifications</li>
          </ul>
        </div>

        <div className="space-y-3">
          <Link
            to="/login"
            className="inline-flex items-center justify-center w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            data-testid="continue-to-login-button"
          >
            Continue to login
          </Link>
          
          <p className="text-sm text-muted-foreground">
            You can now sign in with your verified email address.
          </p>
        </div>
      </CardContent>
    </Card>
  );

  const renderExpired = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mb-4">
          <Clock className="h-6 w-6 text-orange-600" />
        </div>
        <CardTitle className="text-2xl">Verification link expired</CardTitle>
        <CardDescription>
          This email verification link has expired. Verification links are valid for 24 hours.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <div className="bg-orange-50 p-4 rounded-lg">
          <h4 className="font-medium text-orange-800 mb-2">Why did this happen?</h4>
          <ul className="text-sm text-orange-700 space-y-1">
            <li>• Verification links expire after 24 hours for security</li>
            <li>• Links can only be used once</li>
            <li>• Multiple verification requests invalidate previous links</li>
          </ul>
        </div>

        <Alert>
          <Mail className="h-4 w-4" />
          <div className="ml-2">
            <p className="font-medium">Need a new verification link?</p>
            <p className="text-sm opacity-90 mt-1">
              We can send you a new verification email to complete your account setup.
            </p>
          </div>
        </Alert>

        {email && (
          <div className="text-center">
            <p className="text-sm text-muted-foreground mb-4">
              Send new verification email to{' '}
              <span className="font-medium text-foreground">{email}</span>
            </p>
            
            <RateLimitedButton
              type="button"
              onClick={handleResendVerification}
              disabled={resendCooldown > 0 || isResending}
              loading={isResending}
              className="w-full"
              onRateLimitExceeded={(seconds) => {
                toast.error(`Too many attempts. Please try again in ${seconds} seconds.`);
              }}
              data-testid="resend-verification-button"
            >
              {resendCooldown > 0 
                ? `Resend in ${resendCooldown}s` 
                : isResending 
                  ? 'Sending...' 
                  : 'Send new verification email'
              }
            </RateLimitedButton>
          </div>
        )}

        <div className="text-center pt-4 border-t">
          <Link
            to="/login"
            className="inline-flex items-center text-sm text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-2 py-1"
            data-testid="back-to-login-link"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
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
        <CardTitle className="text-2xl">Invalid verification link</CardTitle>
        <CardDescription>
          This email verification link is invalid or malformed.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <Alert type="error">
          <AlertCircle className="h-4 w-4" />
          <div className="ml-2">
            <p className="font-medium">Link Error</p>
            <p className="text-sm opacity-90">
              The verification link you followed is not valid. This could happen if:
            </p>
            <ul className="text-sm opacity-90 mt-2 space-y-1">
              <li>• The link was copied incorrectly</li>
              <li>• The link was already used</li>
              <li>• The link is from an old email</li>
            </ul>
          </div>
        </Alert>

        <div className="space-y-3">
          <Link
            to="/register"
            className="inline-flex items-center justify-center w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            data-testid="create-account-button"
          >
            Create a new account
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

  const renderAlreadyVerified = () => (
    <Card>
      <CardHeader className="text-center">
        <div className="mx-auto w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mb-4">
          <CheckCircle className="h-6 w-6 text-blue-600" />
        </div>
        <CardTitle className="text-2xl">Email already verified</CardTitle>
        <CardDescription>
          {verifiedEmail && (
            <>
              <span className="font-medium text-foreground">{verifiedEmail}</span> is already verified.
            </>
          )}
        </CardDescription>
      </CardHeader>
      
      <CardContent className="text-center space-y-6">
        <Alert>
          <CheckCircle className="h-4 w-4" />
          <div className="ml-2">
            <p className="font-medium">Already Verified</p>
            <p className="text-sm opacity-90">
              This email address was previously verified. You can sign in to your account.
            </p>
          </div>
        </Alert>

        <div className="space-y-3">
          <Link
            to="/login"
            className="inline-flex items-center justify-center w-full px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2"
            data-testid="sign-in-button"
          >
            Sign in to your account
          </Link>
          
          <p className="text-sm text-muted-foreground">
            Your account is ready to use with all features enabled.
          </p>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className={className}>
      {state === 'loading' && renderLoading()}
      {state === 'success' && renderSuccess()}
      {state === 'expired' && renderExpired()}
      {state === 'invalid' && renderInvalid()}
      {state === 'already-verified' && renderAlreadyVerified()}
      
      {/* Help section */}
      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Having trouble with email verification?{' '}
          <Link
            to="/contact"
            className="text-primary hover:text-primary/80 font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-1"
            data-testid="contact-support-link"
          >
            Contact support
          </Link>
        </p>
      </div>
      
      {/* Additional help information */}
      <div className="mt-6">
        <Card>
          <CardContent className="pt-6">
            <h4 className="font-medium mb-3 text-center">Email Verification Tips</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-muted-foreground">
              <div>
                <h5 className="font-medium text-foreground mb-1">Check your spam folder</h5>
                <p>Verification emails sometimes end up in spam or junk folders.</p>
              </div>
              <div>
                <h5 className="font-medium text-foreground mb-1">Add us to your contacts</h5>
                <p>Add our email to your contacts to ensure future emails reach you.</p>
              </div>
              <div>
                <h5 className="font-medium text-foreground mb-1">Check email filters</h5>
                <p>Email filters might redirect our messages automatically.</p>
              </div>
              <div>
                <h5 className="font-medium text-foreground mb-1">Try a different email</h5>
                <p>If problems persist, consider using a different email address.</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

// Wrap with AuthLayout in the router
EmailVerification.displayName = 'EmailVerification';

export default EmailVerification;