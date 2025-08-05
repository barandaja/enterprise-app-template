import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Eye, EyeOff, Mail, Lock, Github, AlertCircle, CheckCircle } from 'lucide-react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { 
  Input, 
  SecurePasswordInput, 
  RateLimitedButton, 
  Alert, 
  Spinner
} from '../components';
import { CSRFToken } from '../components/CSRFToken';
import { useAuthStore, useAuthActions, useAuthError, useAuthLoading } from '../stores/authStore';
import { validateEmail } from '../security/inputValidation';
import type { PageProps } from '../types';
import { toast } from 'react-hot-toast';

// Form validation schema
const loginSchema = z.object({
  email: z.string().min(1, 'Email is required').email('Invalid email address'),
  password: z.string().min(1, 'Password is required').min(6, 'Password must be at least 6 characters'),
  rememberMe: z.boolean().default(false),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LocationState {
  from?: { pathname: string };
  message?: string;
}

function Login({ className }: PageProps) {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuthActions();
  const authError = useAuthError();
  const isLoading = useAuthLoading();
  
  // Get redirect location and success message
  const state = location.state as LocationState | null;
  const from = state?.from?.pathname || '/';
  const successMessage = state?.message;
  
  const [showPassword, setShowPassword] = React.useState(false);
  const [loginError, setLoginError] = React.useState<string | null>(null);
  
  const {
    register,
    handleSubmit,
    formState: { errors },
    setValue,
    watch,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: {
      email: '',
      password: '',
      rememberMe: false,
    },
  });
  
  const watchedEmail = watch('email');
  const watchedPassword = watch('password');

  // Clear errors when user starts typing
  React.useEffect(() => {
    if (loginError) {
      setLoginError(null);
    }
  }, [watchedEmail, watchedPassword]);
  
  // Show success message if redirected from registration
  React.useEffect(() => {
    if (successMessage) {
      toast.success(successMessage);
    }
  }, [successMessage]);

  const onSubmit = async (data: LoginFormData) => {
    console.log('Login form onSubmit called with data:', { email: data.email, hasPassword: !!data.password });
    setLoginError(null);
    
    try {
      // Additional client-side email validation
      const emailValidation = validateEmail(data.email);
      if (!emailValidation.valid) {
        console.error('Email validation failed:', emailValidation.error);
        setLoginError(emailValidation.error || 'Invalid email address');
        return;
      }
      
      console.log('Attempting login...');
      await login({
        email: data.email.toLowerCase().trim(),
        password: data.password,
      });
      
      // Store remember me preference (in production, handle server-side)
      if (data.rememberMe) {
        localStorage.setItem('rememberMe', 'true');
      } else {
        localStorage.removeItem('rememberMe');
      }
      
      console.log('Login successful!');
      toast.success('Welcome back!');
      
      // Navigate to intended destination or dashboard
      navigate(from === '/' ? '/dashboard' : from, { replace: true });
    } catch (error) {
      console.error('Login error:', error);
      setLoginError(authError || 'Invalid email or password. Please try again.');
      toast.error('Login failed. Please try again.');
    }
  };
  
  const handleSocialLogin = (provider: 'google' | 'github') => {
    // In production, implement OAuth flow
    toast.info(`${provider} login coming soon!`);
    console.log(`${provider} login clicked`);
  };

  return (
    <div className={className}>
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6" data-testid="login-form">
        <CSRFToken />
        
        {/* Success message from registration */}
        {successMessage && (
          <Alert type="success" dismissible>
            <CheckCircle className="h-4 w-4" />
            <div className="ml-2">
              <p className="font-medium">Registration successful!</p>
              <p className="text-sm opacity-90">{successMessage}</p>
            </div>
          </Alert>
        )}
        
        {/* Login error */}
        {loginError && (
          <Alert type="error" dismissible onDismiss={() => setLoginError(null)}>
            <AlertCircle className="h-4 w-4" />
            <div className="ml-2">
              <p className="font-medium">Login failed</p>
              <p className="text-sm opacity-90">{loginError}</p>
            </div>
          </Alert>
        )}

        {/* Email field */}
        <Input
          label="Email address"
          type="email"
          autoComplete="email"
          placeholder="Enter your email"
          error={errors.email?.message}
          data-testid="email-input"
          {...register('email')}
        />

        {/* Password field */}
        <div className="space-y-2">
          <label htmlFor="password" className="label">
            Password
          </label>
          <div className="relative">
            <input
              id="password"
              type={showPassword ? 'text' : 'password'}
              autoComplete="current-password"
              placeholder="Enter your password"
              className={`input pr-10 ${errors.password ? 'border-destructive focus-visible:ring-destructive' : ''}`}
              data-testid="password-input"
              {...register('password')}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-muted-foreground hover:text-foreground transition-colors"
              aria-label={showPassword ? 'Hide password' : 'Show password'}
              data-testid="toggle-password-visibility"
            >
              {showPassword ? (
                <EyeOff className="h-4 w-4" />
              ) : (
                <Eye className="h-4 w-4" />
              )}
            </button>
          </div>
          {errors.password && (
            <p className="text-sm text-destructive" role="alert">{errors.password.message}</p>
          )}
        </div>

        {/* Remember me and forgot password */}
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <input
              id="rememberMe"
              type="checkbox"
              className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded transition-colors"
              data-testid="remember-me-checkbox"
              {...register('rememberMe')}
            />
            <label htmlFor="rememberMe" className="ml-2 block text-sm text-muted-foreground select-none">
              Remember me for 30 days
            </label>
          </div>

          <Link
            to="/forgot-password"
            className="text-sm text-primary hover:text-primary/80 font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-1"
            data-testid="forgot-password-link"
          >
            Forgot password?
          </Link>
        </div>

        {/* Submit button with rate limiting */}
        <RateLimitedButton
          type="submit"
          disabled={isLoading}
          loading={isLoading}
          className="w-full"
          onRateLimitExceeded={(seconds) => {
            toast.error(`Too many login attempts. Please try again in ${seconds} seconds.`);
          }}
          data-testid="login-submit-button"
        >
          {isLoading ? 'Signing in...' : 'Sign in'}
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
            className="btn-outline transition-all duration-200 hover:scale-[1.02] focus:scale-[1.02]"
            onClick={() => handleSocialLogin('google')}
            disabled={isLoading}
            data-testid="google-login-button"
            aria-label="Sign in with Google"
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
            onClick={() => handleSocialLogin('github')}
            disabled={isLoading}
            data-testid="github-login-button"
            aria-label="Sign in with GitHub"
          >
            <Github className="h-4 w-4" aria-hidden="true" />
            GitHub
          </button>
        </div>
      </form>

      {/* Sign up link */}
      <div className="mt-8 text-center">
        <p className="text-sm text-muted-foreground">
          Don't have an account?{' '}
          <Link
            to="/register"
            className="font-medium text-primary hover:text-primary/80 transition-colors focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 rounded px-1"
            data-testid="register-link"
          >
            Sign up for free
          </Link>
        </p>
      </div>
      
      {/* Loading overlay */}
      {isLoading && (
        <div className="fixed inset-0 bg-black/20 flex items-center justify-center z-50" data-testid="loading-overlay">
          <div className="bg-background p-6 rounded-lg shadow-lg flex items-center space-x-3">
            <Spinner size="md" />
            <span className="text-sm font-medium">Signing you in...</span>
          </div>
        </div>
      )}
    </div>
  );
}

// Wrap with AuthLayout in the router
Login.displayName = 'Login';

export default Login;