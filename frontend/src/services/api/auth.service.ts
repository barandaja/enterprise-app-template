/**
 * @fileoverview Authentication API Service
 * 
 * Comprehensive authentication service providing:
 * - User login with credentials validation
 * - User registration with email verification
 * - Token refresh and management
 * - Password reset functionality
 * - Email verification handling
 * - Logout and session management
 * - Two-factor authentication support
 */

import { z } from 'zod';
import { apiClient } from './client';
import type {
  ApiResponse,
  LoginResponse,
  RegisterResponse,
  TokenResponse,
  PasswordResetRequest,
  PasswordResetConfirm,
  EmailVerificationRequest,
  EmailVerificationConfirm,
  ChangePasswordRequest,
  ApiRequestConfig
} from './types';
import type { 
  LoginCredentials, 
  RegisterData, 
  User 
} from '../../types';

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Login credentials validation schema
 */
const loginCredentialsSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  password: z.string()
    .min(1, 'Password is required')
    .min(8, 'Password must be at least 8 characters long'),
  rememberMe: z.boolean().optional(),
});

/**
 * Registration data validation schema
 */
const registerDataSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
  confirmPassword: z.string().min(1, 'Please confirm your password'),
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters'),
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters'),
  acceptTerms: z.boolean()
    .refine(val => val === true, 'You must accept the terms and conditions'),
}).refine(
  data => data.password === data.confirmPassword,
  {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }
);

/**
 * Password reset request validation schema
 */
const passwordResetRequestSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  redirectUrl: z.string().url().optional(),
});

/**
 * Password reset confirmation validation schema
 */
const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
  confirmPassword: z.string().min(1, 'Please confirm your password'),
}).refine(
  data => data.password === data.confirmPassword,
  {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }
);

/**
 * Email verification request validation schema
 */
const emailVerificationRequestSchema = z.object({
  email: z.string()
    .email('Please enter a valid email address')
    .min(1, 'Email is required'),
  redirectUrl: z.string().url().optional(),
});

/**
 * Email verification confirmation validation schema
 */
const emailVerificationConfirmSchema = z.object({
  token: z.string().min(1, 'Verification token is required'),
  email: z.string().email().optional(),
});

/**
 * Change password validation schema
 */
const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: z.string()
    .min(8, 'New password must be at least 8 characters long')
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
      'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
  confirmPassword: z.string().min(1, 'Please confirm your new password'),
}).refine(
  data => data.newPassword === data.confirmPassword,
  {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  }
).refine(
  data => data.currentPassword !== data.newPassword,
  {
    message: 'New password must be different from current password',
    path: ['newPassword'],
  }
);

// =============================================================================
// Two-Factor Authentication Types
// =============================================================================

/**
 * Two-factor authentication setup request
 */
export interface TwoFactorSetupRequest {
  readonly method: 'sms' | 'totp' | 'email';
  readonly phoneNumber?: string;
}

/**
 * Two-factor authentication setup response
 */
export interface TwoFactorSetupResponse {
  readonly method: 'sms' | 'totp' | 'email';
  readonly secret?: string; // For TOTP
  readonly qrCode?: string; // For TOTP
  readonly backupCodes: readonly string[];
}

/**
 * Two-factor authentication verification request
 */
export interface TwoFactorVerifyRequest {
  readonly token: string;
  readonly code: string;
  readonly method: 'sms' | 'totp' | 'email' | 'backup';
}

/**
 * Two-factor authentication verification response
 */
export interface TwoFactorVerifyResponse {
  readonly user: User;
  readonly tokens: TokenResponse;
  readonly backupCodesUsed?: number;
}

// =============================================================================
// Social Authentication Types
// =============================================================================

/**
 * Social login providers
 */
export type SocialProvider = 'google' | 'facebook' | 'github' | 'twitter' | 'linkedin';

/**
 * Social login request
 */
export interface SocialLoginRequest {
  readonly provider: SocialProvider;
  readonly accessToken: string;
  readonly redirectUrl?: string;
}

/**
 * Social login response
 */
export interface SocialLoginResponse extends LoginResponse {
  readonly isNewUser: boolean;
  readonly providerData: {
    readonly id: string;
    readonly email: string;
    readonly name: string;
    readonly picture?: string;
  };
}

// =============================================================================
// Authentication Service Class
// =============================================================================

/**
 * Authentication service providing all auth-related API operations
 */
export class AuthService {
  private readonly baseUrl = '/auth';
  private readonly client = apiClient;

  // ===========================================================================
  // Core Authentication Methods
  // ===========================================================================

  /**
   * Authenticate user with email and password
   * 
   * @param credentials - User login credentials
   * @param config - Additional request configuration
   * @returns Promise resolving to login response with user data and tokens
   * 
   * @example
   * ```typescript
   * const response = await authService.login({
   *   email: 'user@example.com',
   *   password: 'securePassword123!'
   * });
   * 
   * if (response.success) {
   *   console.log('User logged in:', response.data.user);
   *   console.log('Access token:', response.data.tokens.accessToken);
   * }
   * ```
   */
  async login(
    credentials: LoginCredentials,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<LoginResponse>> {
    // Validate input
    const validatedCredentials = loginCredentialsSchema.parse(credentials);

    return this.client.post<LoginCredentials, LoginResponse>(
      `${this.baseUrl}/login`,
      validatedCredentials,
      {
        ...config,
        skipAuth: true, // No auth required for login
        cancelKey: 'auth.login',
      }
    );
  }

  /**
   * Register new user account
   * 
   * @param userData - User registration data
   * @param config - Additional request configuration
   * @returns Promise resolving to registration response
   * 
   * @example
   * ```typescript
   * const response = await authService.register({
   *   email: 'newuser@example.com',
   *   password: 'securePassword123!',
   *   confirmPassword: 'securePassword123!',
   *   firstName: 'John',
   *   lastName: 'Doe',
   *   acceptTerms: true
   * });
   * ```
   */
  async register(
    userData: RegisterData & { confirmPassword: string; acceptTerms: boolean },
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<RegisterResponse>> {
    // Validate input
    const validatedData = registerDataSchema.parse(userData);

    return this.client.post<RegisterData, RegisterResponse>(
      `${this.baseUrl}/register`,
      validatedData,
      {
        ...config,
        skipAuth: true, // No auth required for registration
        cancelKey: 'auth.register',
      }
    );
  }

  /**
   * Logout current user and invalidate tokens
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to logout confirmation
   * 
   * @example
   * ```typescript
   * await authService.logout();
   * console.log('User logged out successfully');
   * ```
   */
  async logout(config: ApiRequestConfig = {}): Promise<ApiResponse<void>> {
    return this.client.post<void, void>(
      `${this.baseUrl}/logout`,
      undefined,
      {
        ...config,
        cancelKey: 'auth.logout',
      }
    );
  }

  /**
   * Refresh access token using refresh token
   * 
   * @param refreshToken - The refresh token
   * @param config - Additional request configuration
   * @returns Promise resolving to new token pair
   * 
   * @example
   * ```typescript
   * const response = await authService.refreshToken('refresh_token_here');
   * if (response.success) {
   *   console.log('New access token:', response.data.accessToken);
   * }
   * ```
   */
  async refreshToken(
    refreshToken: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TokenResponse>> {
    return this.client.post<{ refreshToken: string }, TokenResponse>(
      `${this.baseUrl}/refresh`,
      { refreshToken },
      {
        ...config,
        skipAuth: true, // Don't use old token for refresh
        skipRefresh: true, // Prevent infinite refresh loop
        cancelKey: 'auth.refresh',
      }
    );
  }

  // ===========================================================================
  // Password Management Methods
  // ===========================================================================

  /**
   * Request password reset email
   * 
   * @param request - Password reset request data
   * @param config - Additional request configuration
   * @returns Promise resolving to reset confirmation
   * 
   * @example
   * ```typescript
   * await authService.requestPasswordReset({
   *   email: 'user@example.com',
   *   redirectUrl: 'https://app.example.com/reset-password'
   * });
   * ```
   */
  async requestPasswordReset(
    request: PasswordResetRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    // Validate input
    const validatedRequest = passwordResetRequestSchema.parse(request);

    return this.client.post<PasswordResetRequest, void>(
      `${this.baseUrl}/password/reset`,
      validatedRequest,
      {
        ...config,
        skipAuth: true, // No auth required for password reset request
        cancelKey: 'auth.passwordReset',
      }
    );
  }

  /**
   * Confirm password reset with new password
   * 
   * @param confirmation - Password reset confirmation data
   * @param config - Additional request configuration
   * @returns Promise resolving to reset confirmation
   * 
   * @example
   * ```typescript
   * await authService.confirmPasswordReset({
   *   token: 'reset_token_from_email',
   *   password: 'newSecurePassword123!',
   *   confirmPassword: 'newSecurePassword123!'
   * });
   * ```
   */
  async confirmPasswordReset(
    confirmation: PasswordResetConfirm,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    // Validate input
    const validatedConfirmation = passwordResetConfirmSchema.parse(confirmation);

    return this.client.post<PasswordResetConfirm, void>(
      `${this.baseUrl}/password/reset/confirm`,
      validatedConfirmation,
      {
        ...config,
        skipAuth: true, // No auth required for password reset confirmation
        cancelKey: 'auth.passwordResetConfirm',
      }
    );
  }

  /**
   * Change password for authenticated user
   * 
   * @param request - Change password request data
   * @param config - Additional request configuration
   * @returns Promise resolving to change confirmation
   * 
   * @example
   * ```typescript
   * await authService.changePassword({
   *   currentPassword: 'oldPassword123!',
   *   newPassword: 'newSecurePassword123!',
   *   confirmPassword: 'newSecurePassword123!'
   * });
   * ```
   */
  async changePassword(
    request: ChangePasswordRequest & { confirmPassword: string },
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    // Validate input
    const validatedRequest = changePasswordSchema.parse(request);

    return this.client.post<ChangePasswordRequest, void>(
      `${this.baseUrl}/password/change`,
      validatedRequest,
      {
        ...config,
        cancelKey: 'auth.changePassword',
      }
    );
  }

  // ===========================================================================
  // Email Verification Methods
  // ===========================================================================

  /**
   * Request email verification
   * 
   * @param request - Email verification request data
   * @param config - Additional request configuration
   * @returns Promise resolving to verification confirmation
   * 
   * @example
   * ```typescript
   * await authService.requestEmailVerification({
   *   email: 'user@example.com',
   *   redirectUrl: 'https://app.example.com/verify-email'
   * });
   * ```
   */
  async requestEmailVerification(
    request: EmailVerificationRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    // Validate input
    const validatedRequest = emailVerificationRequestSchema.parse(request);

    return this.client.post<EmailVerificationRequest, void>(
      `${this.baseUrl}/email/verify`,
      validatedRequest,
      {
        ...config,
        skipAuth: true, // Can be used before login
        cancelKey: 'auth.emailVerification',
      }
    );
  }

  // ===========================================================================
  // Convenience Methods for Frontend Pages
  // ===========================================================================

  /**
   * Convenience method for forgot password (alias for requestPasswordReset)
   * 
   * @param email - User email address
   * @param config - Additional request configuration 
   * @returns Promise resolving to reset confirmation
   */
  async forgotPassword(
    email: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.requestPasswordReset({ email }, config);
  }

  /**
   * Convenience method for reset password (alias for confirmPasswordReset)
   * 
   * @param params - Reset password parameters
   * @param config - Additional request configuration
   * @returns Promise resolving to reset confirmation
   */
  async resetPassword(
    params: { token: string; email: string; password: string },
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.confirmPasswordReset({
      token: params.token,
      password: params.password,
      confirmPassword: params.password, // Assume frontend already validated
    }, config);
  }

  /**
   * Validate password reset token
   * 
   * @param token - Reset token from email
   * @param email - User email address
   * @param config - Additional request configuration
   * @returns Promise resolving to token validation result
   */
  async validateResetToken(
    token: string,
    email: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ valid: boolean; expiresAt?: string }>> {
    return this.client.post<{ token: string; email: string }, { valid: boolean; expiresAt?: string }>(
      `${this.baseUrl}/password/reset/validate`,
      { token, email },
      {
        ...config,
        skipAuth: true,
        cancelKey: 'auth.validateResetToken',
      }
    );
  }

  /**
   * Verify email with token (alias for confirmEmailVerification)
   * 
   * @param token - Verification token from email
   * @param email - User email address (optional)
   * @param config - Additional request configuration
   * @returns Promise resolving to verification result
   */
  async verifyEmail(
    token: string,
    email?: string | null,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ email?: string; alreadyVerified?: boolean }>> {
    return this.client.post<EmailVerificationConfirm, { email?: string; alreadyVerified?: boolean }>(
      `${this.baseUrl}/email/verify/confirm`,
      { token, email: email || undefined },
      {
        ...config,
        skipAuth: true,
        cancelKey: 'auth.verifyEmail',
      }
    );
  }

  /**
   * Resend email verification
   * 
   * @param email - User email address
   * @param config - Additional request configuration
   * @returns Promise resolving to resend confirmation
   */
  async resendEmailVerification(
    email: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.requestEmailVerification({ email }, config);
  }

  /**
   * Confirm email verification
   * 
   * @param confirmation - Email verification confirmation data
   * @param config - Additional request configuration
   * @returns Promise resolving to verification confirmation
   * 
   * @example
   * ```typescript
   * await authService.confirmEmailVerification({
   *   token: 'verification_token_from_email'
   * });
   * ```
   */
  async confirmEmailVerification(
    confirmation: EmailVerificationConfirm,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    // Validate input
    const validatedConfirmation = emailVerificationConfirmSchema.parse(confirmation);

    return this.client.post<EmailVerificationConfirm, void>(
      `${this.baseUrl}/email/verify/confirm`,
      validatedConfirmation,
      {
        ...config,
        skipAuth: true, // No auth required for email verification
        cancelKey: 'auth.emailVerificationConfirm',
      }
    );
  }

  // ===========================================================================
  // Two-Factor Authentication Methods
  // ===========================================================================

  /**
   * Setup two-factor authentication
   * 
   * @param request - 2FA setup request data
   * @param config - Additional request configuration
   * @returns Promise resolving to 2FA setup response
   */
  async setupTwoFactor(
    request: TwoFactorSetupRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TwoFactorSetupResponse>> {
    return this.client.post<TwoFactorSetupRequest, TwoFactorSetupResponse>(
      `${this.baseUrl}/2fa/setup`,
      request,
      {
        ...config,
        cancelKey: 'auth.2faSetup',
      }
    );
  }

  /**
   * Verify two-factor authentication code
   * 
   * @param request - 2FA verification request data
   * @param config - Additional request configuration
   * @returns Promise resolving to 2FA verification response
   */
  async verifyTwoFactor(
    request: TwoFactorVerifyRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<TwoFactorVerifyResponse>> {
    return this.client.post<TwoFactorVerifyRequest, TwoFactorVerifyResponse>(
      `${this.baseUrl}/2fa/verify`,
      request,
      {
        ...config,
        skipAuth: true, // Used during login flow
        cancelKey: 'auth.2faVerify',
      }
    );
  }

  /**
   * Disable two-factor authentication
   * 
   * @param password - Current user password for confirmation
   * @param config - Additional request configuration
   * @returns Promise resolving to disable confirmation
   */
  async disableTwoFactor(
    password: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.client.post<{ password: string }, void>(
      `${this.baseUrl}/2fa/disable`,
      { password },
      {
        ...config,
        cancelKey: 'auth.2faDisable',
      }
    );
  }

  // ===========================================================================
  // Social Authentication Methods
  // ===========================================================================

  /**
   * Authenticate with social provider
   * 
   * @param request - Social login request data
   * @param config - Additional request configuration
   * @returns Promise resolving to social login response
   */
  async socialLogin(
    request: SocialLoginRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<SocialLoginResponse>> {
    return this.client.post<SocialLoginRequest, SocialLoginResponse>(
      `${this.baseUrl}/social/login`,
      request,
      {
        ...config,
        skipAuth: true, // No auth required for social login
        cancelKey: `auth.social.${request.provider}`,
      }
    );
  }

  /**
   * Get social login URL for provider
   * 
   * @param provider - Social provider name
   * @param redirectUrl - URL to redirect after authentication
   * @param config - Additional request configuration
   * @returns Promise resolving to provider login URL
   */
  async getSocialLoginUrl(
    provider: SocialProvider,
    redirectUrl?: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ url: string }>> {
    return this.client.get<{ url: string }>(
      `${this.baseUrl}/social/${provider}/url`,
      {
        ...config,
        params: { redirectUrl },
        skipAuth: true,
        cancelKey: `auth.social.${provider}.url`,
      }
    );
  }

  // ===========================================================================
  // Session Management Methods
  // ===========================================================================

  /**
   * Get current session information
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to session data
   */
  async getSession(config: ApiRequestConfig = {}): Promise<ApiResponse<{
    user: User;
    expiresAt: string;
    lastActivity: string;
  }>> {
    return this.client.get(
      `${this.baseUrl}/session`,
      {
        ...config,
        cancelKey: 'auth.session',
      }
    );
  }

  /**
   * Validate current authentication token
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to validation result
   */
  async validateToken(config: ApiRequestConfig = {}): Promise<ApiResponse<{
    valid: boolean;
    expiresAt: string;
    user: User;
  }>> {
    return this.client.get(
      `${this.baseUrl}/validate`,
      {
        ...config,
        cancelKey: 'auth.validate',
      }
    );
  }

  /**
   * Get all active sessions for current user
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to active sessions
   */
  async getActiveSessions(config: ApiRequestConfig = {}): Promise<ApiResponse<Array<{
    id: string;
    deviceInfo: string;
    location: string;
    lastActivity: string;
    current: boolean;
  }>>> {
    return this.client.get(
      `${this.baseUrl}/sessions`,
      {
        ...config,
        cancelKey: 'auth.sessions',
      }
    );
  }

  /**
   * Revoke specific session
   * 
   * @param sessionId - ID of session to revoke
   * @param config - Additional request configuration
   * @returns Promise resolving to revocation confirmation
   */
  async revokeSession(
    sessionId: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.client.delete(
      `${this.baseUrl}/sessions/${sessionId}`,
      {
        ...config,
        cancelKey: `auth.revokeSession.${sessionId}`,
      }
    );
  }

  /**
   * Revoke all sessions except current
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to revocation confirmation
   */
  async revokeAllSessions(config: ApiRequestConfig = {}): Promise<ApiResponse<void>> {
    return this.client.post(
      `${this.baseUrl}/sessions/revoke-all`,
      undefined,
      {
        ...config,
        cancelKey: 'auth.revokeAllSessions',
      }
    );
  }
}

// Export singleton instance
export const authService = new AuthService();

// Export validation schemas for external use
export {
  loginCredentialsSchema,
  registerDataSchema,
  passwordResetRequestSchema,
  passwordResetConfirmSchema,
  emailVerificationRequestSchema,
  emailVerificationConfirmSchema,
  changePasswordSchema,
};