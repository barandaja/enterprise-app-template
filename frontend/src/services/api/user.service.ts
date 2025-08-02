/**
 * @fileoverview User Management API Service
 * 
 * Comprehensive user management service providing:
 * - User profile operations (get, update, delete)
 * - Avatar upload and management
 * - Password management for authenticated users
 * - User preferences and settings
 * - Account security features
 * - Activity tracking and history
 */

import { z } from 'zod';
import { apiClient } from './client';
import type {
  ApiResponse,
  ApiRequestConfig,
  FileUploadResponse,
  PaginatedResponse,
} from './types';
import type { 
  User, 
  UpdateProfileData,
  UserPreferences
} from './types';

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Profile update validation schema
 */
const updateProfileSchema = z.object({
  firstName: z.string()
    .min(1, 'First name is required')
    .max(50, 'First name must be less than 50 characters')
    .optional(),
  lastName: z.string()
    .min(1, 'Last name is required')
    .max(50, 'Last name must be less than 50 characters')
    .optional(),
  email: z.string()
    .email('Please enter a valid email address')
    .optional(),
  phoneNumber: z.string()
    .regex(/^\+?[\d\s\-\(\)]+$/, 'Invalid phone number format')
    .optional()
    .nullable(),
  dateOfBirth: z.string()
    .datetime('Invalid date format')
    .optional()
    .nullable(),
  bio: z.string()
    .max(500, 'Bio must be less than 500 characters')
    .optional()
    .nullable(),
  website: z.string()
    .url('Invalid website URL')
    .optional()
    .nullable(),
  location: z.string()
    .max(100, 'Location must be less than 100 characters')
    .optional()
    .nullable(),
});

/**
 * User preferences validation schema
 */
const userPreferencesSchema = z.object({
  theme: z.enum(['light', 'dark', 'system']).optional(),
  language: z.string().min(2).max(5).optional(),
  timezone: z.string().optional(),
  notifications: z.object({
    email: z.boolean().optional(),
    push: z.boolean().optional(),
    sms: z.boolean().optional(),
    marketing: z.boolean().optional(),
  }).optional(),
  privacy: z.object({
    profileVisible: z.boolean().optional(),
    showEmail: z.boolean().optional(),
    allowMessaging: z.boolean().optional(),
  }).optional(),
});

/**
 * Account deletion confirmation schema
 */
const deleteAccountSchema = z.object({
  password: z.string().min(1, 'Password is required for account deletion'),
  confirmation: z.literal('DELETE', {
    errorMap: () => ({ message: 'You must type "DELETE" to confirm account deletion' }),
  }),
  reason: z.string().optional(),
});

// =============================================================================
// Extended User Types
// =============================================================================

/**
 * Extended user profile with additional fields
 */
export interface ExtendedUser extends User {
  readonly phoneNumber?: string;
  readonly dateOfBirth?: string;
  readonly bio?: string;
  readonly website?: string;
  readonly location?: string;
  readonly emailVerified: boolean;
  readonly phoneVerified: boolean;
  readonly twoFactorEnabled: boolean;
  readonly lastLoginAt?: string;
  readonly profileCompleteness: number;
}

/**
 * User activity entry
 */
export interface UserActivity {
  readonly id: string;
  readonly type: 'login' | 'logout' | 'profile_update' | 'password_change' | 'settings_change';
  readonly description: string;
  readonly ipAddress: string;
  readonly userAgent: string;
  readonly location?: string;
  readonly createdAt: string;
}

/**
 * User statistics
 */
export interface UserStats {
  readonly totalLogins: number;
  readonly lastLoginAt?: string;
  readonly accountAge: number; // days since registration
  readonly profileViews: number;
  readonly activeSessions: number;
}

/**
 * Account security status
 */
export interface SecurityStatus {
  readonly twoFactorEnabled: boolean;
  readonly strongPassword: boolean;
  readonly emailVerified: boolean;
  readonly phoneVerified: boolean;
  readonly recentActivity: boolean;
  readonly securityScore: number; // 0-100
  readonly recommendations: readonly string[];
}

/**
 * Export data request
 */
export interface DataExportRequest {
  readonly format: 'json' | 'csv';
  readonly includePersonalData: boolean;
  readonly includeActivityLogs: boolean;
  readonly includePreferences: boolean;
  readonly dateRange?: {
    readonly start: string;
    readonly end: string;
  };
}

/**
 * Data export response
 */
export interface DataExportResponse {
  readonly exportId: string;
  readonly status: 'pending' | 'processing' | 'completed' | 'failed';
  readonly downloadUrl?: string;
  readonly expiresAt?: string;
  readonly fileSize?: number;
  readonly createdAt: string;
}

// =============================================================================
// User Service Class
// =============================================================================

/**
 * User management service providing all user-related API operations
 */
export class UserService {
  private readonly baseUrl = '/users';
  private readonly client = apiClient;

  // ===========================================================================
  // Profile Management Methods
  // ===========================================================================

  /**
   * Get current user profile
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to user profile data
   * 
   * @example
   * ```typescript
   * const response = await userService.getProfile();
   * if (response.success) {
   *   console.log('User profile:', response.data);
   * }
   * ```
   */
  async getProfile(config: ApiRequestConfig = {}): Promise<ApiResponse<ExtendedUser>> {
    return this.client.get<ExtendedUser>(
      `${this.baseUrl}/profile`,
      {
        ...config,
        cancelKey: 'user.profile',
      }
    );
  }

  /**
   * Update user profile
   * 
   * @param data - Profile update data
   * @param config - Additional request configuration
   * @returns Promise resolving to updated user profile
   * 
   * @example
   * ```typescript
   * const response = await userService.updateProfile({
   *   firstName: 'John',
   *   lastName: 'Doe',
   *   bio: 'Software developer passionate about TypeScript'
   * });
   * ```
   */
  async updateProfile(
    data: Partial<UpdateProfileData & {
      phoneNumber?: string;
      dateOfBirth?: string;
      bio?: string;
      website?: string;
      location?: string;
    }>,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<ExtendedUser>> {
    // Validate input
    const validatedData = updateProfileSchema.parse(data);

    return this.client.patch<typeof validatedData, ExtendedUser>(
      `${this.baseUrl}/profile`,
      validatedData,
      {
        ...config,
        cancelKey: 'user.updateProfile',
      }
    );
  }

  /**
   * Upload user avatar
   * 
   * @param file - Avatar image file
   * @param config - Additional request configuration
   * @returns Promise resolving to upload response with avatar URL
   * 
   * @example
   * ```typescript
   * const fileInput = document.getElementById('avatar') as HTMLInputElement;
   * const file = fileInput.files?.[0];
   * 
   * if (file) {
   *   const response = await userService.uploadAvatar(file, {
   *     onUploadProgress: (progress) => {
   *       console.log(`Upload progress: ${progress.progress}%`);
   *     }
   *   });
   * }
   * ```
   */
  async uploadAvatar(
    file: File,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<FileUploadResponse>> {
    // Validate file type and size
    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
    const maxSize = 5 * 1024 * 1024; // 5MB

    if (!allowedTypes.includes(file.type)) {
      throw new Error('Invalid file type. Please upload a JPEG, PNG, or WebP image.');
    }

    if (file.size > maxSize) {
      throw new Error('File size too large. Please upload an image smaller than 5MB.');
    }

    // Create form data
    const formData = new FormData();
    formData.append('avatar', file);

    return this.client.upload<FileUploadResponse>(
      `${this.baseUrl}/avatar`,
      formData,
      {
        ...config,
        cancelKey: 'user.uploadAvatar',
      }
    );
  }

  /**
   * Remove user avatar
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to removal confirmation
   */
  async removeAvatar(config: ApiRequestConfig = {}): Promise<ApiResponse<void>> {
    return this.client.delete<void>(
      `${this.baseUrl}/avatar`,
      {
        ...config,
        cancelKey: 'user.removeAvatar',
      }
    );
  }

  // ===========================================================================
  // Preferences and Settings Methods
  // ===========================================================================

  /**
   * Get user preferences
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to user preferences
   */
  async getPreferences(config: ApiRequestConfig = {}): Promise<ApiResponse<UserPreferences>> {
    return this.client.get<UserPreferences>(
      `${this.baseUrl}/preferences`,
      {
        ...config,
        cancelKey: 'user.preferences',
      }
    );
  }

  /**
   * Update user preferences
   * 
   * @param preferences - Preferences to update
   * @param config - Additional request configuration
   * @returns Promise resolving to updated preferences
   * 
   * @example
   * ```typescript
   * const response = await userService.updatePreferences({
   *   theme: 'dark',
   *   notifications: {
   *     email: true,
   *     push: false
   *   }
   * });
   * ```
   */
  async updatePreferences(
    preferences: Partial<UserPreferences>,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferences>> {
    // Validate input
    const validatedPreferences = userPreferencesSchema.parse(preferences);

    return this.client.patch<typeof validatedPreferences, UserPreferences>(
      `${this.baseUrl}/preferences`,
      validatedPreferences,
      {
        ...config,
        cancelKey: 'user.updatePreferences',
      }
    );
  }

  /**
   * Reset preferences to defaults
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to default preferences
   */
  async resetPreferences(config: ApiRequestConfig = {}): Promise<ApiResponse<UserPreferences>> {
    return this.client.post<void, UserPreferences>(
      `${this.baseUrl}/preferences/reset`,
      undefined,
      {
        ...config,
        cancelKey: 'user.resetPreferences',
      }
    );
  }

  // ===========================================================================
  // Account Security Methods
  // ===========================================================================

  /**
   * Get account security status
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to security status
   */
  async getSecurityStatus(config: ApiRequestConfig = {}): Promise<ApiResponse<SecurityStatus>> {
    return this.client.get<SecurityStatus>(
      `${this.baseUrl}/security`,
      {
        ...config,
        cancelKey: 'user.security',
      }
    );
  }

  /**
   * Get user activity history
   * 
   * @param params - Query parameters for pagination and filtering
   * @param config - Additional request configuration
   * @returns Promise resolving to paginated activity history
   */
  async getActivityHistory(
    params: {
      page?: number;
      limit?: number;
      type?: UserActivity['type'];
      dateFrom?: string;
      dateTo?: string;
    } = {},
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<UserActivity>>> {
    return this.client.get<PaginatedResponse<UserActivity>>(
      `${this.baseUrl}/activity`,
      {
        ...config,
        params,
        cancelKey: 'user.activity',
      }
    );
  }

  /**
   * Get user statistics
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to user statistics
   */
  async getStats(config: ApiRequestConfig = {}): Promise<ApiResponse<UserStats>> {
    return this.client.get<UserStats>(
      `${this.baseUrl}/stats`,
      {
        ...config,
        cancelKey: 'user.stats',
      }
    );
  }

  // ===========================================================================
  // Phone Number Management
  // ===========================================================================

  /**
   * Update phone number
   * 
   * @param phoneNumber - New phone number
   * @param config - Additional request configuration
   * @returns Promise resolving to update confirmation
   */
  async updatePhoneNumber(
    phoneNumber: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ verificationSent: boolean }>> {
    return this.client.post<{ phoneNumber: string }, { verificationSent: boolean }>(
      `${this.baseUrl}/phone`,
      { phoneNumber },
      {
        ...config,
        cancelKey: 'user.updatePhone',
      }
    );
  }

  /**
   * Verify phone number with SMS code
   * 
   * @param code - SMS verification code
   * @param config - Additional request configuration
   * @returns Promise resolving to verification confirmation
   */
  async verifyPhoneNumber(
    code: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.client.post<{ code: string }, void>(
      `${this.baseUrl}/phone/verify`,
      { code },
      {
        ...config,
        cancelKey: 'user.verifyPhone',
      }
    );
  }

  /**
   * Remove phone number
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to removal confirmation
   */
  async removePhoneNumber(config: ApiRequestConfig = {}): Promise<ApiResponse<void>> {
    return this.client.delete<void>(
      `${this.baseUrl}/phone`,
      {
        ...config,
        cancelKey: 'user.removePhone',
      }
    );
  }

  // ===========================================================================
  // Email Management
  // ===========================================================================

  /**
   * Update email address
   * 
   * @param email - New email address
   * @param password - Current password for confirmation
   * @param config - Additional request configuration
   * @returns Promise resolving to update confirmation
   */
  async updateEmail(
    email: string,
    password: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ verificationSent: boolean }>> {
    return this.client.post<{ email: string; password: string }, { verificationSent: boolean }>(
      `${this.baseUrl}/email`,
      { email, password },
      {
        ...config,
        cancelKey: 'user.updateEmail',
      }
    );
  }

  /**
   * Verify new email address
   * 
   * @param token - Email verification token
   * @param config - Additional request configuration
   * @returns Promise resolving to verification confirmation
   */
  async verifyEmail(
    token: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.client.post<{ token: string }, void>(
      `${this.baseUrl}/email/verify`,
      { token },
      {
        ...config,
        skipAuth: true, // Token is in request body
        cancelKey: 'user.verifyEmail',
      }
    );
  }

  // ===========================================================================
  // Data Export and Import
  // ===========================================================================

  /**
   * Request data export
   * 
   * @param request - Export request parameters
   * @param config - Additional request configuration
   * @returns Promise resolving to export response
   */
  async requestDataExport(
    request: DataExportRequest,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<DataExportResponse>> {
    return this.client.post<DataExportRequest, DataExportResponse>(
      `${this.baseUrl}/export`,
      request,
      {
        ...config,
        cancelKey: 'user.dataExport',
      }
    );
  }

  /**
   * Get data export status
   * 
   * @param exportId - Export request ID
   * @param config - Additional request configuration
   * @returns Promise resolving to export status
   */
  async getDataExportStatus(
    exportId: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<DataExportResponse>> {
    return this.client.get<DataExportResponse>(
      `${this.baseUrl}/export/${exportId}`,
      {
        ...config,
        cancelKey: `user.exportStatus.${exportId}`,
      }
    );
  }

  /**
   * Download data export
   * 
   * @param exportId - Export request ID
   * @param config - Additional request configuration
   * @returns Promise resolving to download blob
   */
  async downloadDataExport(
    exportId: string,
    config: ApiRequestConfig = {}
  ): Promise<Blob> {
    const response = await this.client.get(
      `${this.baseUrl}/export/${exportId}/download`,
      {
        ...config,
        responseType: 'blob',
        cancelKey: `user.exportDownload.${exportId}`,
      }
    );

    if (response.success) {
      return response.data as Blob;
    }

    throw new Error('Failed to download export');
  }

  // ===========================================================================
  // Account Deletion
  // ===========================================================================

  /**
   * Request account deletion
   * 
   * @param confirmation - Deletion confirmation data
   * @param config - Additional request configuration
   * @returns Promise resolving to deletion confirmation
   */
  async deleteAccount(
    confirmation: {
      password: string;
      confirmation: 'DELETE';
      reason?: string;
    },
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<{ deletionScheduledFor: string }>> {
    // Validate input
    const validatedConfirmation = deleteAccountSchema.parse(confirmation);

    return this.client.post<typeof validatedConfirmation, { deletionScheduledFor: string }>(
      `${this.baseUrl}/delete`,
      validatedConfirmation,
      {
        ...config,
        cancelKey: 'user.deleteAccount',
      }
    );
  }

  /**
   * Cancel scheduled account deletion
   * 
   * @param config - Additional request configuration
   * @returns Promise resolving to cancellation confirmation
   */
  async cancelAccountDeletion(config: ApiRequestConfig = {}): Promise<ApiResponse<void>> {
    return this.client.post<void, void>(
      `${this.baseUrl}/delete/cancel`,
      undefined,
      {
        ...config,
        cancelKey: 'user.cancelDeletion',
      }
    );
  }

  // ===========================================================================
  // Profile Visibility and Search
  // ===========================================================================

  /**
   * Search for users (if allowed by privacy settings)
   * 
   * @param query - Search query
   * @param params - Additional search parameters
   * @param config - Additional request configuration
   * @returns Promise resolving to search results
   */
  async searchUsers(
    query: string,
    params: {
      page?: number;
      limit?: number;
      filters?: Record<string, unknown>;
    } = {},
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<Pick<ExtendedUser, 'id' | 'firstName' | 'lastName' | 'avatar' | 'bio'>>>> {
    return this.client.get(
      '/users/search',
      {
        ...config,
        params: { query, ...params },
        cancelKey: 'user.search',
      }
    );
  }

  /**
   * Get public user profile
   * 
   * @param userId - User ID to fetch
   * @param config - Additional request configuration
   * @returns Promise resolving to public profile data
   */
  async getPublicProfile(
    userId: string,
    config: ApiRequestConfig = {}
  ): Promise<ApiResponse<Pick<ExtendedUser, 'id' | 'firstName' | 'lastName' | 'avatar' | 'bio' | 'website' | 'location'>>> {
    return this.client.get(
      `/users/${userId}/public`,
      {
        ...config,
        cancelKey: `user.publicProfile.${userId}`,
      }
    );
  }
}

// Export singleton instance
export const userService = new UserService();

// Export validation schemas for external use
export {
  updateProfileSchema,
  userPreferencesSchema,
  deleteAccountSchema,
};