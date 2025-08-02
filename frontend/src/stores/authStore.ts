import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { authService } from '../services/api/auth.service';
import { userService } from '../services/api/user.service';
import { ApiError, createUserFriendlyError } from '../services/api';
import { tokenManager } from '../services/auth/tokenManager';
import { SecurityEventType, SecuritySeverity, logSecurityEvent } from '../security/monitoring';
import type { 
  User, 
  LoginCredentials, 
  RegisterData, 
  UpdateProfileData
} from '../types';
import type { ApiResponse } from '../services/api/types';

// Extended auth state interface for the store
interface AuthState {
  // Core auth state
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  
  // Async state management
  isLoading: boolean;
  isInitializing: boolean;
  error: string | null;
  
  // Token refresh state (managed by TokenManager)
  isRefreshing: boolean;
}

// Auth actions interface
interface AuthActions {
  // Authentication actions
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (data: RegisterData) => Promise<void>;
  logout: () => void;
  
  // Token management (delegated to TokenManager)
  refreshAccessToken: () => Promise<void>;
  setTokens: (token: string, refreshToken: string) => Promise<void>;
  clearTokens: () => Promise<void>;
  
  // User management
  updateProfile: (data: UpdateProfileData) => Promise<void>;
  setUser: (user: User) => void;
  
  // State management
  clearError: () => void;
  setLoading: (loading: boolean) => void;
  initialize: () => Promise<void>;
  
  // Utility actions
  isTokenExpired: (token: string) => boolean;
  scheduleRefresh: () => void;
}

// Combined store type
type AuthStore = AuthState & AuthActions;

// Token payload interface for JWT decoding
interface TokenPayload {
  exp: number;
  iat: number;
  sub: string;
  email: string;
}

// API service integration
const authApi = {
  async login(credentials: LoginCredentials): Promise<ApiResponse<{ user: User; tokens: { accessToken: string; refreshToken: string } }>> {
    const response = await authService.login(credentials);
    if (response.success) {
      return {
        success: true,
        data: {
          user: response.data.user,
          tokens: response.data.tokens,
        },
        meta: response.meta,
      };
    }
    return response;
  },

  async register(data: RegisterData): Promise<ApiResponse<{ user: User; tokens: { accessToken: string; refreshToken: string } }>> {
    const response = await authService.register({
      ...data,
      confirmPassword: data.password, // For compatibility
      acceptTerms: true, // Assume terms are accepted
    });
    if (response.success) {
      return {
        success: true,
        data: {
          user: response.data.user,
          tokens: response.data.tokens,
        },
        meta: response.meta,
      };
    }
    return response;
  },

  async refreshToken(refreshToken: string): Promise<ApiResponse<{ accessToken: string; refreshToken: string }>> {
    const response = await authService.refreshToken(refreshToken);
    if (response.success) {
      return {
        success: true,
        data: {
          accessToken: response.data.accessToken,
          refreshToken: response.data.refreshToken,
        },
        meta: response.meta,
      };
    }
    return response;
  },

  async updateProfile(data: UpdateProfileData): Promise<ApiResponse<User>> {
    return userService.updateProfile(data);
  },
};

// Utility function to decode JWT token
const decodeToken = (token: string): TokenPayload | null => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      window.atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
};

// Create the auth store with secure storage instead of localStorage
// Session timeout event listener
window.addEventListener('session-timeout', () => {
  useAuthStore.getState().logout();
});

export const useAuthStore = create<AuthStore>()(
  devtools(
    immer((set, get) => ({
        // Initial state
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
        isInitializing: true,
        error: null,
        isRefreshing: false,

        // Authentication actions
        login: async (credentials: LoginCredentials) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await authApi.login(credentials);
            if (!response.success) {
              throw new ApiError(response.message, response.code);
            }

            const { user, tokens } = response.data;

            // Store tokens using TokenManager
            await tokenManager.setTokens({
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken
            });
            
            set((state) => {
              state.user = user;
              state.token = tokens.accessToken;
              state.refreshToken = tokens.refreshToken;
              state.isAuthenticated = true;
              state.isLoading = false;
              state.error = null;
            });

            // Log security event
            logSecurityEvent({
              type: SecurityEventType.LOGIN_SUCCESS,
              severity: SecuritySeverity.INFO,
              message: 'User logged in successfully',
              userId: user.id
            });
          } catch (error) {
            const errorMessage = createUserFriendlyError(error, 'Login failed');
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
              state.isAuthenticated = false;
            });
            
            // Log security event
            logSecurityEvent({
              type: SecurityEventType.LOGIN_FAILURE,
              severity: SecuritySeverity.WARNING,
              message: 'Login attempt failed',
              details: { error: errorMessage }
            });
            
            throw error;
          }
        },

        register: async (data: RegisterData) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await authApi.register(data);
            if (!response.success) {
              throw new ApiError(response.message, response.code);
            }

            const { user, tokens } = response.data;

            // Store tokens using TokenManager
            await tokenManager.setTokens({
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken
            });
            
            set((state) => {
              state.user = user;
              state.token = tokens.accessToken;
              state.refreshToken = tokens.refreshToken;
              state.isAuthenticated = true;
              state.isLoading = false;
              state.error = null;
            });
          } catch (error) {
            const errorMessage = createUserFriendlyError(error, 'Registration failed');
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
              state.isAuthenticated = false;
            });
            throw error;
          }
        },

        logout: async () => {
          // Clear tokens using TokenManager
          await tokenManager.clearTokens();
          
          set((state) => {
            state.user = null;
            state.token = null;
            state.refreshToken = null;
            state.isAuthenticated = false;
            state.error = null;
            state.isLoading = false;
            state.isRefreshing = false;
          });
          
          // Log security event
          logSecurityEvent({
            type: SecurityEventType.LOGOUT,
            severity: SecuritySeverity.INFO,
            message: 'User logged out'
          });
        },

        // Token management (delegated to TokenManager)
        refreshAccessToken: async () => {
          set((state) => {
            state.isRefreshing = true;
            state.error = null;
          });

          try {
            // Use TokenManager for thread-safe token refresh
            const tokens = await tokenManager.forceRefresh();
            
            set((state) => {
              state.token = tokens.accessToken;
              state.refreshToken = tokens.refreshToken;
              state.isRefreshing = false;
            });
            
            // Log security event
            logSecurityEvent({
              type: SecurityEventType.TOKEN_REFRESH_SUCCESS,
              severity: SecuritySeverity.INFO,
              message: 'Token refreshed successfully'
            });
          } catch (error) {
            const errorMessage = createUserFriendlyError(error, 'Token refresh failed');
            set((state) => {
              state.isRefreshing = false;
              state.error = errorMessage;
            });
            
            // Log security event
            logSecurityEvent({
              type: SecurityEventType.TOKEN_REFRESH_FAILURE,
              severity: SecuritySeverity.ERROR,
              message: 'Token refresh failed',
              details: { error: errorMessage }
            });
            
            // Logout on refresh failure
            await get().logout();
            throw error;
          }
        },

        setTokens: async (token: string, refreshToken: string) => {
          // Store tokens using TokenManager
          await tokenManager.setTokens({
            accessToken: token,
            refreshToken
          });
          
          set((state) => {
            state.token = token;
            state.refreshToken = refreshToken;
            state.isAuthenticated = true;
          });
        },
        
        clearTokens: async () => {
          await tokenManager.clearTokens();
          set((state) => {
            state.token = null;
            state.refreshToken = null;
            state.isAuthenticated = false;
          });
        },

        // User management
        updateProfile: async (data: UpdateProfileData) => {
          set((state) => {
            state.isLoading = true;
            state.error = null;
          });

          try {
            const response = await authApi.updateProfile(data);
            if (!response.success) {
              throw new ApiError(response.message, response.code);
            }

            const updatedUser = response.data;

            set((state) => {
              state.user = updatedUser;
              state.isLoading = false;
              state.error = null;
            });
          } catch (error) {
            const errorMessage = createUserFriendlyError(error, 'Profile update failed');
            set((state) => {
              state.isLoading = false;
              state.error = errorMessage;
            });
            throw error;
          }
        },

        setUser: (user: User) => {
          set((state) => {
            state.user = user;
          });
        },

        // State management
        clearError: () => {
          set((state) => {
            state.error = null;
          });
        },

        setLoading: (loading: boolean) => {
          set((state) => {
            state.isLoading = loading;
          });
        },

        initialize: async () => {
          set((state) => {
            state.isInitializing = true;
          });

          try {
            // Initialize TokenManager and load existing tokens
            await tokenManager.initialize();
            
            // Try to get current tokens
            const tokens = await tokenManager.getCurrentTokens();
            
            if (tokens) {
              // Check if we need to get a valid token (might trigger refresh)
              try {
                const validToken = await tokenManager.getValidToken();
                
                set((state) => {
                  state.token = validToken;
                  state.refreshToken = tokens.refreshToken;
                  state.isAuthenticated = true;
                  state.isInitializing = false;
                });
                
                // Fetch user data if we have a valid token
                // Note: You might want to add a getCurrentUser API call here
              } catch (refreshError) {
                // Token refresh failed, clear auth state
                await get().logout();
                set((state) => {
                  state.isInitializing = false;
                });
              }
            } else {
              // No tokens available
              set((state) => {
                state.isInitializing = false;
              });
            }
            
            // Subscribe to token changes
            tokenManager.onTokenChange((newTokens) => {
              if (newTokens) {
                set((state) => {
                  state.token = newTokens.accessToken;
                  state.refreshToken = newTokens.refreshToken;
                  state.isAuthenticated = true;
                });
              } else {
                // Tokens cleared
                set((state) => {
                  state.token = null;
                  state.refreshToken = null;
                  state.isAuthenticated = false;
                });
              }
            });
          } catch (error) {
            // Initialization failed
            set((state) => {
              state.isInitializing = false;
              state.error = 'Failed to initialize authentication';
            });
          }
        },

        // Utility actions
        isTokenExpired: (token: string): boolean => {
          const payload = decodeToken(token);
          if (!payload) return true;

          const currentTime = Math.floor(Date.now() / 1000);
          return payload.exp < currentTime;
        },

        scheduleRefresh: () => {
          // Deprecated - TokenManager handles automatic refresh scheduling
          console.warn('scheduleRefresh is deprecated. TokenManager handles automatic token refresh.');
        },
      })),
    {
      name: 'auth-store',
    }
  )
);

// Selectors for performance optimization
export const useAuthUser = () => useAuthStore((state) => state.user);
export const useAuthToken = () => useAuthStore((state) => state.token);
export const useIsAuthenticated = () => useAuthStore((state) => state.isAuthenticated);
export const useAuthLoading = () => useAuthStore((state) => state.isLoading);
export const useAuthError = () => useAuthStore((state) => state.error);
export const useAuthInitializing = () => useAuthStore((state) => state.isInitializing);

// Auth actions selectors
export const useAuthActions = () => useAuthStore((state) => ({
  login: state.login,
  register: state.register,
  logout: state.logout,
  updateProfile: state.updateProfile,
  clearError: state.clearError,
  refreshAccessToken: state.refreshAccessToken,
}));