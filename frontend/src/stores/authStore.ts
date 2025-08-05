import { create } from 'zustand';
import { devtools } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { useShallow } from 'zustand/react/shallow';
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
import type {
  AsyncState,
  BaseStore,
  AsyncStoreMixin,
  UserId,
  AccessToken,
  RefreshToken,
  SessionId,
  StoreEventEmitter,
  EventKey,
  StoreEvent
} from './types';
import {
  createUserId,
  createAccessToken,
  createRefreshToken,
  createSessionId,
  generateStoreId,
  STORE_VERSION,
  isAsyncState,
  isLoadingState,
  isSuccessState,
  isErrorState,
  assertNonNull,
  assertAccessToken
} from './types';

// =============================================================================
// ADVANCED TYPESCRIPT AUTH STORE TYPES
// =============================================================================

/**
 * Enhanced auth state with advanced TypeScript patterns
 */
interface AuthState extends BaseStore, AsyncStoreMixin<AuthState> {
  // Core auth state with branded types
  readonly user: User | null;
  readonly userId: UserId | null;
  readonly token: AccessToken | null;
  readonly refreshToken: RefreshToken | null;
  readonly sessionId: SessionId | null;
  readonly isAuthenticated: boolean;
  readonly isRefreshing: boolean;
  
  // Advanced async state management
  readonly authState: AsyncState<User>;
  readonly tokenState: AsyncState<{ accessToken: AccessToken; refreshToken: RefreshToken }>;
  readonly isInitializing: boolean;
  
  // Session management
  readonly sessionExpiry: number | null;
  readonly sessionStartTime: number | null;
  readonly lastActivity: number | null;
  
  // Security context
  readonly securityContext: {
    readonly ipAddress: string | null;
    readonly userAgent: string | null;
    readonly deviceFingerprint: string | null;
    readonly location: string | null;
  };
  
  // Token refresh state (managed by TokenManager)
  readonly refreshState: AsyncState<{ accessToken: AccessToken; refreshToken: RefreshToken }>;
}

/**
 * Enhanced auth actions with advanced TypeScript patterns
 */
interface AuthActions extends StoreEventEmitter {
  // Authentication actions with enhanced type safety
  readonly login: (credentials: LoginCredentials, options?: LoginOptions) => Promise<AuthResult>;
  readonly register: (data: RegisterData, options?: RegisterOptions) => Promise<AuthResult>;
  readonly logout: (options?: LogoutOptions) => Promise<void>;
  readonly silentLogin: () => Promise<boolean>;
  
  // Token management with branded types
  readonly refreshAccessToken: () => Promise<TokenRefreshResult>;
  readonly setTokens: (tokens: TokenPair) => Promise<void>;
  readonly clearTokens: () => Promise<void>;
  readonly validateToken: (token: AccessToken) => Promise<boolean>;
  
  // User management with type safety
  readonly updateProfile: (data: UpdateProfileData) => Promise<User>;
  readonly setUser: (user: User) => void;
  readonly getCurrentUser: () => Promise<User | null>;
  
  // Session management
  readonly extendSession: () => Promise<void>;
  readonly checkSessionValidity: () => boolean;
  readonly updateLastActivity: () => void;
  
  // Security actions
  readonly updateSecurityContext: (context: Partial<SecurityContext>) => void;
  readonly reportSecurityEvent: (event: SecurityEvent) => void;
  
  // State management with async patterns
  readonly clearError: () => void;
  readonly initialize: () => Promise<void>;
  readonly reset: () => void;
  
  // Advanced utility actions
  readonly isTokenExpired: (token: AccessToken) => boolean;
  readonly getTokenExpiry: (token: AccessToken) => Date | null;
  readonly hasPendingOperations: () => boolean;
  readonly waitForInitialization: () => Promise<void>;
  
  // Type guards and assertions
  readonly assertAuthenticated: () => asserts this is AuthStore & { isAuthenticated: true; user: User; userId: UserId };
  readonly assertTokenValid: (token: AccessToken) => asserts token is AccessToken;
}

// =============================================================================
// SUPPORTING TYPES FOR ENHANCED AUTH STORE
// =============================================================================

/**
 * Login options with advanced configuration
 */
interface LoginOptions {
  readonly rememberMe?: boolean;
  readonly deviceTrust?: boolean;
  readonly sessionTimeout?: number;
  readonly securityContext?: Partial<SecurityContext>;
}

/**
 * Register options with enhanced features
 */
interface RegisterOptions {
  readonly autoLogin?: boolean;
  readonly emailVerification?: boolean;
  readonly securityContext?: Partial<SecurityContext>;
}

/**
 * Logout options with cleanup configuration
 */
interface LogoutOptions {
  readonly everywhere?: boolean;
  readonly clearCache?: boolean;
  readonly redirectTo?: string;
}

/**
 * Authentication result with detailed information
 */
interface AuthResult {
  readonly success: boolean;
  readonly user: User | null;
  readonly tokens: TokenPair | null;
  readonly sessionId: SessionId | null;
  readonly expiresAt: Date | null;
  readonly requiresVerification?: boolean;
  readonly securityWarnings?: string[];
}

/**
 * Token pair with branded types
 */
interface TokenPair {
  readonly accessToken: AccessToken;
  readonly refreshToken: RefreshToken;
}

/**
 * Token refresh result with enhanced information
 */
interface TokenRefreshResult {
  readonly success: boolean;
  readonly tokens: TokenPair | null;
  readonly expiresAt: Date | null;
  readonly error?: Error;
}

/**
 * Security context for enhanced security tracking
 */
interface SecurityContext {
  readonly ipAddress: string;
  readonly userAgent: string;
  readonly deviceFingerprint: string;
  readonly location: string;
  readonly timestamp: number;
}

/**
 * Security event for audit logging
 */
interface SecurityEvent {
  readonly type: SecurityEventType;
  readonly severity: SecuritySeverity;
  readonly message: string;
  readonly context?: Partial<SecurityContext>;
  readonly userId?: UserId;
  readonly sessionId?: SessionId;
}

/**
 * Combined auth store type with advanced TypeScript patterns
 */
type AuthStore = AuthState & AuthActions;

/**
 * Authenticated auth store type guard
 */
type AuthenticatedAuthStore = AuthStore & {
  readonly isAuthenticated: true;
  readonly user: User;
  readonly userId: UserId;
  readonly token: AccessToken;
  readonly sessionId: SessionId;
};

/**
 * Type predicate for authenticated store
 */
const isAuthenticatedStore = (store: AuthStore): store is AuthenticatedAuthStore => {
  return store.isAuthenticated && store.user !== null && store.userId !== null;
};

/**
 * Enhanced token payload interface with branded types
 */
interface TokenPayload {
  readonly exp: number;
  readonly iat: number;
  readonly sub: UserId;
  readonly email: string;
  readonly sessionId: SessionId;
  readonly role: string;
  readonly permissions: string[];
  readonly deviceId?: string;
  readonly scope?: string[];
}

// Helper function to transform backend user to frontend User type
const transformBackendUser = (backendUser: any): User => {
  return {
    id: String(backendUser.id),
    email: backendUser.email,
    firstName: backendUser.first_name || '',
    lastName: backendUser.last_name || '',
    avatar: backendUser.avatar,
    role: backendUser.is_superuser ? 'admin' : 'user', // Map is_superuser to role
    isActive: backendUser.is_active,
    createdAt: backendUser.created_at,
    updatedAt: backendUser.updated_at,
  };
};

// API service integration
const authApi = {
  async login(credentials: LoginCredentials): Promise<ApiResponse<{ user: User; tokens: { accessToken: string; refreshToken: string } }>> {
    const response = await authService.login(credentials);
    if (response.success) {
      // Transform the backend response to match our expected format
      // Backend sends access_token and refresh_token at top level
      const backendData = response.data as any;
      return {
        success: true,
        data: {
          user: transformBackendUser(backendData.user),
          tokens: {
            accessToken: backendData.access_token,
            refreshToken: backendData.refresh_token,
          },
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

/**
 * Enhanced JWT token decoder with type safety and error handling
 */
const decodeToken = (token: AccessToken): TokenPayload | null => {
  try {
    assertAccessToken(token);
    
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }
    
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      window.atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    
    const payload = JSON.parse(jsonPayload);
    
    // Validate required fields
    if (!payload.exp || !payload.iat || !payload.sub) {
      throw new Error('Invalid token payload');
    }
    
    return {
      ...payload,
      sub: createUserId(payload.sub),
      sessionId: payload.sessionId ? createSessionId(payload.sessionId) : createSessionId(''),
    } as TokenPayload;
  } catch (error) {
    console.warn('Token decoding failed:', error);
    return null;
  }
};

/**
 * Generate device fingerprint for security tracking
 */
const generateDeviceFingerprint = (): string => {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  if (ctx) {
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Device fingerprint', 2, 2);
  }
  
  const fingerprint = [
    navigator.userAgent,
    navigator.language,
    screen.width + 'x' + screen.height,
    new Date().getTimezoneOffset(),
    canvas.toDataURL(),
  ].join('|');
  
  return btoa(fingerprint).slice(0, 32);
};

/**
 * Get current security context
 */
const getCurrentSecurityContext = (): Partial<SecurityContext> => {
  return {
    userAgent: navigator.userAgent,
    deviceFingerprint: generateDeviceFingerprint(),
    timestamp: Date.now(),
    // Note: IP address and location would be obtained from server
  };
};

// Create the auth store with secure storage instead of localStorage
// Session timeout event listener
window.addEventListener('session-timeout', () => {
  useAuthStore.getState().logout();
});

/**
 * Create the enhanced auth store with advanced TypeScript patterns
 */
export const useAuthStore = create<AuthStore>()(
  devtools(
    immer((set, get) => ({
        // Initial state with all required fields
        user: null,
        userId: null,
        token: null,
        refreshToken: null,
        sessionId: null,
        isAuthenticated: false,
        isLoading: false,
        isInitializing: true,
        error: null,
        isRefreshing: false,
        
        // Async state management
        authState: { status: 'idle', data: null, error: null, loading: false },
        tokenState: { status: 'idle', data: null, error: null, loading: false },
        refreshState: { status: 'idle', data: null, error: null, loading: false },
        
        // Session management
        sessionExpiry: null,
        sessionStartTime: null,
        lastActivity: null,
        
        // Security context
        securityContext: {
          ipAddress: null,
          userAgent: null,
          deviceFingerprint: null,
          location: null,
        },

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

            // Log the actual response to see its structure
            console.log('[authStore] Login response:', response);
            console.log('[authStore] Response data:', response.data);
            
            // Extract data based on the transformed response structure
            const { user, tokens } = response.data;
            const { accessToken, refreshToken } = tokens;

            // Validate tokens exist
            if (!accessToken) {
              console.error('[authStore] No access token in response:', response.data);
              throw new ApiError('No access token received from server', 'AUTH_NO_TOKEN');
            }

            // Store tokens using TokenManager
            await tokenManager.setTokens({
              accessToken,
              refreshToken
            });
            
            set((state) => {
              state.user = user;
              state.userId = createUserId(user.id);
              // Use helper functions to create branded types
              state.token = createAccessToken(accessToken);
              state.refreshToken = createRefreshToken(refreshToken);
              state.isAuthenticated = true;
              state.isLoading = false;
              state.error = null;
              state.sessionStartTime = Date.now();
              state.lastActivity = Date.now();
              
              // Update security context
              const currentContext = getCurrentSecurityContext();
              state.securityContext = {
                ...state.securityContext,
                ...currentContext,
              };
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
              // Use helper functions to create branded types
              state.token = createAccessToken(tokens.accessToken);
              state.refreshToken = createRefreshToken(tokens.refreshToken);
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
              // Use helper functions to create branded types
              state.token = createAccessToken(tokens.accessToken);
              state.refreshToken = createRefreshToken(tokens.refreshToken);
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
            // Use helper functions to create branded types
            state.token = createAccessToken(token);
            state.refreshToken = createRefreshToken(refreshToken);
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
                  // Use helper functions to create branded types
                  state.token = createAccessToken(validToken);
                  state.refreshToken = createRefreshToken(tokens.refreshToken);
                  state.isAuthenticated = true;
                  state.isInitializing = false;
                  state.lastActivity = Date.now();
                });
                
                // Fetch user data if we have a valid token
                try {
                  const userResponse = await userService.getProfile();
                  if (userResponse.success) {
                    // Transform backend user to frontend User type
                    const user = transformBackendUser(userResponse.data);
                    set((state) => {
                      state.user = user;
                      state.userId = createUserId(user.id);
                    });
                  } else {
                    console.warn('[authStore] Failed to fetch user profile:', userResponse.message);
                  }
                } catch (userError) {
                  console.warn('[authStore] Error fetching user profile:', userError);
                  // Don't fail initialization if user fetch fails, tokens are still valid
                }
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
                  // Use helper functions to create branded types
                  state.token = createAccessToken(newTokens.accessToken);
                  state.refreshToken = createRefreshToken(newTokens.refreshToken);
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
          const payload = decodeToken(token as AccessToken);
          if (!payload) return true;

          const currentTime = Math.floor(Date.now() / 1000);
          return payload.exp < currentTime;
        },

        scheduleRefresh: () => {
          // Deprecated - TokenManager handles automatic refresh scheduling
          console.warn('scheduleRefresh is deprecated. TokenManager handles automatic token refresh.');
        },

        // Additional required methods for the interface
        silentLogin: async () => {
          // This is essentially what initialize() does
          try {
            await get().initialize();
            return get().isAuthenticated;
          } catch {
            return false;
          }
        },

        validateToken: async (token: AccessToken) => {
          try {
            return !get().isTokenExpired(token);
          } catch {
            return false;
          }
        },

        getCurrentUser: async () => {
          try {
            const userResponse = await userService.getProfile();
            if (userResponse.success) {
              // Transform backend user to frontend User type
              const user = transformBackendUser(userResponse.data);
              
              set((state) => {
                state.user = user;
                state.userId = createUserId(user.id);
              });
              return user;
            }
            return null;
          } catch {
            return null;
          }
        },

        extendSession: async () => {
          set((state) => {
            state.lastActivity = Date.now();
          });
        },

        checkSessionValidity: () => {
          const state = get();
          if (!state.isAuthenticated || !state.sessionStartTime) return false;
          
          // Check if session is still valid (example: 24 hours)
          const sessionTimeout = 24 * 60 * 60 * 1000; // 24 hours
          const elapsed = Date.now() - state.sessionStartTime;
          return elapsed < sessionTimeout;
        },

        updateLastActivity: () => {
          set((state) => {
            state.lastActivity = Date.now();
          });
        },

        updateSecurityContext: (context: Partial<SecurityContext>) => {
          set((state) => {
            state.securityContext = {
              ...state.securityContext,
              ...context,
            };
          });
        },

        reportSecurityEvent: (event: SecurityEvent) => {
          logSecurityEvent(event);
        },

        reset: () => {
          set((state) => {
            state.user = null;
            state.userId = null;
            state.token = null;
            state.refreshToken = null;
            state.sessionId = null;
            state.isAuthenticated = false;
            state.isLoading = false;
            state.isInitializing = false;
            state.error = null;
            state.isRefreshing = false;
            state.authState = { status: 'idle', data: null, error: null, loading: false };
            state.tokenState = { status: 'idle', data: null, error: null, loading: false };
            state.refreshState = { status: 'idle', data: null, error: null, loading: false };
            state.sessionExpiry = null;
            state.sessionStartTime = null;
            state.lastActivity = null;
            state.securityContext = {
              ipAddress: null,
              userAgent: null,
              deviceFingerprint: null,
              location: null,
            };
          });
        },

        getTokenExpiry: (token: AccessToken) => {
          const payload = decodeToken(token);
          if (!payload || !payload.exp) return null;
          return new Date(payload.exp * 1000);
        },

        hasPendingOperations: () => {
          const state = get();
          return state.isLoading || state.isRefreshing || state.isInitializing;
        },

        waitForInitialization: async () => {
          return new Promise<void>((resolve) => {
            const check = () => {
              if (!get().isInitializing) {
                resolve();
              } else {
                setTimeout(check, 100);
              }
            };
            check();
          });
        },

        assertAuthenticated(): asserts this is AuthStore & { isAuthenticated: true; user: User; userId: UserId } {
          const state = get();
          if (!state.isAuthenticated || !state.user || !state.userId) {
            throw new Error('User is not authenticated');
          }
        },

        assertTokenValid: (token: AccessToken) => {
          assertAccessToken(token);
          if (get().isTokenExpired(token)) {
            throw new Error('Token is expired');
          }
        },

        // Event emitter methods (simplified implementation)
        on: () => () => {}, // Return cleanup function
        off: () => {},
        emit: () => {},

        // Store metadata
        storeId: generateStoreId(),
        version: STORE_VERSION,
        createdAt: Date.now(),
        updatedAt: Date.now(),
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

// Auth actions selectors with memoization to prevent infinite re-renders
export const useAuthActions = () => useAuthStore(useShallow((state) => ({
  login: state.login,
  register: state.register,
  logout: state.logout,
  updateProfile: state.updateProfile,
  clearError: state.clearError,
  refreshAccessToken: state.refreshAccessToken,
})));

/**
 * Type for the auth actions selector return value
 * This ensures type safety when destructuring the actions
 */
export type AuthActionsType = ReturnType<typeof useAuthActions>;