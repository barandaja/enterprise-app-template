import { useCallback, useMemo } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { 
  useAuthStore, 
  useAuthUser, 
  useIsAuthenticated, 
  useAuthLoading, 
  useAuthError,
  useAuthInitializing,
  useAuthActions 
} from '../stores/authStore';
import type { User, UserRole, LoginCredentials, RegisterData, UpdateProfileData } from '../types';

/**
 * Authentication status enum
 */
export type AuthStatus = 'loading' | 'authenticated' | 'unauthenticated' | 'error';

/**
 * Permission check function type
 */
export type PermissionCheck = (user: User | null) => boolean;

/**
 * Route guard options
 */
interface RouteGuardOptions {
  redirectTo?: string;
  requireRoles?: UserRole[];
  requirePermissions?: PermissionCheck[];
  onUnauthorized?: () => void;
}

/**
 * Enhanced authentication hook that integrates with the auth store
 * and provides comprehensive authentication utilities
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const { user, isAuthenticated, login, logout } = useAuth();
 * 
 * // With route protection
 * const { requireAuth, requireRole } = useAuth();
 * 
 * useEffect(() => {
 *   requireAuth(); // Redirect to login if not authenticated
 * }, [requireAuth]);
 * 
 * // Permission checks
 * const { hasRole, hasPermission, canAccess } = useAuth();
 * 
 * if (!hasRole('admin')) {
 *   return <AccessDenied />;
 * }
 * 
 * // Login with error handling
 * const { login, error, isPending } = useAuth();
 * 
 * const handleLogin = async (credentials: LoginCredentials) => {
 *   try {
 *     await login(credentials);
 *     navigate('/dashboard');
 *   } catch (error) {
 *     // Error is already set in the store
 *     console.error('Login failed:', error);
 *   }
 * };
 * ```
 */
export function useAuth() {
  const navigate = useNavigate();
  const location = useLocation();
  
  // Auth store selectors
  const user = useAuthUser();
  const isAuthenticated = useIsAuthenticated();
  const isLoading = useAuthLoading();
  const error = useAuthError();
  const isInitializing = useAuthInitializing();
  const actions = useAuthActions();

  // Computed authentication status
  const status: AuthStatus = useMemo(() => {
    if (isInitializing || isLoading) return 'loading';
    if (error) return 'error';
    if (isAuthenticated) return 'authenticated';
    return 'unauthenticated';
  }, [isInitializing, isLoading, error, isAuthenticated]);

  // Enhanced login with navigation support
  const login = useCallback(async (credentials: LoginCredentials, redirectTo?: string) => {
    await actions.login(credentials);
    
    // Navigate after successful login
    const targetPath = redirectTo || 
                      (location.state as any)?.from?.pathname || 
                      '/dashboard';
    navigate(targetPath, { replace: true });
  }, [actions, navigate, location.state]);

  // Enhanced logout with navigation
  const logout = useCallback((redirectTo: string = '/login') => {
    actions.logout();
    navigate(redirectTo, { replace: true });
  }, [actions, navigate]);

  // Enhanced register with navigation
  const register = useCallback(async (data: RegisterData, redirectTo?: string) => {
    await actions.register(data);
    
    // Navigate after successful registration
    const targetPath = redirectTo || '/dashboard';
    navigate(targetPath, { replace: true });
  }, [actions, navigate]);

  // Role checking utilities
  const hasRole = useCallback((role: UserRole): boolean => {
    if (!user) return false;
    return user.role === role;
  }, [user]);

  const hasAnyRole = useCallback((roles: UserRole[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  }, [user]);

  // Permission checking utilities
  const hasPermission = useCallback((permissionCheck: PermissionCheck): boolean => {
    return permissionCheck(user);
  }, [user]);

  const hasAllPermissions = useCallback((permissionChecks: PermissionCheck[]): boolean => {
    return permissionChecks.every(check => check(user));
  }, [user]);

  const hasAnyPermission = useCallback((permissionChecks: PermissionCheck[]): boolean => {
    return permissionChecks.some(check => check(user));
  }, [user]);

  // Generic access control
  const canAccess = useCallback((requirements: {
    requireAuth?: boolean;
    requireRoles?: UserRole[];
    requirePermissions?: PermissionCheck[];
    requireAllPermissions?: boolean; // default: true
  }): boolean => {
    const {
      requireAuth = true,
      requireRoles = [],
      requirePermissions = [],
      requireAllPermissions = true
    } = requirements;

    // Check authentication
    if (requireAuth && !isAuthenticated) {
      return false;
    }

    // Check roles
    if (requireRoles.length > 0 && !hasAnyRole(requireRoles)) {
      return false;
    }

    // Check permissions
    if (requirePermissions.length > 0) {
      const permissionCheck = requireAllPermissions 
        ? hasAllPermissions(requirePermissions)
        : hasAnyPermission(requirePermissions);
      
      if (!permissionCheck) {
        return false;
      }
    }

    return true;
  }, [isAuthenticated, hasAnyRole, hasAllPermissions, hasAnyPermission]);

  // Route guard utilities
  const requireAuth = useCallback((options: Omit<RouteGuardOptions, 'requireRoles' | 'requirePermissions'> = {}) => {
    const { redirectTo = '/login', onUnauthorized } = options;

    if (!isAuthenticated) {
      onUnauthorized?.();
      navigate(redirectTo, { 
        replace: true,
        state: { from: location }
      });
      return false;
    }

    return true;
  }, [isAuthenticated, navigate, location]);

  const requireRole = useCallback((roles: UserRole[], options: RouteGuardOptions = {}) => {
    const { redirectTo = '/unauthorized', onUnauthorized } = options;

    if (!requireAuth(options)) {
      return false;
    }

    if (!hasAnyRole(roles)) {
      onUnauthorized?.();
      navigate(redirectTo, { replace: true });
      return false;
    }

    return true;
  }, [requireAuth, hasAnyRole, navigate]);

  const requirePermission = useCallback((
    permissionChecks: PermissionCheck[], 
    options: RouteGuardOptions & { requireAll?: boolean } = {}
  ) => {
    const { redirectTo = '/unauthorized', requireAll = true, onUnauthorized } = options;

    if (!requireAuth(options)) {
      return false;
    }

    const hasRequiredPermissions = requireAll 
      ? hasAllPermissions(permissionChecks)
      : hasAnyPermission(permissionChecks);

    if (!hasRequiredPermissions) {
      onUnauthorized?.();
      navigate(redirectTo, { replace: true });
      return false;
    }

    return true;
  }, [requireAuth, hasAllPermissions, hasAnyPermission, navigate]);

  // User profile utilities
  const updateProfile = useCallback(async (data: UpdateProfileData) => {
    await actions.updateProfile(data);
  }, [actions]);

  const refreshToken = useCallback(async () => {
    await actions.refreshAccessToken();
  }, [actions]);

  // Token utilities
  const getToken = useCallback(() => {
    return useAuthStore.getState().token;
  }, []);

  const isTokenExpired = useCallback((token?: string) => {
    const targetToken = token || getToken();
    if (!targetToken) return true;
    
    return useAuthStore.getState().isTokenExpired(targetToken);
  }, [getToken]);

  // Utility getters
  const isAdmin = useMemo(() => hasRole('admin'), [hasRole]);
  const isModerator = useMemo(() => hasRole('moderator'), [hasRole]);
  const isUser = useMemo(() => hasRole('user'), [hasRole]);

  return {
    // Core state
    user,
    isAuthenticated,
    isLoading,
    isInitializing,
    error,
    status,

    // Authentication actions
    login,
    logout,
    register,
    updateProfile,
    refreshToken,
    clearError: actions.clearError,

    // Permission utilities
    hasRole,
    hasAnyRole,
    hasPermission,
    hasAllPermissions,
    hasAnyPermission,
    canAccess,

    // Route guards
    requireAuth,
    requireRole,
    requirePermission,

    // Token utilities
    getToken,
    isTokenExpired,

    // Convenience flags
    isAdmin,
    isModerator,
    isUser,

    // Direct store access (for advanced use cases)
    store: useAuthStore,
  };
}

/**
 * Hook for protecting routes with authentication and authorization
 * Automatically redirects unauthorized users
 * 
 * @example
 * ```tsx
 * // Protect route with authentication
 * function ProtectedPage() {
 *   const { isAuthorized } = useAuthGuard();
 *   
 *   if (!isAuthorized) {
 *     return <Loading />; // Will redirect automatically
 *   }
 *   
 *   return <PageContent />;
 * }
 * 
 * // Protect route with role requirements
 * function AdminPage() {
 *   const { isAuthorized } = useAuthGuard({
 *     requireRoles: ['admin'],
 *     redirectTo: '/access-denied'
 *   });
 *   
 *   if (!isAuthorized) {
 *     return <Loading />;
 *   }
 *   
 *   return <AdminContent />;
 * }
 * ```
 */
export function useAuthGuard(options: RouteGuardOptions & {
  requireAuth?: boolean;
  requireAllPermissions?: boolean;
} = {}) {
  const {
    requireAuth = true,
    requireRoles = [],
    requirePermissions = [],
    requireAllPermissions = true,
    redirectTo,
    onUnauthorized,
  } = options;

  const { canAccess, requireAuth: doRequireAuth, requireRole, requirePermission } = useAuth();

  const isAuthorized = useMemo(() => {
    return canAccess({
      requireAuth,
      requireRoles,
      requirePermissions,
      requireAllPermissions,
    });
  }, [canAccess, requireAuth, requireRoles, requirePermissions, requireAllPermissions]);

  // Apply route guards based on configuration
  if (requireAuth && requireRoles.length === 0 && requirePermissions.length === 0) {
    doRequireAuth({ redirectTo, onUnauthorized });
  } else if (requireRoles.length > 0) {
    requireRole(requireRoles, { redirectTo, onUnauthorized });
  } else if (requirePermissions.length > 0) {
    requirePermission(requirePermissions, { 
      redirectTo, 
      onUnauthorized,
      requireAll: requireAllPermissions 
    });
  }

  return {
    isAuthorized,
  };
}

/**
 * Common permission checks that can be reused across the application
 */
export const permissions = {
  // Admin permissions
  isAdmin: (user: User | null): boolean => user?.role === 'admin',
  isModerator: (user: User | null): boolean => user?.role === 'moderator' || user?.role === 'admin',
  
  // User permissions
  canEditProfile: (user: User | null): boolean => !!user && user.isActive,
  canViewDashboard: (user: User | null): boolean => !!user && user.isActive,
  
  // Resource permissions
  canCreateContent: (user: User | null): boolean => 
    !!user && user.isActive && ['admin', 'moderator'].includes(user.role),
  
  canDeleteContent: (user: User | null): boolean => 
    !!user && user.isActive && user.role === 'admin',
  
  canManageUsers: (user: User | null): boolean => 
    !!user && user.isActive && user.role === 'admin',
} as const;