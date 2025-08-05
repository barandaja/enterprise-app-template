import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import type { UserRole } from '../types';

/**
 * Props for ProtectedRoute component
 */
interface ProtectedRouteProps {
  children: React.ReactNode;
  requireRoles?: UserRole[];
  redirectTo?: string;
  fallback?: React.ReactNode;
}

/**
 * Loading fallback component
 */
const LoadingFallback: React.FC = () => (
  <div className="min-h-screen flex items-center justify-center bg-background">
    <div className="flex flex-col items-center space-y-4">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      <p className="text-muted-foreground">Loading...</p>
    </div>
  </div>
);

/**
 * ProtectedRoute component that requires authentication and optionally specific roles
 * 
 * @example
 * ```tsx
 * // Basic protection - requires authentication
 * <ProtectedRoute>
 *   <Dashboard />
 * </ProtectedRoute>
 * 
 * // Role-based protection
 * <ProtectedRoute requireRoles={['admin']}>
 *   <AdminPanel />
 * </ProtectedRoute>
 * 
 * // Custom redirect and fallback
 * <ProtectedRoute 
 *   redirectTo="/custom-login" 
 *   fallback={<CustomLoading />}
 * >
 *   <ProtectedContent />
 * </ProtectedRoute>
 * ```
 */
export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  requireRoles = [],
  redirectTo = '/login',
  fallback = <LoadingFallback />
}) => {
  const { isAuthenticated, isInitializing, hasAnyRole } = useAuth();
  const location = useLocation();

  // Show loading while initializing authentication state
  if (isInitializing) {
    return <>{fallback}</>;
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return (
      <Navigate 
        to={redirectTo} 
        state={{ from: location }} 
        replace 
      />
    );
  }

  // Check role requirements if specified
  if (requireRoles.length > 0 && !hasAnyRole(requireRoles)) {
    return (
      <Navigate 
        to="/unauthorized" 
        state={{ from: location, requiredRoles: requireRoles }} 
        replace 
      />
    );
  }

  // All checks passed, render the protected content
  return <>{children}</>;
};

/**
 * Higher-order component version of ProtectedRoute
 * 
 * @example
 * ```tsx
 * const ProtectedDashboard = withAuthGuard(Dashboard);
 * const AdminProtectedPanel = withAuthGuard(AdminPanel, { requireRoles: ['admin'] });
 * ```
 */
export function withAuthGuard<P extends object>(
  Component: React.ComponentType<P>,
  options: Omit<ProtectedRouteProps, 'children'> = {}
) {
  const WrappedComponent = React.forwardRef<any, P>((props, ref) => (
    <ProtectedRoute {...options}>
      <Component {...props} ref={ref} />
    </ProtectedRoute>
  ));

  WrappedComponent.displayName = `withAuthGuard(${Component.displayName || Component.name})`;

  return WrappedComponent;
}

export default ProtectedRoute;