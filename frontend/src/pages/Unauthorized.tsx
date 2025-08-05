import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '../components';
import { useAuth } from '../hooks/useAuth';

/**
 * Unauthorized access page
 * Shown when user doesn't have required permissions/roles
 */
const Unauthorized: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();

  // Get the required roles from navigation state if available
  const requiredRoles = (location.state as any)?.requiredRoles;
  const fromPath = (location.state as any)?.from?.pathname;

  const handleGoBack = () => {
    if (fromPath) {
      navigate(fromPath, { replace: true });
    } else {
      navigate('/dashboard', { replace: true });
    }
  };

  const handleGoHome = () => {
    navigate('/dashboard', { replace: true });
  };

  const handleLogout = () => {
    logout('/login');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background px-4">
      <div className="max-w-md w-full text-center space-y-6">
        <div className="space-y-4">
          <div className="text-6xl">🚫</div>
          <h1 className="text-3xl font-bold text-foreground">Access Denied</h1>
          <p className="text-muted-foreground text-lg">
            You don't have permission to access this page.
          </p>
          
          {requiredRoles && (
            <div className="bg-muted/50 rounded-lg p-4 space-y-2">
              <p className="text-sm font-medium text-muted-foreground">
                Required roles:
              </p>
              <div className="flex flex-wrap gap-2 justify-center">
                {requiredRoles.map((role: string) => (
                  <span
                    key={role}
                    className="px-2 py-1 bg-primary/10 text-primary rounded-full text-xs font-medium"
                  >
                    {role}
                  </span>
                ))}
              </div>
            </div>
          )}

          {user && (
            <div className="bg-card border rounded-lg p-4 space-y-2">
              <p className="text-sm text-muted-foreground">
                Signed in as:
              </p>
              <p className="font-medium text-foreground">
                {user.email}
              </p>
              <p className="text-sm text-muted-foreground">
                Role: <span className="font-medium">{user.role}</span>
              </p>
            </div>
          )}
        </div>

        <div className="space-y-3">
          <Button
            onClick={handleGoHome}
            className="w-full"
            variant="default"
          >
            Go to Dashboard
          </Button>
          
          {fromPath && (
            <Button
              onClick={handleGoBack}
              className="w-full"
              variant="outline"
            >
              Go Back
            </Button>
          )}
          
          <Button
            onClick={handleLogout}
            className="w-full"
            variant="ghost"
          >
            Sign Out
          </Button>
        </div>

        <div className="text-sm text-muted-foreground space-y-1">
          <p>
            If you believe this is an error, please contact your administrator.
          </p>
          <p>
            Need different permissions? 
            <button 
              onClick={() => navigate('/profile')}
              className="text-primary hover:underline ml-1"
            >
              Check your profile
            </button>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Unauthorized;