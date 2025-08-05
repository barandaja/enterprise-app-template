import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from './stores/authStore';
import { ErrorBoundary, RouteAsyncBoundary, ConsentBanner, ProtectedRoute } from './components';
import { initializeSecurityMonitoring } from './security/headers';
import { initializeCSP } from './security/csp';
import { useAuth } from './hooks/useAuth';

// Layouts
import MainLayout from './layouts/MainLayout';
import AuthLayout from './layouts/AuthLayout';

// Pages
import Dashboard from './pages/Dashboard';
import Login from './pages/Login';
import Register from './pages/Register';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import EmailVerification from './pages/EmailVerification';
import Profile from './pages/Profile';
import ProfileEdit from './pages/ProfileEdit';
import PrivacySettings from './pages/PrivacySettings';
import Unauthorized from './pages/Unauthorized';

// 404 Page Component
function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-muted-foreground mb-4">404</h1>
        <h2 className="text-2xl font-semibold text-foreground mb-4">Page Not Found</h2>
        <p className="text-muted-foreground mb-8">
          The page you're looking for doesn't exist.
        </p>
        <a href="/" className="btn-primary">
          Go Home
        </a>
      </div>
    </div>
  );
}

// Auth redirect component for root route
function AuthRedirect() {
  const { isAuthenticated, isInitializing } = useAuth();
  
  if (isInitializing) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="flex flex-col items-center space-y-4">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }
  
  return <Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />;
}

function App() {
  // Initialize auth store and security monitoring on app mount
  useEffect(() => {
    useAuthStore.getState().initialize();
    initializeSecurityMonitoring();
    initializeCSP();
  }, []);


  return (
    <ErrorBoundary 
      level="page" 
      showDetails={process.env.NODE_ENV === 'development'}
      onError={(error, errorInfo) => {
        // Log to error tracking service in production
        console.error('App Error:', error, errorInfo);
      }}
    >
      <Router>
        <div className="App">
          {/* Toast notifications */}
          <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: 'rgb(var(--color-card))',
              color: 'rgb(var(--color-card-foreground))',
              border: '1px solid rgb(var(--color-border))',
            },
            success: {
              iconTheme: {
                primary: 'rgb(var(--color-success))',
                secondary: 'rgb(var(--color-background))',
              },
            },
            error: {
              iconTheme: {
                primary: 'rgb(var(--color-destructive))',
                secondary: 'rgb(var(--color-background))',
              },
            },
          }}
        />

        <Routes>
          {/* Root route - redirect based on authentication */}
          <Route path="/" element={<AuthRedirect />} />

          {/* Authentication routes with AuthLayout */}
          <Route path="/login" element={
            <AuthLayout 
              title="Welcome back" 
              subtitle="Sign in to your account to continue"
            >
              <Login />
            </AuthLayout>
          } />
          <Route path="/register" element={
            <AuthLayout 
              title="Create account" 
              subtitle="Get started with your free account"
            >
              <Register />
            </AuthLayout>
          } />
          <Route path="/forgot-password" element={
            <AuthLayout 
              title="Reset password" 
              subtitle="We'll help you get back into your account"
            >
              <ForgotPassword />
            </AuthLayout>
          } />
          <Route path="/reset-password" element={
            <AuthLayout 
              title="Set new password" 
              subtitle="Choose a strong password for your account"
            >
              <ResetPassword />
            </AuthLayout>
          } />
          <Route path="/verify-email" element={
            <AuthLayout 
              title="Verify your email" 
              subtitle="Complete your account setup"
            >
              <EmailVerification />
            </AuthLayout>
          } />

          {/* Protected routes with MainLayout */}
          <Route path="/dashboard" element={
            <ProtectedRoute>
              <RouteAsyncBoundary>
                <MainLayout>
                  <Dashboard />
                </MainLayout>
              </RouteAsyncBoundary>
            </ProtectedRoute>
          } />
          <Route path="/profile" element={
            <ProtectedRoute>
              <RouteAsyncBoundary>
                <MainLayout>
                  <Profile />
                </MainLayout>
              </RouteAsyncBoundary>
            </ProtectedRoute>
          } />
          <Route path="/profile/edit" element={
            <ProtectedRoute>
              <RouteAsyncBoundary>
                <MainLayout>
                  <ProfileEdit />
                </MainLayout>
              </RouteAsyncBoundary>
            </ProtectedRoute>
          } />
          <Route path="/privacy" element={
            <ProtectedRoute>
              <RouteAsyncBoundary>
                <MainLayout>
                  <PrivacySettings />
                </MainLayout>
              </RouteAsyncBoundary>
            </ProtectedRoute>
          } />

          {/* Access control routes */}
          <Route path="/unauthorized" element={<Unauthorized />} />

          {/* 404 route */}
          <Route path="/404" element={<NotFound />} />
          
          {/* Catch all route - redirect to 404 */}
          <Route path="*" element={<Navigate to="/404" replace />} />
        </Routes>
        
        {/* Global Components */}
        <ConsentBanner />
      </div>
    </Router>
    </ErrorBoundary>
  );
}

export default App;
