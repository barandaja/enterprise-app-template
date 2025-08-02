import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuthStore } from './stores/authStore';
import { ErrorBoundary, RouteAsyncBoundary, ConsentBanner, AgeVerification } from './components';
import { initializeSecurityMonitoring } from './security/headers';

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

function App() {
  // Initialize auth store and security monitoring on app mount
  useEffect(() => {
    useAuthStore.getState().initialize();
    initializeSecurityMonitoring();
  }, []);

  const handleAgeVerified = (age: number, birthDate: Date) => {
    console.log(`User verified: age ${age}, birthdate ${birthDate.toISOString()}`);
    // Store age verification data if needed
  };

  const handleAgeFailed = () => {
    console.log('Age verification failed');
    // Handle users who are too young
  };

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
          <Route path="/" element={
            <RouteAsyncBoundary>
              <MainLayout>
                <Dashboard />
              </MainLayout>
            </RouteAsyncBoundary>
          } />
          <Route path="/profile" element={
            <RouteAsyncBoundary>
              <MainLayout>
                <Profile />
              </MainLayout>
            </RouteAsyncBoundary>
          } />
          <Route path="/profile/edit" element={
            <RouteAsyncBoundary>
              <MainLayout>
                <ProfileEdit />
              </MainLayout>
            </RouteAsyncBoundary>
          } />
          <Route path="/privacy" element={
            <RouteAsyncBoundary>
              <MainLayout>
                <PrivacySettings />
              </MainLayout>
            </RouteAsyncBoundary>
          } />

          {/* 404 route */}
          <Route path="/404" element={<NotFound />} />
          
          {/* Catch all route - redirect to 404 */}
          <Route path="*" element={<Navigate to="/404" replace />} />
        </Routes>
        
        {/* Global Components */}
        <ConsentBanner />
        <AgeVerification 
          minAge={16}
          onVerified={handleAgeVerified}
          onFailed={handleAgeFailed}
          showParentalConsent={true}
          privacyPolicyUrl="/privacy"
          termsUrl="/terms"
        />
      </div>
    </Router>
    </ErrorBoundary>
  );
}

export default App;
