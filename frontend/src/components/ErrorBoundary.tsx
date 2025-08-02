/**
 * Error Boundary Component
 * Catches JavaScript errors anywhere in the component tree and displays a fallback UI
 */

import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home, Bug } from 'lucide-react';
import { Button } from './Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './Card';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
  resetKeys?: Array<string | number>;
  resetOnPropsChange?: boolean;
  isolate?: boolean;
  level?: 'page' | 'section' | 'component';
  showDetails?: boolean;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  errorCount: number;
}

export class ErrorBoundary extends Component<Props, State> {
  private resetTimeoutId: ReturnType<typeof setTimeout> | null = null;

  constructor(props: Props) {
    super(props);

    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorCount: 0,
    };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      error,
      errorInfo: null,
      errorCount: 0,
    };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    const { onError } = this.props;

    // Log error to error reporting service
    console.error('Error caught by ErrorBoundary:', error, errorInfo);

    // Update state with error details
    this.setState(prevState => ({
      errorInfo,
      errorCount: prevState.errorCount + 1,
    }));

    // Call custom error handler if provided
    onError?.(error, errorInfo);

    // In production, send to error tracking service
    if (process.env.NODE_ENV === 'production') {
      // Example: Sentry, LogRocket, etc.
      // window.Sentry?.captureException(error, {
      //   contexts: { react: { componentStack: errorInfo.componentStack } },
      // });
    }
  }

  componentDidUpdate(prevProps: Props) {
    const { resetKeys, resetOnPropsChange } = this.props;
    const { hasError } = this.state;

    if (hasError && prevProps.resetKeys !== resetKeys) {
      if (resetKeys?.some((key, idx) => key !== prevProps.resetKeys?.[idx])) {
        this.resetErrorBoundary();
      }
    }

    if (hasError && resetOnPropsChange && prevProps.children !== this.props.children) {
      this.resetErrorBoundary();
    }
  }

  componentWillUnmount() {
    if (this.resetTimeoutId) {
      clearTimeout(this.resetTimeoutId);
    }
  }

  resetErrorBoundary = () => {
    if (this.resetTimeoutId) {
      clearTimeout(this.resetTimeoutId);
    }

    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorCount: 0,
    });
  };

  render() {
    const { hasError, error, errorInfo, errorCount } = this.state;
    const { children, fallback, level = 'component', showDetails = false, isolate = true } = this.props;

    if (hasError && error) {
      // Use custom fallback if provided
      if (fallback) {
        return <>{fallback}</>;
      }

      // Default error UI based on level
      switch (level) {
        case 'page':
          return <PageErrorFallback 
            error={error} 
            errorInfo={errorInfo}
            onReset={this.resetErrorBoundary}
            showDetails={showDetails}
            errorCount={errorCount}
          />;
        
        case 'section':
          return <SectionErrorFallback
            error={error}
            errorInfo={errorInfo}
            onReset={this.resetErrorBoundary}
            showDetails={showDetails}
            errorCount={errorCount}
          />;
        
        case 'component':
        default:
          return <ComponentErrorFallback
            error={error}
            errorInfo={errorInfo}
            onReset={this.resetErrorBoundary}
            showDetails={showDetails}
            errorCount={errorCount}
            isolate={isolate}
          />;
      }
    }

    return children;
  }
}

// Page-level error fallback
function PageErrorFallback({ 
  error, 
  errorInfo, 
  onReset, 
  showDetails,
  errorCount 
}: {
  error: Error;
  errorInfo: ErrorInfo | null;
  onReset: () => void;
  showDetails: boolean;
  errorCount: number;
}) {
  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-background">
      <Card className="max-w-lg w-full">
        <CardHeader className="text-center">
          <div className="mx-auto w-12 h-12 text-destructive mb-4">
            <AlertTriangle className="w-full h-full" />
          </div>
          <CardTitle className="text-2xl">Something went wrong</CardTitle>
          <CardDescription>
            We're sorry, but something unexpected happened. Please try refreshing the page.
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          {errorCount > 2 && (
            <div className="mb-4 p-3 bg-destructive/10 text-destructive rounded-lg text-sm">
              This error has occurred multiple times. If the problem persists, please contact support.
            </div>
          )}
          
          {showDetails && (
            <details className="mt-4">
              <summary className="cursor-pointer text-sm text-muted-foreground hover:text-foreground">
                Error details
              </summary>
              <div className="mt-2 p-3 bg-muted rounded-lg">
                <p className="text-sm font-mono text-destructive break-all">
                  {error.toString()}
                </p>
                {errorInfo && (
                  <pre className="mt-2 text-xs text-muted-foreground overflow-auto max-h-40">
                    {errorInfo.componentStack}
                  </pre>
                )}
              </div>
            </details>
          )}
        </CardContent>
        
        <CardFooter className="flex gap-3">
          <Button onClick={onReset} className="flex-1">
            <RefreshCw className="w-4 h-4 mr-2" />
            Try again
          </Button>
          <Button 
            variant="outline" 
            onClick={() => window.location.href = '/'}
            className="flex-1"
          >
            <Home className="w-4 h-4 mr-2" />
            Go home
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}

// Section-level error fallback
function SectionErrorFallback({
  error,
  errorInfo,
  onReset,
  showDetails,
  errorCount
}: {
  error: Error;
  errorInfo: ErrorInfo | null;
  onReset: () => void;
  showDetails: boolean;
  errorCount: number;
}) {
  return (
    <div className="p-8 text-center">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-destructive/10 text-destructive mb-4">
        <AlertTriangle className="w-6 h-6" />
      </div>
      
      <h3 className="text-lg font-semibold mb-2">Unable to load this section</h3>
      <p className="text-muted-foreground mb-6 max-w-md mx-auto">
        We encountered an error loading this part of the page. You can try again or continue using other features.
      </p>

      {errorCount > 2 && (
        <p className="text-sm text-destructive mb-4">
          Multiple errors detected. Please refresh the page if the problem persists.
        </p>
      )}
      
      <div className="flex gap-3 justify-center">
        <Button onClick={onReset} size="sm">
          <RefreshCw className="w-4 h-4 mr-2" />
          Retry
        </Button>
        
        {showDetails && (
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              console.error('Section Error:', error);
              console.error('Component Stack:', errorInfo?.componentStack);
            }}
          >
            <Bug className="w-4 h-4 mr-2" />
            Log details
          </Button>
        )}
      </div>
    </div>
  );
}

// Component-level error fallback
function ComponentErrorFallback({
  error,
  errorInfo,
  onReset,
  showDetails,
  errorCount,
  isolate
}: {
  error: Error;
  errorInfo: ErrorInfo | null;
  onReset: () => void;
  showDetails: boolean;
  errorCount: number;
  isolate: boolean;
}) {
  if (!isolate) {
    throw error; // Re-throw to let parent boundary handle it
  }

  return (
    <div className="p-4 border border-destructive/20 rounded-lg bg-destructive/5">
      <div className="flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <p className="text-sm font-medium text-foreground">
            Component error
          </p>
          <p className="text-sm text-muted-foreground mt-1">
            This component couldn't be displayed
          </p>
          
          {showDetails && (
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
                Show details
              </summary>
              <pre className="mt-1 text-xs text-destructive overflow-auto">
                {error.message}
              </pre>
            </details>
          )}
          
          <button
            onClick={onReset}
            className="mt-2 text-xs text-primary hover:underline"
          >
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}

// Higher-order component for adding error boundaries
export function withErrorBoundary<P extends object>(
  Component: React.ComponentType<P>,
  errorBoundaryProps?: Props
) {
  const WrappedComponent = (props: P) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <Component {...props} />
    </ErrorBoundary>
  );

  WrappedComponent.displayName = `withErrorBoundary(${Component.displayName || Component.name})`;

  return WrappedComponent;
}

// Hook for error handling (to be used with error boundaries)
export function useErrorHandler() {
  return (error: Error, errorInfo?: { componentStack?: string }) => {
    console.error('Error handled by useErrorHandler:', error);
    
    // In production, send to error tracking
    if (process.env.NODE_ENV === 'production') {
      // Example: Send to tracking service
    }
    
    // Re-throw to let error boundary catch it
    throw error;
  };
}