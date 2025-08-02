/**
 * AsyncBoundary Component
 * Combines Error Boundary with Suspense for comprehensive async operation handling
 */

import React, { Suspense, type ReactNode, type ComponentType } from 'react';
import { ErrorBoundary, type ErrorBoundaryProps } from './ErrorBoundary';
import { Spinner, LoadingOverlay } from './Spinner';
import { Card, CardContent } from './Card';

interface AsyncBoundaryProps {
  children: ReactNode;
  
  // Error boundary props
  errorFallback?: ReactNode;
  onError?: (error: Error, errorInfo: React.ErrorInfo) => void;
  errorBoundaryProps?: Partial<ErrorBoundaryProps>;
  
  // Suspense props
  loadingFallback?: ReactNode;
  loadingMessage?: string;
  loadingDelay?: number;
  showLoadingOverlay?: boolean;
  
  // Behavior
  resetKeys?: Array<string | number>;
  isolate?: boolean;
}

export function AsyncBoundary({
  children,
  errorFallback,
  onError,
  errorBoundaryProps,
  loadingFallback,
  loadingMessage = 'Loading...',
  loadingDelay,
  showLoadingOverlay = false,
  resetKeys,
  isolate = true,
}: AsyncBoundaryProps) {
  const defaultLoadingFallback = showLoadingOverlay ? (
    <LoadingOverlay isLoading message={loadingMessage} />
  ) : (
    <div className="flex items-center justify-center p-8">
      <div className="text-center">
        <Spinner size="lg" className="mx-auto mb-4" />
        {loadingMessage && (
          <p className="text-sm text-muted-foreground">{loadingMessage}</p>
        )}
      </div>
    </div>
  );

  return (
    <ErrorBoundary
      fallback={errorFallback}
      onError={onError}
      resetKeys={resetKeys}
      isolate={isolate}
      {...errorBoundaryProps}
    >
      <Suspense fallback={loadingFallback || defaultLoadingFallback}>
        {children}
      </Suspense>
    </ErrorBoundary>
  );
}

// Specialized async boundary for data fetching
interface DataBoundaryProps<T> {
  children: (data: T) => ReactNode;
  promise: Promise<T>;
  errorFallback?: (error: Error) => ReactNode;
  loadingFallback?: ReactNode;
  onError?: (error: Error) => void;
}

export function DataBoundary<T>({
  children,
  promise,
  errorFallback,
  loadingFallback,
  onError,
}: DataBoundaryProps<T>) {
  // Use React's use() hook when available, or throw promise for Suspense
  const data = use(promise);
  
  return (
    <AsyncBoundary
      errorFallback={errorFallback && <ErrorFallbackWrapper error={new Error('Data loading failed')} render={errorFallback} />}
      loadingFallback={loadingFallback}
      onError={onError}
    >
      {children(data)}
    </AsyncBoundary>
  );
}

// Helper component for error fallback rendering
function ErrorFallbackWrapper({ error, render }: { error: Error; render: (error: Error) => ReactNode }) {
  return <>{render(error)}</>;
}

// Polyfill for React use() hook until it's stable
function use<T>(promise: Promise<T>): T {
  if (promise.status === 'fulfilled') {
    return promise.value;
  } else if (promise.status === 'rejected') {
    throw promise.reason;
  } else if (promise.status === 'pending') {
    throw promise;
  } else {
    promise.status = 'pending';
    promise.then(
      (result) => {
        promise.status = 'fulfilled';
        promise.value = result;
      },
      (reason) => {
        promise.status = 'rejected';
        promise.reason = reason;
      }
    );
    throw promise;
  }
}

// Extend Promise type for use() hook
declare global {
  interface Promise<T> {
    status?: 'pending' | 'fulfilled' | 'rejected';
    value?: T;
    reason?: any;
  }
}

// Route-level async boundary with nice loading states
export function RouteAsyncBoundary({ children }: { children: ReactNode }) {
  return (
    <AsyncBoundary
      errorBoundaryProps={{
        level: 'page',
        showDetails: process.env.NODE_ENV === 'development',
      }}
      loadingFallback={<RouteLoadingFallback />}
    >
      {children}
    </AsyncBoundary>
  );
}

function RouteLoadingFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-6">
          <div className="flex flex-col items-center text-center">
            <Spinner size="lg" className="mb-4" />
            <h3 className="text-lg font-semibold mb-2">Loading page</h3>
            <p className="text-sm text-muted-foreground">
              Please wait while we load your content...
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// Section-level async boundary
export function SectionAsyncBoundary({ 
  children,
  title = 'Loading section',
  ...props 
}: AsyncBoundaryProps & { title?: string }) {
  return (
    <AsyncBoundary
      {...props}
      errorBoundaryProps={{
        level: 'section',
        showDetails: process.env.NODE_ENV === 'development',
        ...props.errorBoundaryProps,
      }}
      loadingFallback={
        <div className="p-6 text-center">
          <Spinner size="md" className="mx-auto mb-3" />
          <p className="text-sm text-muted-foreground">{title}</p>
        </div>
      }
    >
      {children}
    </AsyncBoundary>
  );
}

// List async boundary for handling lists of async data
export function ListAsyncBoundary({
  children,
  count = 3,
  ...props
}: AsyncBoundaryProps & { count?: number }) {
  return (
    <AsyncBoundary
      {...props}
      loadingFallback={<ListLoadingSkeleton count={count} />}
      errorBoundaryProps={{
        level: 'component',
        isolate: true,
        ...props.errorBoundaryProps,
      }}
    >
      {children}
    </AsyncBoundary>
  );
}

function ListLoadingSkeleton({ count }: { count: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="animate-pulse">
          <div className="h-20 bg-muted rounded-lg" />
        </div>
      ))}
    </div>
  );
}

// HOC for adding async boundary to components
export function withAsyncBoundary<P extends object>(
  Component: ComponentType<P>,
  boundaryProps?: AsyncBoundaryProps
) {
  const WrappedComponent = (props: P) => (
    <AsyncBoundary {...boundaryProps}>
      <Component {...props} />
    </AsyncBoundary>
  );

  WrappedComponent.displayName = `withAsyncBoundary(${Component.displayName || Component.name})`;

  return WrappedComponent;
}