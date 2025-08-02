/**
 * Example component demonstrating Error Boundary usage
 * This file shows best practices for error handling in React components
 */

import React, { useState } from 'react';
import { Button } from './Button';
import { Card, CardContent, CardHeader, CardTitle } from './Card';
import { SectionAsyncBoundary, ErrorBoundary } from './index';
import { useAsyncErrorHandler } from '../hooks/useAsyncError';
import { AlertCircle } from 'lucide-react';

// Component that throws an error (for demonstration)
function BuggyCounter() {
  const [count, setCount] = useState(0);

  const handleClick = () => {
    setCount(count + 1);
  };

  // Throw error when count reaches 5
  if (count === 5) {
    throw new Error('Count reached 5! This is a simulated error.');
  }

  return (
    <div className="text-center p-4">
      <h3 className="text-lg font-semibold mb-2">Buggy Counter</h3>
      <p className="text-muted-foreground mb-4">
        Click the button. An error will occur at count 5.
      </p>
      <div className="text-3xl font-bold mb-4">{count}</div>
      <Button onClick={handleClick}>
        Increment (Current: {count})
      </Button>
    </div>
  );
}

// Component that handles async errors
function AsyncErrorExample() {
  const { runAsync } = useAsyncErrorHandler();
  const [loading, setLoading] = useState(false);

  const simulateAsyncError = async () => {
    setLoading(true);
    await runAsync(async () => {
      // Simulate async operation
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      // Simulate error
      throw new Error('Async operation failed! This error will be caught by the Error Boundary.');
    });
    setLoading(false);
  };

  return (
    <div className="text-center p-4">
      <h3 className="text-lg font-semibold mb-2">Async Error Example</h3>
      <p className="text-muted-foreground mb-4">
        Click to simulate an async error that will be caught by the Error Boundary.
      </p>
      <Button 
        onClick={simulateAsyncError}
        loading={loading}
        variant="destructive"
      >
        Trigger Async Error
      </Button>
    </div>
  );
}

// Main example component
export function ErrorBoundaryExample() {
  const [showBuggy, setShowBuggy] = useState(false);
  const [resetKey, setResetKey] = useState(0);

  const resetErrorBoundary = () => {
    setResetKey(prev => prev + 1);
    setShowBuggy(false);
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Error Boundary Examples</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Example 1: Component-level error boundary */}
          <div>
            <h3 className="text-lg font-semibold mb-3">1. Component Error Boundary</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardContent className="pt-6">
                  <ErrorBoundary
                    level="component"
                    resetKeys={[resetKey]}
                    showDetails={true}
                  >
                    {showBuggy ? (
                      <BuggyCounter />
                    ) : (
                      <div className="text-center p-4">
                        <p className="text-muted-foreground mb-4">
                          Click to mount a component that will error.
                        </p>
                        <Button onClick={() => setShowBuggy(true)}>
                          Show Buggy Component
                        </Button>
                      </div>
                    )}
                  </ErrorBoundary>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="p-4 bg-muted rounded-lg">
                    <h4 className="font-medium mb-2">How it works:</h4>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li>• Component is wrapped in ErrorBoundary</li>
                      <li>• Errors are caught and displayed inline</li>
                      <li>• Component can be reset with resetKeys</li>
                      <li>• Other parts of the app continue working</li>
                    </ul>
                  </div>
                  {showBuggy && (
                    <Button 
                      onClick={resetErrorBoundary}
                      variant="outline"
                      className="mt-4 w-full"
                    >
                      Reset Example
                    </Button>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Example 2: Async error boundary */}
          <div>
            <h3 className="text-lg font-semibold mb-3">2. Async Error Handling</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardContent className="pt-6">
                  <SectionAsyncBoundary
                    title="Loading async component..."
                    errorBoundaryProps={{
                      showDetails: true,
                    }}
                  >
                    <AsyncErrorExample />
                  </SectionAsyncBoundary>
                </CardContent>
              </Card>

              <Card>
                <CardContent className="pt-6">
                  <div className="p-4 bg-muted rounded-lg">
                    <h4 className="font-medium mb-2">Async boundaries:</h4>
                    <ul className="text-sm text-muted-foreground space-y-1">
                      <li>• Combines Suspense with ErrorBoundary</li>
                      <li>• Shows loading states automatically</li>
                      <li>• Catches async errors properly</li>
                      <li>• Handles promise rejections</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Best practices */}
          <div className="mt-8 p-4 bg-primary/5 rounded-lg">
            <div className="flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 text-primary mt-0.5" />
              <div>
                <h4 className="font-medium mb-2">Best Practices:</h4>
                <ul className="text-sm text-muted-foreground space-y-1">
                  <li>• Use page-level boundaries for critical errors</li>
                  <li>• Use section-level boundaries for feature isolation</li>
                  <li>• Use component-level boundaries for non-critical UI</li>
                  <li>• Always provide meaningful error messages</li>
                  <li>• Log errors to monitoring services in production</li>
                  <li>• Test error boundaries during development</li>
                </ul>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}