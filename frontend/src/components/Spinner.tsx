import React from 'react';
import { cn } from '../utils';

export type SpinnerSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

export interface SpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: SpinnerSize;
  color?: string;
  strokeWidth?: number;
  label?: string;
}

const spinnerSizes = {
  xs: 'h-3 w-3',
  sm: 'h-4 w-4',
  md: 'h-6 w-6',
  lg: 'h-8 w-8',
  xl: 'h-12 w-12'
};

const spinnerStrokeWidths = {
  xs: 2,
  sm: 2,
  md: 2,
  lg: 2.5,
  xl: 3
};

export const Spinner = React.forwardRef<HTMLDivElement, SpinnerProps>(
  ({ 
    className, 
    size = 'md',
    color,
    strokeWidth,
    label = 'Loading...',
    ...props 
  }, ref) => {
    const finalStrokeWidth = strokeWidth || spinnerStrokeWidths[size];

    return (
      <div
        ref={ref}
        role="status"
        aria-label={label}
        className={cn('inline-flex items-center justify-center', className)}
        {...props}
      >
        <svg
          className={cn(
            'animate-spin',
            spinnerSizes[size],
            color ? `text-${color}` : 'text-current'
          )}
          fill="none"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
        >
          <circle
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth={finalStrokeWidth}
            className="opacity-25"
          />
          <path
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            className="opacity-75"
          />
        </svg>
        <span className="sr-only">{label}</span>
      </div>
    );
  }
);

Spinner.displayName = 'Spinner';

// Dots spinner variant
export interface DotsSpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: SpinnerSize;
  color?: string;
  label?: string;
}

export const DotsSpinner = React.forwardRef<HTMLDivElement, DotsSpinnerProps>(
  ({ 
    className, 
    size = 'md',
    color,
    label = 'Loading...',
    ...props 
  }, ref) => {
    const dotSizes = {
      xs: 'h-1 w-1',
      sm: 'h-1.5 w-1.5',
      md: 'h-2 w-2',
      lg: 'h-2.5 w-2.5',
      xl: 'h-3 w-3'
    };

    return (
      <div
        ref={ref}
        role="status"
        aria-label={label}
        className={cn('inline-flex items-center space-x-1', className)}
        {...props}
      >
        {[0, 1, 2].map((index) => (
          <div
            key={index}
            className={cn(
              'rounded-full animate-pulse',
              dotSizes[size],
              color ? `bg-${color}` : 'bg-current'
            )}
            style={{
              animationDelay: `${index * 0.15}s`,
              animationDuration: '0.6s'
            }}
          />
        ))}
        <span className="sr-only">{label}</span>
      </div>
    );
  }
);

DotsSpinner.displayName = 'DotsSpinner';

// Pulse spinner variant
export interface PulseSpinnerProps extends React.HTMLAttributes<HTMLDivElement> {
  size?: SpinnerSize;
  color?: string;
  label?: string;
}

export const PulseSpinner = React.forwardRef<HTMLDivElement, PulseSpinnerProps>(
  ({ 
    className, 
    size = 'md',
    color,
    label = 'Loading...',
    ...props 
  }, ref) => {
    return (
      <div
        ref={ref}
        role="status"
        aria-label={label}
        className={cn('inline-flex', className)}
        {...props}
      >
        <div
          className={cn(
            'rounded-full animate-ping',
            spinnerSizes[size],
            color ? `bg-${color}` : 'bg-current opacity-75'
          )}
        />
        <span className="sr-only">{label}</span>
      </div>
    );
  }
);

PulseSpinner.displayName = 'PulseSpinner';

// Loading overlay component
export interface LoadingOverlayProps extends React.HTMLAttributes<HTMLDivElement> {
  isLoading: boolean;
  children?: React.ReactNode;
  spinner?: React.ReactNode;
  text?: string;
  backdrop?: boolean;
  size?: SpinnerSize;
}

export const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  children,
  spinner,
  text = 'Loading...',
  backdrop = true,
  size = 'lg',
  className,
  ...props
}) => {
  if (!isLoading) return <>{children}</>;

  return (
    <div className={cn('relative', className)} {...props}>
      {children}
      
      {/* Loading overlay */}
      <div
        className={cn(
          'absolute inset-0 flex flex-col items-center justify-center z-10',
          backdrop && 'bg-background/80 backdrop-blur-sm'
        )}
      >
        {spinner || <Spinner size={size} />}
        {text && (
          <p className="mt-3 text-sm text-muted-foreground font-medium">
            {text}
          </p>
        )}
      </div>
    </div>
  );
};

// Inline loading component
export interface InlineLoadingProps {
  text?: string;
  size?: SpinnerSize;
  className?: string;
}

export const InlineLoading: React.FC<InlineLoadingProps> = ({
  text = 'Loading...',
  size = 'sm',
  className
}) => (
  <div className={cn('inline-flex items-center gap-2', className)}>
    <Spinner size={size} />
    <span className="text-sm text-muted-foreground">{text}</span>
  </div>
);

// Usage examples:
/*
// Basic spinner
<Spinner />
<Spinner size="lg" />
<Spinner size="sm" color="primary" />

// Different spinner variants
<DotsSpinner />
<PulseSpinner size="lg" />

// Custom spinner with label
<Spinner size="xl" label="Processing your request..." />

// Loading overlay
<LoadingOverlay isLoading={isLoading} text="Saving changes...">
  <div className="p-6">
    <h2>Content that gets overlaid</h2>
    <p>This content will be shown with a loading overlay when isLoading is true.</p>
  </div>
</LoadingOverlay>

// Inline loading
<InlineLoading text="Fetching data..." />

// In buttons (already integrated in Button component)
<Button loading>Save Changes</Button>

// Custom spinner in button
<Button 
  disabled={isLoading}
  leftIcon={isLoading ? <DotsSpinner size="xs" /> : undefined}
>
  {isLoading ? 'Processing...' : 'Submit'}
</Button>

// Loading states in cards
<Card>
  <CardContent className="p-6">
    {isLoading ? (
      <div className="flex items-center justify-center py-8">
        <Spinner size="lg" />
      </div>
    ) : (
      <div>Your content here</div>
    )}
  </CardContent>
</Card>

// Loading overlay without backdrop
<LoadingOverlay 
  isLoading={isLoading} 
  backdrop={false}
  spinner={<PulseSpinner size="xl" />}
  text="Custom loading message"
>
  <YourComponent />
</LoadingOverlay>
*/