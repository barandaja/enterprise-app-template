import React, { useState } from 'react';
import { cn } from '../utils';

export type AlertType = 'success' | 'error' | 'warning' | 'info';

export interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  type?: AlertType;
  title?: string;
  description?: string;
  dismissible?: boolean;
  onDismiss?: () => void;
  icon?: React.ReactNode;
  children?: React.ReactNode;
}

// Default icons for each alert type
const AlertIcon = ({ type, customIcon }: { type: AlertType; customIcon?: React.ReactNode }) => {
  if (customIcon) return <>{customIcon}</>;

  const iconProps = { className: "h-4 w-4", strokeWidth: 2 };

  switch (type) {
    case 'success':
      return (
        <svg {...iconProps} viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M9 12l2 2 4-4" />
          <circle cx="12" cy="12" r="10" />
        </svg>
      );
    case 'error':
      return (
        <svg {...iconProps} viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <circle cx="12" cy="12" r="10" />
          <line x1="15" y1="9" x2="9" y2="15" />
          <line x1="9" y1="9" x2="15" y2="15" />
        </svg>
      );
    case 'warning':
      return (
        <svg {...iconProps} viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" />
          <line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      );
    case 'info':
    default:
      return (
        <svg {...iconProps} viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="16" x2="12" y2="12" />
          <line x1="12" y1="8" x2="12.01" y2="8" />
        </svg>
      );
  }
};

const alertVariants = {
  success: 'alert-success',
  error: 'alert-destructive',
  warning: 'alert-warning',
  info: 'alert-info'
};

export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ 
    className, 
    type = 'info',
    title,
    description,
    dismissible = false,
    onDismiss,
    icon,
    children,
    ...props 
  }, ref) => {
    const [isVisible, setIsVisible] = useState(true);

    const handleDismiss = () => {
      setIsVisible(false);
      onDismiss?.();
    };

    if (!isVisible) return null;

    return (
      <div
        ref={ref}
        role="alert"
        className={cn(
          'alert',
          alertVariants[type],
          'transition-all duration-200 ease-in-out',
          className
        )}
        {...props}
      >
        <div className="flex">
          <div className="flex-shrink-0">
            <AlertIcon type={type} customIcon={icon} />
          </div>
          
          <div className="ml-3 flex-1">
            {title && (
              <div className="alert-title">
                {title}
              </div>
            )}
            
            {description && (
              <div className={cn(
                'alert-description',
                title && 'mt-1'
              )}>
                {description}
              </div>
            )}
            
            {children && (
              <div className={cn(
                'text-sm',
                (title || description) && 'mt-2'
              )}>
                {children}
              </div>
            )}
          </div>

          {dismissible && (
            <div className="ml-auto pl-3">
              <button
                type="button"
                onClick={handleDismiss}
                className={cn(
                  'inline-flex rounded-md p-1.5 transition-colors',
                  'hover:bg-black/10 focus:outline-none focus:ring-2 focus:ring-offset-2',
                  'dark:hover:bg-white/10',
                  type === 'success' && 'text-success hover:bg-success/10 focus:ring-success',
                  type === 'error' && 'text-destructive hover:bg-destructive/10 focus:ring-destructive',
                  type === 'warning' && 'text-warning hover:bg-warning/10 focus:ring-warning',
                  type === 'info' && 'text-info hover:bg-info/10 focus:ring-info'
                )}
                aria-label="Dismiss alert"
              >
                <svg className="h-4 w-4" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
                </svg>
              </button>
            </div>
          )}
        </div>
      </div>
    );
  }
);

Alert.displayName = 'Alert';

// Convenience components for specific alert types
export const SuccessAlert: React.FC<Omit<AlertProps, 'type'>> = (props) => (
  <Alert type="success" {...props} />
);

export const ErrorAlert: React.FC<Omit<AlertProps, 'type'>> = (props) => (
  <Alert type="error" {...props} />
);

export const WarningAlert: React.FC<Omit<AlertProps, 'type'>> = (props) => (
  <Alert type="warning" {...props} />
);

export const InfoAlert: React.FC<Omit<AlertProps, 'type'>> = (props) => (
  <Alert type="info" {...props} />
);

// Alert with custom content
export interface AlertContentProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export const AlertContent = React.forwardRef<HTMLDivElement, AlertContentProps>(
  ({ className, children, ...props }, ref) => (
    <div
      ref={ref}
      className={cn('alert-description', className)}
      {...props}
    >
      {children}
    </div>
  )
);

AlertContent.displayName = 'AlertContent';

// Usage examples:
/*
// Basic alerts
<Alert type="success" title="Success!" description="Your changes have been saved." />
<Alert type="error" title="Error" description="Something went wrong. Please try again." />
<Alert type="warning" title="Warning" description="This action cannot be undone." />
<Alert type="info" title="Info" description="New updates are available." />

// Dismissible alert
<Alert 
  type="success" 
  title="Success!" 
  description="Your account has been created successfully."
  dismissible
  onDismiss={() => console.log('Alert dismissed')}
/>

// Alert with custom icon
<Alert 
  type="info"
  title="Custom Icon"
  description="This alert has a custom icon."
  icon={<CustomIcon className="h-4 w-4" />}
/>

// Alert with custom content
<Alert type="warning" title="Update Required">
  <AlertContent>
    <p>Your subscription will expire in 3 days.</p>
    <div className="mt-2">
      <Button size="sm" variant="outline">
        Renew Subscription
      </Button>
    </div>
  </AlertContent>
</Alert>

// Using convenience components
<SuccessAlert title="Success!" description="Operation completed successfully." />
<ErrorAlert title="Error" description="Failed to save changes." dismissible />

// Alert with children content
<Alert type="info" title="Welcome!">
  <p>Thanks for joining our platform. Here's what you can do next:</p>
  <ul className="list-disc list-inside mt-2 space-y-1">
    <li>Complete your profile</li>
    <li>Invite team members</li>
    <li>Explore features</li>
  </ul>
</Alert>
*/