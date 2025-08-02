import React from 'react';
import { cn } from '../utils';

// Button variant types - expanded for enterprise use
export type ButtonVariant = 
  | 'primary' 
  | 'secondary' 
  | 'destructive' 
  | 'outline' 
  | 'ghost' 
  | 'link'
  | 'success'
  | 'warning'
  | 'info';

export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg' | 'xl';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  children: React.ReactNode;
  asChild?: boolean;
  fullWidth?: boolean;
  rounded?: boolean;
  pulse?: boolean;
  badge?: string | number;
  tooltip?: string;
}

const buttonVariants = {
  primary: 'bg-primary-600 text-white hover:bg-primary-700 focus:ring-primary-500 dark:bg-primary-500 dark:hover:bg-primary-600',
  secondary: 'bg-gray-100 text-gray-900 hover:bg-gray-200 focus:ring-gray-500 dark:bg-gray-800 dark:text-gray-100 dark:hover:bg-gray-700',
  destructive: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500 dark:bg-red-500 dark:hover:bg-red-600',
  outline: 'border border-gray-300 bg-transparent text-gray-700 hover:bg-gray-50 focus:ring-gray-500 dark:border-gray-600 dark:text-gray-300 dark:hover:bg-gray-800',
  ghost: 'bg-transparent text-gray-700 hover:bg-gray-100 focus:ring-gray-500 dark:text-gray-300 dark:hover:bg-gray-800',
  link: 'bg-transparent text-primary-600 hover:text-primary-700 underline-offset-4 hover:underline p-0 h-auto font-medium focus:ring-primary-500 dark:text-primary-400 dark:hover:text-primary-300',
  success: 'bg-green-600 text-white hover:bg-green-700 focus:ring-green-500 dark:bg-green-500 dark:hover:bg-green-600',
  warning: 'bg-yellow-600 text-white hover:bg-yellow-700 focus:ring-yellow-500 dark:bg-yellow-500 dark:hover:bg-yellow-600',
  info: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500 dark:bg-blue-500 dark:hover:bg-blue-600'
};

const buttonSizes = {
  xs: 'h-6 px-2 text-xs',
  sm: 'h-8 px-3 text-sm',
  md: 'h-10 px-4 text-sm',
  lg: 'h-11 px-6 text-base',
  xl: 'h-12 px-8 text-lg'
};

const LoadingSpinner = ({ size = 16 }: { size?: number }) => (
  <svg
    className="animate-spin"
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
  >
    <circle
      cx="12"
      cy="12"
      r="10"
      stroke="currentColor"
      strokeWidth="4"
      className="opacity-25"
    />
    <path
      fill="currentColor"
      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      className="opacity-75"
    />
  </svg>
);

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ 
    className, 
    variant = 'primary', 
    size = 'md', 
    loading = false,
    leftIcon,
    rightIcon,
    disabled,
    children,
    asChild = false,
    fullWidth = false,
    rounded = false,
    pulse = false,
    badge,
    tooltip,
    ...props 
  }, ref) => {
    const isDisabled = disabled || loading;
    
    const spinnerSizes = {
      xs: 12,
      sm: 14,
      md: 16,
      lg: 18,
      xl: 20
    };

    const buttonContent = (
      <>
        {loading && <LoadingSpinner size={spinnerSizes[size]} />}
        {!loading && leftIcon && (
          <span className="inline-flex items-center justify-center">
            {leftIcon}
          </span>
        )}
        <span className={cn(
          'inline-flex items-center justify-center',
          loading && 'opacity-0'
        )}>
          {children}
        </span>
        {!loading && rightIcon && (
          <span className="inline-flex items-center justify-center">
            {rightIcon}
          </span>
        )}
        {badge && (
          <span className="absolute -top-1 -right-1 inline-flex items-center justify-center px-1.5 py-0.5 text-xs font-bold leading-none text-white bg-red-600 rounded-full">
            {badge}
          </span>
        )}
      </>
    );

    const buttonElement = (
      <button
        className={cn(
          // Base styles
          'relative inline-flex items-center justify-center gap-2 font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:pointer-events-none disabled:opacity-50',
          // Size-specific styles
          variant !== 'link' && buttonSizes[size],
          // Variant-specific styles
          buttonVariants[variant],
          // Width styles
          fullWidth && 'w-full',
          // Border radius
          rounded ? 'rounded-full' : 'rounded-md',
          // Pulse animation
          pulse && 'animate-pulse',
          // Loading state
          loading && 'cursor-wait',
          // Custom className
          className
        )}
        ref={ref}
        disabled={isDisabled}
        aria-disabled={isDisabled}
        aria-label={tooltip}
        title={tooltip}
        {...props}
      >
        {buttonContent}
      </button>
    );

    return buttonElement;
  }
);

Button.displayName = 'Button';

// Button Group Component for related actions
export interface ButtonGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  orientation?: 'horizontal' | 'vertical';
  size?: ButtonSize;
  variant?: ButtonVariant;
  attached?: boolean;
}

export const ButtonGroup = React.forwardRef<HTMLDivElement, ButtonGroupProps>(
  ({ 
    className,
    children,
    orientation = 'horizontal',
    size,
    variant,
    attached = false,
    ...props
  }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'inline-flex',
          orientation === 'horizontal' ? 'flex-row' : 'flex-col',
          attached && orientation === 'horizontal' && '[&>*]:rounded-none [&>*:first-child]:rounded-l-md [&>*:last-child]:rounded-r-md [&>*]:border-r-0 [&>*:last-child]:border-r',
          attached && orientation === 'vertical' && '[&>*]:rounded-none [&>*:first-child]:rounded-t-md [&>*:last-child]:rounded-b-md [&>*]:border-b-0 [&>*:last-child]:border-b',
          !attached && 'gap-2',
          className
        )}
        role="group"
        {...props}
      >
        {React.Children.map(children, (child) => {
          if (React.isValidElement(child) && child.type === Button) {
            return React.cloneElement(child, {
              size: size || child.props.size,
              variant: variant || child.props.variant,
            });
          }
          return child;
        })}
      </div>
    );
  }
);

ButtonGroup.displayName = 'ButtonGroup';

// Icon Button for compact actions
export interface IconButtonProps extends Omit<ButtonProps, 'leftIcon' | 'rightIcon' | 'children'> {
  icon: React.ReactNode;
  'aria-label': string;
}

export const IconButton = React.forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ icon, className, size = 'md', ...props }, ref) => {
    return (
      <Button
        ref={ref}
        className={cn('aspect-square p-0', className)}
        size={size}
        {...props}
      >
        {icon}
      </Button>
    );
  }
);

IconButton.displayName = 'IconButton';

// Floating Action Button for primary actions
export interface FABProps extends Omit<ButtonProps, 'variant' | 'size'> {
  size?: 'sm' | 'md' | 'lg';
  position?: 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left';
  extended?: boolean;
}

export const FAB = React.forwardRef<HTMLButtonElement, FABProps>(
  ({ 
    className,
    size = 'md',
    position = 'bottom-right',
    extended = false,
    children,
    ...props
  }, ref) => {
    const fabSizes = {
      sm: 'h-12 w-12',
      md: 'h-14 w-14',
      lg: 'h-16 w-16'
    };

    const positions = {
      'bottom-right': 'fixed bottom-6 right-6',
      'bottom-left': 'fixed bottom-6 left-6',
      'top-right': 'fixed top-6 right-6',
      'top-left': 'fixed top-6 left-6'
    };

    return (
      <Button
        ref={ref}
        variant="primary"
        className={cn(
          'rounded-full shadow-lg hover:shadow-xl z-50',
          extended ? 'px-6' : fabSizes[size],
          positions[position],
          className
        )}
        {...props}
      >
        {children}
      </Button>
    );
  }
);

FAB.displayName = 'FAB';

// Usage examples and exports
export type { ButtonProps, ButtonGroupProps, IconButtonProps, FABProps };

/*
Usage Examples:

// Basic Button
<Button>Click me</Button>

// With variants
<Button variant="destructive">Delete</Button>
<Button variant="outline">Cancel</Button>
<Button variant="success">Save</Button>

// With loading state
<Button loading>Saving...</Button>

// With icons
<Button leftIcon={<PlusIcon />}>Add Item</Button>
<Button rightIcon={<ArrowRightIcon />}>Continue</Button>

// Full width
<Button fullWidth>Submit Form</Button>

// With badge
<Button badge={5}>Messages</Button>

// Button Group
<ButtonGroup attached>
  <Button>Left</Button>
  <Button>Center</Button>
  <Button>Right</Button>
</ButtonGroup>

// Icon Button
<IconButton 
  icon={<TrashIcon />} 
  aria-label="Delete item"
  variant="destructive" 
/>

// Floating Action Button
<FAB position="bottom-right">
  <PlusIcon />
</FAB>

// Extended FAB
<FAB extended leftIcon={<EditIcon />}>
  Edit
</FAB>
*/