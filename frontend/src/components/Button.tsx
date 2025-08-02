import React from 'react';
import { cn } from '../utils';

// Button variant types
export type ButtonVariant = 'primary' | 'secondary' | 'destructive' | 'outline' | 'ghost' | 'link';
export type ButtonSize = 'sm' | 'md' | 'lg';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
  children: React.ReactNode;
  asChild?: boolean;
}

const buttonVariants = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  destructive: 'btn-destructive',
  outline: 'btn-outline',
  ghost: 'btn-ghost',
  link: 'underline-offset-4 hover:underline text-primary p-0 h-auto font-medium'
};

const buttonSizes = {
  sm: 'btn-sm text-xs',
  md: 'h-10 px-4 py-2',
  lg: 'btn-lg text-base'
};

const Spinner = ({ size = 16 }: { size?: number }) => (
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
    ...props 
  }, ref) => {
    const isDisabled = disabled || loading;

    return (
      <button
        className={cn(
          'btn',
          variant !== 'link' && buttonVariants[variant],
          variant === 'link' && buttonVariants.link,
          variant !== 'link' && buttonSizes[size],
          className
        )}
        ref={ref}
        disabled={isDisabled}
        aria-disabled={isDisabled}
        {...props}
      >
        {loading && <Spinner size={size === 'sm' ? 14 : size === 'lg' ? 20 : 16} />}
        {!loading && leftIcon && <span className="inline-flex">{leftIcon}</span>}
        <span className={cn(loading && 'opacity-0')}>{children}</span>
        {!loading && rightIcon && <span className="inline-flex">{rightIcon}</span>}
      </button>
    );
  }
);

Button.displayName = 'Button';

// Usage examples:
/*
// Basic usage
<Button>Click me</Button>

// With variants
<Button variant="secondary">Secondary</Button>
<Button variant="destructive">Delete</Button>
<Button variant="outline">Outline</Button>
<Button variant="ghost">Ghost</Button>
<Button variant="link">Link</Button>

// With sizes
<Button size="sm">Small</Button>
<Button size="lg">Large</Button>

// With loading state
<Button loading>Loading...</Button>

// With icons
<Button leftIcon={<PlusIcon />}>Add Item</Button>
<Button rightIcon={<ArrowRightIcon />}>Continue</Button>

// Disabled
<Button disabled>Disabled</Button>
*/