import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { cn } from '../utils';
import { useThemeWithActions } from '../stores/themeStore';
import type { Theme } from '../types';

// =============================================================================
// THEME TOGGLE COMPONENT INTERFACES
// =============================================================================

interface ThemeToggleProps {
  /** Size variant for the toggle */
  size?: 'sm' | 'md' | 'lg';
  /** Visual variant */
  variant?: 'default' | 'subtle' | 'outline';
  /** Whether to show theme labels */
  showLabels?: boolean;
  /** Whether to include system theme option */
  includeSystem?: boolean;
  /** Whether to show as dropdown or button group */
  layout?: 'dropdown' | 'buttons' | 'compact';
  /** Custom class name */
  className?: string;
  /** Tooltip position */
  tooltipPosition?: 'top' | 'bottom' | 'left' | 'right';
}

interface ThemeOption {
  value: Theme;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}

// =============================================================================
// THEME OPTIONS CONFIGURATION
// =============================================================================

const themeOptions: ThemeOption[] = [
  {
    value: 'light',
    label: 'Light',
    icon: Sun,
    description: 'Light theme for bright environments'
  },
  {
    value: 'dark',
    label: 'Dark',
    icon: Moon,
    description: 'Dark theme for low-light environments'
  },
  {
    value: 'system',
    label: 'System',
    icon: Monitor,
    description: 'Follow system preference'
  }
];

// =============================================================================
// THEME TOGGLE VARIANTS
// =============================================================================

const sizeVariants = {
  sm: {
    button: 'h-8 w-8 text-xs',
    icon: 'h-3 w-3',
    text: 'text-xs',
    padding: 'p-1.5'
  },
  md: {
    button: 'h-10 w-10 text-sm',
    icon: 'h-4 w-4',
    text: 'text-sm',
    padding: 'p-2'
  },
  lg: {
    button: 'h-12 w-12 text-base',
    icon: 'h-5 w-5',
    text: 'text-base',
    padding: 'p-3'
  }
};

const variantStyles = {
  default: {
    button: 'bg-background hover:bg-muted border border-border shadow-sm',
    active: 'bg-primary text-primary-foreground shadow-md'
  },
  subtle: {
    button: 'bg-transparent hover:bg-muted/50',
    active: 'bg-muted text-foreground'
  },
  outline: {
    button: 'bg-transparent border border-border hover:bg-muted',
    active: 'bg-primary text-primary-foreground border-primary'
  }
};

// =============================================================================
// COMPACT THEME TOGGLE COMPONENT
// =============================================================================

interface CompactThemeToggleProps extends Omit<ThemeToggleProps, 'layout'> {}

function CompactThemeToggle({
  size = 'md',
  variant = 'default',
  className,
  tooltipPosition = 'bottom'
}: CompactThemeToggleProps) {
  const { theme, resolvedTheme, toggleTheme } = useThemeWithActions();
  
  const sizeConfig = sizeVariants[size];
  const variantConfig = variantStyles[variant];
  
  // Get current theme display info
  const currentOption = themeOptions.find(option => option.value === theme) || themeOptions[0];
  const CurrentIcon = currentOption.icon;
  
  const handleToggle = () => {
    toggleTheme();
  };

  return (
    <div className="relative group">
      <button
        onClick={handleToggle}
        className={cn(
          'relative rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:ring-offset-2',
          sizeConfig.button,
          sizeConfig.padding,
          variantConfig.button,
          'hover:scale-105 active:scale-95',
          className
        )}
        aria-label={`Switch to ${theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light'} theme`}
        title={currentOption.description}
      >
        <CurrentIcon className={cn('transition-all duration-200', sizeConfig.icon)} />
        
        {/* Theme indicator */}
        <div className={cn(
          'absolute -top-1 -right-1 w-2 h-2 rounded-full border border-background',
          resolvedTheme === 'dark' ? 'bg-blue-500' : 'bg-yellow-500'
        )} />
      </button>
      
      {/* Tooltip */}
      <div className={cn(
        'absolute z-50 px-2 py-1 bg-popover text-popover-foreground text-xs rounded-md shadow-md border opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap',
        {
          'bottom-full mb-2 left-1/2 -translate-x-1/2': tooltipPosition === 'top',
          'top-full mt-2 left-1/2 -translate-x-1/2': tooltipPosition === 'bottom',
          'right-full mr-2 top-1/2 -translate-y-1/2': tooltipPosition === 'left',
          'left-full ml-2 top-1/2 -translate-y-1/2': tooltipPosition === 'right',
        }
      )}>
        {currentOption.label} theme
      </div>
    </div>
  );
}

// =============================================================================
// BUTTON GROUP THEME TOGGLE COMPONENT
// =============================================================================

interface ButtonGroupThemeToggleProps extends Omit<ThemeToggleProps, 'layout'> {}

function ButtonGroupThemeToggle({
  size = 'md',
  variant = 'default',
  showLabels = false,
  includeSystem = true,
  className
}: ButtonGroupThemeToggleProps) {
  const { theme, setTheme } = useThemeWithActions();
  
  const sizeConfig = sizeVariants[size];
  const variantConfig = variantStyles[variant];
  
  const availableOptions = includeSystem ? themeOptions : themeOptions.slice(0, 2);

  return (
    <div className={cn(
      'inline-flex rounded-lg border border-border bg-background p-1 shadow-sm',
      className
    )}>
      {availableOptions.map((option, index) => {
        const Icon = option.icon;
        const isActive = theme === option.value;
        
        return (
          <button
            key={option.value}
            onClick={() => setTheme(option.value)}
            className={cn(
              'inline-flex items-center justify-center rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:ring-offset-1',
              sizeConfig.padding,
              showLabels ? 'px-3 gap-2' : sizeConfig.button,
              isActive 
                ? cn(variantConfig.active, 'shadow-sm') 
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
            )}
            aria-label={`Switch to ${option.label.toLowerCase()} theme`}
            title={option.description}
          >
            <Icon className={sizeConfig.icon} />
            {showLabels && (
              <span className={sizeConfig.text}>{option.label}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}

// =============================================================================
// DROPDOWN THEME TOGGLE COMPONENT
// =============================================================================

interface DropdownThemeToggleProps extends Omit<ThemeToggleProps, 'layout'> {}

function DropdownThemeToggle({
  size = 'md',
  variant = 'default',
  includeSystem = true,
  className
}: DropdownThemeToggleProps) {
  const { theme, resolvedTheme, setTheme } = useThemeWithActions();
  const [isOpen, setIsOpen] = React.useState(false);
  const dropdownRef = React.useRef<HTMLDivElement>(null);
  
  const sizeConfig = sizeVariants[size];
  const variantConfig = variantStyles[variant];
  
  const currentOption = themeOptions.find(option => option.value === theme) || themeOptions[0];
  const CurrentIcon = currentOption.icon;
  const availableOptions = includeSystem ? themeOptions : themeOptions.slice(0, 2);

  // Close dropdown when clicking outside
  React.useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [isOpen]);

  // Close dropdown on escape key
  React.useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setIsOpen(false);
      }
    }

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    }
  }, [isOpen]);

  const handleOptionSelect = (selectedTheme: Theme) => {
    setTheme(selectedTheme);
    setIsOpen(false);
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          'relative inline-flex items-center gap-2 rounded-md transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:ring-offset-2',
          sizeConfig.padding,
          variantConfig.button,
          'hover:scale-105 active:scale-95',
          className
        )}
        aria-label="Theme selector"
        aria-expanded={isOpen}
        aria-haspopup="menu"
      >
        <CurrentIcon className={sizeConfig.icon} />
        <span className={cn('capitalize', sizeConfig.text)}>{currentOption.label}</span>
        
        {/* Dropdown arrow */}
        <svg
          className={cn(
            'transition-transform duration-200',
            sizeConfig.icon,
            isOpen && 'rotate-180'
          )}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
        
        {/* Theme indicator */}
        <div className={cn(
          'absolute -top-1 -right-1 w-2 h-2 rounded-full border border-background',
          resolvedTheme === 'dark' ? 'bg-blue-500' : 'bg-yellow-500'
        )} />
      </button>

      {/* Dropdown menu */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-48 bg-popover border border-border rounded-md shadow-lg z-50 py-1">
          {availableOptions.map((option) => {
            const Icon = option.icon;
            const isActive = theme === option.value;
            
            return (
              <button
                key={option.value}
                onClick={() => handleOptionSelect(option.value)}
                className={cn(
                  'w-full flex items-center gap-3 px-3 py-2 text-left transition-colors duration-150',
                  'hover:bg-muted focus:bg-muted focus:outline-none',
                  isActive && 'bg-muted text-primary font-medium'
                )}
                role="menuitem"
              >
                <Icon className="h-4 w-4" />
                <div className="flex-1">
                  <div className="text-sm font-medium">{option.label}</div>
                  <div className="text-xs text-muted-foreground">{option.description}</div>
                </div>
                {isActive && (
                  <div className="h-2 w-2 rounded-full bg-primary" />
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// =============================================================================
// MAIN THEME TOGGLE COMPONENT
// =============================================================================

/**
 * Versatile theme toggle component that supports multiple layouts and configurations.
 * 
 * Features:
 * - Multiple layout options: compact, button group, dropdown
 * - Configurable sizes and variants
 * - Accessibility compliant with ARIA labels and keyboard navigation
 * - System theme detection support
 * - Smooth animations and transitions
 * - Integration with theme store
 * 
 * @example
 * ```tsx
 * // Compact toggle button (default)
 * <ThemeToggle />
 * 
 * // Button group with labels
 * <ThemeToggle layout="buttons" showLabels />
 * 
 * // Dropdown with system option
 * <ThemeToggle layout="dropdown" includeSystem />
 * ```
 */
export function ThemeToggle({
  layout = 'compact',
  ...props
}: ThemeToggleProps) {
  switch (layout) {
    case 'buttons':
      return <ButtonGroupThemeToggle {...props} />;
    case 'dropdown':
      return <DropdownThemeToggle {...props} />;
    case 'compact':
    default:
      return <CompactThemeToggle {...props} />;
  }
}

// =============================================================================
// ADDITIONAL UTILITY COMPONENTS
// =============================================================================

/**
 * Simple theme toggle hook for custom implementations
 */
export function useThemeToggle() {
  const { theme, resolvedTheme, setTheme, toggleTheme } = useThemeWithActions();
  
  return {
    theme,
    resolvedTheme,
    setTheme,
    toggleTheme,
    isLight: resolvedTheme === 'light',
    isDark: resolvedTheme === 'dark',
    isSystem: theme === 'system'
  };
}

/**
 * Theme-aware icon component that changes based on current theme
 */
export function ThemeIcon({ 
  className, 
  size = 'md' 
}: { 
  className?: string; 
  size?: 'sm' | 'md' | 'lg' 
}) {
  const { theme } = useThemeWithActions();
  const sizeConfig = sizeVariants[size];
  
  const currentOption = themeOptions.find(option => option.value === theme) || themeOptions[0];
  const Icon = currentOption.icon;
  
  return <Icon className={cn(sizeConfig.icon, className)} />;
}

export default ThemeToggle;