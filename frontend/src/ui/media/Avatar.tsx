import React from 'react';
import { cn } from '../../utils';

export interface AvatarProps extends React.HTMLAttributes<HTMLDivElement> {
  src?: string;
  alt?: string;
  name?: string;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  variant?: 'circular' | 'rounded' | 'square';
  showBorder?: boolean;
  borderColor?: string;
  fallbackIcon?: React.ReactNode;
  loading?: 'eager' | 'lazy';
  onError?: () => void;
  status?: 'online' | 'offline' | 'away' | 'busy';
  statusPosition?: 'top-right' | 'bottom-right' | 'top-left' | 'bottom-left';
}

const generateInitials = (name: string, maxLength: number = 2): string => {
  if (!name) return '';
  
  return name
    .split(' ')
    .map(word => word.charAt(0).toUpperCase())
    .slice(0, maxLength)
    .join('');
};

const generateColorFromName = (name: string): string => {
  const colors = [
    'bg-red-500', 'bg-orange-500', 'bg-amber-500', 'bg-yellow-500',
    'bg-lime-500', 'bg-green-500', 'bg-emerald-500', 'bg-teal-500',
    'bg-cyan-500', 'bg-sky-500', 'bg-blue-500', 'bg-indigo-500',
    'bg-violet-500', 'bg-purple-500', 'bg-fuchsia-500', 'bg-pink-500',
    'bg-rose-500'
  ];
  
  if (!name) return colors[0];
  
  const hash = name
    .split('')
    .reduce((acc, char) => char.charCodeAt(0) + acc, 0);
    
  return colors[hash % colors.length];
};

export const Avatar = React.forwardRef<HTMLDivElement, AvatarProps>(
  ({
    src,
    alt,
    name = '',
    size = 'md',
    variant = 'circular',
    showBorder = false,
    borderColor = 'border-white dark:border-gray-800',
    fallbackIcon,
    loading = 'lazy',
    onError,
    status,
    statusPosition = 'bottom-right',
    className,
    ...props
  }, ref) => {
    const [imageError, setImageError] = React.useState(false);
    const [imageLoaded, setImageLoaded] = React.useState(false);

    const handleImageError = () => {
      setImageError(true);
      onError?.();
    };

    const handleImageLoad = () => {
      setImageLoaded(true);
    };

    const sizeClasses = {
      xs: 'h-6 w-6 text-xs',
      sm: 'h-8 w-8 text-sm',
      md: 'h-10 w-10 text-sm',
      lg: 'h-12 w-12 text-base',
      xl: 'h-16 w-16 text-lg',
      '2xl': 'h-20 w-20 text-xl'
    };

    const variantClasses = {
      circular: 'rounded-full',
      rounded: 'rounded-lg',
      square: 'rounded-none'
    };

    const statusSizes = {
      xs: 'h-1.5 w-1.5',
      sm: 'h-2 w-2',
      md: 'h-2.5 w-2.5',
      lg: 'h-3 w-3',
      xl: 'h-3.5 w-3.5',
      '2xl': 'h-4 w-4'
    };

    const statusColors = {
      online: 'bg-green-400',
      offline: 'bg-gray-400',
      away: 'bg-yellow-400',
      busy: 'bg-red-400'
    };

    const statusPositions = {
      'top-right': 'top-0 right-0',
      'bottom-right': 'bottom-0 right-0',
      'top-left': 'top-0 left-0',
      'bottom-left': 'bottom-0 left-0'
    };

    const initials = generateInitials(name);
    const fallbackBgColor = generateColorFromName(name);
    const showImage = src && !imageError;
    const showInitials = !showImage && initials;
    const showFallbackIcon = !showImage && !showInitials && fallbackIcon;

    return (
      <div
        ref={ref}
        className={cn(
          'relative inline-flex items-center justify-center overflow-hidden bg-gray-100 dark:bg-gray-700',
          sizeClasses[size],
          variantClasses[variant],
          showBorder && `border-2 ${borderColor}`,
          !showImage && fallbackBgColor,
          className
        )}
        {...props}
      >
        {/* Image */}
        {showImage && (
          <img
            src={src}
            alt={alt || name}
            loading={loading}
            onError={handleImageError}
            onLoad={handleImageLoad}
            className={cn(
              'h-full w-full object-cover transition-opacity duration-300',
              variantClasses[variant],
              imageLoaded ? 'opacity-100' : 'opacity-0'
            )}
          />
        )}

        {/* Initials */}
        {showInitials && (
          <span className="font-medium text-white select-none">
            {initials}
          </span>
        )}

        {/* Fallback Icon */}
        {showFallbackIcon && (
          <span className="text-gray-400 dark:text-gray-500">
            {fallbackIcon}
          </span>
        )}

        {/* Default User Icon */}
        {!showImage && !showInitials && !showFallbackIcon && (
          <svg
            className="h-1/2 w-1/2 text-gray-400 dark:text-gray-500"
            fill="currentColor"
            viewBox="0 0 20 20"
          >
            <path
              fillRule="evenodd"
              d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z"
              clipRule="evenodd"
            />
          </svg>
        )}

        {/* Status Indicator */}
        {status && (
          <span
            className={cn(
              'absolute rounded-full ring-2 ring-white dark:ring-gray-800',
              statusSizes[size],
              statusColors[status],
              statusPositions[statusPosition]
            )}
            aria-label={`Status: ${status}`}
          />
        )}

        {/* Loading State */}
        {showImage && !imageLoaded && !imageError && (
          <div className="absolute inset-0 flex items-center justify-center bg-gray-100 dark:bg-gray-700">
            <svg
              className="h-1/3 w-1/3 animate-spin text-gray-400"
              fill="none"
              viewBox="0 0 24 24"
            >
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
              />
            </svg>
          </div>
        )}
      </div>
    );
  }
);

Avatar.displayName = 'Avatar';

// Avatar Group Component
export interface AvatarGroupProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  max?: number;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  spacing?: 'none' | 'sm' | 'md' | 'lg';
  showBorder?: boolean;
  borderColor?: string;
  excessLabel?: string;
  onExcessClick?: () => void;
  layout?: 'stack' | 'grid';
  maxRows?: number;
}

export const AvatarGroup = React.forwardRef<HTMLDivElement, AvatarGroupProps>(
  ({
    children,
    max = 5,
    size = 'md',
    spacing = 'md',
    showBorder = true,
    borderColor = 'border-white dark:border-gray-800',
    excessLabel = '+{count}',
    onExcessClick,
    layout = 'stack',
    maxRows = 2,
    className,
    ...props
  }, ref) => {
    const avatars = React.Children.toArray(children);
    const visibleAvatars = avatars.slice(0, max);
    const excessCount = Math.max(0, avatars.length - max);
    const hasExcess = excessCount > 0;

    const spacingClasses = {
      none: '',
      sm: '-space-x-1',
      md: '-space-x-2',
      lg: '-space-x-3'
    };

    const gridSpacingClasses = {
      none: 'gap-0',
      sm: 'gap-1',
      md: 'gap-2',
      lg: 'gap-3'
    };

    if (layout === 'grid') {
      return (
        <div
          ref={ref}
          className={cn(
            'grid grid-cols-3 place-items-center',
            gridSpacingClasses[spacing],
            className
          )}
          style={{
            gridTemplateRows: `repeat(${maxRows}, 1fr)`
          }}
          {...props}
        >
          {visibleAvatars.map((avatar, index) => (
            <div key={index}>
              {React.cloneElement(avatar as React.ReactElement, {
                size,
                showBorder,
                borderColor
              })}
            </div>
          ))}
          
          {hasExcess && (
            <Avatar
              size={size}
              name={excessLabel.replace('{count}', excessCount.toString())}
              showBorder={showBorder}
              borderColor={borderColor}
              className="bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-500 transition-colors"
              onClick={onExcessClick}
            />
          )}
        </div>
      );
    }

    return (
      <div
        ref={ref}
        className={cn(
          'flex items-center',
          spacingClasses[spacing],
          className
        )}
        {...props}
      >
        {visibleAvatars.map((avatar, index) => (
          <div key={index} style={{ zIndex: avatars.length - index }}>
            {React.cloneElement(avatar as React.ReactElement, {
              size,
              showBorder,
              borderColor
            })}
          </div>
        ))}
        
        {hasExcess && (
          <Avatar
            size={size}
            name={excessLabel.replace('{count}', excessCount.toString())}
            showBorder={showBorder}
            borderColor={borderColor}
            className="bg-gray-200 dark:bg-gray-600 text-gray-600 dark:text-gray-300 cursor-pointer hover:bg-gray-300 dark:hover:bg-gray-500 transition-colors"
            onClick={onExcessClick}
            style={{ zIndex: 0 }}
          />
        )}
      </div>
    );
  }
);

AvatarGroup.displayName = 'AvatarGroup';

export type { AvatarProps, AvatarGroupProps };

/*
Usage Examples:

// Basic Avatar
<Avatar
  src="/user-avatar.jpg"
  alt="John Doe"
  name="John Doe"
  size="md"
/>

// Avatar with initials fallback
<Avatar
  name="Jane Smith"
  size="lg"
  variant="rounded"
/>

// Avatar with status
<Avatar
  src="/user.jpg"
  name="Alice Johnson"
  status="online"
  statusPosition="bottom-right"
  showBorder
/>

// Avatar Group - Stacked
<AvatarGroup max={4} spacing="md">
  <Avatar src="/user1.jpg" name="User 1" />
  <Avatar src="/user2.jpg" name="User 2" />
  <Avatar src="/user3.jpg" name="User 3" />
  <Avatar src="/user4.jpg" name="User 4" />
  <Avatar src="/user5.jpg" name="User 5" />
  <Avatar src="/user6.jpg" name="User 6" />
</AvatarGroup>

// Avatar Group - Grid Layout
<AvatarGroup 
  layout="grid" 
  max={6} 
  maxRows={2}
  onExcessClick={() => setShowAllUsers(true)}
>
  {users.map(user => (
    <Avatar
      key={user.id}
      src={user.avatar}
      name={user.name}
      status={user.status}
    />
  ))}
</AvatarGroup>

// Different sizes and variants
<Avatar size="xs" variant="square" name="XS" />
<Avatar size="sm" variant="rounded" name="SM" />
<Avatar size="md" variant="circular" name="MD" />
<Avatar size="lg" name="LG" />
<Avatar size="xl" name="XL" />
<Avatar size="2xl" name="2XL" />

// Custom fallback icon
<Avatar
  name="Bot User"
  fallbackIcon={<BotIcon className="w-6 h-6" />}
  size="lg"
/>
*/