import React from 'react';
import { Link } from 'react-router-dom';
import {
  MoreHorizontal,
  ExternalLink,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  Minus,
} from 'lucide-react';
import { cn } from '../utils';
import { Button } from './Button';
import { Spinner } from './Spinner';

export interface DashboardCardProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  
  // Header options
  subtitle?: string;
  icon?: React.ComponentType<{ className?: string }>;
  
  // Actions
  onRefresh?: () => void;
  refreshing?: boolean;
  href?: string;
  actions?: Array<{
    label: string;
    onClick?: () => void;
    href?: string;
    icon?: React.ComponentType<{ className?: string }>;
  }>;
  
  // State
  loading?: boolean;
  error?: string | null;
  
  // Variants
  variant?: 'default' | 'metric' | 'chart' | 'list' | 'status';
  size?: 'sm' | 'md' | 'lg';
  
  // Accessibility
  'data-testid'?: string;
}

export interface MetricCardProps extends Omit<DashboardCardProps, 'children' | 'variant'> {
  value: string | number;
  previousValue?: string | number;
  unit?: string;
  trend?: 'up' | 'down' | 'neutral';
  trendValue?: string;
  description?: string;
  icon: React.ComponentType<{ className?: string }>;
}

export interface StatusCardProps extends Omit<DashboardCardProps, 'children' | 'variant'> {
  status: 'success' | 'warning' | 'error' | 'info';
  message: string;
  lastUpdated?: string;
  actionLabel?: string;
  onActionClick?: () => void;
}

export function DashboardCard({
  title,
  subtitle,
  children,
  className,
  icon: Icon,
  onRefresh,
  refreshing = false,
  href,
  actions = [],
  loading = false,
  error = null,
  variant = 'default',
  size = 'md',
  'data-testid': testId,
}: DashboardCardProps) {
  const [isActionsOpen, setIsActionsOpen] = React.useState(false);

  const cardSizeClasses = {
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8',
  };

  const CardWrapper = href ? Link : 'div';
  const cardProps = href ? { to: href } : {};

  return (
    <CardWrapper
      {...cardProps}
      className={cn(
        'card transition-all duration-200',
        href && 'hover:shadow-md hover:-translate-y-0.5',
        variant === 'metric' && 'hover:bg-accent/5',
        className
      )}
      data-testid={testId}
    >
      <div className={cardSizeClasses[size]}>
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-start space-x-3 min-w-0 flex-1">
            {Icon && (
              <div className={cn(
                'flex-shrink-0 rounded-lg flex items-center justify-center',
                variant === 'metric' && 'h-12 w-12 bg-primary/10',
                variant !== 'metric' && 'h-10 w-10 bg-muted/50'
              )}>
                <Icon className={cn(
                  variant === 'metric' ? 'h-6 w-6 text-primary' : 'h-5 w-5 text-muted-foreground'
                )} />
              </div>
            )}
            
            <div className="min-w-0 flex-1">
              <h3 className={cn(
                'font-semibold text-foreground truncate',
                size === 'sm' && 'text-sm',
                size === 'md' && 'text-base',
                size === 'lg' && 'text-lg'
              )}>
                {title}
              </h3>
              {subtitle && (
                <p className="text-sm text-muted-foreground mt-1 truncate">
                  {subtitle}
                </p>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center space-x-1 flex-shrink-0">
            {onRefresh && (
              <Button
                variant="ghost"
                size="icon"
                onClick={onRefresh}
                disabled={refreshing}
                className="h-8 w-8"
                aria-label="Refresh"
              >
                <RefreshCw className={cn(
                  'h-4 w-4',
                  refreshing && 'animate-spin'
                )} />
              </Button>
            )}

            {href && (
              <Button
                variant="ghost"
                size="icon"
                className="h-8 w-8"
                aria-label="Open"
              >
                <ExternalLink className="h-4 w-4" />
              </Button>
            )}

            {actions.length > 0 && (
              <div className="relative">
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setIsActionsOpen(!isActionsOpen)}
                  className="h-8 w-8"
                  aria-label="More actions"
                >
                  <MoreHorizontal className="h-4 w-4" />
                </Button>

                {isActionsOpen && (
                  <div className="absolute right-0 top-full mt-1 w-48 bg-popover border border-border rounded-lg shadow-lg z-50">
                    {actions.map((action, index) => {
                      const ActionIcon = action.icon;
                      const ActionWrapper = action.href ? Link : 'button';
                      const actionProps = action.href 
                        ? { to: action.href }
                        : { onClick: action.onClick };

                      return (
                        <ActionWrapper
                          key={index}
                          {...actionProps}
                          className="flex items-center w-full px-3 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground first:rounded-t-lg last:rounded-b-lg"
                          onClick={() => {
                            if (!action.href) action.onClick?.();
                            setIsActionsOpen(false);
                          }}
                        >
                          {ActionIcon && <ActionIcon className="h-4 w-4 mr-2" />}
                          {action.label}
                        </ActionWrapper>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Content */}
        <div className="relative">
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Spinner size="md" />
            </div>
          ) : error ? (
            <div className="flex items-center space-x-2 text-destructive py-4">
              <AlertCircle className="h-4 w-4 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          ) : (
            children
          )}
        </div>
      </div>
    </CardWrapper>
  );
}

export function MetricCard({
  title,
  value,
  previousValue,
  unit = '',
  trend,
  trendValue,
  description,
  icon,
  ...props
}: MetricCardProps) {
  const getTrendIcon = () => {
    switch (trend) {
      case 'up':
        return <TrendingUp className="h-3 w-3" />;
      case 'down':
        return <TrendingDown className="h-3 w-3" />;
      default:
        return <Minus className="h-3 w-3" />;
    }
  };

  const getTrendColor = () => {
    switch (trend) {
      case 'up':
        return 'text-green-600 dark:text-green-400';
      case 'down':
        return 'text-red-600 dark:text-red-400';
      default:
        return 'text-muted-foreground';
    }
  };

  return (
    <DashboardCard
      title={title}
      icon={icon}
      variant="metric"
      {...props}
    >
      <div className="space-y-3">
        {/* Main Value */}
        <div className="flex items-baseline space-x-2">
          <span className="text-3xl font-bold text-foreground">
            {value}
          </span>
          {unit && (
            <span className="text-sm text-muted-foreground">
              {unit}
            </span>
          )}
        </div>

        {/* Trend and Description */}
        <div className="flex items-center justify-between">
          {trendValue && (
            <div className={cn(
              'flex items-center space-x-1 text-sm font-medium',
              getTrendColor()
            )}>
              {getTrendIcon()}
              <span>{trendValue}</span>
            </div>
          )}

          {description && (
            <span className="text-sm text-muted-foreground">
              {description}
            </span>
          )}
        </div>
      </div>
    </DashboardCard>
  );
}

export function StatusCard({
  title,
  status,
  message,
  lastUpdated,
  actionLabel,
  onActionClick,
  ...props
}: StatusCardProps) {
  const getStatusIcon = () => {
    switch (status) {
      case 'success':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'warning':
        return <AlertCircle className="h-5 w-5 text-yellow-500" />;
      case 'error':
        return <AlertCircle className="h-5 w-5 text-red-500" />;
      default:
        return <AlertCircle className="h-5 w-5 text-blue-500" />;
    }
  };

  const getStatusColor = () => {
    switch (status) {
      case 'success':
        return 'border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-950/20';
      case 'warning':
        return 'border-yellow-200 bg-yellow-50 dark:border-yellow-800 dark:bg-yellow-950/20';
      case 'error':
        return 'border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-950/20';
      default:
        return 'border-blue-200 bg-blue-50 dark:border-blue-800 dark:bg-blue-950/20';
    }
  };

  return (
    <DashboardCard
      title={title}
      variant="status"
      {...props}
    >
      <div className={cn(
        'rounded-lg border p-4',
        getStatusColor()
      )}>
        <div className="flex items-start space-x-3">
          {getStatusIcon()}
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-foreground">
              {message}
            </p>
            {lastUpdated && (
              <div className="flex items-center mt-2 text-xs text-muted-foreground">
                <Clock className="h-3 w-3 mr-1" />
                <span>Last updated: {lastUpdated}</span>
              </div>
            )}
            {actionLabel && onActionClick && (
              <Button
                variant="outline"
                size="sm"
                onClick={onActionClick}
                className="mt-3 h-8"
              >
                {actionLabel}
              </Button>
            )}
          </div>
        </div>
      </div>
    </DashboardCard>
  );
}

export default DashboardCard;