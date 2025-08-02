import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';
import { cn } from '../utils';
import type { BreadcrumbItem } from '../types';

interface BreadcrumbsProps {
  items?: BreadcrumbItem[];
  className?: string;
  showHome?: boolean;
  maxItems?: number;
}

// Route to breadcrumb mapping - customize this based on your routes
const routeToBreadcrumb: Record<string, string> = {
  '/': 'Dashboard',
  '/profile': 'Profile',
  '/profile/edit': 'Edit Profile',
  '/profile/settings': 'Profile Settings',
  '/profile/security': 'Security Settings',
  '/settings': 'Settings',
  '/privacy-settings': 'Privacy Settings',
  '/security': 'Security',
  '/users': 'Users',
  '/analytics': 'Analytics',
  '/activity': 'Activity',
  '/admin': 'Admin Panel',
  '/admin/logs': 'System Logs',
  '/admin/notifications': 'Notifications',
  '/help': 'Help & Support',
  '/monitoring': 'Monitoring',
  '/notifications': 'All Notifications',
};

// Generate breadcrumbs from current route
const generateBreadcrumbsFromRoute = (pathname: string): BreadcrumbItem[] => {
  if (pathname === '/') {
    return [{ label: 'Dashboard', href: '/' }];
  }

  const segments = pathname.split('/').filter(Boolean);
  const breadcrumbs: BreadcrumbItem[] = [];

  // Add home/dashboard
  breadcrumbs.push({ label: 'Dashboard', href: '/' });

  // Build path segments
  let currentPath = '';
  segments.forEach((segment, index) => {
    currentPath += `/${segment}`;
    const label = routeToBreadcrumb[currentPath] || segment.charAt(0).toUpperCase() + segment.slice(1);
    
    breadcrumbs.push({
      label,
      href: index === segments.length - 1 ? undefined : currentPath, // Last item has no href
    });
  });

  return breadcrumbs;
};

export function Breadcrumbs({ 
  items, 
  className, 
  showHome = true, 
  maxItems = 5 
}: BreadcrumbsProps) {
  const location = useLocation();
  
  // Use provided items or generate from route
  const breadcrumbItems = React.useMemo(() => {
    if (items) {
      return showHome && items[0]?.href !== '/' 
        ? [{ label: 'Dashboard', href: '/' }, ...items]
        : items;
    }
    
    return generateBreadcrumbsFromRoute(location.pathname);
  }, [items, location.pathname, showHome]);

  // Handle truncation if there are too many items
  const displayItems = React.useMemo(() => {
    if (breadcrumbItems.length <= maxItems) {
      return breadcrumbItems;
    }

    // Keep first item, last two items, and add ellipsis
    const first = breadcrumbItems[0];
    const last = breadcrumbItems[breadcrumbItems.length - 1];
    const secondLast = breadcrumbItems[breadcrumbItems.length - 2];

    return [
      first,
      { label: '...', href: undefined },
      secondLast,
      last,
    ];
  }, [breadcrumbItems, maxItems]);

  // Don't render if only one item (just dashboard)
  if (displayItems.length <= 1) {
    return null;
  }

  return (
    <nav 
      aria-label="Breadcrumb" 
      className={cn('flex items-center space-x-1 text-sm', className)}
      data-testid="breadcrumbs"
    >
      <ol className="flex items-center space-x-1">
        {displayItems.map((item, index) => {
          const isLast = index === displayItems.length - 1;
          const isEllipsis = item.label === '...';

          return (
            <li key={`${item.href}-${item.label}-${index}`} className="flex items-center">
              {index > 0 && (
                <ChevronRight 
                  className="h-4 w-4 text-muted-foreground mx-1 flex-shrink-0" 
                  aria-hidden="true"
                />
              )}
              
              {isEllipsis ? (
                <span 
                  className="text-muted-foreground px-1"
                  aria-hidden="true"
                >
                  {item.label}
                </span>
              ) : isLast ? (
                <span 
                  className="font-medium text-foreground truncate max-w-32 sm:max-w-none"
                  aria-current="page"
                  data-testid={`breadcrumb-current`}
                >
                  {item.label}
                </span>
              ) : item.href ? (
                <Link
                  to={item.href}
                  className="text-muted-foreground hover:text-foreground transition-colors truncate max-w-32 sm:max-w-none focus:outline-none focus:ring-2 focus:ring-primary/20 rounded px-1"
                  data-testid={`breadcrumb-link-${index}`}
                >
                  {index === 0 && showHome ? (
                    <span className="flex items-center space-x-1">
                      <Home className="h-3 w-3" />
                      <span className="hidden sm:inline">{item.label}</span>
                    </span>
                  ) : (
                    item.label
                  )}
                </Link>
              ) : (
                <span className="text-muted-foreground truncate max-w-32 sm:max-w-none">
                  {item.label}
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

// Hook for programmatically setting breadcrumbs
export function useBreadcrumbs() {
  const [customBreadcrumbs, setCustomBreadcrumbs] = React.useState<BreadcrumbItem[]>([]);

  const setBreadcrumbs = React.useCallback((items: BreadcrumbItem[]) => {
    setCustomBreadcrumbs(items);
  }, []);

  const clearBreadcrumbs = React.useCallback(() => {
    setCustomBreadcrumbs([]);
  }, []);

  return {
    breadcrumbs: customBreadcrumbs,
    setBreadcrumbs,
    clearBreadcrumbs,
  };
}

export default Breadcrumbs;