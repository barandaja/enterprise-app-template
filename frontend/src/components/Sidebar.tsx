import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Home,
  User,
  Settings,
  Shield,
  BarChart3,
  Users,
  HelpCircle,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Lock,
  FileText,
  Activity,
  Bell,
  Zap,
} from 'lucide-react';
import { useAuthUser, useAuthActions } from '../stores/authStore';
import { useSidebar, useUIActions } from '../stores/uiStore';
import { cn } from '../utils';
import { Button } from './Button';
import type { NavItem } from '../types';

interface SidebarProps {
  className?: string;
}

// Navigation configuration with role-based access
const getNavigationItems = (userRole: string): NavItem[] => {
  const baseItems: NavItem[] = [
    {
      label: 'Dashboard',
      href: '/',
      icon: Home,
    },
    {
      label: 'Profile',
      href: '/profile',
      icon: User,
    },
    {
      label: 'Privacy Settings',
      href: '/privacy-settings',
      icon: Lock,
    },
  ];

  // Add analytics for all users
  const analyticsItems: NavItem[] = [
    {
      label: 'Analytics',
      href: '/analytics',
      icon: BarChart3,
    },
    {
      label: 'Activity',
      href: '/activity',
      icon: Activity,
    },
  ];

  // Moderator and Admin items
  const moderatorItems: NavItem[] = [
    {
      label: 'User Management',
      href: '/users',
      icon: Users,
    },
    {
      label: 'Security',
      href: '/security',
      icon: Shield,
    },
    {
      label: 'Monitoring',
      href: '/monitoring',
      icon: Activity,
    },
  ];

  // Admin-only items
  const adminItems: NavItem[] = [
    {
      label: 'Admin Panel',
      href: '/admin',
      icon: Zap,
    },
    {
      label: 'System Logs',
      href: '/admin/logs',
      icon: FileText,
    },
    {
      label: 'Notifications',
      href: '/admin/notifications',
      icon: Bell,
    },
  ];

  // Support items for all users
  const supportItems: NavItem[] = [
    {
      label: 'Help & Support',
      href: '/help',
      icon: HelpCircle,
    },
    {
      label: 'Settings',
      href: '/settings',
      icon: Settings,
    },
  ];

  let items = [...baseItems, ...analyticsItems];

  if (userRole === 'moderator' || userRole === 'admin') {
    items = [...items, ...moderatorItems];
  }

  if (userRole === 'admin') {
    items = [...items, ...adminItems];
  }

  items = [...items, ...supportItems];

  return items;
};

export function Sidebar({ className }: SidebarProps) {
  const location = useLocation();
  const user = useAuthUser();
  const { logout } = useAuthActions();
  const sidebar = useSidebar();
  const { toggleSidebar, setSidebarPinned } = useUIActions();

  const navigationItems = React.useMemo(() => 
    user ? getNavigationItems(user.role) : [], 
    [user]
  );

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(href);
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  if (!user) {
    return null;
  }

  return (
    <>
      {/* Mobile Backdrop */}
      {!sidebar.isCollapsed && (
        <div 
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={toggleSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed left-0 top-0 z-50 h-full bg-card border-r border-border transition-all duration-300 ease-in-out',
          'lg:sticky lg:top-16 lg:h-[calc(100vh-4rem)]', // On desktop, account for header height
          sidebar.isCollapsed ? '-translate-x-full lg:translate-x-0 lg:w-16' : 'w-80 lg:w-80',
          className
        )}
        style={{
          width: sidebar.isCollapsed ? (window.innerWidth >= 1024 ? '4rem' : '0') : '20rem'
        }}
        data-testid="sidebar"
      >
        <div className="flex flex-col h-full">
          {/* Sidebar Header */}
          <div className={cn(
            'flex items-center justify-between p-4 border-b border-border',
            sidebar.isCollapsed && 'lg:justify-center'
          )}>
            {/* Logo */}
            {!sidebar.isCollapsed && (
              <Link 
                to="/" 
                className="flex items-center space-x-2 font-bold text-xl text-foreground hover:text-primary transition-colors"
                data-testid="sidebar-logo"
              >
                <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center text-primary-foreground font-bold">
                  E
                </div>
                <span>Enterprise App</span>
              </Link>
            )}

            {sidebar.isCollapsed && (
              <Link 
                to="/" 
                className="flex items-center justify-center"
                data-testid="sidebar-logo-collapsed"
              >
                <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center text-primary-foreground font-bold">
                  E
                </div>
              </Link>
            )}

            {/* Toggle Button (Desktop) */}
            {!sidebar.isCollapsed && (
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleSidebar}
                className="hidden lg:flex h-8 w-8"
                aria-label="Collapse sidebar"
                data-testid="sidebar-collapse-button"
              >
                <ChevronLeft className="h-4 w-4" />
              </Button>
            )}
          </div>

          {/* Expand Button (when collapsed) */}
          {sidebar.isCollapsed && (
            <div className="hidden lg:flex justify-center p-2 border-b border-border">
              <Button
                variant="ghost"
                size="icon"
                onClick={toggleSidebar}
                className="h-8 w-8"
                aria-label="Expand sidebar"
                data-testid="sidebar-expand-button"
              >
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          )}

          {/* Navigation */}
          <nav className="flex-1 overflow-y-auto p-4" role="navigation">
            <div className="space-y-1">
              {navigationItems.map((item) => {
                const Icon = item.icon;
                const active = isActive(item.href);
                
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    className={cn(
                      'flex items-center space-x-3 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200',
                      'hover:bg-accent hover:text-accent-foreground',
                      'focus:outline-none focus:ring-2 focus:ring-primary/20',
                      active && 'bg-primary text-primary-foreground hover:bg-primary/90',
                      sidebar.isCollapsed && 'lg:justify-center lg:space-x-0'
                    )}
                    title={sidebar.isCollapsed ? item.label : undefined}
                    data-testid={`nav-item-${item.href.replace('/', '') || 'home'}`}
                  >
                    {Icon && <Icon className="h-5 w-5 flex-shrink-0" />}
                    {!sidebar.isCollapsed && (
                      <span className="truncate">{item.label}</span>
                    )}
                    
                    {/* Active indicator for collapsed sidebar */}
                    {sidebar.isCollapsed && active && (
                      <div className="absolute left-0 w-1 h-6 bg-primary-foreground rounded-r-full" />
                    )}
                  </Link>
                );
              })}
            </div>
          </nav>

          {/* User Section */}
          <div className="border-t border-border p-4">
            {!sidebar.isCollapsed ? (
              <div className="space-y-3">
                {/* User Info */}
                <div className="flex items-center space-x-3 px-3 py-2">
                  {user.avatar ? (
                    <img
                      src={user.avatar}
                      alt={`${user.firstName} ${user.lastName}`}
                      className="h-8 w-8 rounded-full object-cover"
                    />
                  ) : (
                    <div className="h-8 w-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-medium">
                      {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                    </div>
                  )}
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {user.firstName} {user.lastName}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {user.email}
                    </p>
                  </div>
                </div>

                {/* Logout Button */}
                <Button
                  variant="ghost"
                  onClick={handleLogout}
                  className="w-full justify-start space-x-3 px-3 py-2 text-destructive hover:bg-destructive/10 hover:text-destructive"
                  data-testid="sidebar-logout-button"
                >
                  <LogOut className="h-5 w-5" />
                  <span>Sign Out</span>
                </Button>
              </div>
            ) : (
              <div className="flex flex-col items-center space-y-2">
                {/* User Avatar */}
                <div className="relative group">
                  {user.avatar ? (
                    <img
                      src={user.avatar}
                      alt={`${user.firstName} ${user.lastName}`}
                      className="h-8 w-8 rounded-full object-cover"
                    />
                  ) : (
                    <div className="h-8 w-8 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-medium">
                      {user.firstName.charAt(0)}{user.lastName.charAt(0)}
                    </div>
                  )}
                  
                  {/* Tooltip */}
                  <div className="absolute left-full ml-2 top-1/2 -translate-y-1/2 bg-popover border border-border rounded px-2 py-1 text-xs whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50">
                    {user.firstName} {user.lastName}
                  </div>
                </div>

                {/* Logout Button */}
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={handleLogout}
                  className="h-8 w-8 text-destructive hover:bg-destructive/10 hover:text-destructive"
                  title="Sign Out"
                  data-testid="sidebar-logout-button-collapsed"
                >
                  <LogOut className="h-4 w-4" />
                </Button>
              </div>
            )}
          </div>

          {/* Version Info */}
          {!sidebar.isCollapsed && (
            <div className="px-4 py-2 border-t border-border bg-muted/30">
              <p className="text-xs text-muted-foreground text-center">
                Enterprise App v1.0.0
              </p>
            </div>
          )}
        </div>
      </aside>
    </>
  );
}

export default Sidebar;