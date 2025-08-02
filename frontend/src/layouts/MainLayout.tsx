import React from 'react';
import { useLocation } from 'react-router-dom';
import { useAuthUser, useIsAuthenticated } from '../stores/authStore';
import { useSidebar, useViewport } from '../stores/uiStore';
import { cn } from '../utils';
import { Header } from '../components/Header';
import { Sidebar } from '../components/Sidebar';
import { Breadcrumbs } from '../components/Breadcrumbs';
import type { PageProps, BreadcrumbItem } from '../types';

interface MainLayoutProps extends PageProps {
  children: React.ReactNode;
  breadcrumbs?: BreadcrumbItem[];
  showBreadcrumbs?: boolean;
  fullWidth?: boolean;
  maxWidth?: 'sm' | 'md' | 'lg' | 'xl' | '2xl' | 'full';
  padding?: 'none' | 'sm' | 'md' | 'lg';
}

export function MainLayout({ 
  children, 
  className, 
  breadcrumbs, 
  showBreadcrumbs = true,
  fullWidth = false,
  maxWidth = 'full',
  padding = 'md'
}: MainLayoutProps) {
  const location = useLocation();
  const user = useAuthUser();
  const isAuthenticated = useIsAuthenticated();
  const sidebar = useSidebar();
  const viewport = useViewport();
  
  // Get container and padding classes
  const getContainerClasses = () => {
    if (fullWidth) return 'w-full';
    
    const maxWidthClasses = {
      sm: 'max-w-screen-sm',
      md: 'max-w-screen-md', 
      lg: 'max-w-screen-lg',
      xl: 'max-w-screen-xl',
      '2xl': 'max-w-screen-2xl',
      full: 'max-w-none'
    };
    
    return cn('w-full mx-auto', maxWidthClasses[maxWidth]);
  };
  
  const getPaddingClasses = () => {
    const paddingClasses = {
      none: '',
      sm: 'p-4',
      md: 'p-6',
      lg: 'p-8'
    };
    
    return paddingClasses[padding];
  };

  // Don't render sidebar and header for unauthenticated users
  if (!isAuthenticated || !user) {
    return (
      <div className="min-h-screen bg-background">
        <main className={cn('flex-1', className)}>
          {children}
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex">
      {/* Sidebar */}
      <Sidebar />
      
      {/* Main Content Area */}
      <div className={cn(
        'flex-1 flex flex-col min-w-0 transition-all duration-300',
        sidebar.isCollapsed ? 'lg:ml-16' : 'lg:ml-80'
      )}>
        {/* Header */}
        <Header />
        
        {/* Breadcrumbs */}
        {showBreadcrumbs && (
          <div className="border-b bg-muted/30 transition-all duration-300">
            <div className={cn(
              getContainerClasses(),
              'px-6 py-3'
            )}>
              <Breadcrumbs items={breadcrumbs} />
            </div>
          </div>
        )}
        
        {/* Page Content */}
        <main className={cn(
          'flex-1 transition-all duration-300',
          getContainerClasses(),
          getPaddingClasses(),
          className
        )}>
          {/* Scroll to top on route change */}
          <div className="min-h-0">
            {children}
          </div>
        </main>
        
        {/* Footer */}
        <footer className="border-t bg-muted/50 mt-auto">
          <div className={cn(
            getContainerClasses(),
            'px-6 py-8'
          )}>
            <div className="flex flex-col md:flex-row justify-between items-center space-y-4 md:space-y-0">
              <div className="flex items-center space-x-2">
                <div className="h-6 w-6 rounded bg-primary flex items-center justify-center text-primary-foreground text-xs font-bold">
                  E
                </div>
                <span className="text-sm text-muted-foreground">
                  © 2024 Enterprise App. All rights reserved.
                </span>
              </div>
              
              <div className="flex items-center space-x-6 text-sm text-muted-foreground">
                <a href="/privacy" className="hover:text-foreground transition-colors focus:outline-none focus:ring-2 focus:ring-primary/20 rounded px-1">
                  Privacy Policy
                </a>
                <a href="/terms" className="hover:text-foreground transition-colors focus:outline-none focus:ring-2 focus:ring-primary/20 rounded px-1">
                  Terms of Service
                </a>
                <a href="/support" className="hover:text-foreground transition-colors focus:outline-none focus:ring-2 focus:ring-primary/20 rounded px-1">
                  Support
                </a>
              </div>
            </div>
          </div>
        </footer>
      </div>
      
      {/* Mobile Overlay */}
      {!sidebar.isCollapsed && viewport.isMobile && (
        <div 
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => {/* Will be handled by sidebar component */}}
          aria-hidden="true"
        />
      )}
    </div>
  );
}

export default MainLayout;