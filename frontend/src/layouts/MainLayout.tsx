import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  Home, 
  User, 
  Settings, 
  Menu, 
  X, 
  Sun, 
  Moon, 
  LogOut,
  Bell
} from 'lucide-react';
import { cn } from '../utils';
import { NavItem, PageProps } from '../types';

interface MainLayoutProps extends PageProps {
  children: React.ReactNode;
}

const navigationItems: NavItem[] = [
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
];

export function MainLayout({ children, className }: MainLayoutProps) {
  const location = useLocation();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = React.useState(false);
  const [isDarkMode, setIsDarkMode] = React.useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('theme') === 'dark' ||
        (!localStorage.getItem('theme') && window.matchMedia('(prefers-color-scheme: dark)').matches);
    }
    return false;
  });

  // Toggle dark mode
  const toggleDarkMode = () => {
    const newMode = !isDarkMode;
    setIsDarkMode(newMode);
    
    if (newMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  };

  // Apply theme on mount
  React.useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, []);

  // Close mobile menu on route change
  React.useEffect(() => {
    setIsMobileMenuOpen(false);
  }, [location.pathname]);

  const isActive = (href: string) => {
    if (href === '/') {
      return location.pathname === '/';
    }
    return location.pathname.startsWith(href);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          {/* Logo */}
          <Link 
            to="/" 
            className="flex items-center space-x-2 font-bold text-xl text-foreground hover:text-primary transition-colors"
          >
            <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center text-primary-foreground font-bold">
              E
            </div>
            <span>Enterprise App</span>
          </Link>

          {/* Desktop Navigation */}
          <nav className="hidden md:flex items-center space-x-1">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  to={item.href}
                  className={cn(
                    'nav-link',
                    isActive(item.href) && 'nav-link-active'
                  )}
                >
                  {Icon && <Icon className="h-4 w-4" />}
                  {item.label}
                </Link>
              );
            })}
          </nav>

          {/* Right side actions */}
          <div className="flex items-center space-x-2">
            {/* Notifications */}
            <button
              className="btn-ghost btn-icon hidden sm:flex"
              aria-label="Notifications"
            >
              <Bell className="h-4 w-4" />
            </button>

            {/* Theme toggle */}
            <button
              onClick={toggleDarkMode}
              className="btn-ghost btn-icon"
              aria-label="Toggle theme"
            >
              {isDarkMode ? (
                <Sun className="h-4 w-4" />
              ) : (
                <Moon className="h-4 w-4" />
              )}
            </button>

            {/* User menu - placeholder */}
            <div className="hidden sm:flex items-center space-x-2">
              <Link to="/profile" className="btn-ghost">
                <User className="h-4 w-4" />
                <span className="hidden lg:inline">Profile</span>
              </Link>
              <button className="btn-ghost text-destructive hover:bg-destructive/10">
                <LogOut className="h-4 w-4" />
                <span className="hidden lg:inline">Logout</span>
              </button>
            </div>

            {/* Mobile menu button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="btn-ghost btn-icon md:hidden"
              aria-label="Toggle menu"
            >
              {isMobileMenuOpen ? (
                <X className="h-4 w-4" />
              ) : (
                <Menu className="h-4 w-4" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isMobileMenuOpen && (
          <div className="md:hidden border-t bg-background">
            <nav className="container py-4 space-y-2">
              {navigationItems.map((item) => {
                const Icon = item.icon;
                return (
                  <Link
                    key={item.href}
                    to={item.href}
                    className={cn(
                      'flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground',
                      isActive(item.href) && 'bg-accent text-accent-foreground'
                    )}
                  >
                    {Icon && <Icon className="h-4 w-4" />}
                    <span>{item.label}</span>
                  </Link>
                );
              })}
              
              {/* Mobile-only items */}
              <div className="pt-2 border-t space-y-2">
                <button className="flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground w-full text-left">
                  <Bell className="h-4 w-4" />
                  <span>Notifications</span>
                </button>
                <Link
                  to="/profile"
                  className="flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors hover:bg-accent hover:text-accent-foreground"
                >
                  <User className="h-4 w-4" />
                  <span>Profile</span>
                </Link>
                <button className="flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors hover:bg-destructive/10 text-destructive w-full text-left">
                  <LogOut className="h-4 w-4" />
                  <span>Logout</span>
                </button>
              </div>
            </nav>
          </div>
        )}
      </header>

      {/* Main Content */}
      <main className={cn('flex-1', className)}>
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t bg-muted/50">
        <div className="container py-8">
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
              <Link to="/privacy" className="hover:text-foreground transition-colors">
                Privacy Policy
              </Link>
              <Link to="/terms" className="hover:text-foreground transition-colors">
                Terms of Service
              </Link>
              <Link to="/support" className="hover:text-foreground transition-colors">
                Support
              </Link>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default MainLayout;