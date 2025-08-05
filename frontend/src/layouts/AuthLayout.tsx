import React from 'react';
import { Link } from 'react-router-dom';
import { Sun, Moon } from 'lucide-react';
import { cn } from '../utils';
import type { PageProps } from '../types';

interface AuthLayoutProps extends PageProps {
  children: React.ReactNode;
  title?: string;
  subtitle?: string;
}

export function AuthLayout({ 
  children, 
  className, 
  title,
  subtitle 
}: AuthLayoutProps) {
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

  return (
    <div className="min-h-screen bg-background">
      {/* Theme toggle in top right */}
      <div className="absolute top-4 right-4 z-10">
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
      </div>

      <div className="flex min-h-screen">
        {/* Left side - Branding/Info */}
        <div className="hidden lg:flex lg:w-1/2 bg-primary relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-primary-600 to-primary-800" />
          <div className="relative z-10 flex flex-col justify-center px-12 text-primary-foreground">
            <div className="max-w-md">
              <Link 
                to="/" 
                className="inline-flex items-center space-x-3 mb-8 text-primary-foreground hover:text-primary-foreground/90 transition-colors"
              >
                <div className="h-10 w-10 rounded-xl bg-white/20 backdrop-blur-sm flex items-center justify-center text-xl font-bold">
                  E
                </div>
                <span className="text-2xl font-bold">Enterprise App</span>
              </Link>
              
              <h1 className="text-4xl font-bold mb-6">
                Welcome to the future of enterprise solutions
              </h1>
              
              <p className="text-xl text-primary-foreground/90 mb-8">
                Streamline your workflow, enhance productivity, and drive growth with our comprehensive platform.
              </p>
              
              <div className="space-y-4">
                <div className="flex items-start space-x-3">
                  <div className="h-2 w-2 rounded-full bg-primary-foreground/60 mt-2 flex-shrink-0" />
                  <p className="text-primary-foreground/80">
                    Advanced analytics and reporting tools
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="h-2 w-2 rounded-full bg-primary-foreground/60 mt-2 flex-shrink-0" />
                  <p className="text-primary-foreground/80">
                    Seamless team collaboration features
                  </p>
                </div>
                <div className="flex items-start space-x-3">
                  <div className="h-2 w-2 rounded-full bg-primary-foreground/60 mt-2 flex-shrink-0" />
                  <p className="text-primary-foreground/80">
                    Enterprise-grade security and compliance
                  </p>
                </div>
              </div>
            </div>
          </div>
          
          {/* Decorative elements */}
          <div className="absolute top-20 right-20 h-40 w-40 rounded-full bg-white/10 backdrop-blur-sm" />
          <div className="absolute bottom-20 right-40 h-24 w-24 rounded-full bg-white/5 backdrop-blur-sm" />
          <div className="absolute top-1/2 right-10 h-32 w-32 rounded-full bg-white/5 backdrop-blur-sm" />
        </div>

        {/* Right side - Auth form */}
        <div className="flex-1 flex flex-col justify-center lg:w-1/2">
          <div className="w-full max-w-md mx-auto px-6 py-12">
            {/* Mobile logo */}
            <div className="lg:hidden mb-8 text-center">
              <Link 
                to="/" 
                className="inline-flex items-center space-x-2 text-foreground hover:text-primary transition-colors"
              >
                <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center text-primary-foreground font-bold">
                  E
                </div>
                <span className="text-xl font-bold">Enterprise App</span>
              </Link>
            </div>

            {/* Header */}
            {(title || subtitle) && (
              <div className="mb-8">
                {title && (
                  <h1 className="text-3xl font-bold text-foreground mb-2">
                    {title}
                  </h1>
                )}
                {subtitle && (
                  <p className="text-muted-foreground">
                    {subtitle}
                  </p>
                )}
              </div>
            )}

            {/* Form content */}
            <div className={cn('w-full', className)}>
              {children}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AuthLayout;