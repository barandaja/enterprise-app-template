import React from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Menu,
  X,
  Settings,
  HelpCircle,
} from 'lucide-react';
import { useAuthUser } from '../stores/authStore';
import { useUIStore, useUIActions } from '../stores/uiStore';
import { cn } from '../utils';
import { UserMenu } from './UserMenu';
import { NotificationCenter } from './NotificationCenter';
import { ThemeToggle } from './ThemeToggle';
import { Button } from './Button';
import { Input } from './Input';

interface HeaderProps {
  className?: string;
}

export function Header({ className }: HeaderProps) {
  const user = useAuthUser();
  const { sidebar } = useUIStore();
  const { toggleSidebar } = useUIActions();
  const [searchQuery, setSearchQuery] = React.useState('');
  const [isSearchExpanded, setIsSearchExpanded] = React.useState(false);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      // TODO: Implement global search functionality
      console.log('Searching for:', searchQuery);
      setSearchQuery('');
      setIsSearchExpanded(false);
    }
  };

  return (
    <header 
      className={cn(
        'sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60',
        className
      )}
      data-testid="main-header"
    >
      <div className="flex h-16 items-center justify-between px-6">
        {/* Left Section */}
        <div className="flex items-center space-x-4">
          {/* Mobile Sidebar Toggle */}
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleSidebar}
            className="lg:hidden"
            aria-label={sidebar.isCollapsed ? 'Open sidebar' : 'Close sidebar'}
            data-testid="mobile-sidebar-toggle"
          >
            {sidebar.isCollapsed ? (
              <Menu className="h-5 w-5" />
            ) : (
              <X className="h-5 w-5" />
            )}
          </Button>

          {/* Desktop Sidebar Toggle */}
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleSidebar}
            className="hidden lg:flex"
            aria-label={sidebar.isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            data-testid="desktop-sidebar-toggle"
          >
            <Menu className="h-5 w-5" />
          </Button>

          {/* Logo (hidden when sidebar is expanded on larger screens) */}
          <Link 
            to="/" 
            className={cn(
              'flex items-center space-x-2 font-bold text-xl text-foreground hover:text-primary transition-colors',
              'lg:hidden xl:flex', // Always show on mobile/tablet, hide on lg when sidebar is visible, show on xl+
              !sidebar.isCollapsed && 'lg:hidden'
            )}
            data-testid="header-logo"
          >
            <div className="h-8 w-8 rounded-lg bg-primary flex items-center justify-center text-primary-foreground font-bold">
              E
            </div>
            <span className="hidden sm:inline">Enterprise App</span>
          </Link>
        </div>

        {/* Center Section - Search */}
        <div className="flex-1 max-w-md mx-4">
          <form onSubmit={handleSearch} className="relative">
            <div className={cn(
              'relative transition-all duration-200',
              isSearchExpanded ? 'w-full' : 'w-full sm:w-80'
            )}>
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onFocus={() => setIsSearchExpanded(true)}
                onBlur={() => setIsSearchExpanded(false)}
                className="pl-10 pr-4 h-9 w-full bg-muted/50 border-0 focus:bg-background focus:ring-2 focus:ring-primary/20"
                data-testid="global-search"
                aria-label="Global search"
              />
            </div>
            {searchQuery && (
              <div className="absolute top-full left-0 right-0 mt-2 p-4 bg-popover border rounded-lg shadow-lg z-50">
                <p className="text-sm text-muted-foreground">
                  Press Enter to search for "{searchQuery}"
                </p>
              </div>
            )}
          </form>
        </div>

        {/* Right Section */}
        <div className="flex items-center space-x-2">
          {/* Quick Actions (Desktop Only) */}
          <div className="hidden md:flex items-center space-x-1">
            <Button
              variant="ghost"
              size="icon"
              asChild
              className="text-muted-foreground hover:text-foreground"
              data-testid="help-button"
            >
              <Link to="/help" aria-label="Help & Support">
                <HelpCircle className="h-4 w-4" />
              </Link>
            </Button>

            <Button
              variant="ghost"
              size="icon"
              asChild
              className="text-muted-foreground hover:text-foreground"
              data-testid="settings-button"
            >
              <Link to="/settings" aria-label="Settings">
                <Settings className="h-4 w-4" />
              </Link>
            </Button>
          </div>

          {/* Theme Toggle */}
          <ThemeToggle 
            size="md" 
            variant="subtle"
            tooltipPosition="bottom"
            data-testid="theme-toggle"
          />

          {/* Notifications */}
          <NotificationCenter />

          {/* User Menu */}
          {user && <UserMenu user={user} />}
        </div>
      </div>
    </header>
  );
}

export default Header;