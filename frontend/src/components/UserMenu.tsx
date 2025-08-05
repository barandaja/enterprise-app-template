import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  User,
  Settings,
  Shield,
  LogOut,
  ChevronDown,
  UserCircle,
  Lock,
  HelpCircle,
} from 'lucide-react';
import { useAuthActions } from '../stores/authStore';
import { useClickOutside } from '../hooks/useClickOutside';
import { cn } from '../utils';
import { Button } from './Button';
import type { User as UserType } from '../types';

interface UserMenuProps {
  user: UserType;
  className?: string;
}

export function UserMenu({ user, className }: UserMenuProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const { logout } = useAuthActions();
  const navigate = useNavigate();
  const menuRef = useClickOutside<HTMLDivElement>(() => setIsOpen(false));

  const handleLogout = async () => {
    try {
      await logout();
      navigate('/login');
    } catch (error) {
      console.error('Logout failed:', error);
    }
    setIsOpen(false);
  };

  const handleMenuItemClick = () => {
    setIsOpen(false);
  };

  const getInitials = (firstName: string, lastName: string) => {
    return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
  };

  // Role-based menu items
  const isAdmin = user.role === 'admin';
  const isModerator = user.role === 'moderator' || isAdmin;

  return (
    <div className={cn('relative', className)} ref={menuRef}>
      {/* User Avatar/Trigger */}
      <Button
        variant="ghost"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center space-x-2 h-9 px-2 hover:bg-accent/50"
        aria-label="User menu"
        aria-expanded={isOpen}
        aria-haspopup="true"
        data-testid="user-menu-trigger"
      >
        {user.avatar ? (
          <img
            src={user.avatar}
            alt={`${user.firstName} ${user.lastName}`}
            className="h-6 w-6 rounded-full object-cover"
          />
        ) : (
          <div className="h-6 w-6 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-xs font-medium">
            {getInitials(user.firstName, user.lastName)}
          </div>
        )}
        <span className="hidden sm:block text-sm font-medium truncate max-w-32">
          {user.firstName}
        </span>
        <ChevronDown 
          className={cn(
            'h-3 w-3 transition-transform duration-200',
            isOpen && 'transform rotate-180'
          )} 
        />
      </Button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div 
          className="absolute right-0 top-full mt-2 w-64 bg-popover border border-border rounded-lg shadow-lg z-50"
          role="menu"
          aria-orientation="vertical"
          data-testid="user-menu-dropdown"
        >
          {/* User Info Header */}
          <div className="px-4 py-3 border-b border-border">
            <div className="flex items-center space-x-3">
              {user.avatar ? (
                <img
                  src={user.avatar}
                  alt={`${user.firstName} ${user.lastName}`}
                  className="h-10 w-10 rounded-full object-cover"
                />
              ) : (
                <div className="h-10 w-10 rounded-full bg-primary flex items-center justify-center text-primary-foreground text-sm font-medium">
                  {getInitials(user.firstName, user.lastName)}
                </div>
              )}
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">
                  {user.firstName} {user.lastName}
                </p>
                <p className="text-xs text-muted-foreground truncate">
                  {user.email}
                </p>
                <div className="flex items-center mt-1">
                  <span className={cn(
                    'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium',
                    user.role === 'admin' && 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
                    user.role === 'moderator' && 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
                    user.role === 'user' && 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
                  )}>
                    {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Menu Items */}
          <div className="py-1">
            {/* Profile Section */}
            <Link
              to="/profile"
              onClick={handleMenuItemClick}
              className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              role="menuitem"
              data-testid="profile-menu-item"
            >
              <UserCircle className="h-4 w-4 mr-3" />
              View Profile
            </Link>

            <Link
              to="/profile/edit"
              onClick={handleMenuItemClick}
              className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              role="menuitem"
              data-testid="edit-profile-menu-item"
            >
              <User className="h-4 w-4 mr-3" />
              Edit Profile
            </Link>

            {/* Settings Section */}
            <div className="my-1 border-t border-border"></div>
            
            <Link
              to="/settings"
              onClick={handleMenuItemClick}
              className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              role="menuitem"
              data-testid="settings-menu-item"
            >
              <Settings className="h-4 w-4 mr-3" />
              Settings
            </Link>

            <Link
              to="/privacy-settings"
              onClick={handleMenuItemClick}
              className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              role="menuitem"
              data-testid="privacy-settings-menu-item"
            >
              <Lock className="h-4 w-4 mr-3" />
              Privacy Settings
            </Link>

            {/* Security Section (for moderators and admins) */}
            {isModerator && (
              <>
                <div className="my-1 border-t border-border"></div>
                <Link
                  to="/security"
                  onClick={handleMenuItemClick}
                  className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                  role="menuitem"
                  data-testid="security-menu-item"
                >
                  <Shield className="h-4 w-4 mr-3" />
                  Security Settings
                </Link>
              </>
            )}

            {/* Admin Section */}
            {isAdmin && (
              <>
                <div className="my-1 border-t border-border"></div>
                <Link
                  to="/admin"
                  onClick={handleMenuItemClick}
                  className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
                  role="menuitem"
                  data-testid="admin-menu-item"
                >
                  <Shield className="h-4 w-4 mr-3" />
                  Admin Panel
                </Link>
              </>
            )}

            {/* Help Section */}
            <div className="my-1 border-t border-border"></div>
            
            <Link
              to="/help"
              onClick={handleMenuItemClick}
              className="flex items-center px-4 py-2 text-sm text-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
              role="menuitem"
              data-testid="help-menu-item"
            >
              <HelpCircle className="h-4 w-4 mr-3" />
              Help & Support
            </Link>

            {/* Logout */}
            <div className="my-1 border-t border-border"></div>
            
            <button
              onClick={handleLogout}
              className="flex items-center w-full px-4 py-2 text-sm text-destructive hover:bg-destructive/10 hover:text-destructive transition-colors"
              role="menuitem"
              data-testid="logout-menu-item"
            >
              <LogOut className="h-4 w-4 mr-3" />
              Sign Out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default UserMenu;