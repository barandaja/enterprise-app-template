import React from 'react';
import { Link } from 'react-router-dom';
import {
  Bell,
  BellRing,
  Shield,
  User,
  AlertTriangle,
  CheckCircle,
  Info,
  X,
  MoreHorizontal,
  Trash2,
} from 'lucide-react';
import { useClickOutside } from '../hooks/useClickOutside';
import { cn } from '../utils';
import { Button } from './Button';

// Mock notification types - in a real app, these would come from your API/store
interface Notification {
  id: string;
  type: 'security' | 'user' | 'system' | 'info';
  title: string;
  message: string;
  timestamp: string;
  read: boolean;
  priority: 'high' | 'medium' | 'low';
  actionUrl?: string;
  actionLabel?: string;
}

// Mock notifications data - replace with real data from your store/API
const mockNotifications: Notification[] = [
  {
    id: '1',
    type: 'security',
    title: 'Security Alert',
    message: 'Multiple failed login attempts detected for your account',
    timestamp: '5 minutes ago',
    read: false,
    priority: 'high',
    actionUrl: '/security/alerts',
    actionLabel: 'View Details',
  },
  {
    id: '2',
    type: 'user',
    title: 'Profile Updated',
    message: 'Your profile information has been successfully updated',
    timestamp: '2 hours ago',
    read: false,
    priority: 'medium',
  },
  {
    id: '3',
    type: 'system',
    title: 'System Maintenance',
    message: 'Scheduled maintenance will begin at 2:00 AM UTC',
    timestamp: '1 day ago',
    read: true,
    priority: 'medium',
    actionUrl: '/maintenance',
    actionLabel: 'Learn More',
  },
  {
    id: '4',
    type: 'info',
    title: 'New Feature Available',
    message: 'Check out our new dashboard analytics feature',
    timestamp: '2 days ago',
    read: true,
    priority: 'low',
    actionUrl: '/features/analytics',
    actionLabel: 'Explore',
  },
];

interface NotificationCenterProps {
  className?: string;
}

export function NotificationCenter({ className }: NotificationCenterProps) {
  const [isOpen, setIsOpen] = React.useState(false);
  const [notifications, setNotifications] = React.useState(mockNotifications);
  const dropdownRef = useClickOutside<HTMLDivElement>(() => setIsOpen(false));

  const unreadCount = notifications.filter(n => !n.read).length;
  const hasUnread = unreadCount > 0;

  const getNotificationIcon = (type: Notification['type'], priority: Notification['priority']) => {
    const iconClass = cn(
      'h-4 w-4 flex-shrink-0',
      type === 'security' && priority === 'high' && 'text-red-500',
      type === 'security' && priority !== 'high' && 'text-orange-500',
      type === 'user' && 'text-blue-500',
      type === 'system' && 'text-purple-500',
      type === 'info' && 'text-green-500',
    );

    switch (type) {
      case 'security':
        return priority === 'high' ? 
          <AlertTriangle className={iconClass} /> : 
          <Shield className={iconClass} />;
      case 'user':
        return <User className={iconClass} />;
      case 'system':
        return <Info className={iconClass} />;
      case 'info':
        return <CheckCircle className={iconClass} />;
      default:
        return <Info className={iconClass} />;
    }
  };

  const markAsRead = (notificationId: string) => {
    setNotifications(prev => 
      prev.map(n => 
        n.id === notificationId ? { ...n, read: true } : n
      )
    );
  };

  const markAllAsRead = () => {
    setNotifications(prev => 
      prev.map(n => ({ ...n, read: true }))
    );
  };

  const deleteNotification = (notificationId: string) => {
    setNotifications(prev => 
      prev.filter(n => n.id !== notificationId)
    );
  };

  const clearAllNotifications = () => {
    setNotifications([]);
  };

  return (
    <div className={cn('relative', className)} ref={dropdownRef}>
      {/* Notification Bell */}
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setIsOpen(!isOpen)}
        className="relative text-muted-foreground hover:text-foreground"
        aria-label={`Notifications ${hasUnread ? `(${unreadCount} unread)` : ''}`}
        aria-expanded={isOpen}
        data-testid="notification-bell"
      >
        {hasUnread ? (
          <BellRing className="h-4 w-4" />
        ) : (
          <Bell className="h-4 w-4" />
        )}
        
        {/* Notification Badge */}
        {hasUnread && (
          <span 
            className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center font-medium"
            aria-label={`${unreadCount} unread notifications`}
            data-testid="notification-badge"
          >
            {unreadCount > 9 ? '9+' : unreadCount}
          </span>
        )}
      </Button>

      {/* Dropdown Panel */}
      {isOpen && (
        <div 
          className="absolute right-0 top-full mt-2 w-80 bg-popover border border-border rounded-lg shadow-lg z-50"
          role="dialog"
          aria-label="Notifications"
          data-testid="notification-dropdown"
        >
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-semibold text-foreground">Notifications</h3>
              {hasUnread && (
                <span className="bg-primary/10 text-primary text-xs px-2 py-0.5 rounded-full">
                  {unreadCount} new
                </span>
              )}
            </div>
            
            <div className="flex items-center space-x-1">
              {hasUnread && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={markAllAsRead}
                  className="text-xs h-7 px-2"
                  data-testid="mark-all-read"
                >
                  Mark all read
                </Button>
              )}
              
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setIsOpen(false)}
                className="h-7 w-7"
                aria-label="Close notifications"
              >
                <X className="h-3 w-3" />
              </Button>
            </div>
          </div>

          {/* Notifications List */}
          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="px-4 py-8 text-center">
                <Bell className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
                <p className="text-sm text-muted-foreground">No notifications</p>
              </div>
            ) : (
              <div className="py-1">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={cn(
                      'group flex items-start space-x-3 px-4 py-3 hover:bg-accent/50 transition-colors',
                      !notification.read && 'bg-primary/5'
                    )}
                    data-testid={`notification-${notification.id}`}
                  >
                    {/* Icon */}
                    <div className="mt-1">
                      {getNotificationIcon(notification.type, notification.priority)}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between">
                        <div className="flex-1 min-w-0">
                          <p className={cn(
                            'text-sm font-medium truncate',
                            notification.read ? 'text-muted-foreground' : 'text-foreground'
                          )}>
                            {notification.title}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                            {notification.message}
                          </p>
                          <p className="text-xs text-muted-foreground/70 mt-1">
                            {notification.timestamp}
                          </p>
                        </div>

                        {/* Actions */}
                        <div className="flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity">
                          {!notification.read && (
                            <Button
                              variant="ghost"
                              size="icon"
                              onClick={() => markAsRead(notification.id)}
                              className="h-6 w-6"
                              aria-label="Mark as read"
                            >
                              <CheckCircle className="h-3 w-3" />
                            </Button>
                          )}
                          
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={() => deleteNotification(notification.id)}
                            className="h-6 w-6 text-muted-foreground hover:text-destructive"
                            aria-label="Delete notification"
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>

                      {/* Action Button */}
                      {notification.actionUrl && notification.actionLabel && (
                        <div className="mt-2">
                          <Button
                            variant="outline"
                            size="sm"
                            asChild
                            className="h-7 text-xs"
                          >
                            <Link 
                              to={notification.actionUrl}
                              onClick={() => {
                                markAsRead(notification.id);
                                setIsOpen(false);
                              }}
                            >
                              {notification.actionLabel}
                            </Link>
                          </Button>
                        </div>
                      )}
                    </div>

                    {/* Unread Indicator */}
                    {!notification.read && (
                      <div className="mt-2">
                        <div className="h-2 w-2 bg-primary rounded-full"></div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          {notifications.length > 0 && (
            <div className="px-4 py-3 border-t border-border bg-muted/30">
              <div className="flex items-center justify-between">
                <Button
                  variant="ghost"
                  size="sm"
                  asChild
                  className="text-xs h-7"
                >
                  <Link 
                    to="/notifications" 
                    onClick={() => setIsOpen(false)}
                  >
                    View all notifications
                  </Link>
                </Button>
                
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={clearAllNotifications}
                  className="text-xs h-7 text-muted-foreground hover:text-destructive"
                >
                  Clear all
                </Button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default NotificationCenter;