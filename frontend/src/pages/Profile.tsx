import React from 'react';
import { Link } from 'react-router-dom';
import { 
  User, 
  Mail, 
  Calendar, 
  Shield, 
  Edit, 
  Settings, 
  Activity,
  MapPin,
  Phone,
  Key,
  UserCog,
  Clock,
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import { useAuthUser } from '../stores/authStore';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/Card';
import { Button } from '../components/Button';
import { Alert } from '../components/Alert';
import type { PageProps, BreadcrumbItem } from '../types';

// Mock activity and statistics data - in a real app, this would come from APIs
const mockStats = {
  loginCount: 156,
  lastLogin: '2024-01-30T09:15:00Z',
  accountCreated: '2023-06-01T00:00:00Z',
  profileViews: 42,
  projectsCompleted: 23,
  tasksDone: 89,
};

const recentActivities = [
  {
    id: '1',
    action: 'Updated profile information',
    timestamp: '2024-02-01T14:20:00Z',
    type: 'profile' as const,
  },
  {
    id: '2',
    action: 'Completed project review',
    timestamp: '2024-01-31T16:45:00Z',
    type: 'work' as const,
  },
  {
    id: '3',
    action: 'Logged in from new device',
    timestamp: '2024-01-30T09:15:00Z',
    type: 'security' as const,
  },
  {
    id: '4',
    action: 'Changed password',
    timestamp: '2024-01-28T11:30:00Z',
    type: 'security' as const,
  },
];

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function formatRelativeTime(dateString: string) {
  const date = new Date(dateString);
  const now = new Date();
  const diffInHours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));
  
  if (diffInHours < 1) return 'Just now';
  if (diffInHours < 24) return `${diffInHours} hours ago`;
  
  const diffInDays = Math.floor(diffInHours / 24);
  if (diffInDays < 7) return `${diffInDays} days ago`;
  
  const diffInWeeks = Math.floor(diffInDays / 7);
  return `${diffInWeeks} weeks ago`;
}

function getInitials(firstName?: string, lastName?: string) {
  const firstInitial = firstName?.charAt(0) || '';
  const lastInitial = lastName?.charAt(0) || '';
  return `${firstInitial}${lastInitial}`.toUpperCase() || 'U';
}

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  color?: 'blue' | 'green' | 'purple' | 'orange';
  description?: string;
}

function StatCard({ title, value, icon: Icon, color = 'blue', description }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300',
    green: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300',
    purple: 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300',
    orange: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-300',
  };

  return (
    <Card>
      <CardContent className="flex items-center space-x-4 p-6">
        <div className={`h-12 w-12 rounded-lg flex items-center justify-center ${colorClasses[color]}`}>
          <Icon className="h-6 w-6" />
        </div>
        <div className="flex-1">
          <p className="text-2xl font-bold text-foreground">{value}</p>
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          {description && (
            <p className="text-xs text-muted-foreground mt-1">{description}</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function Profile({ className }: PageProps) {
  const user = useAuthUser();

  // Generate breadcrumbs
  const breadcrumbs: BreadcrumbItem[] = [
    { label: 'Profile', href: '/profile' }
  ];

  // Handle missing user data gracefully
  if (!user) {
    return (
      <Alert variant="warning" className="mb-6">
        <AlertCircle className="h-4 w-4" />
        <div>
          <h4 className="font-semibold">Profile data unavailable</h4>
          <p>Unable to load user profile information. Please try refreshing the page.</p>
        </div>
      </Alert>
    );
  }

  return (
    <div className={className}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Profile Overview</h1>
            <p className="text-muted-foreground">
              Manage your account information and view your activity
            </p>
          </div>
          <div className="flex items-center space-x-3 mt-4 sm:mt-0">
            <Button asChild variant="outline">
              <Link to="/profile/settings">
                <Settings className="h-4 w-4" />
                Settings
              </Link>
            </Button>
            <Button asChild>
              <Link to="/profile/security">
                <Key className="h-4 w-4" />
                Security
              </Link>
            </Button>
          </div>
        </div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Logins"
            value={mockStats.loginCount}
            icon={Activity}
            color="blue"
            description="Since account creation"
          />
          <StatCard
            title="Profile Views"
            value={mockStats.profileViews}
            icon={User}
            color="green"
            description="Last 30 days"
          />
          <StatCard
            title="Projects"
            value={mockStats.projectsCompleted}
            icon={CheckCircle}
            color="purple"
            description="Completed projects"
          />
          <StatCard
            title="Tasks Done"
            value={mockStats.tasksDone}
            icon={UserCog}
            color="orange"
            description="This month"
          />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Profile Summary Card */}
          <div className="lg:col-span-1">
            <Card>
              <CardContent className="text-center p-6">
                {/* Avatar */}
                <div className="mb-6">
                  {user.avatar ? (
                    <img
                      src={user.avatar}
                      alt={`${user.firstName || ''} ${user.lastName || ''}`}
                      className="w-24 h-24 rounded-full mx-auto object-cover border-4 border-background shadow-lg"
                    />
                  ) : (
                    <div className="w-24 h-24 rounded-full mx-auto bg-primary/10 flex items-center justify-center border-4 border-background shadow-lg">
                      <span className="text-2xl font-bold text-primary">
                        {getInitials(user.firstName, user.lastName)}
                      </span>
                    </div>
                  )}
                </div>

                {/* Basic Info */}
                <div className="mb-6">
                  <h2 className="text-2xl font-bold text-foreground mb-1">
                    {user.firstName || 'Unknown'} {user.lastName || 'User'}
                  </h2>
                  <div className="flex items-center justify-center space-x-2 mb-4">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      user.role === 'admin' 
                        ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300'
                        : 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300'
                    }`}>
                      <Shield className="h-3 w-3 mr-1" />
                      {user.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'User'}
                    </span>
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                      user.isActive
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300'
                        : 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300'
                    }`}>
                      {user.isActive ? 'Active' : 'Inactive'}
                    </span>
                  </div>
                </div>

                {/* Contact Info */}
                <div className="space-y-3 text-left">
                  <div className="flex items-center space-x-3 text-sm">
                    <Mail className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <span className="text-foreground truncate">{user.email || 'No email'}</span>
                  </div>
                  <div className="flex items-center space-x-3 text-sm">
                    <Calendar className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <span className="text-foreground">
                      Joined {formatDate(user.createdAt)}
                    </span>
                  </div>
                  <div className="flex items-center space-x-3 text-sm">
                    <Clock className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <span className="text-foreground">
                      Last login {formatRelativeTime(mockStats.lastLogin)}
                    </span>
                  </div>
                </div>
              </CardContent>
              <CardFooter className="flex space-x-2">
                <Button asChild variant="outline" size="sm" className="flex-1">
                  <Link to="/profile/settings">
                    <Edit className="h-4 w-4" />
                    Edit Profile
                  </Link>
                </Button>
              </CardFooter>
            </Card>
          </div>

          {/* Account Information and Activity */}
          <div className="lg:col-span-2 space-y-6">
            {/* Account Details */}
            <Card>
              <CardHeader>
                <CardTitle>Account Information</CardTitle>
                <CardDescription>
                  Your account details and verification status
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Full Name
                    </label>
                    <p className="text-foreground font-medium">
                      {user.firstName || 'Unknown'} {user.lastName || 'User'}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Email Address
                    </label>
                    <div className="flex items-center space-x-2">
                      <p className="text-foreground font-medium">{user.email || 'No email'}</p>
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      User Role
                    </label>
                    <p className="text-foreground font-medium capitalize">{user.role}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Account Status
                    </label>
                    <p className="text-foreground font-medium">
                      {user.isActive ? 'Active' : 'Inactive'}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Member Since
                    </label>
                    <p className="text-foreground font-medium">
                      {formatDate(user.createdAt)}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-muted-foreground">
                      Last Updated
                    </label>
                    <p className="text-foreground font-medium">
                      {formatDate(user.updatedAt)}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader>
                <div className="flex items-center space-x-2">
                  <Activity className="h-5 w-5" />
                  <CardTitle>Recent Activity</CardTitle>
                </div>
                <CardDescription>
                  Your recent account and security activities
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {recentActivities.map((activity) => (
                    <div key={activity.id} className="flex items-start space-x-3 pb-4 border-b border-border last:border-b-0 last:pb-0">
                      <div className={`h-2 w-2 rounded-full mt-2 flex-shrink-0 ${
                        activity.type === 'security' 
                          ? 'bg-yellow-500' 
                          : activity.type === 'work'
                          ? 'bg-blue-500'
                          : 'bg-green-500'
                      }`} />
                      <div className="flex-1">
                        <p className="text-sm font-medium text-foreground">
                          {activity.action}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {formatRelativeTime(activity.timestamp)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" size="sm" className="w-full">
                  View full activity log
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>

        {/* Quick Actions */}
        <Card>
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>
              Common profile and account management tasks
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <Button asChild variant="outline" className="h-auto p-4 flex-col space-y-2">
                <Link to="/profile/settings">
                  <Settings className="h-6 w-6" />
                  <div className="text-center">
                    <p className="font-medium">Profile Settings</p>
                    <p className="text-xs text-muted-foreground">Update preferences</p>
                  </div>
                </Link>
              </Button>
              
              <Button asChild variant="outline" className="h-auto p-4 flex-col space-y-2">
                <Link to="/profile/security">
                  <Key className="h-6 w-6" />
                  <div className="text-center">
                    <p className="font-medium">Security Settings</p>
                    <p className="text-xs text-muted-foreground">Password & 2FA</p>
                  </div>
                </Link>
              </Button>
              
              <Button asChild variant="outline" className="h-auto p-4 flex-col space-y-2">
                <Link to="/privacy-settings">
                  <Shield className="h-6 w-6" />
                  <div className="text-center">
                    <p className="font-medium">Privacy Settings</p>
                    <p className="text-xs text-muted-foreground">Data & privacy</p>
                  </div>
                </Link>
              </Button>
              
              <Button asChild variant="outline" className="h-auto p-4 flex-col space-y-2">
                <Link to="/activity">
                  <Activity className="h-6 w-6" />
                  <div className="text-center">
                    <p className="font-medium">Activity Log</p>
                    <p className="text-xs text-muted-foreground">View all activity</p>
                  </div>
                </Link>
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export default Profile;