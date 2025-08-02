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
  Phone
} from 'lucide-react';
import { PageProps } from '../types';

// Mock user data - in a real app, this would come from a store or API
const mockUser = {
  id: '1',
  firstName: 'John',
  lastName: 'Doe',
  email: 'john.doe@example.com',
  avatar: '',
  role: 'admin' as const,
  isActive: true,
  createdAt: '2024-01-15T10:30:00Z',
  updatedAt: '2024-02-01T14:20:00Z',
  phone: '+1 (555) 123-4567',
  location: 'San Francisco, CA',
  bio: 'Senior Frontend Developer with 5+ years of experience building modern web applications. Passionate about React, TypeScript, and creating exceptional user experiences.',
  department: 'Engineering',
  position: 'Senior Frontend Developer',
  joinDate: '2023-06-01',
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

function getInitials(firstName: string, lastName: string) {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
}

function Profile({ className }: PageProps) {
  return (
    <div className="container py-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-foreground mb-2">Profile</h1>
          <p className="text-muted-foreground">
            Manage your account information and preferences
          </p>
        </div>
        <div className="flex items-center space-x-3 mt-4 sm:mt-0">
          <Link to="/profile/edit" className="btn-primary">
            <Edit className="h-4 w-4" />
            Edit Profile
          </Link>
          <Link to="/privacy" className="btn-outline">
            <Shield className="h-4 w-4" />
            Privacy Settings
          </Link>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Card */}
        <div className="lg:col-span-1">
          <div className="card">
            <div className="card-content text-center">
              {/* Avatar */}
              <div className="mb-6">
                {mockUser.avatar ? (
                  <img
                    src={mockUser.avatar}
                    alt={`${mockUser.firstName} ${mockUser.lastName}`}
                    className="w-24 h-24 rounded-full mx-auto object-cover border-4 border-background shadow-lg"
                  />
                ) : (
                  <div className="w-24 h-24 rounded-full mx-auto bg-primary/10 flex items-center justify-center border-4 border-background shadow-lg">
                    <span className="text-2xl font-bold text-primary">
                      {getInitials(mockUser.firstName, mockUser.lastName)}
                    </span>
                  </div>
                )}
              </div>

              {/* Basic Info */}
              <div className="mb-6">
                <h2 className="text-2xl font-bold text-foreground mb-1">
                  {mockUser.firstName} {mockUser.lastName}
                </h2>
                <p className="text-muted-foreground mb-2">{mockUser.position}</p>
                <div className="flex items-center justify-center space-x-2">
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    mockUser.role === 'admin' 
                      ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300'
                      : 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300'
                  }`}>
                    <Shield className="h-3 w-3 mr-1" />
                    {mockUser.role.charAt(0).toUpperCase() + mockUser.role.slice(1)}
                  </span>
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                    mockUser.isActive
                      ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300'
                      : 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300'
                  }`}>
                    {mockUser.isActive ? 'Active' : 'Inactive'}
                  </span>
                </div>
              </div>

              {/* Bio */}
              {mockUser.bio && (
                <div className="mb-6">
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {mockUser.bio}
                  </p>
                </div>
              )}

              {/* Contact Info */}
              <div className="space-y-3 text-left">
                <div className="flex items-center space-x-3 text-sm">
                  <Mail className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <span className="text-foreground">{mockUser.email}</span>
                </div>
                {mockUser.phone && (
                  <div className="flex items-center space-x-3 text-sm">
                    <Phone className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <span className="text-foreground">{mockUser.phone}</span>
                  </div>
                )}
                {mockUser.location && (
                  <div className="flex items-center space-x-3 text-sm">
                    <MapPin className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <span className="text-foreground">{mockUser.location}</span>
                  </div>
                )}
                <div className="flex items-center space-x-3 text-sm">
                  <Calendar className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                  <span className="text-foreground">
                    Joined {formatDate(mockUser.createdAt)}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Details & Activity */}
        <div className="lg:col-span-2 space-y-6">
          {/* Account Details */}
          <div className="card">
            <div className="card-header">
              <h3 className="card-title">Account Details</h3>
              <p className="card-description">
                Your account information and work details
              </p>
            </div>
            <div className="card-content">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Full Name
                  </label>
                  <p className="text-foreground font-medium">
                    {mockUser.firstName} {mockUser.lastName}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Email Address
                  </label>
                  <p className="text-foreground font-medium">{mockUser.email}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Department
                  </label>
                  <p className="text-foreground font-medium">{mockUser.department}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Position
                  </label>
                  <p className="text-foreground font-medium">{mockUser.position}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Join Date
                  </label>
                  <p className="text-foreground font-medium">
                    {formatDate(mockUser.joinDate + 'T00:00:00Z')}
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-muted-foreground">
                    Last Updated
                  </label>
                  <p className="text-foreground font-medium">
                    {formatDate(mockUser.updatedAt)}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="card">
            <div className="card-header">
              <div className="flex items-center space-x-2">
                <Activity className="h-5 w-5" />
                <h3 className="card-title">Recent Activity</h3>
              </div>
              <p className="card-description">
                Your recent account and work activities
              </p>
            </div>
            <div className="card-content">
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
            </div>
            <div className="card-footer">
              <button className="btn-ghost btn-sm w-full">
                View all activities
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Profile;