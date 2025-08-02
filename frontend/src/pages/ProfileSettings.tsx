import React, { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { z } from 'zod';
import {
  User,
  Save,
  X,
  Upload,
  Globe,
  Bell,
  Monitor,
  Moon,
  Sun,
  Smartphone,
  Mail,
  ArrowLeft,
  AlertCircle,
  CheckCircle,
  Camera
} from 'lucide-react';
import { useAuthUser, useAuthActions } from '../stores/authStore';
import { useThemeStore } from '../stores/themeStore';
import { ThemeToggle } from '../components/ThemeToggle';
import { MainLayout } from '../layouts/MainLayout';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/Card';
import { Button } from '../components/Button';
import { Input, FormField } from '../components/Input';
import { Alert } from '../components/Alert';
import { SecureFileUpload } from '../components/SecureFileUpload';
import { useForm, validationSchemas } from '../hooks/useForm';
import { useToast } from '../hooks/useToast';
import type { PageProps, BreadcrumbItem, UpdateProfileData, NotificationPreferences, Theme } from '../types';

// Validation schema for profile form
const profileSchema = z.object({
  firstName: validationSchemas.name,
  lastName: validationSchemas.name,
  phone: z.string().optional(),
  bio: z.string().max(500, 'Bio must be less than 500 characters').optional(),
  location: z.string().max(100, 'Location must be less than 100 characters').optional(),
});

type ProfileFormData = z.infer<typeof profileSchema>;

// Mock data for settings - in real app, would come from API/store
const mockNotificationPreferences: NotificationPreferences = {
  email: {
    securityAlerts: true,
    accountUpdates: true,
    marketing: false,
    productUpdates: true,
  },
  push: {
    securityAlerts: true,
    accountUpdates: false,
    reminders: true,
  },
  inApp: {
    securityAlerts: true,
    accountUpdates: true,
    systemNotifications: true,
  },
};

const languages = [
  { value: 'en', label: 'English' },
  { value: 'es', label: 'Español' },
  { value: 'fr', label: 'Français' },
  { value: 'de', label: 'Deutsch' },
  { value: 'pt', label: 'Português' },
];

const timezones = [
  { value: 'America/New_York', label: 'Eastern Time (ET)' },
  { value: 'America/Chicago', label: 'Central Time (CT)' },
  { value: 'America/Denver', label: 'Mountain Time (MT)' },
  { value: 'America/Los_Angeles', label: 'Pacific Time (PT)' },
  { value: 'Europe/London', label: 'Greenwich Mean Time (GMT)' },
  { value: 'Europe/Paris', label: 'Central European Time (CET)' },
  { value: 'Asia/Tokyo', label: 'Japan Standard Time (JST)' },
];

interface ToggleSwitchProps {
  id: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}

function ToggleSwitch({ id, checked, onChange, disabled = false }: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-labelledby={`${id}-label`}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`
        relative inline-flex h-6 w-11 items-center rounded-full transition-colors
        focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2
        ${checked ? 'bg-primary' : 'bg-muted'}
        ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
      `}
    >
      <span
        className={`
          inline-block h-4 w-4 transform rounded-full bg-background transition-transform
          ${checked ? 'translate-x-6' : 'translate-x-1'}
        `}
      />
    </button>
  );
}

function ProfileSettings({ className }: PageProps) {
  const user = useAuthUser();
  const { updateProfile } = useAuthActions();
  const { theme, setTheme } = useThemeStore();
  const { showToast } = useToast();
  
  // Local state for preferences
  const [notifications, setNotifications] = useState<NotificationPreferences>(mockNotificationPreferences);
  const [selectedLanguage, setSelectedLanguage] = useState('en');
  const [selectedTimezone, setSelectedTimezone] = useState('America/New_York');
  const [avatarFile, setAvatarFile] = useState<File | null>(null);
  const [avatarPreview, setAvatarPreview] = useState<string | null>(null);

  // Generate breadcrumbs
  const breadcrumbs: BreadcrumbItem[] = [
    { label: 'Profile', href: '/profile' },
    { label: 'Settings' },
  ];

  // Profile form setup
  const profileForm = useForm<ProfileFormData>({
    schema: profileSchema,
    defaultValues: {
      firstName: user?.firstName || '',
      lastName: user?.lastName || '',
      phone: '',
      bio: '',
      location: '',
    },
    onSubmit: async (data) => {
      try {
        const updateData: UpdateProfileData = {
          firstName: data.firstName,
          lastName: data.lastName,
          phone: data.phone || undefined,
          bio: data.bio || undefined,
          location: data.location || undefined,
        };

        // Include avatar if uploaded
        if (avatarFile) {
          // In a real app, you would upload the file and get a URL
          updateData.avatar = avatarPreview || undefined;
        }

        await updateProfile(updateData);
        showToast({
          title: 'Profile Updated',
          description: 'Your profile information has been successfully updated.',
          variant: 'success',
        });
      } catch (error) {
        showToast({
          title: 'Update Failed',
          description: 'Failed to update profile. Please try again.',
          variant: 'error',
        });
      }
    },
  });

  // Handle avatar upload
  const handleAvatarUpload = useCallback((files: File[]) => {
    if (files.length > 0) {
      const file = files[0];
      setAvatarFile(file);
      
      // Create preview URL
      const reader = new FileReader();
      reader.onload = (e) => {
        setAvatarPreview(e.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  }, []);

  // Handle notification preference changes
  const updateNotificationPreference = useCallback((
    category: keyof NotificationPreferences,
    key: string,
    value: boolean
  ) => {
    setNotifications(prev => ({
      ...prev,
      [category]: {
        ...prev[category],
        [key]: value,
      },
    }));
  }, []);

  // Save preferences
  const savePreferences = useCallback(async () => {
    try {
      // In a real app, you would call an API to save preferences
      await new Promise(resolve => setTimeout(resolve, 1000)); // Simulate API call
      
      showToast({
        title: 'Preferences Saved',
        description: 'Your preferences have been successfully updated.',
        variant: 'success',
      });
    } catch (error) {
      showToast({
        title: 'Save Failed',
        description: 'Failed to save preferences. Please try again.',
        variant: 'error',
      });
    }
  }, [showToast]);

  if (!user) {
    return (
      <MainLayout breadcrumbs={breadcrumbs}>
        <Alert variant="warning">
          <AlertCircle className="h-4 w-4" />
          <div>
            <h4 className="font-semibold">Access Denied</h4>
            <p>You must be logged in to access profile settings.</p>
          </div>
        </Alert>
      </MainLayout>
    );
  }

  return (
    <MainLayout breadcrumbs={breadcrumbs} className={className}>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Profile Settings</h1>
            <p className="text-muted-foreground">
              Manage your personal information and account preferences
            </p>
          </div>
          <Button asChild variant="outline">
            <Link to="/profile">
              <ArrowLeft className="h-4 w-4" />
              Back to Profile
            </Link>
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Profile Information */}
          <div className="lg:col-span-2 space-y-6">
            {/* Personal Information */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <User className="h-5 w-5" />
                  <span>Personal Information</span>
                </CardTitle>
                <CardDescription>
                  Update your personal details and contact information
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={profileForm.handleSubmit} className="space-y-4">
                  {/* Avatar Upload */}
                  <div>
                    <label className="text-sm font-medium text-foreground mb-2 block">
                      Profile Picture
                    </label>
                    <div className="flex items-center space-x-4">
                      <div className="relative">
                        {avatarPreview || user.avatar ? (
                          <img
                            src={avatarPreview || user.avatar}
                            alt="Profile"
                            className="w-16 h-16 rounded-full object-cover border-2 border-border"
                          />
                        ) : (
                          <div className="w-16 h-16 rounded-full bg-primary/10 flex items-center justify-center border-2 border-border">
                            <User className="h-8 w-8 text-primary" />
                          </div>
                        )}
                        <div className="absolute -bottom-1 -right-1 p-1 bg-background border border-border rounded-full">
                          <Camera className="h-3 w-3 text-muted-foreground" />
                        </div>
                      </div>
                      <div className="flex-1">
                        <SecureFileUpload
                          onUpload={handleAvatarUpload}
                          accept="image/*"
                          maxSize={5 * 1024 * 1024} // 5MB
                          className="w-full"
                        >
                          <Button type="button" variant="outline" size="sm">
                            <Upload className="h-4 w-4" />
                            Upload Photo
                          </Button>
                        </SecureFileUpload>
                        <p className="text-xs text-muted-foreground mt-1">
                          JPG, PNG up to 5MB
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <FormField
                      label="First Name"
                      error={profileForm.getFieldError('firstName')}
                      required
                    >
                      <Input
                        {...profileForm.register('firstName')}
                        placeholder="Enter your first name"
                      />
                    </FormField>

                    <FormField
                      label="Last Name"
                      error={profileForm.getFieldError('lastName')}
                      required
                    >
                      <Input
                        {...profileForm.register('lastName')}
                        placeholder="Enter your last name"
                      />
                    </FormField>
                  </div>

                  <FormField
                    label="Phone Number"
                    error={profileForm.getFieldError('phone')}
                  >
                    <Input
                      {...profileForm.register('phone')}
                      type="tel"
                      placeholder="+1 (555) 123-4567"
                    />
                  </FormField>

                  <FormField
                    label="Location"
                    error={profileForm.getFieldError('location')}
                  >
                    <Input
                      {...profileForm.register('location')}
                      placeholder="City, State/Country"
                    />
                  </FormField>

                  <FormField
                    label="Bio"
                    error={profileForm.getFieldError('bio')}
                    description="Tell us a bit about yourself (optional)"
                  >
                    <textarea
                      {...profileForm.register('bio')}
                      rows={4}
                      className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary resize-none"
                      placeholder="Write a brief description about yourself..."
                    />
                  </FormField>
                </form>
              </CardContent>
              <CardFooter className="flex justify-between">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => profileForm.reset()}
                >
                  <X className="h-4 w-4" />
                  Reset
                </Button>
                <Button
                  onClick={profileForm.handleSubmit}
                  disabled={profileForm.isSubmitting || !profileForm.isDirty}
                  loading={profileForm.isSubmitting}
                >
                  <Save className="h-4 w-4" />
                  Save Changes
                </Button>
              </CardFooter>
            </Card>

            {/* Account Preferences */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Globe className="h-5 w-5" />
                  <span>Account Preferences</span>
                </CardTitle>
                <CardDescription>
                  Customize your account settings and regional preferences
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Theme Selection */}
                <div>
                  <label className="text-sm font-medium text-foreground mb-3 block">
                    Theme Preference
                  </label>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm text-foreground font-medium">Appearance</p>
                        <p className="text-xs text-muted-foreground">
                          Choose your preferred theme or follow system settings
                        </p>
                      </div>
                      <ThemeToggle 
                        layout="buttons" 
                        showLabels 
                        includeSystem 
                        size="md"
                        variant="outline"
                      />
                    </div>
                    
                    {/* Current theme display */}
                    <div className="flex items-center space-x-2 p-3 bg-muted/50 rounded-lg">
                      <div className="flex items-center space-x-2">
                        {theme === 'light' && <Sun className="h-4 w-4 text-yellow-500" />}
                        {theme === 'dark' && <Moon className="h-4 w-4 text-blue-500" />}
                        {theme === 'system' && <Monitor className="h-4 w-4 text-primary" />}
                        <span className="text-sm text-muted-foreground">
                          Current theme: <span className="font-medium text-foreground capitalize">{theme}</span>
                          {theme === 'system' && (
                            <span className="ml-1">
                              (using {theme === 'system' ? 'system' : 'manual'} preference)
                            </span>
                          )}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Language & Timezone */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <FormField label="Language">
                    <select
                      value={selectedLanguage}
                      onChange={(e) => setSelectedLanguage(e.target.value)}
                      className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                    >
                      {languages.map((lang) => (
                        <option key={lang.value} value={lang.value}>
                          {lang.label}
                        </option>
                      ))}
                    </select>
                  </FormField>

                  <FormField label="Timezone">
                    <select
                      value={selectedTimezone}
                      onChange={(e) => setSelectedTimezone(e.target.value)}
                      className="w-full px-3 py-2 border border-border rounded-md focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary"
                    >
                      {timezones.map((tz) => (
                        <option key={tz.value} value={tz.value}>
                          {tz.label}
                        </option>
                      ))}
                    </select>
                  </FormField>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Notification Settings */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Bell className="h-5 w-5" />
                  <span>Notifications</span>
                </CardTitle>
                <CardDescription>
                  Manage how you receive notifications
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Email Notifications */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-3 flex items-center space-x-2">
                    <Mail className="h-4 w-4" />
                    <span>Email Notifications</span>
                  </h4>
                  <div className="space-y-3">
                    {Object.entries(notifications.email).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between">
                        <label
                          id={`email-${key}-label`}
                          className="text-sm text-foreground cursor-pointer"
                        >
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </label>
                        <ToggleSwitch
                          id={`email-${key}`}
                          checked={value}
                          onChange={(checked) => updateNotificationPreference('email', key, checked)}
                        />
                      </div>
                    ))}
                  </div>
                </div>

                {/* Push Notifications */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-3 flex items-center space-x-2">
                    <Smartphone className="h-4 w-4" />
                    <span>Push Notifications</span>
                  </h4>
                  <div className="space-y-3">
                    {Object.entries(notifications.push).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between">
                        <label
                          id={`push-${key}-label`}
                          className="text-sm text-foreground cursor-pointer"
                        >
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </label>
                        <ToggleSwitch
                          id={`push-${key}`}
                          checked={value}
                          onChange={(checked) => updateNotificationPreference('push', key, checked)}
                        />
                      </div>
                    ))}
                  </div>
                </div>

                {/* In-App Notifications */}
                <div>
                  <h4 className="text-sm font-medium text-foreground mb-3 flex items-center space-x-2">
                    <Bell className="h-4 w-4" />
                    <span>In-App Notifications</span>
                  </h4>
                  <div className="space-y-3">
                    {Object.entries(notifications.inApp).map(([key, value]) => (
                      <div key={key} className="flex items-center justify-between">
                        <label
                          id={`inapp-${key}-label`}
                          className="text-sm text-foreground cursor-pointer"
                        >
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </label>
                        <ToggleSwitch
                          id={`inapp-${key}`}
                          checked={value}
                          onChange={(checked) => updateNotificationPreference('inApp', key, checked)}
                        />
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
              <CardFooter>
                <Button onClick={savePreferences} className="w-full">
                  <Save className="h-4 w-4" />
                  Save Preferences
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}

export default ProfileSettings;