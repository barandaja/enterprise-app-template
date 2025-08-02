import React, { useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { z } from 'zod';
import {
  Key,
  Shield,
  Smartphone,
  Monitor,
  AlertTriangle,
  ArrowLeft,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  Clock,
  MapPin,
  Trash2,
  Download,
  Lock,
  Unlock,
  AlertCircle,
  QrCode
} from 'lucide-react';
import { useAuthUser, useAuthActions } from '../stores/authStore';
import { MainLayout } from '../layouts/MainLayout';
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from '../components/Card';
import { Button } from '../components/Button';
import { Input, FormField } from '../components/Input';
import { Alert } from '../components/Alert';
import { Modal, ModalHeader, ModalTitle, ModalContent, ModalFooter } from '../components/Modal';
import { SecurePasswordInput, PasswordStrengthMeter } from '../components/SecurePasswordInput';
import { useForm, validationSchemas, createPasswordConfirmationSchema } from '../hooks/useForm';
import { useToast } from '../hooks/useToast';
import type { PageProps, BreadcrumbItem, ChangePasswordData, ActiveSession, SecurityLog } from '../types';

// Password change validation schema
const passwordChangeSchema = createPasswordConfirmationSchema(
  z.object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: validationSchemas.password,
  })
);

type PasswordChangeFormData = z.infer<typeof passwordChangeSchema>;

// Mock data - in real app, would come from APIs
const mockActiveSessions: ActiveSession[] = [
  {
    id: '1',
    deviceName: 'MacBook Pro',
    browser: 'Chrome 120.0',
    os: 'macOS 14.2',
    location: 'San Francisco, CA',
    ipAddress: '192.168.1.100',
    lastActive: '2024-01-30T14:30:00Z',
    isCurrent: true,
  },
  {
    id: '2',
    deviceName: 'iPhone 15',
    browser: 'Safari Mobile',
    os: 'iOS 17.2',
    location: 'San Francisco, CA',
    ipAddress: '192.168.1.101',
    lastActive: '2024-01-30T12:15:00Z',
    isCurrent: false,
  },
  {
    id: '3',
    deviceName: 'Windows Desktop',
    browser: 'Firefox 121.0',
    os: 'Windows 11',
    location: 'Oakland, CA',
    ipAddress: '192.168.2.50',
    lastActive: '2024-01-29T18:45:00Z',
    isCurrent: false,
  },
];

const mockSecurityLogs: SecurityLog[] = [
  {
    id: '1',
    event: 'Password Changed',
    description: 'Password was successfully changed',
    timestamp: '2024-01-28T11:30:00Z',
    ipAddress: '192.168.1.100',
    location: 'San Francisco, CA',
    success: true,
  },
  {
    id: '2',
    event: 'Login Attempt',
    description: 'Successful login from new device',
    timestamp: '2024-01-27T09:15:00Z',
    ipAddress: '192.168.1.101',
    location: 'San Francisco, CA',
    success: true,
  },
  {
    id: '3',
    event: 'Failed Login',
    description: 'Multiple failed login attempts detected',
    timestamp: '2024-01-26T16:22:00Z',
    ipAddress: '203.0.113.1',
    location: 'Unknown',
    success: false,
  },
  {
    id: '4',
    event: '2FA Enabled',
    description: 'Two-factor authentication was enabled',
    timestamp: '2024-01-25T14:10:00Z',
    ipAddress: '192.168.1.100',
    location: 'San Francisco, CA',
    success: true,
  },
];

function formatDate(dateString: string) {
  return new Date(dateString).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
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

function SecuritySettings({ className }: PageProps) {
  const user = useAuthUser();
  const { showToast } = useToast();
  
  // State management
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [showPasswordModal, setShowPasswordModal] = useState(false);
  const [showTwoFactorModal, setShowTwoFactorModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [sessionToDelete, setSessionToDelete] = useState<string | null>(null);
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');

  // Generate breadcrumbs
  const breadcrumbs: BreadcrumbItem[] = [
    { label: 'Profile', href: '/profile' },
    { label: 'Security Settings' },
  ];

  // Password change form
  const passwordForm = useForm<PasswordChangeFormData>({
    schema: passwordChangeSchema,
    onSubmit: async (data) => {
      try {
        // In a real app, you would call an API to change the password
        await new Promise(resolve => setTimeout(resolve, 2000)); // Simulate API call
        
        showToast({
          title: 'Password Changed',
          description: 'Your password has been successfully updated.',
          variant: 'success',
        });
        
        setShowPasswordModal(false);
        passwordForm.reset();
      } catch (error) {
        showToast({
          title: 'Password Change Failed',
          description: 'Failed to change password. Please try again.',
          variant: 'error',
        });
      }
    },
  });

  // Handle 2FA setup
  const handleTwoFactorSetup = useCallback(async () => {
    try {
      // In a real app, you would call an API to generate QR code
      const mockQrUrl = 'data:image/svg+xml;base64,' + btoa(`
        <svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
          <rect width="200" height="200" fill="white"/>
          <text x="100" y="100" text-anchor="middle" font-size="14">QR Code Placeholder</text>
          <text x="100" y="120" text-anchor="middle" font-size="10">Scan with authenticator app</text>
        </svg>
      `);
      
      setQrCodeUrl(mockQrUrl);
      setShowTwoFactorModal(true);
    } catch (error) {
      showToast({
        title: 'Setup Failed',
        description: 'Failed to generate 2FA setup. Please try again.',
        variant: 'error',
      });
    }
  }, [showToast]);

  // Enable/disable 2FA
  const toggleTwoFactor = useCallback(async () => {
    try {
      if (twoFactorEnabled) {
        // Disable 2FA
        setTwoFactorEnabled(false);
        showToast({
          title: '2FA Disabled',
          description: 'Two-factor authentication has been disabled.',
          variant: 'success',
        });
      } else {
        // Start 2FA setup process
        await handleTwoFactorSetup();
      }
    } catch (error) {
      showToast({
        title: 'Operation Failed',
        description: 'Failed to update 2FA settings. Please try again.',
        variant: 'error',
      });
    }
  }, [twoFactorEnabled, handleTwoFactorSetup, showToast]);

  // Complete 2FA setup
  const completeTwoFactorSetup = useCallback(async () => {
    try {
      // In a real app, you would verify the TOTP code and enable 2FA
      setTwoFactorEnabled(true);
      setShowTwoFactorModal(false);
      showToast({
        title: '2FA Enabled',
        description: 'Two-factor authentication has been successfully enabled.',
        variant: 'success',
      });
    } catch (error) {
      showToast({
        title: 'Setup Failed',
        description: 'Failed to complete 2FA setup. Please try again.',
        variant: 'error',
      });
    }
  }, [showToast]);

  // Terminate session
  const terminateSession = useCallback(async (sessionId: string) => {
    try {
      // In a real app, you would call an API to terminate the session
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      showToast({
        title: 'Session Terminated',
        description: 'The selected session has been terminated.',
        variant: 'success',
      });
      
      setSessionToDelete(null);
    } catch (error) {
      showToast({
        title: 'Termination Failed',
        description: 'Failed to terminate session. Please try again.',
        variant: 'error',
      });
    }
  }, [showToast]);

  // Download security logs
  const downloadSecurityLogs = useCallback(() => {
    const csvContent = [
      'Event,Description,Timestamp,IP Address,Location,Success',
      ...mockSecurityLogs.map(log => 
        `"${log.event}","${log.description}","${log.timestamp}","${log.ipAddress}","${log.location}","${log.success}"`
      )
    ].join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security-logs.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    window.URL.revokeObjectURL(url);
    
    showToast({
      title: 'Download Started',
      description: 'Security logs are being downloaded.',
      variant: 'success',
    });
  }, [showToast]);

  if (!user) {
    return (
      <MainLayout breadcrumbs={breadcrumbs}>
        <Alert variant="warning">
          <AlertCircle className="h-4 w-4" />
          <div>
            <h4 className="font-semibold">Access Denied</h4>
            <p>You must be logged in to access security settings.</p>
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
            <h1 className="text-3xl font-bold text-foreground mb-2">Security Settings</h1>
            <p className="text-muted-foreground">
              Manage your account security and authentication methods
            </p>
          </div>
          <Button asChild variant="outline">
            <Link to="/profile">
              <ArrowLeft className="h-4 w-4" />
              Back to Profile
            </Link>
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Password & Authentication */}
          <div className="space-y-6">
            {/* Password Settings */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Key className="h-5 w-5" />
                  <span>Password</span>
                </CardTitle>
                <CardDescription>
                  Change your password and manage authentication settings
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Lock className="h-5 w-5 text-muted-foreground" />
                    <div>
                      <p className="font-medium text-foreground">Password</p>
                      <p className="text-sm text-muted-foreground">
                        Last changed 3 days ago
                      </p>
                    </div>
                  </div>
                  <Button onClick={() => setShowPasswordModal(true)} variant="outline" size="sm">
                    Change Password
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Two-Factor Authentication */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Shield className="h-5 w-5" />
                  <span>Two-Factor Authentication</span>
                </CardTitle>
                <CardDescription>
                  Add an extra layer of security to your account
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between p-4 border border-border rounded-lg">
                  <div className="flex items-center space-x-3">
                    <div className={`h-3 w-3 rounded-full ${twoFactorEnabled ? 'bg-green-500' : 'bg-red-500'}`} />
                    <div>
                      <p className="font-medium text-foreground">
                        {twoFactorEnabled ? 'Enabled' : 'Disabled'}
                      </p>
                      <p className="text-sm text-muted-foreground">
                        {twoFactorEnabled 
                          ? 'Your account is protected with 2FA'
                          : 'Secure your account with an authenticator app'
                        }
                      </p>
                    </div>
                  </div>
                  <Button 
                    onClick={toggleTwoFactor}
                    variant={twoFactorEnabled ? "destructive" : "default"}
                    size="sm"
                  >
                    {twoFactorEnabled ? 'Disable' : 'Enable'} 2FA
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Account Deletion */}
            <Card className="border-destructive/20">
              <CardHeader>
                <CardTitle className="flex items-center space-x-2 text-destructive">
                  <AlertTriangle className="h-5 w-5" />
                  <span>Danger Zone</span>
                </CardTitle>
                <CardDescription>
                  Permanently delete your account and all associated data
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Alert variant="destructive" className="mb-4">
                  <AlertTriangle className="h-4 w-4" />
                  <div>
                    <h4 className="font-semibold">Account Deletion</h4>
                    <p>This action cannot be undone. All your data will be permanently deleted.</p>
                  </div>
                </Alert>
                <Button 
                  variant="destructive" 
                  onClick={() => setShowDeleteModal(true)}
                  className="w-full"
                >
                  <Trash2 className="h-4 w-4" />
                  Delete Account
                </Button>
              </CardContent>
            </Card>
          </div>

          {/* Sessions & Activity */}
          <div className="space-y-6">
            {/* Active Sessions */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center space-x-2">
                  <Monitor className="h-5 w-5" />
                  <span>Active Sessions</span>
                </CardTitle>
                <CardDescription>
                  Manage your active sessions across all devices
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockActiveSessions.map((session) => (
                    <div key={session.id} className="flex items-start justify-between p-4 border border-border rounded-lg">
                      <div className="flex items-start space-x-3">
                        <div className="mt-1">
                          {session.deviceName.includes('iPhone') || session.deviceName.includes('iPad') ? (
                            <Smartphone className="h-5 w-5 text-muted-foreground" />
                          ) : (
                            <Monitor className="h-5 w-5 text-muted-foreground" />
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <p className="font-medium text-foreground">{session.deviceName}</p>
                            {session.isCurrent && (
                              <span className="px-2 py-1 text-xs bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300 rounded-full">
                                Current
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground">
                            {session.browser} • {session.os}
                          </p>
                          <div className="flex items-center space-x-4 mt-1 text-xs text-muted-foreground">
                            <span className="flex items-center space-x-1">
                              <MapPin className="h-3 w-3" />
                              <span>{session.location}</span>
                            </span>
                            <span className="flex items-center space-x-1">
                              <Clock className="h-3 w-3" />
                              <span>{formatRelativeTime(session.lastActive)}</span>
                            </span>
                          </div>
                        </div>
                      </div>
                      {!session.isCurrent && (
                        <Button
                          onClick={() => setSessionToDelete(session.id)}
                          variant="outline"
                          size="sm"
                        >
                          Terminate
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Security Log */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center space-x-2">
                      <AlertTriangle className="h-5 w-5" />
                      <span>Security Activity</span>
                    </CardTitle>
                    <CardDescription>
                      Recent security events and login activity
                    </CardDescription>
                  </div>
                  <Button onClick={downloadSecurityLogs} variant="outline" size="sm">
                    <Download className="h-4 w-4" />
                    Export
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {mockSecurityLogs.slice(0, 6).map((log) => (
                    <div key={log.id} className="flex items-start space-x-3 pb-4 border-b border-border last:border-b-0 last:pb-0">
                      <div className="mt-2">
                        {log.success ? (
                          <CheckCircle className="h-4 w-4 text-green-500" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-500" />
                        )}
                      </div>
                      <div className="flex-1">
                        <p className="text-sm font-medium text-foreground">{log.event}</p>
                        <p className="text-xs text-muted-foreground">{log.description}</p>
                        <div className="flex items-center space-x-4 mt-1 text-xs text-muted-foreground">
                          <span>{formatDate(log.timestamp)}</span>
                          <span>{log.location}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" size="sm" className="w-full">
                  View Full Security Log
                </Button>
              </CardFooter>
            </Card>
          </div>
        </div>

        {/* Password Change Modal */}
        <Modal
          isOpen={showPasswordModal}
          onClose={() => setShowPasswordModal(false)}
          size="md"
        >
          <ModalHeader>
            <ModalTitle>Change Password</ModalTitle>
          </ModalHeader>
          <ModalContent>
            <form onSubmit={passwordForm.handleSubmit} className="space-y-4">
              <FormField
                label="Current Password"
                error={passwordForm.getFieldError('currentPassword')}
                required
              >
                <SecurePasswordInput
                  {...passwordForm.register('currentPassword')}
                  placeholder="Enter your current password"
                />
              </FormField>

              <FormField
                label="New Password"
                error={passwordForm.getFieldError('newPassword')}
                required
              >
                <SecurePasswordInput
                  {...passwordForm.register('newPassword')}
                  placeholder="Enter your new password"
                />
              </FormField>

              <PasswordStrengthMeter 
                password={passwordForm.watch('newPassword') || ''} 
              />

              <FormField
                label="Confirm New Password"
                error={passwordForm.getFieldError('confirmPassword')}
                required
              >
                <SecurePasswordInput
                  {...passwordForm.register('confirmPassword')}
                  placeholder="Confirm your new password"
                />
              </FormField>
            </form>
          </ModalContent>
          <ModalFooter>
            <Button
              onClick={() => setShowPasswordModal(false)}
              variant="outline"
            >
              Cancel
            </Button>
            <Button
              onClick={passwordForm.handleSubmit}
              disabled={passwordForm.isSubmitting || !passwordForm.isValid}
              loading={passwordForm.isSubmitting}
            >
              Change Password
            </Button>
          </ModalFooter>
        </Modal>

        {/* 2FA Setup Modal */}
        <Modal
          isOpen={showTwoFactorModal}
          onClose={() => setShowTwoFactorModal(false)}
          size="md"
        >
          <ModalHeader>
            <ModalTitle>Enable Two-Factor Authentication</ModalTitle>
          </ModalHeader>
          <ModalContent>
            <div className="space-y-4">
              <div className="text-center">
                <div className="mb-4">
                  <QrCode className="h-12 w-12 mx-auto text-muted-foreground mb-2" />
                  <h3 className="text-lg font-semibold">Scan QR Code</h3>
                  <p className="text-sm text-muted-foreground">
                    Use your authenticator app to scan this QR code
                  </p>
                </div>
                
                {qrCodeUrl && (
                  <div className="flex justify-center mb-4">
                    <img 
                      src={qrCodeUrl} 
                      alt="2FA QR Code" 
                      className="border border-border rounded-lg"
                    />
                  </div>
                )}
                
                <div className="text-xs text-muted-foreground mb-4">
                  <p>Can't scan? Enter this code manually:</p>
                  <code className="bg-muted px-2 py-1 rounded text-xs">
                    JBSWY3DPEHPK3PXP
                  </code>
                </div>
              </div>

              <FormField label="Verification Code" required>
                <Input
                  placeholder="Enter 6-digit code from your app"
                  maxLength={6}
                  className="text-center text-lg tracking-widest"
                />
              </FormField>
            </div>
          </ModalContent>
          <ModalFooter>
            <Button
              onClick={() => setShowTwoFactorModal(false)}
              variant="outline"
            >
              Cancel
            </Button>
            <Button onClick={completeTwoFactorSetup}>
              Enable 2FA
            </Button>
          </ModalFooter>
        </Modal>

        {/* Session Termination Confirmation */}
        <Modal
          isOpen={!!sessionToDelete}
          onClose={() => setSessionToDelete(null)}
          size="sm"
        >
          <ModalHeader>
            <ModalTitle>Terminate Session</ModalTitle>
          </ModalHeader>
          <ModalContent>
            <p>Are you sure you want to terminate this session? The user will be logged out immediately.</p>
          </ModalContent>
          <ModalFooter>
            <Button
              onClick={() => setSessionToDelete(null)}
              variant="outline"
            >
              Cancel
            </Button>
            <Button
              onClick={() => sessionToDelete && terminateSession(sessionToDelete)}
              variant="destructive"
            >
              Terminate Session
            </Button>
          </ModalFooter>
        </Modal>

        {/* Account Deletion Confirmation */}
        <Modal
          isOpen={showDeleteModal}
          onClose={() => setShowDeleteModal(false)}
          size="md"
        >
          <ModalHeader>
            <ModalTitle className="text-destructive">Delete Account</ModalTitle>
          </ModalHeader>
          <ModalContent>
            <Alert variant="destructive" className="mb-4">
              <AlertTriangle className="h-4 w-4" />
              <div>
                <h4 className="font-semibold">This action cannot be undone</h4>
                <p>Your account and all associated data will be permanently deleted.</p>
              </div>
            </Alert>
            <div className="space-y-4">
              <p>Please type <code className="bg-muted px-1 py-0.5 rounded text-sm">DELETE</code> to confirm:</p>
              <Input placeholder="Type DELETE to confirm" />
            </div>
          </ModalContent>
          <ModalFooter>
            <Button
              onClick={() => setShowDeleteModal(false)}
              variant="outline"
            >
              Cancel
            </Button>
            <Button variant="destructive">
              Delete My Account
            </Button>
          </ModalFooter>
        </Modal>
      </div>
    </MainLayout>
  );
}

export default SecuritySettings;