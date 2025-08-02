/**
 * Data Privacy Components
 * GDPR-compliant data export and deletion functionality
 */

import React, { useState } from 'react';
import { Download, Trash2, Shield, AlertTriangle, FileText, Clock, CheckCircle } from 'lucide-react';
import { Button } from './Button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './Card';
import { Alert, AlertContent } from './Alert';
import { Modal, ModalContent, ModalDescription, ModalFooter, ModalHeader, ModalTitle } from './Modal';
import { Input } from './Input';
import { useAuthStore } from '../stores/authStore';
import { apiClient } from '../services/api/client';
import { toast } from 'react-hot-toast';
import { cn } from '../utils';

interface DataExportStatus {
  status: 'idle' | 'requesting' | 'processing' | 'ready' | 'error';
  requestId?: string;
  downloadUrl?: string;
  expiresAt?: string;
  error?: string;
}

export function DataPrivacySettings() {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold mb-2">Privacy & Data</h2>
        <p className="text-muted-foreground">
          Manage your personal data in compliance with GDPR and other privacy regulations
        </p>
      </div>

      <DataExportSection />
      <DataDeletionSection />
      <DataRetentionInfo />
    </div>
  );
}

function DataExportSection() {
  const [exportStatus, setExportStatus] = useState<DataExportStatus>({ status: 'idle' });
  const [isRequesting, setIsRequesting] = useState(false);

  const requestDataExport = async () => {
    setIsRequesting(true);
    setExportStatus({ status: 'requesting' });

    try {
      // Request data export from API
      const response = await apiClient.post<{ requestId: string }>('/user/data-export');
      
      setExportStatus({
        status: 'processing',
        requestId: response.data.requestId,
      });

      toast.success('Data export requested. You will receive an email when it\'s ready.');
      
      // Poll for export status
      pollExportStatus(response.data.requestId);
    } catch (error) {
      setExportStatus({
        status: 'error',
        error: 'Failed to request data export. Please try again.',
      });
      toast.error('Failed to request data export');
    } finally {
      setIsRequesting(false);
    }
  };

  const pollExportStatus = async (requestId: string) => {
    const checkStatus = async () => {
      try {
        const response = await apiClient.get<{
          status: 'processing' | 'ready' | 'failed';
          downloadUrl?: string;
          expiresAt?: string;
        }>(`/user/data-export/${requestId}`);

        if (response.data.status === 'ready' && response.data.downloadUrl) {
          setExportStatus({
            status: 'ready',
            requestId,
            downloadUrl: response.data.downloadUrl,
            expiresAt: response.data.expiresAt,
          });
          toast.success('Your data export is ready for download!');
        } else if (response.data.status === 'failed') {
          setExportStatus({
            status: 'error',
            error: 'Data export failed. Please try again.',
          });
        } else {
          // Continue polling
          setTimeout(() => checkStatus(), 5000);
        }
      } catch (error) {
        setExportStatus({
          status: 'error',
          error: 'Failed to check export status',
        });
      }
    };

    // Start polling after 5 seconds
    setTimeout(() => checkStatus(), 5000);
  };

  const downloadExport = () => {
    if (exportStatus.downloadUrl) {
      window.open(exportStatus.downloadUrl, '_blank');
      toast.success('Download started');
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Download className="h-5 w-5" />
          Export Your Data
        </CardTitle>
        <CardDescription>
          Download a copy of all your personal data in a machine-readable format (JSON/CSV)
        </CardDescription>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-4">
          <div className="p-4 bg-muted rounded-lg">
            <h4 className="font-medium text-sm mb-2">What's included:</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Profile information</li>
              <li>• Account settings and preferences</li>
              <li>• Activity history and logs</li>
              <li>• Uploaded files and content</li>
              <li>• Communication preferences</li>
            </ul>
          </div>

          {exportStatus.status === 'processing' && (
            <Alert>
              <Clock className="h-4 w-4" />
              <AlertContent>
                <h4 className="font-medium">Export in progress</h4>
                <p className="text-sm">
                  We're preparing your data export. This may take a few minutes.
                  Request ID: {exportStatus.requestId}
                </p>
              </AlertContent>
            </Alert>
          )}

          {exportStatus.status === 'ready' && (
            <Alert type="success">
              <CheckCircle className="h-4 w-4" />
              <AlertContent>
                <h4 className="font-medium">Export ready!</h4>
                <p className="text-sm">
                  Your data export is ready for download. 
                  {exportStatus.expiresAt && (
                    <span> Expires on {new Date(exportStatus.expiresAt).toLocaleDateString()}</span>
                  )}
                </p>
              </AlertContent>
            </Alert>
          )}

          {exportStatus.status === 'error' && (
            <Alert type="error">
              <AlertTriangle className="h-4 w-4" />
              <AlertContent>
                <p className="text-sm">{exportStatus.error}</p>
              </AlertContent>
            </Alert>
          )}
        </div>
      </CardContent>
      
      <CardFooter>
        {exportStatus.status === 'ready' && exportStatus.downloadUrl ? (
          <Button onClick={downloadExport} className="w-full">
            <Download className="h-4 w-4 mr-2" />
            Download Export
          </Button>
        ) : (
          <Button
            onClick={requestDataExport}
            loading={isRequesting || exportStatus.status === 'processing'}
            disabled={exportStatus.status === 'processing'}
            className="w-full"
          >
            <FileText className="h-4 w-4 mr-2" />
            Request Data Export
          </Button>
        )}
      </CardFooter>
    </Card>
  );
}

function DataDeletionSection() {
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);
  const { user, logout } = useAuthStore();

  const handleDeleteAccount = async () => {
    if (confirmText !== 'DELETE') return;

    setIsDeleting(true);
    try {
      await apiClient.delete('/user/account');
      
      toast.success('Your account has been scheduled for deletion');
      
      // Log out user
      setTimeout(() => {
        logout();
        window.location.href = '/';
      }, 2000);
    } catch (error) {
      toast.error('Failed to delete account. Please try again.');
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <>
      <Card className="border-destructive/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" />
            Delete Your Account
          </CardTitle>
          <CardDescription>
            Permanently delete your account and all associated data
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          <Alert type="error">
            <AlertTriangle className="h-4 w-4" />
            <AlertContent>
              <h4 className="font-medium">Warning: This action cannot be undone</h4>
              <p className="text-sm mt-1">
                Deleting your account will permanently remove all your data including:
              </p>
              <ul className="text-sm mt-2 space-y-1">
                <li>• Your profile and account information</li>
                <li>• All uploaded files and content</li>
                <li>• Activity history and preferences</li>
                <li>• Access to all services</li>
              </ul>
            </AlertContent>
          </Alert>

          <div className="mt-4 p-4 bg-muted rounded-lg">
            <h4 className="font-medium text-sm mb-2">What happens next:</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Your account will be immediately deactivated</li>
              <li>• Your data will be deleted within 30 days</li>
              <li>• Some data may be retained for legal compliance (anonymized)</li>
              <li>• You will receive a confirmation email</li>
            </ul>
          </div>
        </CardContent>
        
        <CardFooter>
          <Button
            variant="destructive"
            onClick={() => setShowDeleteModal(true)}
            className="w-full"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete My Account
          </Button>
        </CardFooter>
      </Card>

      {/* Delete Confirmation Modal */}
      <Modal isOpen={showDeleteModal} onClose={() => setShowDeleteModal(false)}>
        <ModalHeader>
          <ModalTitle className="text-destructive">Delete Account</ModalTitle>
          <ModalDescription>
            This action is permanent and cannot be undone. All your data will be deleted.
          </ModalDescription>
        </ModalHeader>
        
        <ModalContent>
          <div className="space-y-4">
            <Alert type="error">
              <AlertTriangle className="h-4 w-4" />
              <AlertContent>
                <p className="text-sm">
                  You are about to permanently delete your account: <strong>{user?.email}</strong>
                </p>
              </AlertContent>
            </Alert>

            <div>
              <label htmlFor="confirm-delete" className="text-sm font-medium mb-2 block">
                Type <strong>DELETE</strong> to confirm
              </label>
              <Input
                id="confirm-delete"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="Type DELETE to confirm"
                className={cn(
                  confirmText === 'DELETE' ? 'border-destructive' : ''
                )}
              />
            </div>
          </div>
        </ModalContent>
        
        <ModalFooter>
          <Button
            variant="outline"
            onClick={() => {
              setShowDeleteModal(false);
              setConfirmText('');
            }}
          >
            Cancel
          </Button>
          <Button
            variant="destructive"
            onClick={handleDeleteAccount}
            disabled={confirmText !== 'DELETE' || isDeleting}
            loading={isDeleting}
          >
            Delete My Account
          </Button>
        </ModalFooter>
      </Modal>
    </>
  );
}

function DataRetentionInfo() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Data Retention Policy
        </CardTitle>
        <CardDescription>
          How we handle your data according to privacy regulations
        </CardDescription>
      </CardHeader>
      
      <CardContent>
        <div className="space-y-4">
          <div>
            <h4 className="font-medium text-sm mb-2">Active Account Data</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Profile data: Retained while account is active</li>
              <li>• Activity logs: Retained for 90 days</li>
              <li>• Communication logs: Retained for 1 year</li>
              <li>• Uploaded content: Retained until deletion</li>
            </ul>
          </div>

          <div>
            <h4 className="font-medium text-sm mb-2">After Account Deletion</h4>
            <ul className="text-sm text-muted-foreground space-y-1">
              <li>• Most data: Deleted within 30 days</li>
              <li>• Backups: Purged within 90 days</li>
              <li>• Legal obligations: Anonymized data may be retained</li>
              <li>• Security logs: Retained for 6 months (anonymized)</li>
            </ul>
          </div>

          <div className="p-4 bg-muted rounded-lg">
            <p className="text-sm text-muted-foreground">
              We comply with GDPR, CCPA, and other privacy regulations. For more information, 
              please review our{' '}
              <a href="/privacy" className="text-primary hover:underline">
                Privacy Policy
              </a>{' '}
              and{' '}
              <a href="/terms" className="text-primary hover:underline">
                Terms of Service
              </a>.
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}