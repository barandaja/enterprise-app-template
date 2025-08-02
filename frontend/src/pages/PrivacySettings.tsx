/**
 * Privacy Settings Page
 * Central hub for all privacy and data management features
 */

import React from 'react';
import { Shield, Cookie, Download, Trash2, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';
import { ConsentSettings, DataPrivacySettings } from '../components';
import { Card } from '../components/Card';
import { Button } from '../components/Button';
import { PageProps } from '../types';

function PrivacySettings({ className }: PageProps) {
  return (
    <div className="container py-8 max-w-4xl">
      {/* Header */}
      <div className="mb-8">
        <Link
          to="/profile"
          className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-4"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Profile
        </Link>
        
        <div className="flex items-center gap-3 mb-4">
          <div className="p-3 rounded-full bg-primary/10">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-foreground">Privacy Settings</h1>
            <p className="text-muted-foreground">
              Manage your privacy preferences and personal data
            </p>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        <QuickAction
          icon={Cookie}
          title="Cookie Preferences"
          description="Manage cookie consent"
          onClick={() => {
            const element = document.getElementById('consent-settings');
            element?.scrollIntoView({ behavior: 'smooth' });
          }}
        />
        <QuickAction
          icon={Download}
          title="Export Data"
          description="Download your data"
          onClick={() => {
            const element = document.getElementById('data-export');
            element?.scrollIntoView({ behavior: 'smooth' });
          }}
        />
        <QuickAction
          icon={Trash2}
          title="Delete Account"
          description="Remove all data"
          variant="destructive"
          onClick={() => {
            const element = document.getElementById('data-deletion');
            element?.scrollIntoView({ behavior: 'smooth' });
          }}
        />
      </div>

      {/* Privacy Overview */}
      <Card className="mb-8">
        <div className="p-6">
          <h2 className="text-lg font-semibold mb-4">Your Privacy Rights</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <h3 className="font-medium text-sm mb-2">Under GDPR you have the right to:</h3>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Access your personal data</li>
                <li>• Correct inaccurate data</li>
                <li>• Request deletion of your data</li>
                <li>• Object to data processing</li>
                <li>• Data portability</li>
                <li>• Withdraw consent at any time</li>
              </ul>
            </div>
            <div>
              <h3 className="font-medium text-sm mb-2">We are committed to:</h3>
              <ul className="text-sm text-muted-foreground space-y-1">
                <li>• Transparent data practices</li>
                <li>• Minimal data collection</li>
                <li>• Secure data storage</li>
                <li>• Regular security audits</li>
                <li>• Prompt breach notifications</li>
                <li>• Respecting your choices</li>
              </ul>
            </div>
          </div>
        </div>
      </Card>

      {/* Consent Settings Section */}
      <div id="consent-settings" className="mb-8">
        <Card>
          <div className="p-6">
            <ConsentSettings />
          </div>
        </Card>
      </div>

      {/* Data Privacy Section */}
      <div id="data-export">
        <DataPrivacySettings />
      </div>

      {/* Help Section */}
      <Card className="mt-8">
        <div className="p-6">
          <h3 className="text-lg font-semibold mb-3">Need Help?</h3>
          <p className="text-sm text-muted-foreground mb-4">
            If you have questions about your privacy or need assistance with your data, 
            our privacy team is here to help.
          </p>
          <div className="flex flex-wrap gap-3">
            <Button variant="outline" size="sm" asChild>
              <Link to="/privacy">Privacy Policy</Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <Link to="/terms">Terms of Service</Link>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href="mailto:privacy@example.com">Contact Privacy Team</a>
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}

interface QuickActionProps {
  icon: React.ElementType;
  title: string;
  description: string;
  onClick: () => void;
  variant?: 'default' | 'destructive';
}

function QuickAction({ 
  icon: Icon, 
  title, 
  description, 
  onClick,
  variant = 'default' 
}: QuickActionProps) {
  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-lg border text-left transition-colors ${
        variant === 'destructive'
          ? 'border-destructive/20 hover:bg-destructive/5 hover:border-destructive/40'
          : 'border-border hover:bg-muted hover:border-primary/20'
      }`}
    >
      <Icon className={`h-5 w-5 mb-2 ${
        variant === 'destructive' ? 'text-destructive' : 'text-primary'
      }`} />
      <h3 className="font-medium text-sm">{title}</h3>
      <p className="text-xs text-muted-foreground">{description}</p>
    </button>
  );
}

export default PrivacySettings;