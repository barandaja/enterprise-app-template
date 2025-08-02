/**
 * Cookie Consent Banner Component
 * GDPR-compliant consent collection UI
 */

import React, { useState, useEffect } from 'react';
import { Cookie, Settings, X } from 'lucide-react';
import { Button } from './Button';
import { Modal, ModalContent, ModalDescription, ModalFooter, ModalHeader, ModalTitle } from './Modal';
import { useConsentStore, consentCategories, useConsentBanner } from '../stores/consentStore';
import { cn } from '../utils';

export function ConsentBanner() {
  const showBanner = useConsentBanner();
  const { acceptAll, rejectAll, hideBanner } = useConsentStore();
  const [showSettings, setShowSettings] = useState(false);
  
  useEffect(() => {
    const handleShowSettings = () => setShowSettings(true);
    window.addEventListener('consent:showSettings', handleShowSettings);
    return () => window.removeEventListener('consent:showSettings', handleShowSettings);
  }, []);

  if (!showBanner) return null;

  return (
    <>
      {/* Banner */}
      <div className="fixed bottom-0 left-0 right-0 z-50 p-4 bg-background border-t border-border shadow-lg animate-in slide-in-from-bottom-5">
        <div className="container max-w-7xl mx-auto">
          <div className="flex flex-col lg:flex-row items-center justify-between gap-4">
            <div className="flex items-start gap-3 flex-1">
              <Cookie className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
              <div className="space-y-1">
                <h3 className="text-sm font-semibold">We value your privacy</h3>
                <p className="text-sm text-muted-foreground">
                  We use cookies to enhance your browsing experience, analyze site traffic, and personalize content. 
                  By clicking "Accept All", you consent to our use of cookies. 
                  <button
                    onClick={() => setShowSettings(true)}
                    className="text-primary hover:underline ml-1"
                  >
                    Customize settings
                  </button>
                </p>
              </div>
            </div>
            
            <div className="flex items-center gap-3 flex-shrink-0">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowSettings(true)}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={rejectAll}
              >
                Reject All
              </Button>
              <Button
                size="sm"
                onClick={acceptAll}
              >
                Accept All
              </Button>
            </div>
          </div>
        </div>
      </div>

      {/* Settings Modal */}
      <ConsentSettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />
    </>
  );
}

interface ConsentSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

function ConsentSettingsModal({ isOpen, onClose }: ConsentSettingsModalProps) {
  const { preferences, savePreferences } = useConsentStore();
  const [settings, setSettings] = useState({
    analytics: preferences?.analytics || false,
    marketing: preferences?.marketing || false,
    preferences: preferences?.preferences || false,
  });

  const handleSave = () => {
    savePreferences(settings);
    onClose();
  };

  const handleToggle = (category: keyof typeof settings) => {
    setSettings(prev => ({
      ...prev,
      [category]: !prev[category],
    }));
  };

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="lg">
      <ModalHeader>
        <ModalTitle>Privacy Preferences</ModalTitle>
        <ModalDescription>
          Manage your cookie preferences. You can enable or disable different types of cookies below.
        </ModalDescription>
      </ModalHeader>
      
      <ModalContent>
        <div className="space-y-4">
          {consentCategories.map((category) => (
            <div
              key={category.id}
              className={cn(
                "p-4 rounded-lg border",
                category.required ? "bg-muted/50 border-muted" : "border-border"
              )}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <h4 className="font-medium text-sm mb-1">
                    {category.name}
                    {category.required && (
                      <span className="text-xs text-muted-foreground ml-2">(Required)</span>
                    )}
                  </h4>
                  <p className="text-sm text-muted-foreground">
                    {category.description}
                  </p>
                </div>
                
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    className="sr-only peer"
                    checked={category.required || settings[category.id as keyof typeof settings]}
                    onChange={() => !category.required && handleToggle(category.id as keyof typeof settings)}
                    disabled={category.required}
                  />
                  <div className={cn(
                    "w-11 h-6 rounded-full peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 transition-colors",
                    category.required
                      ? "bg-primary cursor-not-allowed"
                      : "bg-muted peer-checked:bg-primary cursor-pointer"
                  )}>
                    <div className={cn(
                      "absolute top-[2px] left-[2px] bg-white rounded-full h-5 w-5 transition-transform",
                      (category.required || settings[category.id as keyof typeof settings]) && "translate-x-5"
                    )} />
                  </div>
                </label>
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-6 p-4 bg-muted/50 rounded-lg">
          <p className="text-xs text-muted-foreground">
            By clicking "Save Preferences", you agree to the storing of cookies on your device to enhance site navigation, 
            analyze site usage, and assist in our marketing efforts. You can change your preferences at any time by 
            accessing the cookie settings in your account.
          </p>
        </div>
      </ModalContent>
      
      <ModalFooter>
        <Button variant="outline" onClick={onClose}>
          Cancel
        </Button>
        <Button onClick={handleSave}>
          Save Preferences
        </Button>
      </ModalFooter>
    </Modal>
  );
}

// Standalone consent settings component for profile/settings pages
export function ConsentSettings() {
  const { preferences, savePreferences, resetConsent } = useConsentStore();
  const [settings, setSettings] = useState({
    analytics: preferences?.analytics || false,
    marketing: preferences?.marketing || false,
    preferences: preferences?.preferences || false,
  });
  const [hasChanges, setHasChanges] = useState(false);

  useEffect(() => {
    const changed = 
      settings.analytics !== preferences?.analytics ||
      settings.marketing !== preferences?.marketing ||
      settings.preferences !== preferences?.preferences;
    setHasChanges(changed);
  }, [settings, preferences]);

  const handleToggle = (category: keyof typeof settings) => {
    setSettings(prev => ({
      ...prev,
      [category]: !prev[category],
    }));
  };

  const handleSave = () => {
    savePreferences(settings);
    setHasChanges(false);
  };

  const handleReset = () => {
    if (window.confirm('Are you sure you want to reset your consent preferences? You will need to provide consent again.')) {
      resetConsent();
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold mb-1">Privacy Preferences</h3>
        <p className="text-sm text-muted-foreground">
          Control how we use cookies and similar technologies
        </p>
      </div>

      <div className="space-y-4">
        {consentCategories.map((category) => (
          <div
            key={category.id}
            className={cn(
              "p-4 rounded-lg border",
              category.required ? "bg-muted/50 border-muted" : "border-border"
            )}
          >
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1">
                <h4 className="font-medium text-sm mb-1">
                  {category.name}
                  {category.required && (
                    <span className="text-xs text-muted-foreground ml-2">(Required)</span>
                  )}
                </h4>
                <p className="text-sm text-muted-foreground">
                  {category.description}
                </p>
              </div>
              
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  className="sr-only peer"
                  checked={category.required || settings[category.id as keyof typeof settings]}
                  onChange={() => !category.required && handleToggle(category.id as keyof typeof settings)}
                  disabled={category.required}
                />
                <div className={cn(
                  "w-11 h-6 rounded-full peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary/20 transition-colors",
                  category.required
                    ? "bg-primary cursor-not-allowed"
                    : "bg-muted peer-checked:bg-primary cursor-pointer"
                )}>
                  <div className={cn(
                    "absolute top-[2px] left-[2px] bg-white rounded-full h-5 w-5 transition-transform",
                    (category.required || settings[category.id as keyof typeof settings]) && "translate-x-5"
                  )} />
                </div>
              </label>
            </div>
          </div>
        ))}
      </div>

      {preferences && (
        <div className="text-sm text-muted-foreground">
          Last updated: {new Date(preferences.timestamp).toLocaleDateString()}
        </div>
      )}

      <div className="flex items-center justify-between">
        <Button
          variant="outline"
          onClick={handleReset}
          className="text-destructive hover:text-destructive"
        >
          Reset Consent
        </Button>
        
        <Button
          onClick={handleSave}
          disabled={!hasChanges}
        >
          Save Preferences
        </Button>
      </div>
    </div>
  );
}