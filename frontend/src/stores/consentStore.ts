/**
 * Consent Management Store
 * Handles user consent preferences for GDPR compliance
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface ConsentCategory {
  id: string;
  name: string;
  description: string;
  required: boolean;
}

export interface ConsentPreferences {
  necessary: boolean; // Always true, required for basic functionality
  analytics: boolean;
  marketing: boolean;
  preferences: boolean;
  timestamp: string;
  version: string;
}

interface ConsentState {
  // State
  preferences: ConsentPreferences | null;
  hasConsented: boolean;
  showBanner: boolean;
  consentVersion: string;
  
  // Actions
  updateConsent: (preferences: Partial<ConsentPreferences>) => void;
  acceptAll: () => void;
  rejectAll: () => void;
  savePreferences: (preferences: Partial<ConsentPreferences>) => void;
  checkConsentRequired: () => boolean;
  resetConsent: () => void;
  hideBanner: () => void;
  showConsentSettings: () => void;
}

const CURRENT_CONSENT_VERSION = '1.0.0';

const defaultPreferences: ConsentPreferences = {
  necessary: true,
  analytics: false,
  marketing: false,
  preferences: false,
  timestamp: new Date().toISOString(),
  version: CURRENT_CONSENT_VERSION,
};

export const consentCategories: ConsentCategory[] = [
  {
    id: 'necessary',
    name: 'Necessary Cookies',
    description: 'Essential cookies required for the website to function properly. These cannot be disabled.',
    required: true,
  },
  {
    id: 'analytics',
    name: 'Analytics Cookies',
    description: 'Help us understand how visitors interact with our website by collecting and reporting information anonymously.',
    required: false,
  },
  {
    id: 'marketing',
    name: 'Marketing Cookies',
    description: 'Used to track visitors across websites to display relevant advertisements.',
    required: false,
  },
  {
    id: 'preferences',
    name: 'Preference Cookies',
    description: 'Allow the website to remember choices you make (such as language or region).',
    required: false,
  },
];

export const useConsentStore = create<ConsentState>()(
  persist(
    (set, get) => ({
      preferences: null,
      hasConsented: false,
      showBanner: true,
      consentVersion: CURRENT_CONSENT_VERSION,

      updateConsent: (newPreferences) => {
        set((state) => ({
          preferences: state.preferences
            ? { ...state.preferences, ...newPreferences }
            : { ...defaultPreferences, ...newPreferences },
        }));
      },

      acceptAll: () => {
        const preferences: ConsentPreferences = {
          necessary: true,
          analytics: true,
          marketing: true,
          preferences: true,
          timestamp: new Date().toISOString(),
          version: CURRENT_CONSENT_VERSION,
        };
        
        set({
          preferences,
          hasConsented: true,
          showBanner: false,
        });

        // Trigger consent callbacks
        if (preferences.analytics) {
          window.dispatchEvent(new CustomEvent('consent:analytics', { detail: true }));
        }
        if (preferences.marketing) {
          window.dispatchEvent(new CustomEvent('consent:marketing', { detail: true }));
        }
      },

      rejectAll: () => {
        const preferences: ConsentPreferences = {
          necessary: true,
          analytics: false,
          marketing: false,
          preferences: false,
          timestamp: new Date().toISOString(),
          version: CURRENT_CONSENT_VERSION,
        };
        
        set({
          preferences,
          hasConsented: true,
          showBanner: false,
        });

        // Trigger consent callbacks
        window.dispatchEvent(new CustomEvent('consent:analytics', { detail: false }));
        window.dispatchEvent(new CustomEvent('consent:marketing', { detail: false }));
      },

      savePreferences: (newPreferences) => {
        const preferences: ConsentPreferences = {
          necessary: true,
          analytics: newPreferences.analytics || false,
          marketing: newPreferences.marketing || false,
          preferences: newPreferences.preferences || false,
          timestamp: new Date().toISOString(),
          version: CURRENT_CONSENT_VERSION,
        };
        
        set({
          preferences,
          hasConsented: true,
          showBanner: false,
        });

        // Trigger consent callbacks
        window.dispatchEvent(new CustomEvent('consent:analytics', { detail: preferences.analytics }));
        window.dispatchEvent(new CustomEvent('consent:marketing', { detail: preferences.marketing }));
        window.dispatchEvent(new CustomEvent('consent:preferences', { detail: preferences.preferences }));
      },

      checkConsentRequired: () => {
        const state = get();
        
        // Check if consent is needed
        if (!state.hasConsented) return true;
        if (!state.preferences) return true;
        if (state.preferences.version !== CURRENT_CONSENT_VERSION) return true;
        
        // Check if consent is older than 1 year (re-consent required)
        const consentDate = new Date(state.preferences.timestamp);
        const oneYearAgo = new Date();
        oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
        
        return consentDate < oneYearAgo;
      },

      resetConsent: () => {
        set({
          preferences: null,
          hasConsented: false,
          showBanner: true,
        });
        
        // Clear all consent-related data
        window.dispatchEvent(new CustomEvent('consent:reset'));
      },

      hideBanner: () => {
        set({ showBanner: false });
      },

      showConsentSettings: () => {
        window.dispatchEvent(new CustomEvent('consent:showSettings'));
      },
    }),
    {
      name: 'consent-preferences',
      partialize: (state) => ({
        preferences: state.preferences,
        hasConsented: state.hasConsented,
      }),
    }
  )
);

// Helper hooks
export function useConsent(category: keyof Omit<ConsentPreferences, 'timestamp' | 'version'>) {
  const preferences = useConsentStore((state) => state.preferences);
  return preferences?.[category] ?? (category === 'necessary');
}

export function useConsentBanner() {
  const showBanner = useConsentStore((state) => state.showBanner);
  const hasConsented = useConsentStore((state) => state.hasConsented);
  const checkConsentRequired = useConsentStore((state) => state.checkConsentRequired);
  
  return showBanner && checkConsentRequired();
}