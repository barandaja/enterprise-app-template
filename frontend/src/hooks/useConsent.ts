/**
 * Consent Management Hooks
 * Provides easy integration with consent management system
 */

import { useEffect, useCallback } from 'react';
import { useConsentStore } from '../stores/consentStore';

/**
 * Hook to check if a specific consent category is granted
 */
export function useConsent(category: 'necessary' | 'analytics' | 'marketing' | 'preferences') {
  const consentStore = useConsentStore();
  return consentStore.preferences?.[category] ?? (category === 'necessary');
}

/**
 * Hook to conditionally load scripts based on consent
 */
export function useConsentScript(
  category: 'analytics' | 'marketing' | 'preferences',
  scriptLoader: () => void | Promise<void>
) {
  const consentStore = useConsentStore();
  const hasConsent = consentStore.preferences?.[category] || false;

  useEffect(() => {
    if (hasConsent) {
      scriptLoader();
    }

    // Listen for consent changes
    const handleConsentChange = (event: CustomEvent<boolean>) => {
      if (event.detail) {
        scriptLoader();
      }
    };

    window.addEventListener(`consent:${category}` as any, handleConsentChange);

    return () => {
      window.removeEventListener(`consent:${category}` as any, handleConsentChange);
    };
  }, [hasConsent, category, scriptLoader]);

  return hasConsent;
}

/**
 * Hook to track analytics events with consent
 */
export function useAnalytics() {
  const consentStore = useConsentStore();
  const hasConsent = consentStore.preferences?.analytics || false;

  const trackEvent = useCallback(
    (eventName: string, properties?: Record<string, any>) => {
      if (!hasConsent) {
        console.log('[Analytics] Event blocked due to consent:', eventName);
        return;
      }

      // Track event with your analytics provider
      console.log('[Analytics] Event tracked:', eventName, properties);
      
      // Example integrations:
      // window.gtag?.('event', eventName, properties);
      // window.analytics?.track(eventName, properties);
      // window.mixpanel?.track(eventName, properties);
    },
    [hasConsent]
  );

  const trackPageView = useCallback(
    (pageName?: string, properties?: Record<string, any>) => {
      if (!hasConsent) {
        console.log('[Analytics] Page view blocked due to consent:', pageName);
        return;
      }

      console.log('[Analytics] Page view tracked:', pageName || window.location.pathname, properties);
      
      // Example integrations:
      // window.gtag?.('event', 'page_view', { page_path: pageName, ...properties });
      // window.analytics?.page(pageName, properties);
    },
    [hasConsent]
  );

  return {
    trackEvent,
    trackPageView,
    hasConsent,
  };
}

/**
 * Hook for managing marketing/advertising scripts
 */
export function useMarketing() {
  const consentStore = useConsentStore();
  const hasConsent = consentStore.preferences?.marketing || false;

  const loadMarketingScript = useCallback(
    (scriptUrl: string, onLoad?: () => void) => {
      if (!hasConsent) {
        console.log('[Marketing] Script blocked due to consent:', scriptUrl);
        return;
      }

      const script = document.createElement('script');
      script.src = scriptUrl;
      script.async = true;
      
      if (onLoad) {
        script.onload = onLoad;
      }

      document.body.appendChild(script);

      return () => {
        document.body.removeChild(script);
      };
    },
    [hasConsent]
  );

  return {
    hasConsent,
    loadMarketingScript,
  };
}

/**
 * Hook to manage user preferences with consent
 */
export function usePreferences<T extends Record<string, any>>(
  key: string,
  defaultValue: T
): [T, (newValue: T) => void] {
  const consentStore = useConsentStore();
  const hasConsent = consentStore.preferences?.preferences || false;
  
  const getPreferences = useCallback((): T => {
    if (!hasConsent) {
      return defaultValue;
    }

    try {
      const stored = localStorage.getItem(`pref_${key}`);
      return stored ? JSON.parse(stored) : defaultValue;
    } catch {
      return defaultValue;
    }
  }, [hasConsent, key, defaultValue]);

  const setPreferences = useCallback(
    (newValue: T) => {
      if (!hasConsent) {
        console.log('[Preferences] Storage blocked due to consent');
        return;
      }

      try {
        localStorage.setItem(`pref_${key}`, JSON.stringify(newValue));
        window.dispatchEvent(new CustomEvent(`preferences:${key}`, { detail: newValue }));
      } catch (error) {
        console.error('[Preferences] Failed to save:', error);
      }
    },
    [hasConsent, key]
  );

  const preferences = getPreferences();

  useEffect(() => {
    const handlePreferenceChange = (event: CustomEvent<T>) => {
      // Handle preference changes from other tabs/windows
    };

    window.addEventListener(`preferences:${key}` as any, handlePreferenceChange);

    return () => {
      window.removeEventListener(`preferences:${key}` as any, handlePreferenceChange);
    };
  }, [key]);

  return [preferences, setPreferences];
}