/**
 * Zustand Store Exports
 * 
 * This file provides a centralized export for all Zustand stores and their related
 * types, selectors, and utilities. It serves as the main entry point for state
 * management throughout the application.
 */

// Auth Store
export {
  useAuthStore,
  useAuthUser,
  useAuthToken,
  useIsAuthenticated,
  useAuthLoading,
  useAuthError,
  useAuthInitializing,
  useAuthActions,
} from './authStore';

// Theme Store
export {
  useThemeStore,
  useTheme,
  useResolvedTheme,
  useSystemTheme,
  useThemeInitialized,
  useThemeActions,
  useThemeState,
  useThemeWithActions,
} from './themeStore';

// User Store
export {
  useUserStore,
  useUserProfile,
  useUserPreferences,
  useUserProfileState,
  useUpdateProfileState,
  useUploadAvatarState,
  useUserActions,
  useUserUtils,
  useUserWithActions,
} from './userStore';

// UI Store
export {
  useUIStore,
  useGlobalLoading,
  useIsAnyLoading,
  useToasts,
  useModals,
  useActiveModal,
  useSidebar,
  useFormStates,
  useHasUnsavedChanges,
  useIsOffline,
  useViewport,
  useUIActions,
  useLoadingState,
  useModalState,
  useFormDirtyState,
} from './uiStore';

// Re-export types from UI store
export type { Toast, ModalState, FormDirtyState, GlobalLoadingState, SidebarState } from './uiStore';

// Store combination types for advanced use cases
export interface StoreState {
  auth: ReturnType<typeof useAuthStore.getState>;
  theme: ReturnType<typeof useThemeStore.getState>;
  user: ReturnType<typeof useUserStore.getState>;
  ui: ReturnType<typeof useUIStore.getState>;
}

// Helper function to get all store states
export const getAllStoreStates = (): StoreState => ({
  auth: useAuthStore.getState(),
  theme: useThemeStore.getState(),
  user: useUserStore.getState(),
  ui: useUIStore.getState(),
});

// Store reset function for testing and cleanup
export const resetAllStores = (): void => {
  useAuthStore.getState().logout();
  useUserStore.getState().resetProfile();
  useUIStore.getState().reset();
  // Note: Theme store intentionally not reset to preserve user preference
};

// Store initialization function
export const initializeStores = async (): Promise<void> => {
  try {
    // Initialize theme first as it affects UI rendering
    const themeStore = useThemeStore.getState();
    if (!themeStore.isInitialized) {
      themeStore.initialize();
    }

    // Initialize auth store (includes token validation and refresh)
    const authStore = useAuthStore.getState();
    if (authStore.isInitializing) {
      await authStore.initialize();
    }

    // Initialize user profile if authenticated
    if (authStore.isAuthenticated) {
      const userStore = useUserStore.getState();
      if (!userStore.profile && !userStore.profileState.loading) {
        await userStore.fetchProfile();
      }
    }
  } catch (error) {
    console.error('Store initialization failed:', error);
    // Continue execution even if initialization fails
  }
};

// Store subscription utilities
export const subscribeToAuth = (callback: (state: ReturnType<typeof useAuthStore.getState>) => void) => {
  return useAuthStore.subscribe(callback);
};

export const subscribeToTheme = (callback: (state: ReturnType<typeof useThemeStore.getState>) => void) => {
  return useThemeStore.subscribe(callback);
};

export const subscribeToUser = (callback: (state: ReturnType<typeof useUserStore.getState>) => void) => {
  return useUserStore.subscribe(callback);
};

export const subscribeToUI = (callback: (state: ReturnType<typeof useUIStore.getState>) => void) => {
  return useUIStore.subscribe(callback);
};

// Composite selectors for complex state combinations
export const useAuthenticatedUser = () => {
  const isAuthenticated = useIsAuthenticated();
  const user = useAuthUser();
  const profile = useUserProfile();
  
  return {
    isAuthenticated,
    user,
    profile: isAuthenticated ? profile : null,
  };
};

export const useAppTheme = () => {
  const theme = useTheme();
  const resolvedTheme = useResolvedTheme();
  const systemTheme = useSystemTheme();
  const actions = useThemeActions();
  
  return {
    theme,
    resolvedTheme,
    systemTheme,
    isDark: resolvedTheme === 'dark',
    isLight: resolvedTheme === 'light',
    isSystem: theme === 'system',
    ...actions,
  };
};

export const useAppLoading = () => {
  const authLoading = useAuthLoading();
  const authInitializing = useAuthInitializing();
  const globalLoading = useIsAnyLoading();
  const userProfileState = useUserProfileState();
  
  return {
    isAuthLoading: authLoading,
    isAuthInitializing: authInitializing,
    isGlobalLoading: globalLoading,
    isUserLoading: userProfileState.loading,
    isAnyLoading: authLoading || authInitializing || globalLoading || userProfileState.loading,
  };
};

export const useAppState = () => {
  const auth = useAuthenticatedUser();
  const theme = useAppTheme();
  const loading = useAppLoading();
  const offline = useIsOffline();
  const viewport = useViewport();
  const unsavedChanges = useHasUnsavedChanges();
  
  return {
    ...auth,
    theme,
    loading,
    offline,
    viewport,
    unsavedChanges,
  };
};

// Store debugging utilities (development only)
export const getStoreDebugInfo = () => {
  if (process.env.NODE_ENV !== 'development') {
    return null;
  }
  
  return {
    auth: {
      state: useAuthStore.getState(),
      persistedKeys: ['user', 'token', 'refreshToken', 'isAuthenticated'],
    },
    theme: {
      state: useThemeStore.getState(),
      persistedKeys: ['theme'],
    },
    user: {
      state: useUserStore.getState(),
      persistedKeys: ['profile', 'preferences', 'lastFetched'],
    },
    ui: {
      state: useUIStore.getState(),
      persistedKeys: ['sidebar', 'maxToasts'],
    },
  };
};

// Error boundary integration
export const handleStoreError = (error: Error, errorInfo: { componentStack: string }) => {
  console.error('Store error:', error, errorInfo);
  
  // Add error toast if UI store is available
  try {
    const uiStore = useUIStore.getState();
    uiStore.addToast({
      type: 'error',
      title: 'Application Error',
      message: 'An unexpected error occurred. Please refresh the page.',
      persistent: true,
    });
  } catch {
    // UI store not available, fail silently
  }
};

// Performance monitoring utilities
export const measureStorePerformance = <T>(
  storeName: string,
  operation: string,
  fn: () => T
): T => {
  if (process.env.NODE_ENV !== 'development') {
    return fn();
  }
  
  const start = performance.now();
  const result = fn();
  const end = performance.now();
  
  console.log(`[Store Performance] ${storeName}.${operation}: ${(end - start).toFixed(2)}ms`);
  
  return result;
};

// Type guards for store state validation
export const isValidAuthState = (state: unknown): state is ReturnType<typeof useAuthStore.getState> => {
  return (
    typeof state === 'object' &&
    state !== null &&
    'isAuthenticated' in state &&
    'user' in state &&
    'token' in state
  );
};

export const isValidThemeState = (state: unknown): state is ReturnType<typeof useThemeStore.getState> => {
  return (
    typeof state === 'object' &&
    state !== null &&
    'theme' in state &&
    'resolvedTheme' in state &&
    'systemTheme' in state
  );
};

export const isValidUserState = (state: unknown): state is ReturnType<typeof useUserStore.getState> => {
  return (
    typeof state === 'object' &&
    state !== null &&
    'profile' in state &&
    'profileState' in state
  );
};

export const isValidUIState = (state: unknown): state is ReturnType<typeof useUIStore.getState> => {
  return (
    typeof state === 'object' &&
    state !== null &&
    'toasts' in state &&
    'modals' in state &&
    'sidebar' in state
  );
};