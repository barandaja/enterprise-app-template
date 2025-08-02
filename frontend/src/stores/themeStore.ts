import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type { Theme } from '../types';

// Extended theme state interface
interface ThemeState {
  // Theme configuration
  theme: Theme;
  systemTheme: 'light' | 'dark';
  resolvedTheme: 'light' | 'dark';
  
  // State management
  isInitialized: boolean;
  isSystemPreferenceSupported: boolean;
}

// Theme actions interface
interface ThemeActions {
  // Theme management
  setTheme: (theme: Theme) => void;
  toggleTheme: () => void;
  
  // System theme detection
  detectSystemTheme: () => 'light' | 'dark';
  updateSystemTheme: (systemTheme: 'light' | 'dark') => void;
  
  // Theme application
  applyTheme: (theme: 'light' | 'dark') => void;
  
  // Initialization
  initialize: () => void;
  
  // Utility methods
  getResolvedTheme: () => 'light' | 'dark';
  subscribeToSystemChanges: () => () => void;
}

// Combined store type
type ThemeStore = ThemeState & ThemeActions;

// Theme utility functions
const THEME_STORAGE_KEY = 'theme-preference';
const DARK_CLASS = 'dark';
const LIGHT_CLASS = 'light';

// Check if system theme preference is supported
const isSystemPreferenceSupported = (): boolean => {
  return typeof window !== 'undefined' && window.matchMedia !== undefined;
};

// Detect system theme preference
const detectSystemTheme = (): 'light' | 'dark' => {
  if (!isSystemPreferenceSupported()) {
    return 'light';
  }
  
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

// Apply theme to document
const applyThemeToDocument = (theme: 'light' | 'dark'): void => {
  if (typeof document === 'undefined') return;

  const root = document.documentElement;
  const body = document.body;

  // Remove existing theme classes
  root.classList.remove(DARK_CLASS, LIGHT_CLASS);
  body.classList.remove(DARK_CLASS, LIGHT_CLASS);

  // Add new theme class
  root.classList.add(theme);
  body.classList.add(theme);

  // Set data attribute for CSS custom properties
  root.setAttribute('data-theme', theme);
  
  // Update meta theme-color for mobile browsers
  let metaThemeColor = document.querySelector('meta[name="theme-color"]');
  if (!metaThemeColor) {
    metaThemeColor = document.createElement('meta');
    metaThemeColor.setAttribute('name', 'theme-color');
    document.head.appendChild(metaThemeColor);
  }
  
  // Set appropriate colors based on theme
  const themeColors = {
    light: '#ffffff',
    dark: '#0f172a', // slate-900
  };
  
  metaThemeColor.setAttribute('content', themeColors[theme]);
};

// Get stored theme preference
const getStoredTheme = (): Theme | null => {
  if (typeof localStorage === 'undefined') return null;
  
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY);
    return stored as Theme || null;
  } catch {
    return null;
  }
};

// Store theme preference
const storeTheme = (theme: Theme): void => {
  if (typeof localStorage === 'undefined') return;
  
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Storage failed, continue silently
  }
};

// Create the theme store
export const useThemeStore = create<ThemeStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        theme: 'system',
        systemTheme: 'light',
        resolvedTheme: 'light',
        isInitialized: false,
        isSystemPreferenceSupported: isSystemPreferenceSupported(),

        // Theme management actions
        setTheme: (theme: Theme) => {
          set((state) => {
            state.theme = theme;
            state.resolvedTheme = get().getResolvedTheme();
          });
          
          // Apply theme immediately
          get().applyTheme(get().resolvedTheme);
          
          // Store preference
          storeTheme(theme);
        },

        toggleTheme: () => {
          const { theme, resolvedTheme } = get();
          
          if (theme === 'system') {
            // If currently using system, toggle to opposite of current resolved theme
            get().setTheme(resolvedTheme === 'light' ? 'dark' : 'light');
          } else {
            // If using explicit theme, toggle to opposite
            get().setTheme(theme === 'light' ? 'dark' : 'light');
          }
        },

        // System theme detection
        detectSystemTheme: () => {
          return detectSystemTheme();
        },

        updateSystemTheme: (systemTheme: 'light' | 'dark') => {
          set((state) => {
            state.systemTheme = systemTheme;
            // Update resolved theme if using system preference
            if (state.theme === 'system') {
              state.resolvedTheme = systemTheme;
            }
          });
          
          // Apply theme if using system preference
          const { theme } = get();
          if (theme === 'system') {
            get().applyTheme(systemTheme);
          }
        },

        // Theme application
        applyTheme: (theme: 'light' | 'dark') => {
          applyThemeToDocument(theme);
        },

        // Initialization
        initialize: () => {
          if (get().isInitialized) return;

          const systemTheme = get().detectSystemTheme();
          
          set((state) => {
            state.systemTheme = systemTheme;
            state.resolvedTheme = get().getResolvedTheme();
            state.isInitialized = true;
          });

          // Apply initial theme
          get().applyTheme(get().resolvedTheme);

          // Subscribe to system changes if supported
          if (get().isSystemPreferenceSupported) {
            get().subscribeToSystemChanges();
          }
        },

        // Utility methods
        getResolvedTheme: (): 'light' | 'dark' => {
          const { theme, systemTheme } = get();
          return theme === 'system' ? systemTheme : theme;
        },

        subscribeToSystemChanges: () => {
          if (!isSystemPreferenceSupported()) {
            return () => {}; // Return empty cleanup function
          }

          const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
          
          const handleChange = (e: MediaQueryListEvent) => {
            const newSystemTheme = e.matches ? 'dark' : 'light';
            get().updateSystemTheme(newSystemTheme);
          };

          // Use addEventListener if available (modern browsers)
          if (mediaQuery.addEventListener) {
            mediaQuery.addEventListener('change', handleChange);
            
            return () => {
              mediaQuery.removeEventListener('change', handleChange);
            };
          } 
          // Fallback for older browsers
          else if (mediaQuery.addListener) {
            mediaQuery.addListener(handleChange);
            
            return () => {
              mediaQuery.removeListener(handleChange);
            };
          }

          return () => {}; // Return empty cleanup function
        },
      })),
      {
        name: 'theme-storage',
        partialize: (state) => ({
          theme: state.theme,
        }),
        onRehydrateStorage: () => (state) => {
          // Initialize after rehydration
          if (state) {
            // Ensure we have the latest system theme
            const currentSystemTheme = detectSystemTheme();
            state.systemTheme = currentSystemTheme;
            state.resolvedTheme = state.theme === 'system' ? currentSystemTheme : state.theme;
            
            // Initialize the store
            state.initialize();
          }
        },
      }
    ),
    {
      name: 'theme-store',
    }
  )
);

// Initialize theme on store creation (for SSR compatibility)
if (typeof window !== 'undefined') {
  const store = useThemeStore.getState();
  if (!store.isInitialized) {
    store.initialize();
  }
}

// Selectors for performance optimization
export const useTheme = () => useThemeStore((state) => state.theme);
export const useResolvedTheme = () => useThemeStore((state) => state.resolvedTheme);
export const useSystemTheme = () => useThemeStore((state) => state.systemTheme);
export const useThemeInitialized = () => useThemeStore((state) => state.isInitialized);

// Theme actions selectors
export const useThemeActions = () => useThemeStore((state) => ({
  setTheme: state.setTheme,
  toggleTheme: state.toggleTheme,
  initialize: state.initialize,
}));

// Hook for complete theme state
export const useThemeState = () => useThemeStore((state) => ({
  theme: state.theme,
  systemTheme: state.systemTheme,
  resolvedTheme: state.resolvedTheme,
  isInitialized: state.isInitialized,
  isSystemPreferenceSupported: state.isSystemPreferenceSupported,
}));

// Hook for theme with actions (convenience hook)
export const useThemeWithActions = () => {
  const theme = useTheme();
  const resolvedTheme = useResolvedTheme();
  const actions = useThemeActions();
  
  return {
    theme,
    resolvedTheme,
    ...actions,
  };
};