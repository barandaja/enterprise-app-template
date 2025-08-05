import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { useShallow } from 'zustand/react/shallow';
import type { LoadingState } from '../types';

// Toast/Notification types
export interface Toast {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title?: string;
  message: string;
  duration?: number;
  persistent?: boolean;
  action?: {
    label: string;
    onClick: () => void;
  };
  createdAt: number;
}

// Modal state interface
export interface ModalState {
  id: string;
  isOpen: boolean;
  component?: React.ComponentType<{ onClose: () => void }>;
  props?: Record<string, unknown>;
  persistent?: boolean;
  size?: 'sm' | 'md' | 'lg' | 'xl' | 'full';
  backdrop?: boolean;
}

// Form dirty state interface
export interface FormDirtyState {
  formId: string;
  isDirty: boolean;
  fields: Record<string, boolean>;
  lastModified: number;
}

// Loading state interface
export interface GlobalLoadingState {
  id: string;
  message?: string;
  progress?: number;
  cancellable?: boolean;
  onCancel?: () => void;
}

// Sidebar state interface
export interface SidebarState {
  isCollapsed: boolean;
  isPinned: boolean;
  width: number;
  defaultWidth: number;
  minWidth: number;
  maxWidth: number;
}

// UI store state interface
interface UIState {
  // Loading states
  globalLoading: GlobalLoadingState[];
  isAnyLoading: boolean;
  
  // Toast/Notification queue
  toasts: Toast[];
  maxToasts: number;
  
  // Modal management
  modals: ModalState[];
  activeModalId: string | null;
  
  // Sidebar state
  sidebar: SidebarState;
  
  // Form dirty states
  formStates: FormDirtyState[];
  hasUnsavedChanges: boolean;
  
  // General UI state
  isOffline: boolean;
  lastOnlineAt: number | null;
  viewport: {
    width: number;
    height: number;
    isMobile: boolean;
    isTablet: boolean;
    isDesktop: boolean;
  };
  
  // Focus management
  focusTrap: string | null;
  previousFocus: HTMLElement | null;
}

// UI actions interface
interface UIActions {
  // Loading state management
  addLoading: (loading: Omit<GlobalLoadingState, 'id'>) => string;
  removeLoading: (id: string) => void;
  updateLoading: (id: string, updates: Partial<GlobalLoadingState>) => void;
  clearAllLoading: () => void;
  
  // Toast management
  addToast: (toast: Omit<Toast, 'id' | 'createdAt'>) => string;
  removeToast: (id: string) => void;
  clearToast: (id: string) => void;
  clearAllToasts: () => void;
  updateToast: (id: string, updates: Partial<Toast>) => void;
  
  // Modal management
  openModal: (modal: Omit<ModalState, 'isOpen'>) => void;
  closeModal: (id: string) => void;
  closeAllModals: () => void;
  updateModal: (id: string, updates: Partial<ModalState>) => void;
  
  // Sidebar management
  toggleSidebar: () => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  setSidebarPinned: (pinned: boolean) => void;
  setSidebarWidth: (width: number) => void;
  resetSidebar: () => void;
  
  // Form dirty state management
  setFormDirty: (formId: string, isDirty: boolean, fields?: Record<string, boolean>) => void;
  clearFormDirty: (formId: string) => void;
  isFormDirty: (formId: string) => boolean;
  hasAnyDirtyForms: () => boolean;
  
  // Network state
  setOnlineStatus: (isOnline: boolean) => void;
  
  // Viewport management
  updateViewport: (dimensions: { width: number; height: number }) => void;
  
  // Focus management
  setFocusTrap: (elementId: string | null) => void;
  restoreFocus: () => void;
  
  // Utility actions
  reset: () => void;
}

// Combined store type
type UIStore = UIState & UIActions;

// Default sidebar state
const defaultSidebarState: SidebarState = {
  isCollapsed: false,
  isPinned: true,
  width: 280,
  defaultWidth: 280,
  minWidth: 200,
  maxWidth: 400,
};

// Utility functions
const generateId = (): string => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

const getViewportType = (width: number) => ({
  isMobile: width < 768,
  isTablet: width >= 768 && width < 1024,
  isDesktop: width >= 1024,
});

// Create the UI store
export const useUIStore = create<UIStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        globalLoading: [],
        isAnyLoading: false,
        
        toasts: [],
        maxToasts: 5,
        
        modals: [],
        activeModalId: null,
        
        sidebar: defaultSidebarState,
        
        formStates: [],
        hasUnsavedChanges: false,
        
        isOffline: false,
        lastOnlineAt: Date.now(),
        
        viewport: {
          width: typeof window !== 'undefined' ? window.innerWidth : 1024,
          height: typeof window !== 'undefined' ? window.innerHeight : 768,
          ...getViewportType(typeof window !== 'undefined' ? window.innerWidth : 1024),
        },
        
        focusTrap: null,
        previousFocus: null,

        // Loading state management
        addLoading: (loading: Omit<GlobalLoadingState, 'id'>): string => {
          const id = generateId();
          
          set((state) => {
            state.globalLoading.push({ ...loading, id });
            state.isAnyLoading = true;
          });
          
          return id;
        },

        removeLoading: (id: string) => {
          set((state) => {
            state.globalLoading = state.globalLoading.filter(loading => loading.id !== id);
            state.isAnyLoading = state.globalLoading.length > 0;
          });
        },

        updateLoading: (id: string, updates: Partial<GlobalLoadingState>) => {
          set((state) => {
            const loading = state.globalLoading.find(l => l.id === id);
            if (loading) {
              Object.assign(loading, updates);
            }
          });
        },

        clearAllLoading: () => {
          set((state) => {
            state.globalLoading = [];
            state.isAnyLoading = false;
          });
        },

        // Toast management
        addToast: (toast: Omit<Toast, 'id' | 'createdAt'>): string => {
          const id = generateId();
          const newToast: Toast = {
            ...toast,
            id,
            createdAt: Date.now(),
            duration: toast.duration ?? (toast.type === 'error' ? 0 : 4000),
          };
          
          set((state) => {
            // Remove oldest toast if at max capacity
            if (state.toasts.length >= state.maxToasts) {
              state.toasts.shift();
            }
            state.toasts.push(newToast);
          });
          
          // Auto-remove toast if it has a duration
          if (newToast.duration && newToast.duration > 0) {
            setTimeout(() => {
              get().removeToast(id);
            }, newToast.duration);
          }
          
          return id;
        },

        removeToast: (id: string) => {
          set((state) => {
            state.toasts = state.toasts.filter(toast => toast.id !== id);
          });
        },

        clearToast: (id: string) => {
          get().removeToast(id);
        },

        clearAllToasts: () => {
          set((state) => {
            state.toasts = [];
          });
        },

        updateToast: (id: string, updates: Partial<Toast>) => {
          set((state) => {
            const toast = state.toasts.find(t => t.id === id);
            if (toast) {
              Object.assign(toast, updates);
            }
          });
        },

        // Modal management
        openModal: (modal: Omit<ModalState, 'isOpen'>) => {
          set((state) => {
            // Close existing modal with same id if it exists
            const existingIndex = state.modals.findIndex(m => m.id === modal.id);
            if (existingIndex !== -1) {
              state.modals[existingIndex] = { ...modal, isOpen: true };
            } else {
              state.modals.push({ ...modal, isOpen: true });
            }
            state.activeModalId = modal.id;
          });
          
          // Store previous focus for restoration
          if (typeof document !== 'undefined') {
            set((state) => {
              state.previousFocus = document.activeElement as HTMLElement;
            });
          }
        },

        closeModal: (id: string) => {
          set((state) => {
            const modal = state.modals.find(m => m.id === id);
            if (modal) {
              modal.isOpen = false;
              
              // Update active modal
              const openModals = state.modals.filter(m => m.isOpen);
              state.activeModalId = openModals.length > 0 ? openModals[openModals.length - 1].id : null;
            }
          });
          
          // Remove modal after animation delay
          setTimeout(() => {
            set((state) => {
              state.modals = state.modals.filter(m => m.id !== id);
            });
          }, 300);
          
          // Restore focus if this was the last modal
          const { activeModalId } = get();
          if (!activeModalId) {
            get().restoreFocus();
          }
        },

        closeAllModals: () => {
          set((state) => {
            state.modals.forEach(modal => {
              modal.isOpen = false;
            });
            state.activeModalId = null;
          });
          
          // Remove all modals after animation delay
          setTimeout(() => {
            set((state) => {
              state.modals = [];
            });
          }, 300);
          
          get().restoreFocus();
        },

        updateModal: (id: string, updates: Partial<ModalState>) => {
          set((state) => {
            const modal = state.modals.find(m => m.id === id);
            if (modal) {
              Object.assign(modal, updates);
            }
          });
        },

        // Sidebar management
        toggleSidebar: () => {
          set((state) => {
            state.sidebar.isCollapsed = !state.sidebar.isCollapsed;
          });
        },

        setSidebarCollapsed: (collapsed: boolean) => {
          set((state) => {
            state.sidebar.isCollapsed = collapsed;
          });
        },

        setSidebarPinned: (pinned: boolean) => {
          set((state) => {
            state.sidebar.isPinned = pinned;
          });
        },

        setSidebarWidth: (width: number) => {
          const { minWidth, maxWidth } = get().sidebar;
          const constrainedWidth = Math.max(minWidth, Math.min(maxWidth, width));
          
          set((state) => {
            state.sidebar.width = constrainedWidth;
          });
        },

        resetSidebar: () => {
          set((state) => {
            state.sidebar = { ...defaultSidebarState };
          });
        },

        // Form dirty state management
        setFormDirty: (formId: string, isDirty: boolean, fields?: Record<string, boolean>) => {
          set((state) => {
            const existingIndex = state.formStates.findIndex(f => f.formId === formId);
            
            if (existingIndex !== -1) {
              const existing = state.formStates[existingIndex];
              existing.isDirty = isDirty;
              existing.lastModified = Date.now();
              if (fields) {
                existing.fields = { ...existing.fields, ...fields };
              }
            } else {
              state.formStates.push({
                formId,
                isDirty,
                fields: fields || {},
                lastModified: Date.now(),
              });
            }
            
            // Update global dirty state
            state.hasUnsavedChanges = state.formStates.some(f => f.isDirty);
          });
        },

        clearFormDirty: (formId: string) => {
          set((state) => {
            state.formStates = state.formStates.filter(f => f.formId !== formId);
            state.hasUnsavedChanges = state.formStates.some(f => f.isDirty);
          });
        },

        isFormDirty: (formId: string): boolean => {
          const formState = get().formStates.find(f => f.formId === formId);
          return formState?.isDirty ?? false;
        },

        hasAnyDirtyForms: (): boolean => {
          return get().formStates.some(f => f.isDirty);
        },

        // Network state
        setOnlineStatus: (isOnline: boolean) => {
          set((state) => {
            state.isOffline = !isOnline;
            if (isOnline) {
              state.lastOnlineAt = Date.now();
            }
          });
        },

        // Viewport management
        updateViewport: (dimensions: { width: number; height: number }) => {
          set((state) => {
            state.viewport = {
              ...dimensions,
              ...getViewportType(dimensions.width),
            };
          });
        },

        // Focus management
        setFocusTrap: (elementId: string | null) => {
          set((state) => {
            state.focusTrap = elementId;
          });
        },

        restoreFocus: () => {
          const { previousFocus } = get();
          if (previousFocus && typeof previousFocus.focus === 'function') {
            try {
              previousFocus.focus();
            } catch {
              // Focus restoration failed, continue silently
            }
          }
          
          set((state) => {
            state.previousFocus = null;
          });
        },

        // Utility actions
        reset: () => {
          set((state) => {
            state.globalLoading = [];
            state.isAnyLoading = false;
            state.toasts = [];
            state.modals = [];
            state.activeModalId = null;
            state.formStates = [];
            state.hasUnsavedChanges = false;
            state.focusTrap = null;
            state.previousFocus = null;
          });
        },
      })),
      {
        name: 'ui-storage',
        partialize: (state) => ({
          sidebar: state.sidebar,
          maxToasts: state.maxToasts,
        }),
      }
    ),
    {
      name: 'ui-store',
    }
  )
);

// Initialize viewport tracking
if (typeof window !== 'undefined') {
  const handleResize = () => {
    useUIStore.getState().updateViewport({
      width: window.innerWidth,
      height: window.innerHeight,
    });
  };
  
  const handleOnline = () => useUIStore.getState().setOnlineStatus(true);
  const handleOffline = () => useUIStore.getState().setOnlineStatus(false);
  
  window.addEventListener('resize', handleResize);
  window.addEventListener('online', handleOnline);
  window.addEventListener('offline', handleOffline);
  
  // Set initial online status
  useUIStore.getState().setOnlineStatus(navigator.onLine);
}

// Selectors for performance optimization
export const useGlobalLoading = () => useUIStore((state) => state.globalLoading);
export const useIsAnyLoading = () => useUIStore((state) => state.isAnyLoading);
export const useToasts = () => useUIStore((state) => state.toasts);
export const useModals = () => useUIStore((state) => state.modals);
export const useActiveModal = () => {
  const modals = useUIStore((state) => state.modals);
  const activeModalId = useUIStore((state) => state.activeModalId);
  return modals.find(modal => modal.id === activeModalId) || null;
};
export const useSidebar = () => useUIStore((state) => state.sidebar);
export const useFormStates = () => useUIStore((state) => state.formStates);
export const useHasUnsavedChanges = () => useUIStore((state) => state.hasUnsavedChanges);
export const useIsOffline = () => useUIStore((state) => state.isOffline);
export const useViewport = () => useUIStore((state) => state.viewport);

// Action selectors
export const useUIActions = () => useUIStore(useShallow((state) => ({
  // Loading
  addLoading: state.addLoading,
  removeLoading: state.removeLoading,
  updateLoading: state.updateLoading,
  clearAllLoading: state.clearAllLoading,
  
  // Toasts
  addToast: state.addToast,
  removeToast: state.removeToast,
  clearAllToasts: state.clearAllToasts,
  
  // Modals
  openModal: state.openModal,
  closeModal: state.closeModal,
  closeAllModals: state.closeAllModals,
  
  // Sidebar
  toggleSidebar: state.toggleSidebar,
  setSidebarCollapsed: state.setSidebarCollapsed,
  setSidebarPinned: state.setSidebarPinned,
  setSidebarWidth: state.setSidebarWidth,
  
  // Forms
  setFormDirty: state.setFormDirty,
  clearFormDirty: state.clearFormDirty,
  isFormDirty: state.isFormDirty,
  
  // Focus
  setFocusTrap: state.setFocusTrap,
  restoreFocus: state.restoreFocus,
})));

// Utility hooks
export const useLoadingState = (loadingId?: string) => {
  const loading = useUIStore((state) => 
    loadingId ? state.globalLoading.find(l => l.id === loadingId) : null
  );
  const isAnyLoading = useUIStore((state) => state.isAnyLoading);
  
  return loadingId ? loading : { isAnyLoading };
};

export const useModalState = (modalId: string) => {
  const modal = useUIStore((state) => state.modals.find(m => m.id === modalId));
  return modal || null;
};

export const useFormDirtyState = (formId: string) => {
  const formState = useUIStore((state) => state.formStates.find(f => f.formId === formId));
  const actions = useUIActions();
  
  return {
    isDirty: formState?.isDirty ?? false,
    fields: formState?.fields ?? {},
    lastModified: formState?.lastModified,
    setDirty: (isDirty: boolean, fields?: Record<string, boolean>) => 
      actions.setFormDirty(formId, isDirty, fields),
    clear: () => actions.clearFormDirty(formId),
  };
};