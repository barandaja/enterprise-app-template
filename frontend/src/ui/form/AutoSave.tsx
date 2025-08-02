import React from 'react';
import { cn } from '../../utils';

export interface AutoSaveProps {
  data: Record<string, any>;
  onSave: (data: Record<string, any>) => Promise<void> | void;
  interval?: number;
  debounceMs?: number;
  enabled?: boolean;
  storageKey?: string;
  onSaveStart?: () => void;
  onSaveSuccess?: () => void;
  onSaveError?: (error: Error) => void;
  indicator?: 'dot' | 'text' | 'spinner' | 'none';
  indicatorPosition?: 'top-right' | 'top-left' | 'bottom-right' | 'bottom-left';
  className?: string;
  children?: React.ReactNode;
}

type SaveStatus = 'idle' | 'saving' | 'saved' | 'error';

export const AutoSave: React.FC<AutoSaveProps> = ({
  data,
  onSave,
  interval = 30000, // 30 seconds
  debounceMs = 2000, // 2 seconds after last change
  enabled = true,
  storageKey,
  onSaveStart,
  onSaveSuccess,
  onSaveError,
  indicator = 'dot',
  indicatorPosition = 'top-right',
  className,
  children
}) => {
  const [saveStatus, setSaveStatus] = React.useState<SaveStatus>('idle');
  const [lastSaved, setLastSaved] = React.useState<Date | null>(null);
  const saveTimeoutRef = React.useRef<NodeJS.Timeout>();
  const intervalRef = React.useRef<NodeJS.Timeout>();
  const lastDataRef = React.useRef<Record<string, any>>(data);
  const isMountedRef = React.useRef(true);

  React.useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  // Save to localStorage if storageKey is provided
  const saveToStorage = React.useCallback((dataToSave: Record<string, any>) => {
    if (storageKey && typeof window !== 'undefined') {
      try {
        localStorage.setItem(storageKey, JSON.stringify({
          data: dataToSave,
          timestamp: new Date().toISOString()
        }));
      } catch (error) {
        console.warn('Failed to save to localStorage:', error);
      }
    }
  }, [storageKey]);

  // Load from localStorage if available
  const loadFromStorage = React.useCallback(() => {
    if (storageKey && typeof window !== 'undefined') {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const parsed = JSON.parse(stored);
          return parsed.data;
        }
      } catch (error) {
        console.warn('Failed to load from localStorage:', error);
      }
    }
    return null;
  }, [storageKey]);

  // Clear storage
  const clearStorage = React.useCallback(() => {
    if (storageKey && typeof window !== 'undefined') {
      try {
        localStorage.removeItem(storageKey);
      } catch (error) {
        console.warn('Failed to clear localStorage:', error);
      }
    }
  }, [storageKey]);

  // Perform save operation
  const performSave = React.useCallback(async (dataToSave: Record<string, any>) => {
    if (!isMountedRef.current || !enabled) return;

    setSaveStatus('saving');
    onSaveStart?.();

    try {
      await onSave(dataToSave);
      if (isMountedRef.current) {
        setSaveStatus('saved');
        setLastSaved(new Date());
        saveToStorage(dataToSave);
        onSaveSuccess?.();
      }
    } catch (error) {
      if (isMountedRef.current) {
        setSaveStatus('error');
        onSaveError?.(error as Error);
      }
    }

    // Reset status after a delay
    setTimeout(() => {
      if (isMountedRef.current) {
        setSaveStatus('idle');
      }
    }, 3000);
  }, [enabled, onSave, onSaveStart, onSaveSuccess, onSaveError, saveToStorage]);

  // Debounced save when data changes
  React.useEffect(() => {
    if (!enabled) return;

    // Check if data has actually changed
    const hasChanged = JSON.stringify(data) !== JSON.stringify(lastDataRef.current);
    if (!hasChanged) return;

    lastDataRef.current = data;

    // Clear existing timeout
    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    // Set new timeout for debounced save
    saveTimeoutRef.current = setTimeout(() => {
      performSave(data);
    }, debounceMs);

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, [data, enabled, debounceMs, performSave]);

  // Interval-based save
  React.useEffect(() => {
    if (!enabled || interval <= 0) return;

    intervalRef.current = setInterval(() => {
      // Only save if data has changed since last save
      const hasChanged = JSON.stringify(data) !== JSON.stringify(lastDataRef.current);
      if (hasChanged) {
        performSave(data);
      }
    }, interval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [data, enabled, interval, performSave]);

  // Load initial data from storage
  React.useEffect(() => {
    const storedData = loadFromStorage();
    if (storedData) {
      // You might want to emit an event or callback here to restore the data
      console.log('AutoSave: Found stored data', storedData);
    }
  }, [loadFromStorage]);

  // Cleanup on unmount
  React.useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  // Render indicator
  const renderIndicator = () => {
    if (indicator === 'none') return null;

    const getIndicatorContent = () => {
      switch (saveStatus) {
        case 'saving':
          return indicator === 'spinner' ? (
            <svg className="animate-spin h-4 w-4 text-blue-500" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
          ) : indicator === 'text' ? (
            <span className="text-xs text-blue-600 dark:text-blue-400">Saving...</span>
          ) : (
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
          );

        case 'saved':
          return indicator === 'text' ? (
            <span className="text-xs text-green-600 dark:text-green-400">
              Saved {lastSaved ? `at ${lastSaved.toLocaleTimeString()}` : ''}
            </span>
          ) : (
            <div className="w-2 h-2 bg-green-500 rounded-full"></div>
          );

        case 'error':
          return indicator === 'text' ? (
            <span className="text-xs text-red-600 dark:text-red-400">Save failed</span>
          ) : (
            <div className="w-2 h-2 bg-red-500 rounded-full"></div>
          );

        default:
          return indicator === 'text' ? (
            <span className="text-xs text-gray-400">Auto-save enabled</span>
          ) : (
            <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
          );
      }
    };

    const positionClasses = {
      'top-right': 'top-2 right-2',
      'top-left': 'top-2 left-2',
      'bottom-right': 'bottom-2 right-2',
      'bottom-left': 'bottom-2 left-2'
    };

    return (
      <div className={cn(
        'absolute z-10 flex items-center justify-center',
        positionClasses[indicatorPosition]
      )}>
        {getIndicatorContent()}
      </div>
    );
  };

  // If no children, just return null (headless mode)
  if (!children) {
    return null;
  }

  return (
    <div className={cn('relative', className)}>
      {children}
      {renderIndicator()}
    </div>
  );
};

// Hook for using AutoSave functionality
export interface UseAutoSaveOptions {
  data: Record<string, any>;
  onSave: (data: Record<string, any>) => Promise<void> | void;
  interval?: number;
  debounceMs?: number;
  enabled?: boolean;
  storageKey?: string;
}

export const useAutoSave = (options: UseAutoSaveOptions) => {
  const [saveStatus, setSaveStatus] = React.useState<SaveStatus>('idle');
  const [lastSaved, setLastSaved] = React.useState<Date | null>(null);
  const saveTimeoutRef = React.useRef<NodeJS.Timeout>();
  const intervalRef = React.useRef<NodeJS.Timeout>();
  const lastDataRef = React.useRef<Record<string, any>>(options.data);

  const {
    data,
    onSave,
    interval = 30000,
    debounceMs = 2000,
    enabled = true,
    storageKey
  } = options;

  const performSave = React.useCallback(async (dataToSave: Record<string, any>) => {
    if (!enabled) return;

    setSaveStatus('saving');

    try {
      await onSave(dataToSave);
      setSaveStatus('saved');
      setLastSaved(new Date());

      // Save to localStorage if key provided
      if (storageKey && typeof window !== 'undefined') {
        try {
          localStorage.setItem(storageKey, JSON.stringify({
            data: dataToSave,
            timestamp: new Date().toISOString()
          }));
        } catch (error) {
          console.warn('Failed to save to localStorage:', error);
        }
      }
    } catch (error) {
      setSaveStatus('error');
      throw error;
    }

    // Reset status after delay
    setTimeout(() => setSaveStatus('idle'), 3000);
  }, [enabled, onSave, storageKey]);

  // Manual save function
  const save = React.useCallback(() => {
    return performSave(data);
  }, [data, performSave]);

  // Load from storage
  const loadFromStorage = React.useCallback(() => {
    if (storageKey && typeof window !== 'undefined') {
      try {
        const stored = localStorage.getItem(storageKey);
        if (stored) {
          const parsed = JSON.parse(stored);
          return parsed.data;
        }
      } catch (error) {
        console.warn('Failed to load from localStorage:', error);
      }
    }
    return null;
  }, [storageKey]);

  // Clear storage
  const clearStorage = React.useCallback(() => {
    if (storageKey && typeof window !== 'undefined') {
      try {
        localStorage.removeItem(storageKey);
      } catch (error) {
        console.warn('Failed to clear localStorage:', error);
      }
    }
  }, [storageKey]);

  // Auto-save logic (same as component)
  React.useEffect(() => {
    if (!enabled) return;

    const hasChanged = JSON.stringify(data) !== JSON.stringify(lastDataRef.current);
    if (!hasChanged) return;

    lastDataRef.current = data;

    if (saveTimeoutRef.current) {
      clearTimeout(saveTimeoutRef.current);
    }

    saveTimeoutRef.current = setTimeout(() => {
      performSave(data);
    }, debounceMs);

    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
    };
  }, [data, enabled, debounceMs, performSave]);

  React.useEffect(() => {
    if (!enabled || interval <= 0) return;

    intervalRef.current = setInterval(() => {
      const hasChanged = JSON.stringify(data) !== JSON.stringify(lastDataRef.current);
      if (hasChanged) {
        performSave(data);
      }
    }, interval);

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [data, enabled, interval, performSave]);

  React.useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) {
        clearTimeout(saveTimeoutRef.current);
      }
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  return {
    saveStatus,
    lastSaved,
    save,
    loadFromStorage,
    clearStorage,
    isIdle: saveStatus === 'idle',
    isSaving: saveStatus === 'saving',
    isSaved: saveStatus === 'saved',
    hasError: saveStatus === 'error'
  };
};

export type { SaveStatus, UseAutoSaveOptions };

/*
Usage Examples:

// Component with AutoSave wrapper
<AutoSave
  data={formData}
  onSave={async (data) => {
    await saveFormData(data);
  }}
  interval={30000}
  debounceMs={2000}
  storageKey="user-profile-form"
  indicator="text"
  indicatorPosition="top-right"
  onSaveSuccess={() => toast.success('Form saved!')}
  onSaveError={(error) => toast.error('Failed to save')}
>
  <form>
    <FormField label="Name">
      <Input 
        value={formData.name}
        onChange={(e) => setFormData({...formData, name: e.target.value})}
      />
    </FormField>
  </form>
</AutoSave>

// Using the hook
const MyForm = () => {
  const [formData, setFormData] = useState({});
  
  const autoSave = useAutoSave({
    data: formData,
    onSave: async (data) => {
      await api.saveForm(data);
    },
    storageKey: 'my-form-draft',
    debounceMs: 1000
  });

  // Load draft on mount
  useEffect(() => {
    const draft = autoSave.loadFromStorage();
    if (draft) {
      setFormData(draft);
    }
  }, []);

  return (
    <div>
      <form>
        <Input 
          value={formData.title}
          onChange={(e) => setFormData({...formData, title: e.target.value})}
        />
        
        <div className="flex items-center gap-2">
          <Button onClick={autoSave.save} disabled={autoSave.isSaving}>
            Save Now
          </Button>
          
          {autoSave.isSaving && <span>Saving...</span>}
          {autoSave.isSaved && <span>Saved at {autoSave.lastSaved?.toLocaleTimeString()}</span>}
          {autoSave.hasError && <span>Failed to save</span>}
        </div>
      </form>
    </div>
  );
};

// Headless mode (no UI, just functionality)
<AutoSave
  data={formData}
  onSave={handleSave}
  indicator="none"
/>
*/