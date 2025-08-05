import { useEffect, useRef, useCallback } from 'react';

/**
 * Event types that trigger outside clicks
 */
type EventType = 'mousedown' | 'mouseup' | 'touchstart' | 'touchend' | 'focusin' | 'focusout';

/**
 * Configuration options for click outside detection
 */
interface UseClickOutsideOptions {
  /**
   * Event types to listen for (default: ['mousedown', 'touchstart'])
   */
  events?: EventType[];
  /**
   * Whether the hook is enabled (default: true)
   */
  enabled?: boolean;
  /**
   * Elements to ignore when detecting outside clicks
   */
  ignore?: (HTMLElement | null | undefined)[] | (() => (HTMLElement | null | undefined)[]);
}

/**
 * Hook for detecting clicks outside of specified elements
 * Supports multiple refs, event cleanup, and TypeScript safety
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const ref = useRef<HTMLDivElement>(null);
 * useClickOutside(ref, () => {
 *   console.log('Clicked outside');
 * });
 * 
 * // Multiple elements
 * const modalRef = useRef<HTMLDivElement>(null);
 * const triggerRef = useRef<HTMLButtonElement>(null);
 * useClickOutside([modalRef, triggerRef], () => {
 *   setIsOpen(false);
 * });
 * 
 * // With options
 * useClickOutside(ref, handleClickOutside, {
 *   events: ['mousedown', 'focusin'],
 *   enabled: isOpen,
 *   ignore: [overlayRef.current, tooltipRef.current]
 * });
 * 
 * // Dropdown example
 * const DropdownMenu = () => {
 *   const [isOpen, setIsOpen] = useState(false);
 *   const menuRef = useRef<HTMLDivElement>(null);
 *   const buttonRef = useRef<HTMLButtonElement>(null);
 * 
 *   useClickOutside([menuRef, buttonRef], () => {
 *     setIsOpen(false);
 *   }, { enabled: isOpen });
 * 
 *   return (
 *     <div>
 *       <button ref={buttonRef} onClick={() => setIsOpen(!isOpen)}>
 *         Menu
 *       </button>
 *       {isOpen && (
 *         <div ref={menuRef}>
 *           <MenuItem />
 *         </div>
 *       )}
 *     </div>
 *   );
 * };
 * ```
 * 
 * @param refs - Single ref or array of refs to elements that should not trigger the callback
 * @param callback - Function to call when clicking outside
 * @param options - Configuration options
 */
export function useClickOutside<T extends HTMLElement = HTMLElement>(
  refs: React.RefObject<T> | React.RefObject<T>[],
  callback: (event: Event) => void,
  options: UseClickOutsideOptions = {}
): void {
  const {
    events = ['mousedown', 'touchstart'],
    enabled = true,
    ignore = [],
  } = options;

  const callbackRef = useRef(callback);
  const optionsRef = useRef(options);

  // Update refs when props change
  callbackRef.current = callback;
  optionsRef.current = options;

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const handleEvent = (event: Event) => {
      const target = event.target as HTMLElement;
      if (!target) return;

      // Convert refs to array for consistent handling
      const refArray = Array.isArray(refs) ? refs : [refs];
      
      // Get ignore elements
      const ignoreElements = typeof ignore === 'function' ? ignore() : ignore;
      const allIgnoreElements = ignoreElements.filter(Boolean) as HTMLElement[];

      // Check if click is inside any of the ref elements
      const isInsideRefs = refArray.some(ref => {
        const element = ref.current;
        return element && (element === target || element.contains(target));
      });

      // Check if click is inside any ignored elements
      const isInsideIgnored = allIgnoreElements.some(element => {
        return element && (element === target || element.contains(target));
      });

      // If click is outside refs and not in ignored elements, call callback
      if (!isInsideRefs && !isInsideIgnored && typeof callbackRef.current === 'function') {
        callbackRef.current(event);
      }
    };

    // Add event listeners for each event type
    events.forEach(eventType => {
      document.addEventListener(eventType, handleEvent, true);
    });

    // Cleanup event listeners
    return () => {
      events.forEach(eventType => {
        document.removeEventListener(eventType, handleEvent, true);
      });
    };
  }, [refs, events, enabled, ignore]);
}

/**
 * Hook that returns both a ref and click outside functionality
 * Useful when you need to create the ref within the hook
 * 
 * @example
 * ```tsx
 * const { ref, isClickedOutside } = useClickOutsideRef<HTMLDivElement>();
 * 
 * const [isOpen, setIsOpen] = useState(false);
 * 
 * useEffect(() => {
 *   if (isClickedOutside && isOpen) {
 *     setIsOpen(false);
 *   }
 * }, [isClickedOutside, isOpen]);
 * 
 * return (
 *   <div ref={ref}>
 *     Content that closes when clicked outside
 *   </div>
 * );
 * ```
 * 
 * @param options - Configuration options
 * @returns Object with ref and click outside state
 */
export function useClickOutsideRef<T extends HTMLElement = HTMLElement>(
  options: UseClickOutsideOptions = {}
): {
  ref: React.RefObject<T>;
  isClickedOutside: boolean;
  resetClickedOutside: () => void;
} {
  const ref = useRef<T>(null);
  const [isClickedOutside, setIsClickedOutside] = useState(false);

  const resetClickedOutside = useCallback(() => {
    setIsClickedOutside(false);
  }, []);

  useClickOutside(
    ref,
    () => {
      setIsClickedOutside(true);
    },
    options
  );

  return {
    ref,
    isClickedOutside,
    resetClickedOutside,
  };
}

/**
 * Hook for handling escape key presses along with click outside
 * Common pattern for modals, dropdowns, and popups
 * 
 * @example
 * ```tsx
 * const ref = useRef<HTMLDivElement>(null);
 * 
 * useClickOutsideWithEscape(ref, () => {
 *   setIsOpen(false);
 * }, {
 *   enabled: isOpen,
 *   escapeKey: true
 * });
 * ```
 * 
 * @param refs - Ref or array of refs to elements
 * @param callback - Function to call when clicking outside or pressing escape
 * @param options - Configuration options with escape key support
 */
export function useClickOutsideWithEscape<T extends HTMLElement = HTMLElement>(
  refs: React.RefObject<T> | React.RefObject<T>[],
  callback: (event: Event) => void,
  options: UseClickOutsideOptions & {
    escapeKey?: boolean;
    escapeKeyCode?: string;
  } = {}
): void {
  const { escapeKey = true, escapeKeyCode = 'Escape', ...clickOutsideOptions } = options;

  // Handle click outside
  useClickOutside(refs, callback, clickOutsideOptions);

  // Handle escape key
  useEffect(() => {
    if (!escapeKey || !clickOutsideOptions.enabled) {
      return;
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === escapeKeyCode) {
        event.preventDefault();
        callback(event);
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [escapeKey, escapeKeyCode, callback, clickOutsideOptions.enabled]);
}

/**
 * Hook for managing focus trap along with click outside detection
 * Perfect for accessible modals and dialogs
 * 
 * @example
 * ```tsx
 * const { ref, focusFirst, focusLast } = useClickOutsideWithFocusTrap<HTMLDivElement>(
 *   () => setIsOpen(false),
 *   { enabled: isOpen }
 * );
 * 
 * useEffect(() => {
 *   if (isOpen) {
 *     focusFirst();
 *   }
 * }, [isOpen, focusFirst]);
 * ```
 * 
 * @param callback - Function to call when clicking outside
 * @param options - Configuration options
 * @returns Object with ref and focus utilities
 */
export function useClickOutsideWithFocusTrap<T extends HTMLElement = HTMLElement>(
  callback: (event: Event) => void,
  options: UseClickOutsideOptions = {}
): {
  ref: React.RefObject<T>;
  focusFirst: () => void;
  focusLast: () => void;
  getAllFocusableElements: () => HTMLElement[];
} {
  const ref = useRef<T>(null);

  // Get all focusable elements within the container
  const getAllFocusableElements = useCallback((): HTMLElement[] => {
    if (!ref.current) return [];

    const focusableSelectors = [
      'button:not([disabled])',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      'a[href]',
      '[tabindex]:not([tabindex="-1"])',
      '[contenteditable="true"]',
    ].join(', ');

    return Array.from(ref.current.querySelectorAll(focusableSelectors)) as HTMLElement[];
  }, []);

  const focusFirst = useCallback(() => {
    const focusableElements = getAllFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[0].focus();
    }
  }, [getAllFocusableElements]);

  const focusLast = useCallback(() => {
    const focusableElements = getAllFocusableElements();
    if (focusableElements.length > 0) {
      focusableElements[focusableElements.length - 1].focus();
    }
  }, [getAllFocusableElements]);

  // Handle tab key for focus trap
  useEffect(() => {
    if (!options.enabled) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Tab') return;

      const focusableElements = getAllFocusableElements();
      if (focusableElements.length === 0) return;

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      if (event.shiftKey) {
        // Shift + Tab: moving backwards
        if (document.activeElement === firstElement) {
          event.preventDefault();
          lastElement.focus();
        }
      } else {
        // Tab: moving forwards
        if (document.activeElement === lastElement) {
          event.preventDefault();
          firstElement.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [options.enabled, getAllFocusableElements]);

  useClickOutsideWithEscape(ref, callback, options);

  return {
    ref,
    focusFirst,
    focusLast,
    getAllFocusableElements,
  };
}