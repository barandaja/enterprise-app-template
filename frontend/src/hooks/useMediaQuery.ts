import { useState, useEffect, useCallback, useMemo } from 'react';
import { useDebounce } from './useDebounce';

/**
 * Breakpoint definitions following common design systems
 */
export const breakpoints = {
  xs: '(min-width: 0px)',
  sm: '(min-width: 640px)',
  md: '(min-width: 768px)',
  lg: '(min-width: 1024px)',
  xl: '(min-width: 1280px)',
  '2xl': '(min-width: 1536px)',
  // Max-width breakpoints
  'max-xs': '(max-width: 639px)',
  'max-sm': '(max-width: 767px)',
  'max-md': '(max-width: 1023px)',
  'max-lg': '(max-width: 1279px)',
  'max-xl': '(max-width: 1535px)',
  // Orientation
  portrait: '(orientation: portrait)',
  landscape: '(orientation: landscape)',
  // Features
  'hover-hover': '(hover: hover)',
  'hover-none': '(hover: none)',
  // Reduced motion
  'reduce-motion': '(prefers-reduced-motion: reduce)',
  'no-reduce-motion': '(prefers-reduced-motion: no-preference)',
  // Color scheme
  'dark': '(prefers-color-scheme: dark)',
  'light': '(prefers-color-scheme: light)',
  // High contrast
  'high-contrast': '(prefers-contrast: high)',
  'low-contrast': '(prefers-contrast: low)',
} as const;

export type BreakpointKey = keyof typeof breakpoints;

/**
 * Hook for responsive design with media query matching
 * Includes SSR compatibility and debounced resize handling for performance
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const isMobile = useMediaQuery('(max-width: 768px)');
 * const isDesktop = useMediaQuery('(min-width: 1024px)');
 * 
 * // Using predefined breakpoints
 * const isSmallScreen = useMediaQuery(breakpoints.sm);
 * const isDarkMode = useMediaQuery(breakpoints.dark);
 * 
 * // With debouncing for performance
 * const isLarge = useMediaQuery('(min-width: 1024px)', { debounceMs: 100 });
 * 
 * // With SSR default value
 * const isMobile = useMediaQuery('(max-width: 768px)', { 
 *   defaultValue: false,
 *   debounceMs: 50 
 * });
 * 
 * // Conditional rendering
 * return (
 *   <div>
 *     {isMobile ? <MobileNav /> : <DesktopNav />}
 *     {isDesktop && <Sidebar />}
 *   </div>
 * );
 * ```
 * 
 * @param query - Media query string
 * @param options - Configuration options
 * @returns Boolean indicating if the media query matches
 */
export function useMediaQuery(
  query: string,
  options: {
    defaultValue?: boolean;
    debounceMs?: number;
  } = {}
): boolean {
  const { defaultValue = false, debounceMs = 0 } = options;

  // Initialize with default value for SSR compatibility
  const [matches, setMatches] = useState<boolean>(() => {
    // On server-side, return default value
    if (typeof window === 'undefined') {
      return defaultValue;
    }

    // On client-side, check if matchMedia is available
    if (!window.matchMedia) {
      return defaultValue;
    }

    try {
      return window.matchMedia(query).matches;
    } catch {
      console.warn(`Invalid media query: ${query}`);
      return defaultValue;
    }
  });

  // Debounce the matches value for performance
  const debouncedMatches = useDebounce(matches, debounceMs);

  useEffect(() => {
    // Skip if not in browser environment
    if (typeof window === 'undefined' || !window.matchMedia) {
      return;
    }

    let mediaQueryList: MediaQueryList;

    try {
      mediaQueryList = window.matchMedia(query);
    } catch (error) {
      console.warn(`Invalid media query: ${query}`, error);
      return;
    }

    // Update matches when media query changes
    const handleChange = (event: MediaQueryListEvent) => {
      setMatches(event.matches);
    };

    // Set initial value
    setMatches(mediaQueryList.matches);

    // Add listener
    if (mediaQueryList.addEventListener) {
      mediaQueryList.addEventListener('change', handleChange);
    } else {
      // Fallback for older browsers
      mediaQueryList.addListener(handleChange);
    }

    // Cleanup
    return () => {
      if (mediaQueryList.removeEventListener) {
        mediaQueryList.removeEventListener('change', handleChange);
      } else {
        // Fallback for older browsers
        mediaQueryList.removeListener(handleChange);
      }
    };
  }, [query]);

  return debounceMs > 0 ? debouncedMatches : matches;
}

/**
 * Hook for using predefined breakpoints with TypeScript safety
 * 
 * @example
 * ```tsx
 * const isMobile = useBreakpoint('max-sm');
 * const isDesktop = useBreakpoint('lg');
 * const prefersDark = useBreakpoint('dark');
 * ```
 * 
 * @param breakpoint - Predefined breakpoint key
 * @param options - Configuration options
 * @returns Boolean indicating if the breakpoint matches
 */
export function useBreakpoint(
  breakpoint: BreakpointKey,
  options?: {
    defaultValue?: boolean;
    debounceMs?: number;
  }
): boolean {
  return useMediaQuery(breakpoints[breakpoint], options);
}

/**
 * Hook that provides multiple breakpoint states at once
 * Useful for complex responsive logic
 * 
 * @example
 * ```tsx
 * const { isMobile, isTablet, isDesktop, isLarge } = useBreakpoints();
 * 
 * const columns = useMemo(() => {
 *   if (isMobile) return 1;
 *   if (isTablet) return 2;
 *   if (isDesktop) return 3;
 *   return 4;
 * }, [isMobile, isTablet, isDesktop]);
 * ```
 * 
 * @param options - Configuration options
 * @returns Object with common breakpoint states
 */
export function useBreakpoints(options?: {
  debounceMs?: number;
}) {
  const isMobile = useBreakpoint('max-sm', options);
  const isTablet = useMediaQuery('(min-width: 640px) and (max-width: 1023px)', options);
  const isDesktop = useBreakpoint('lg', options);
  const isLarge = useBreakpoint('xl', options);
  const isExtraLarge = useBreakpoint('2xl', options);

  const isSmallScreen = useBreakpoint('max-md', options);
  const isLargeScreen = useBreakpoint('lg', options);

  return {
    isMobile,
    isTablet,
    isDesktop,
    isLarge,
    isExtraLarge,
    isSmallScreen,
    isLargeScreen,
  };
}

/**
 * Hook that provides viewport information and responsive utilities
 * 
 * @example
 * ```tsx
 * const { 
 *   width, 
 *   height, 
 *   aspectRatio, 
 *   orientation,
 *   currentBreakpoint 
 * } = useViewport();
 * 
 * const columns = getColumnsForBreakpoint(currentBreakpoint);
 * ```
 * 
 * @param options - Configuration options
 * @returns Object with viewport information
 */
export function useViewport(options: {
  debounceMs?: number;
} = {}) {
  const { debounceMs = 100 } = options;

  const [viewport, setViewport] = useState(() => ({
    width: typeof window !== 'undefined' ? window.innerWidth : 1024,
    height: typeof window !== 'undefined' ? window.innerHeight : 768,
  }));

  const debouncedViewport = useDebounce(viewport, debounceMs);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }

    const handleResize = () => {
      setViewport({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    };

    window.addEventListener('resize', handleResize);
    
    // Set initial values
    handleResize();

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  const { width, height } = debouncedViewport;

  // Calculate derived values
  const aspectRatio = useMemo(() => width / height, [width, height]);
  
  const orientation = useMemo(() => {
    return width > height ? 'landscape' : 'portrait';
  }, [width, height]);

  const currentBreakpoint = useMemo(() => {
    if (width < 640) return 'xs';
    if (width < 768) return 'sm';
    if (width < 1024) return 'md';
    if (width < 1280) return 'lg';
    if (width < 1536) return 'xl';
    return '2xl';
  }, [width]);

  const breakpointStates = useBreakpoints({ debounceMs: 0 }); // No debounce since viewport is already debounced

  return {
    width,
    height,
    aspectRatio,
    orientation,
    currentBreakpoint,
    ...breakpointStates,
  };
}

/**
 * Hook for detecting preference-based media queries
 * 
 * @example
 * ```tsx
 * const { 
 *   prefersDarkMode, 
 *   prefersReducedMotion, 
 *   prefersHighContrast 
 * } = useMediaPreferences();
 * 
 * // Apply preferences
 * const shouldAnimate = !prefersReducedMotion;
 * const theme = prefersDarkMode ? 'dark' : 'light';
 * ```
 * 
 * @returns Object with user preference states
 */
export function useMediaPreferences() {
  const prefersDarkMode = useBreakpoint('dark');
  const prefersLightMode = useBreakpoint('light');
  const prefersReducedMotion = useBreakpoint('reduce-motion');
  const prefersHighContrast = useBreakpoint('high-contrast');
  const prefersLowContrast = useBreakpoint('low-contrast');
  const canHover = useBreakpoint('hover-hover');

  return {
    prefersDarkMode,
    prefersLightMode,
    prefersReducedMotion,
    prefersHighContrast,
    prefersLowContrast,
    canHover,
  };
}

/**
 * Utility function to get responsive values based on current breakpoint
 * 
 * @example
 * ```tsx
 * const Component = () => {
 *   const currentBreakpoint = useViewport().currentBreakpoint;
 *   
 *   const columns = getResponsiveValue(currentBreakpoint, {
 *     xs: 1,
 *     sm: 2,
 *     md: 3,
 *     lg: 4,
 *     xl: 5,
 *     '2xl': 6,
 *   });
 * 
 *   return <Grid columns={columns} />;
 * };
 * ```
 */
export function getResponsiveValue<T>(
  currentBreakpoint: string,
  values: Partial<Record<BreakpointKey | string, T>>,
  fallback?: T
): T | undefined {
  // Define breakpoint order
  const breakpointOrder = ['xs', 'sm', 'md', 'lg', 'xl', '2xl'];
  
  // Try exact match first
  if (values[currentBreakpoint] !== undefined) {
    return values[currentBreakpoint];
  }
  
  // Find the closest smaller breakpoint
  const currentIndex = breakpointOrder.indexOf(currentBreakpoint);
  if (currentIndex > 0) {
    for (let i = currentIndex - 1; i >= 0; i--) {
      const breakpoint = breakpointOrder[i];
      if (values[breakpoint] !== undefined) {
        return values[breakpoint];
      }
    }
  }
  
  return fallback;
}

/**
 * Hook that combines getResponsiveValue with current breakpoint
 * 
 * @example
 * ```tsx
 * const columns = useResponsiveValue({
 *   xs: 1,
 *   sm: 2,
 *   md: 3,
 *   lg: 4,
 * }, 1);
 * ```
 */
export function useResponsiveValue<T>(
  values: Partial<Record<BreakpointKey | string, T>>,
  fallback?: T
): T | undefined {
  const { currentBreakpoint } = useViewport();
  
  return useMemo(() => {
    return getResponsiveValue(currentBreakpoint, values, fallback);
  }, [currentBreakpoint, values, fallback]);
}