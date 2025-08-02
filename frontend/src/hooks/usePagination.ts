import { useState, useCallback, useMemo } from 'react';
import type { PaginatedResponse } from '../types';

/**
 * Pagination configuration options
 */
export interface PaginationOptions {
  /**
   * Initial page number (1-based)
   */
  initialPage?: number;
  /**
   * Number of items per page
   */
  pageSize?: number;
  /**
   * Total number of items (if known)
   */
  totalItems?: number;
  /**
   * Number of pages to show around current page in pagination controls
   */
  siblingCount?: number;
  /**
   * Always show first and last page
   */
  showFirstLast?: boolean;
  /**
   * Show ellipsis when there are gaps
   */
  showEllipsis?: boolean;
}

/**
 * Pagination state and utilities
 */
export interface PaginationState {
  currentPage: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
  hasNextPage: boolean;
  hasPreviousPage: boolean;
  isFirstPage: boolean;
  isLastPage: boolean;
  startIndex: number;
  endIndex: number;
  offset: number;
}

/**
 * Pagination actions
 */
export interface PaginationActions {
  goToPage: (page: number) => void;
  nextPage: () => void;
  previousPage: () => void;
  firstPage: () => void;
  lastPage: () => void;
  setPageSize: (size: number) => void;
  setTotalItems: (total: number) => void;
  reset: () => void;
}

/**
 * Pagination range item types
 */
export type PaginationRangeItem = number | 'ellipsis';

/**
 * Complete pagination return type
 */
export interface UsePaginationReturn extends PaginationState, PaginationActions {
  /**
   * Array of page numbers and ellipsis for rendering pagination controls
   */
  paginationRange: PaginationRangeItem[];
  /**
   * Get query parameters for API calls
   */
  getQueryParams: () => { page: number; limit: number; offset: number };
  /**
   * Update pagination from API response
   */
  updateFromResponse: (response: PaginatedResponse<any>) => void;
}

/**
 * Hook for managing pagination state and calculations
 * Provides comprehensive pagination utilities for tables, lists, and API integration
 * 
 * @example
 * ```tsx
 * // Basic usage
 * const pagination = usePagination({
 *   pageSize: 10,
 *   totalItems: 100
 * });
 * 
 * // Render pagination controls
 * <div className="pagination">
 *   <button 
 *     onClick={pagination.previousPage}
 *     disabled={!pagination.hasPreviousPage}
 *   >
 *     Previous
 *   </button>
 *   
 *   {pagination.paginationRange.map((page, index) => (
 *     <button
 *       key={index}
 *       onClick={() => page !== 'ellipsis' && pagination.goToPage(page)}
 *       className={page === pagination.currentPage ? 'active' : ''}
 *       disabled={page === 'ellipsis'}
 *     >
 *       {page === 'ellipsis' ? '...' : page}
 *     </button>
 *   ))}
 *   
 *   <button 
 *     onClick={pagination.nextPage}
 *     disabled={!pagination.hasNextPage}
 *   >
 *     Next
 *   </button>
 * </div>
 * 
 * // With API integration
 * const UserList = () => {
 *   const [users, setUsers] = useState([]);
 *   const pagination = usePagination({ pageSize: 20 });
 *   
 *   const fetchUsers = async () => {
 *     const params = pagination.getQueryParams();
 *     const response = await api.getUsers(params);
 *     setUsers(response.data);
 *     pagination.updateFromResponse(response);
 *   };
 *   
 *   useEffect(() => {
 *     fetchUsers();
 *   }, [pagination.currentPage, pagination.pageSize]);
 *   
 *   return (
 *     <div>
 *       <UserTable users={users} />
 *       <PaginationControls {...pagination} />
 *       <div>
 *         Showing {pagination.startIndex}-{pagination.endIndex} of {pagination.totalItems}
 *       </div>
 *     </div>
 *   );
 * };
 * ```
 * 
 * @param options - Pagination configuration
 * @returns Pagination state and actions
 */
export function usePagination(options: PaginationOptions = {}): UsePaginationReturn {
  const {
    initialPage = 1,
    pageSize: initialPageSize = 10,
    totalItems: initialTotalItems = 0,
    siblingCount = 1,
    showFirstLast = true,
    showEllipsis = true,
  } = options;

  const [currentPage, setCurrentPage] = useState(initialPage);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [totalItems, setTotalItems] = useState(initialTotalItems);

  // Calculated values
  const totalPages = useMemo(() => {
    return Math.ceil(totalItems / pageSize) || 1;
  }, [totalItems, pageSize]);

  const hasNextPage = useMemo(() => {
    return currentPage < totalPages;
  }, [currentPage, totalPages]);

  const hasPreviousPage = useMemo(() => {
    return currentPage > 1;
  }, [currentPage]);

  const isFirstPage = useMemo(() => {
    return currentPage === 1;
  }, [currentPage]);

  const isLastPage = useMemo(() => {
    return currentPage === totalPages;
  }, [currentPage, totalPages]);

  const startIndex = useMemo(() => {
    return (currentPage - 1) * pageSize + 1;
  }, [currentPage, pageSize]);

  const endIndex = useMemo(() => {
    return Math.min(currentPage * pageSize, totalItems);
  }, [currentPage, pageSize, totalItems]);

  const offset = useMemo(() => {
    return (currentPage - 1) * pageSize;
  }, [currentPage, pageSize]);

  // Generate pagination range for UI controls
  const paginationRange = useMemo((): PaginationRangeItem[] => {
    // If total pages is less than or equal to 7, show all pages
    if (totalPages <= 7) {
      return Array.from({ length: totalPages }, (_, i) => i + 1);
    }

    const leftSiblingIndex = Math.max(currentPage - siblingCount, 1);
    const rightSiblingIndex = Math.min(currentPage + siblingCount, totalPages);

    const shouldShowLeftEllipsis = leftSiblingIndex > 2;
    const shouldShowRightEllipsis = rightSiblingIndex < totalPages - 1;

    const firstPageIndex = 1;
    const lastPageIndex = totalPages;

    // Case 1: Show right ellipsis only
    if (!shouldShowLeftEllipsis && shouldShowRightEllipsis) {
      const leftRange = Array.from({ length: 3 + 2 * siblingCount }, (_, i) => i + 1);
      
      if (showEllipsis) {
        return showFirstLast 
          ? [...leftRange, 'ellipsis', lastPageIndex]
          : [...leftRange, 'ellipsis'];
      }
      
      return showFirstLast ? [...leftRange, lastPageIndex] : leftRange;
    }

    // Case 2: Show left ellipsis only
    if (shouldShowLeftEllipsis && !shouldShowRightEllipsis) {
      const rightRange = Array.from(
        { length: 3 + 2 * siblingCount },
        (_, i) => totalPages - (3 + 2 * siblingCount) + i + 1
      );
      
      if (showEllipsis) {
        return showFirstLast 
          ? [firstPageIndex, 'ellipsis', ...rightRange]
          : ['ellipsis', ...rightRange];
      }
      
      return showFirstLast ? [firstPageIndex, ...rightRange] : rightRange;
    }

    // Case 3: Show both ellipses
    if (shouldShowLeftEllipsis && shouldShowRightEllipsis) {
      const middleRange = Array.from(
        { length: rightSiblingIndex - leftSiblingIndex + 1 },
        (_, i) => leftSiblingIndex + i
      );
      
      if (showEllipsis) {
        return showFirstLast
          ? [firstPageIndex, 'ellipsis', ...middleRange, 'ellipsis', lastPageIndex]
          : ['ellipsis', ...middleRange, 'ellipsis'];
      }
      
      return showFirstLast
        ? [firstPageIndex, ...middleRange, lastPageIndex]
        : middleRange;
    }

    // Fallback: show all pages
    return Array.from({ length: totalPages }, (_, i) => i + 1);
  }, [currentPage, totalPages, siblingCount, showFirstLast, showEllipsis]);

  // Actions
  const goToPage = useCallback((page: number) => {
    const targetPage = Math.max(1, Math.min(page, totalPages));
    setCurrentPage(targetPage);
  }, [totalPages]);

  const nextPage = useCallback(() => {
    if (hasNextPage) {
      setCurrentPage(prev => prev + 1);
    }
  }, [hasNextPage]);

  const previousPage = useCallback(() => {
    if (hasPreviousPage) {
      setCurrentPage(prev => prev - 1);
    }
  }, [hasPreviousPage]);

  const firstPage = useCallback(() => {
    setCurrentPage(1);
  }, []);

  const lastPage = useCallback(() => {
    setCurrentPage(totalPages);
  }, [totalPages]);

  const updatePageSize = useCallback((size: number) => {
    const newPageSize = Math.max(1, size);
    setPageSize(newPageSize);
    
    // Adjust current page to maintain roughly the same position
    const currentFirstItem = (currentPage - 1) * pageSize + 1;
    const newPage = Math.ceil(currentFirstItem / newPageSize);
    setCurrentPage(Math.max(1, newPage));
  }, [currentPage, pageSize]);

  const updateTotalItems = useCallback((total: number) => {
    setTotalItems(Math.max(0, total));
    
    // Adjust current page if it's beyond the new total pages
    const newTotalPages = Math.ceil(total / pageSize) || 1;
    if (currentPage > newTotalPages) {
      setCurrentPage(newTotalPages);
    }
  }, [currentPage, pageSize]);

  const reset = useCallback(() => {
    setCurrentPage(initialPage);
    setPageSize(initialPageSize);
    setTotalItems(initialTotalItems);
  }, [initialPage, initialPageSize, initialTotalItems]);

  const getQueryParams = useCallback(() => {
    return {
      page: currentPage,
      limit: pageSize,
      offset: offset,
    };
  }, [currentPage, pageSize, offset]);

  const updateFromResponse = useCallback((response: PaginatedResponse<any>) => {
    const { pagination: paginationData } = response;
    
    setCurrentPage(paginationData.page);
    setPageSize(paginationData.limit);
    setTotalItems(paginationData.total);
  }, []);

  return {
    // State
    currentPage,
    pageSize,
    totalItems,
    totalPages,
    hasNextPage,
    hasPreviousPage,
    isFirstPage,
    isLastPage,
    startIndex,
    endIndex,
    offset,
    paginationRange,

    // Actions
    goToPage,
    nextPage,
    previousPage,
    firstPage,
    lastPage,
    setPageSize: updatePageSize,
    setTotalItems: updateTotalItems,
    reset,

    // Utilities
    getQueryParams,
    updateFromResponse,
  };
}

/**
 * Hook for cursor-based pagination (infinite scroll pattern)
 * Useful for social feeds, chat messages, and large datasets
 * 
 * @example
 * ```tsx
 * const {
 *   items,
 *   isLoading,
 *   hasMore,
 *   loadMore,
 *   reset
 * } = useCursorPagination(
 *   async (cursor) => {
 *     const response = await api.getPosts({ cursor, limit: 20 });
 *     return {
 *       items: response.data,
 *       nextCursor: response.nextCursor,
 *       hasMore: response.hasMore
 *     };
 *   }
 * );
 * 
 * return (
 *   <div>
 *     {items.map(item => <PostCard key={item.id} post={item} />)}
 *     {hasMore && (
 *       <button onClick={loadMore} disabled={isLoading}>
 *         {isLoading ? 'Loading...' : 'Load More'}
 *       </button>
 *     )}
 *   </div>
 * );
 * ```
 */
export function useCursorPagination<T, TCursor = string>(
  fetchFn: (cursor?: TCursor) => Promise<{
    items: T[];
    nextCursor?: TCursor;
    hasMore: boolean;
  }>,
  options: {
    initialLoad?: boolean;
  } = {}
) {
  const { initialLoad = true } = options;
  
  const [items, setItems] = useState<T[]>([]);
  const [cursor, setCursor] = useState<TCursor | undefined>();
  const [isLoading, setIsLoading] = useState(false);
  const [hasMore, setHasMore] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const loadMore = useCallback(async () => {
    if (isLoading || !hasMore) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await fetchFn(cursor);
      
      setItems(prev => [...prev, ...result.items]);
      setCursor(result.nextCursor);
      setHasMore(result.hasMore);
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to load more items'));
    } finally {
      setIsLoading(false);
    }
  }, [fetchFn, cursor, isLoading, hasMore]);

  const reset = useCallback(() => {
    setItems([]);
    setCursor(undefined);
    setHasMore(true);
    setError(null);
  }, []);

  const refresh = useCallback(async () => {
    reset();
    // Load first page
    await loadMore();
  }, [reset, loadMore]);

  // Initial load
  useState(() => {
    if (initialLoad) {
      loadMore();
    }
  });

  return {
    items,
    isLoading,
    hasMore,
    error,
    loadMore,
    reset,
    refresh,
  };
}

/**
 * Hook for table pagination with sorting and filtering
 * Provides a complete solution for data tables
 * 
 * @example
 * ```tsx
 * const {
 *   pagination,
 *   sorting,
 *   filters,
 *   queryParams,
 *   updateSort,
 *   updateFilter,
 *   clearFilters
 * } = useTablePagination({
 *   defaultSort: { field: 'createdAt', order: 'desc' },
 *   defaultFilters: { status: 'active' }
 * });
 * ```
 */
export function useTablePagination<TFilters extends Record<string, any> = Record<string, any>>(options: {
  defaultSort?: { field: string; order: 'asc' | 'desc' };
  defaultFilters?: TFilters;
  pageSize?: number;
} = {}) {
  const { defaultSort, defaultFilters = {} as TFilters, pageSize = 10 } = options;

  const pagination = usePagination({ pageSize });
  
  const [sorting, setSorting] = useState(defaultSort || { field: '', order: 'asc' as const });
  const [filters, setFilters] = useState<TFilters>(defaultFilters);

  const updateSort = useCallback((field: string, order?: 'asc' | 'desc') => {
    setSorting(prev => ({
      field,
      order: order || (prev.field === field && prev.order === 'asc' ? 'desc' : 'asc'),
    }));
    pagination.goToPage(1); // Reset to first page when sorting changes
  }, [pagination]);

  const updateFilter = useCallback((key: keyof TFilters, value: any) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    pagination.goToPage(1); // Reset to first page when filters change
  }, [pagination]);

  const clearFilters = useCallback(() => {
    setFilters(defaultFilters);
    pagination.goToPage(1);
  }, [defaultFilters, pagination]);

  const queryParams = useMemo(() => {
    const paginationParams = pagination.getQueryParams();
    
    return {
      ...paginationParams,
      sort: sorting.field,
      order: sorting.order,
      ...filters,
    };
  }, [pagination, sorting, filters]);

  return {
    pagination,
    sorting,
    filters,
    queryParams,
    updateSort,
    updateFilter,
    clearFilters,
  };
}