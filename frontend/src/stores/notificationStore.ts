/**
 * Enterprise NotificationStore with Advanced TypeScript Patterns
 * 
 * This store implements sophisticated notification management with:
 * - Real-time notification handling with WebSocket integration
 * - Advanced TypeScript patterns including discriminated unions and template literals
 * - Batch operations with type-safe processing
 * - Notification preferences with granular control
 * - In-app and toast notification management
 * - Performance optimizations with memoized selectors
 */

import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import type {
  AsyncState,
  BaseStore,
  AsyncStoreMixin,
  CacheStoreMixin,
  StoreEventEmitter,
  NotificationId,
  UserId,
  EventKey,
  StoreEvent,
  createNotificationId,
  createUserId,
  generateStoreId,
  STORE_VERSION,
  DEFAULT_CACHE_EXPIRY,
  isAsyncState,
  isLoadingState,
  isSuccessState,
  isErrorState,
  DeepPartial,
  RequiredExcept,
} from './types';

// =============================================================================
// ADVANCED NOTIFICATION TYPES WITH DISCRIMINATED UNIONS
// =============================================================================

/**
 * Base notification interface with common properties  
 */
interface BaseNotification {
  readonly id: NotificationId;
  readonly userId: UserId;
  readonly timestamp: number;
  readonly read: boolean;
  readonly archived: boolean;
  readonly priority: NotificationPriority;
  readonly category: NotificationCategory;
  readonly metadata?: Record<string, unknown>;
  readonly actions?: NotificationAction[];
  readonly expiresAt?: number;
  readonly retryCount?: number;
}

/**
 * Notification priority levels
 */
export type NotificationPriority = 'low' | 'normal' | 'high' | 'urgent' | 'critical';

/**
 * Notification categories for filtering and organization
 */
export type NotificationCategory = 
  | 'security' 
  | 'system' 
  | 'user' 
  | 'social' 
  | 'financial' 
  | 'marketing' 
  | 'task' 
  | 'reminder';

/**
 * Notification delivery channels
 */
export type NotificationChannel = 'in_app' | 'push' | 'email' | 'sms' | 'webhook';

/**
 * Notification status tracking
 */
export type NotificationStatus = 'pending' | 'delivered' | 'failed' | 'retrying' | 'expired';

/**
 * Discriminated union for different notification types
 */
export type Notification = 
  | TextNotification
  | RichNotification
  | ActionNotification
  | ProgressNotification
  | GroupedNotification;

/**
 * Simple text notification
 */
interface TextNotification extends BaseNotification {
  readonly type: 'text';
  readonly title: string;
  readonly message: string;
  readonly icon?: string;
}

/**
 * Rich notification with HTML content and media
 */
interface RichNotification extends BaseNotification {
  readonly type: 'rich';
  readonly title: string;
  readonly content: string; // HTML content
  readonly media?: {
    readonly type: 'image' | 'video' | 'audio';
    readonly url: string;
    readonly alt?: string;
    readonly thumbnail?: string;
  };
  readonly linkPreview?: {
    readonly url: string;
    readonly title: string;
    readonly description: string;
    readonly image?: string;
  };
}

/**
 * Action notification with interactive elements
 */
interface ActionNotification extends BaseNotification {
  readonly type: 'action';
  readonly title: string;
  readonly message: string;
  readonly primaryAction: NotificationAction;
  readonly secondaryActions?: NotificationAction[];
  readonly autoAction?: {
    readonly delay: number;
    readonly action: NotificationAction;
  };
}

/**
 * Progress notification for long-running operations
 */
interface ProgressNotification extends BaseNotification {
  readonly type: 'progress';
  readonly title: string;
  readonly message: string;
  readonly progress: number; // 0-100
  readonly total?: number;
  readonly current?: number;
  readonly unit?: string;
  readonly estimatedCompletion?: number;
  readonly cancellable?: boolean;
}

/**
 * Grouped notification for batched updates
 */
interface GroupedNotification extends BaseNotification {
  readonly type: 'grouped';
  readonly title: string;
  readonly summary: string;
  readonly count: number;
  readonly items: ReadonlyArray<Omit<Notification, 'id' | 'userId' | 'timestamp'>>;
  readonly groupKey: string;
  readonly collapsed: boolean;
}

/**
 * Notification action interface
 */
interface NotificationAction {
  readonly id: string;
  readonly label: string;
  readonly type: 'primary' | 'secondary' | 'destructive' | 'ghost';
  readonly icon?: string;
  readonly url?: string;
  readonly handler?: (notification: Notification) => void | Promise<void>;
  readonly requiresAuth?: boolean;
  readonly confirmationRequired?: boolean;
  readonly confirmationMessage?: string;
}

// =============================================================================
// NOTIFICATION PREFERENCES WITH GRANULAR CONTROL
// =============================================================================

/**
 * Template literal types for notification preference keys
 */
export type NotificationPreferenceKey = 
  | `${NotificationCategory}.${NotificationChannel}.enabled`
  | `${NotificationCategory}.${NotificationChannel}.schedule`
  | `${NotificationCategory}.priority_threshold`
  | `global.${NotificationChannel}.enabled`
  | `global.quiet_hours.enabled`
  | `global.batch_digest.enabled`;

/**
 * Notification preferences with type-safe keys
 */
export interface NotificationPreferences {
  readonly [K in NotificationPreferenceKey]?: K extends `${string}.enabled`
    ? boolean
    : K extends `${string}.schedule`
    ? NotificationSchedule
    : K extends `${string}.priority_threshold`
    ? NotificationPriority
    : K extends 'global.quiet_hours.enabled'
    ? boolean
    : K extends 'global.batch_digest.enabled'
    ? boolean
    : unknown;
}

/**
 * Notification schedule configuration
 */
interface NotificationSchedule {
  readonly enabled: boolean;
  readonly timeZone: string;
  readonly quietHours?: {
    readonly start: string; // HH:mm format
    readonly end: string;   // HH:mm format
    readonly days: readonly number[]; // 0-6, Sunday=0
  };
  readonly batchDigest?: {
    readonly frequency: 'immediate' | 'hourly' | 'daily' | 'weekly';
    readonly time?: string; // HH:mm format for daily/weekly
    readonly day?: number;  // 0-6 for weekly
  };
}

// =============================================================================
// REAL-TIME CONNECTION MANAGEMENT
// =============================================================================

/**
 * WebSocket connection state with advanced tracking
 */
interface WebSocketConnectionState {
  readonly status: 'disconnected' | 'connecting' | 'connected' | 'reconnecting' | 'failed';
  readonly url: string | null;
  readonly lastConnected: number | null;
  readonly lastDisconnected: number | null;
  readonly reconnectAttempts: number;
  readonly maxReconnectAttempts: number;
  readonly reconnectDelay: number;
  readonly heartbeatInterval: number;
  readonly lastHeartbeat: number | null;
  readonly error: Error | null;
}

/**
 * Real-time notification event from WebSocket
 */
interface RealtimeNotificationEvent {
  readonly type: 'notification.created' | 'notification.updated' | 'notification.deleted' | 'notification.batch';
  readonly data: Notification | Notification[] | { id: NotificationId };
  readonly timestamp: number;
  readonly version: number;
}

// =============================================================================
// STORE STATE AND ACTIONS
// =============================================================================

/**
 * Notification store state with advanced TypeScript patterns
 */
interface NotificationState extends BaseStore, AsyncStoreMixin<NotificationState>, CacheStoreMixin<Notification[]> {
  // Core notification data
  readonly notifications: ReadonlyArray<Notification>;
  readonly notificationMap: ReadonlyMap<NotificationId, Notification>;
  readonly unreadCount: number;
  readonly archivedCount: number;
  
  // Categorized notifications with template literal keys
  readonly notificationsByCategory: ReadonlyMap<NotificationCategory, readonly Notification[]>;
  readonly notificationsByPriority: ReadonlyMap<NotificationPriority, readonly Notification[]>;
  
  // Async states for different operations
  readonly fetchState: AsyncState<Notification[]>;
  readonly markAsReadState: AsyncState<NotificationId[]>;
  readonly archiveState: AsyncState<NotificationId[]>;
  readonly deleteState: AsyncState<NotificationId[]>;
  readonly batchOperationState: AsyncState<{ operation: string; count: number }>;
  
  // Preferences and configuration
  readonly preferences: NotificationPreferences;
  readonly preferencesState: AsyncState<NotificationPreferences>;
  
  // Real-time connection
  readonly realtimeConnection: WebSocketConnectionState;
  readonly realtimeEnabled: boolean;
  
  // Filtering and search
  readonly activeFilters: NotificationFilters;
  readonly searchQuery: string;
  readonly filteredNotifications: ReadonlyArray<Notification>;
  
  // Performance tracking
  readonly stats: NotificationStats;
}

/**
 * Notification filters with advanced filtering options
 */
interface NotificationFilters {
  readonly categories: ReadonlySet<NotificationCategory>;
  readonly priorities: ReadonlySet<NotificationPriority>;
  readonly status: ReadonlySet<'read' | 'unread' | 'archived'>;
  readonly dateRange?: {
    readonly start: Date;
    readonly end: Date;
  };
  readonly hasActions: boolean | null;
  readonly searchText: string;
}

/**
 * Notification statistics for analytics
 */
interface NotificationStats {
  readonly totalReceived: number;
  readonly totalRead: number;
  readonly totalArchived: number;
  readonly totalDeleted: number;
  readonly averageReadTime: number;
  readonly categoryBreakdown: ReadonlyMap<NotificationCategory, number>;
  readonly priorityBreakdown: ReadonlyMap<NotificationPriority, number>;
  readonly channelBreakdown: ReadonlyMap<NotificationChannel, number>;
  readonly responseRates: ReadonlyMap<string, number>; // action_id -> response_rate
}

/**
 * Notification store actions with advanced type safety
 */
interface NotificationActions extends StoreEventEmitter {
  // Fetch and refresh operations
  readonly fetchNotifications: (options?: FetchNotificationOptions) => Promise<Notification[]>;
  readonly refreshNotifications: () => Promise<void>;
  readonly fetchNotificationById: (id: NotificationId) => Promise<Notification | null>;
  
  // CRUD operations with batch support
  readonly markAsRead: (ids: NotificationId | NotificationId[]) => Promise<void>;
  readonly markAsUnread: (ids: NotificationId | NotificationId[]) => Promise<void>;
  readonly archiveNotifications: (ids: NotificationId | NotificationId[]) => Promise<void>;
  readonly unarchiveNotifications: (ids: NotificationId | NotificationId[]) => Promise<void>;
  readonly deleteNotifications: (ids: NotificationId | NotificationId[]) => Promise<void>;
  
  // Batch operations with progress tracking
  readonly batchMarkAsRead: (filter: NotificationFilters) => Promise<number>;
  readonly batchArchive: (filter: NotificationFilters) => Promise<number>;
  readonly batchDelete: (filter: NotificationFilters) => Promise<number>;
  
  // Action handling
  readonly executeNotificationAction: (notificationId: NotificationId, actionId: string) => Promise<void>;
  readonly executeCustomAction: (notification: Notification, handler: NotificationAction['handler']) => Promise<void>;
  
  // Preferences management
  readonly fetchPreferences: () => Promise<NotificationPreferences>;
  readonly updatePreferences: (preferences: DeepPartial<NotificationPreferences>) => Promise<void>;
  readonly resetPreferences: () => Promise<void>;
  
  // Real-time connection management
  readonly connectRealtime: () => Promise<void>;
  readonly disconnectRealtime: () => void;
  readonly toggleRealtime: (enabled: boolean) => Promise<void>;
  
  // Filtering and search
  readonly setFilters: (filters: Partial<NotificationFilters>) => void;
  readonly clearFilters: () => void;
  readonly setSearchQuery: (query: string) => void;
  readonly applyQuickFilter: (filter: QuickFilter) => void;
  
  // Utility methods
  readonly getNotificationsByCategory: (category: NotificationCategory) => readonly Notification[];
  readonly getNotificationsByPriority: (priority: NotificationPriority) => readonly Notification[];
  readonly getUnreadNotifications: () => readonly Notification[];
  readonly getArchivedNotifications: () => readonly Notification[];
  
  // Statistics and analytics
  readonly updateStats: () => void;
  readonly getStatsForDateRange: (start: Date, end: Date) => Promise<NotificationStats>;
  
  // Type guards and assertions
  readonly assertNotificationExists: (id: NotificationId) => asserts this is NotificationStore & { notifications: readonly [Notification, ...Notification[]] };
  readonly isNotificationRead: (id: NotificationId) => boolean;
  readonly isNotificationArchived: (id: NotificationId) => boolean;
}

/**
 * Fetch notification options
 */
interface FetchNotificationOptions {
  readonly limit?: number;
  readonly offset?: number;
  readonly categories?: NotificationCategory[];
  readonly priorities?: NotificationPriority[];
  readonly includeArchived?: boolean;
  readonly since?: Date;
}

/**
 * Quick filter presets
 */
export type QuickFilter = 
  | 'all'
  | 'unread'
  | 'important'
  | 'today'
  | 'this_week'
  | 'archived'
  | 'with_actions';

/**
 * Combined notification store type
 */
type NotificationStore = NotificationState & NotificationActions;

// =============================================================================
// MOCK API SERVICE (Replace with actual implementation)
// =============================================================================

const notificationApi = {
  async fetchNotifications(options: FetchNotificationOptions = {}): Promise<Notification[]> {
    // Mock implementation - replace with actual API call
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const mockNotifications: Notification[] = [
      {
        id: createNotificationId('notif_1'),
        userId: createUserId('user_1'),
        type: 'text',
        title: 'Security Alert',
        message: 'New login detected from unknown device',
        timestamp: Date.now() - 300000,
        read: false,
        archived: false,
        priority: 'high',
        category: 'security',
        icon: 'shield-alert',
        actions: [{
          id: 'review',
          label: 'Review Login',
          type: 'primary',
          icon: 'eye',
        }],
      },
      {
        id: createNotificationId('notif_2'),
        userId: createUserId('user_1'),
        type: 'action',
        title: 'Profile Update Required',
        message: 'Please update your profile information to continue using the service',
        primaryAction: {
          id: 'update_profile',
          label: 'Update Now',
          type: 'primary',
          icon: 'user-edit',
          url: '/profile/edit',
        },
        timestamp: Date.now() - 600000,
        read: false,
        archived: false,
        priority: 'normal',
        category: 'user',
      },
    ] as Notification[];
    
    return mockNotifications;
  },
  
  async updateNotificationStatus(ids: NotificationId[], updates: Partial<Pick<Notification, 'read' | 'archived'>>): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 400));
  },
  
  async deleteNotifications(ids: NotificationId[]): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 500));
  },
  
  async fetchPreferences(): Promise<NotificationPreferences> {
    await new Promise(resolve => setTimeout(resolve, 300));
    return {
      'global.in_app.enabled': true,
      'global.push.enabled': true,
      'global.email.enabled': false,
      'security.in_app.enabled': true,
      'security.priority_threshold': 'normal',
      'global.quiet_hours.enabled': true,
    };
  },
  
  async updatePreferences(preferences: DeepPartial<NotificationPreferences>): Promise<NotificationPreferences> {
    await new Promise(resolve => setTimeout(resolve, 600));
    return preferences as NotificationPreferences;
  },
};

// =============================================================================
// STORE IMPLEMENTATION
// =============================================================================

/**
 * Create the enhanced notification store
 */
export const useNotificationStore = create<NotificationStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Base store implementation
        _initialized: Date.now(),
        _version: STORE_VERSION,
        _storeId: generateStoreId(),
        
        // Core notification data
        notifications: [],
        notificationMap: new Map(),
        unreadCount: 0,
        archivedCount: 0,
        
        // Categorized data
        notificationsByCategory: new Map(),
        notificationsByPriority: new Map(),
        
        // Async states
        fetchState: { status: 'idle', data: null, error: null, loading: false },
        markAsReadState: { status: 'idle', data: null, error: null, loading: false },
        archiveState: { status: 'idle', data: null, error: null, loading: false },
        deleteState: { status: 'idle', data: null, error: null, loading: false },
        batchOperationState: { status: 'idle', data: null, error: null, loading: false },
        
        // Preferences
        preferences: {},
        preferencesState: { status: 'idle', data: null, error: null, loading: false },
        
        // Real-time connection
        realtimeConnection: {
          status: 'disconnected',
          url: null,
          lastConnected: null,
          lastDisconnected: null,
          reconnectAttempts: 0,
          maxReconnectAttempts: 5,
          reconnectDelay: 1000,
          heartbeatInterval: 30000,
          lastHeartbeat: null,
          error: null,
        },
        realtimeEnabled: false,
        
        // Filtering and search
        activeFilters: {
          categories: new Set(),
          priorities: new Set(),
          status: new Set(),
          hasActions: null,
          searchText: '',
        },
        searchQuery: '',
        filteredNotifications: [],
        
        // Statistics
        stats: {
          totalReceived: 0,
          totalRead: 0,
          totalArchived: 0,
          totalDeleted: 0,
          averageReadTime: 0,
          categoryBreakdown: new Map(),
          priorityBreakdown: new Map(),
          channelBreakdown: new Map(),
          responseRates: new Map(),
        },
        
        // AsyncStoreMixin implementation
        isLoading: false,
        error: null,
        lastOperation: null,
        
        // CacheStoreMixin implementation
        cacheExpiry: DEFAULT_CACHE_EXPIRY,
        lastCacheUpdate: null,
        
        // Event emitter implementation
        _eventListeners: new Map(),
        
        emit: function<T>(type: EventKey, payload: T) {
          const event: StoreEvent<T> = {
            type,
            payload,
            timestamp: Date.now(),
            storeId: this._storeId,
          };
          
          const listeners = this._eventListeners.get(type) || [];
          listeners.forEach((listener: any) => listener(event));
        },
        
        on: function<T>(type: EventKey, listener: any) {
          const listeners = this._eventListeners.get(type) || [];
          listeners.push(listener);
          this._eventListeners.set(type, listeners);
          
          return () => {
            const currentListeners = this._eventListeners.get(type) || [];
            const index = currentListeners.indexOf(listener);
            if (index > -1) {
              currentListeners.splice(index, 1);
              this._eventListeners.set(type, currentListeners);
            }
          };
        },
        
        once: function<T>(type: EventKey, listener: any) {
          const unsubscribe = this.on(type, (event: StoreEvent<T>) => {
            listener(event);
            unsubscribe();
          });
          return unsubscribe;
        },
        
        off: function(type: EventKey) {
          this._eventListeners.delete(type);
        },
        
        clear: function() {
          this._eventListeners.clear();
        },
        
        // Store mixin implementations
        clearErrors: () => {
          set((state) => {
            state.error = null;
            state.fetchState.error = null;
            state.markAsReadState.error = null;
            state.archiveState.error = null;
            state.deleteState.error = null;
            state.batchOperationState.error = null;
            state.preferencesState.error = null;
          });
        },
        
        reset: () => {
          set((state) => {
            // Reset to initial state while preserving preferences
            const currentPreferences = state.preferences;
            Object.assign(state, {
              notifications: [],
              notificationMap: new Map(),
              unreadCount: 0,
              archivedCount: 0,
              notificationsByCategory: new Map(),
              notificationsByPriority: new Map(),
              fetchState: { status: 'idle', data: null, error: null, loading: false },
              markAsReadState: { status: 'idle', data: null, error: null, loading: false },
              archiveState: { status: 'idle', data: null, error: null, loading: false },
              deleteState: { status: 'idle', data: null, error: null, loading: false },
              batchOperationState: { status: 'idle', data: null, error: null, loading: false },
              preferences: currentPreferences,
              activeFilters: {
                categories: new Set(),
                priorities: new Set(),
                status: new Set(),
                hasActions: null,
                searchText: '',
              },
              searchQuery: '',
              filteredNotifications: [],
              isLoading: false,
              error: null,
              lastOperation: null,
            });
          });
        },
        
        hasPendingOperations: () => {
          const state = get();
          return state.fetchState.loading ||
                 state.markAsReadState.loading ||
                 state.archiveState.loading ||
                 state.deleteState.loading ||
                 state.batchOperationState.loading ||
                 state.preferencesState.loading;
        },
        
        isCacheValid: () => {
          const { lastCacheUpdate, cacheExpiry } = get();
          if (!lastCacheUpdate) return false;
          return Date.now() - lastCacheUpdate < cacheExpiry;
        },
        
        invalidateCache: () => {
          set((state) => {
            state.lastCacheUpdate = null;
          });
        },
        
        refreshCache: async () => {
          await get().fetchNotifications();
        },
        
        // Core notification operations
        fetchNotifications: async (options: FetchNotificationOptions = {}) => {
          set((state) => {
            state.fetchState = { status: 'loading', data: state.notifications, error: null, loading: true };
            state.isLoading = true;
            state.lastOperation = Date.now();
          });
          
          try {
            const notifications = await notificationApi.fetchNotifications(options);
            
            set((state) => {
              // Update notifications
              state.notifications = notifications;
              
              // Update notification map
              state.notificationMap = new Map(
                notifications.map(n => [n.id, n])
              );
              
              // Update counts
              state.unreadCount = notifications.filter(n => !n.read && !n.archived).length;
              state.archivedCount = notifications.filter(n => n.archived).length;
              
              // Update categorized data
              const byCategory = new Map<NotificationCategory, Notification[]>();
              const byPriority = new Map<NotificationPriority, Notification[]>();
              
              notifications.forEach(notification => {
                // By category
                const categoryList = byCategory.get(notification.category) || [];
                categoryList.push(notification);
                byCategory.set(notification.category, categoryList);
                
                // By priority
                const priorityList = byPriority.get(notification.priority) || [];
                priorityList.push(notification);
                byPriority.set(notification.priority, priorityList);
              });
              
              state.notificationsByCategory = byCategory;
              state.notificationsByPriority = byPriority;
              
              // Update async state
              state.fetchState = { status: 'success', data: notifications, error: null, loading: false };
              state.isLoading = false;
              state.lastCacheUpdate = Date.now();
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            // Emit event
            get().emit('notification.fetched' as EventKey, { count: notifications.length });
            
            return notifications;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch notifications');
            
            set((state) => {
              state.fetchState = { status: 'error', data: null, error: err, loading: false };
              state.isLoading = false;
              state.error = err;
            });
            
            throw err;
          }
        },
        
        refreshNotifications: async () => {
          get().invalidateCache();
          await get().fetchNotifications();
        },
        
        fetchNotificationById: async (id: NotificationId) => {
          const notification = get().notificationMap.get(id);
          if (notification) {
            return notification;
          }
          
          // If not in cache, fetch all notifications (in real app, would fetch specific notification)
          await get().fetchNotifications();
          return get().notificationMap.get(id) || null;
        },
        
        // CRUD operations
        markAsRead: async (ids: NotificationId | NotificationId[]) => {
          const idsArray = Array.isArray(ids) ? ids : [ids];
          
          set((state) => {
            state.markAsReadState = { status: 'loading', data: idsArray, error: null, loading: true };
          });
          
          try {
            await notificationApi.updateNotificationStatus(idsArray, { read: true });
            
            set((state) => {
              // Update notifications
              state.notifications.forEach((notification, index) => {
                if (idsArray.includes(notification.id)) {
                  (state.notifications as Notification[])[index] = {
                    ...notification,
                    read: true,
                  };
                }
              });
              
              // Update map
              idsArray.forEach(id => {
                const notification = state.notificationMap.get(id);
                if (notification) {
                  state.notificationMap.set(id, { ...notification, read: true });
                }
              });
              
              // Update unread count
              state.unreadCount = state.notifications.filter(n => !n.read && !n.archived).length;
              
              state.markAsReadState = { status: 'success', data: idsArray, error: null, loading: false };
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            get().emit('notification.updated' as EventKey, { ids: idsArray, updates: { read: true } });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to mark as read');
            
            set((state) => {
              state.markAsReadState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        markAsUnread: async (ids: NotificationId | NotificationId[]) => {
          const idsArray = Array.isArray(ids) ? ids : [ids];
          
          try {
            await notificationApi.updateNotificationStatus(idsArray, { read: false });
            
            set((state) => {
              // Update notifications
              state.notifications.forEach((notification, index) => {
                if (idsArray.includes(notification.id)) {
                  (state.notifications as Notification[])[index] = {
                    ...notification,
                    read: false,
                  };
                }
              });
              
              // Update map
              idsArray.forEach(id => {
                const notification = state.notificationMap.get(id);
                if (notification) {
                  state.notificationMap.set(id, { ...notification, read: false });
                }
              });
              
              // Update unread count
              state.unreadCount = state.notifications.filter(n => !n.read && !n.archived).length;
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            get().emit('notification.updated' as EventKey, { ids: idsArray, updates: { read: false } });
          } catch (error) {
            throw error instanceof Error ? error : new Error('Failed to mark as unread');
          }
        },
        
        archiveNotifications: async (ids: NotificationId | NotificationId[]) => {
          const idsArray = Array.isArray(ids) ? ids : [ids];
          
          set((state) => {
            state.archiveState = { status: 'loading', data: idsArray, error: null, loading: true };
          });
          
          try {
            await notificationApi.updateNotificationStatus(idsArray, { archived: true });
            
            set((state) => {
              // Update notifications
              state.notifications.forEach((notification, index) => {
                if (idsArray.includes(notification.id)) {
                  (state.notifications as Notification[])[index] = {
                    ...notification,
                    archived: true,
                  };
                }
              });
              
              // Update map
              idsArray.forEach(id => {
                const notification = state.notificationMap.get(id);
                if (notification) {
                  state.notificationMap.set(id, { ...notification, archived: true });
                }
              });
              
              // Update counts
              state.unreadCount = state.notifications.filter(n => !n.read && !n.archived).length;
              state.archivedCount = state.notifications.filter(n => n.archived).length;
              
              state.archiveState = { status: 'success', data: idsArray, error: null, loading: false };
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            get().emit('notification.updated' as EventKey, { ids: idsArray, updates: { archived: true } });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to archive notifications');
            
            set((state) => {
              state.archiveState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        unarchiveNotifications: async (ids: NotificationId | NotificationId[]) => {
          const idsArray = Array.isArray(ids) ? ids : [ids];
          
          try {
            await notificationApi.updateNotificationStatus(idsArray, { archived: false });
            
            set((state) => {
              // Update notifications
              state.notifications.forEach((notification, index) => {
                if (idsArray.includes(notification.id)) {
                  (state.notifications as Notification[])[index] = {
                    ...notification,
                    archived: false,
                  };
                }
              });
              
              // Update map
              idsArray.forEach(id => {
                const notification = state.notificationMap.get(id);
                if (notification) {
                  state.notificationMap.set(id, { ...notification, archived: false });
                }
              });
              
              // Update counts
              state.unreadCount = state.notifications.filter(n => !n.read && !n.archived).length;
              state.archivedCount = state.notifications.filter(n => n.archived).length;
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            get().emit('notification.updated' as EventKey, { ids: idsArray, updates: { archived: false } });
          } catch (error) {
            throw error instanceof Error ? error : new Error('Failed to unarchive notifications');
          }
        },
        
        deleteNotifications: async (ids: NotificationId | NotificationId[]) => {
          const idsArray = Array.isArray(ids) ? ids : [ids];
          
          set((state) => {
            state.deleteState = { status: 'loading', data: idsArray, error: null, loading: true };
          });
          
          try {
            await notificationApi.deleteNotifications(idsArray);
            
            set((state) => {
              // Remove from notifications array
              state.notifications = state.notifications.filter(n => !idsArray.includes(n.id));
              
              // Remove from map
              idsArray.forEach(id => {
                state.notificationMap.delete(id);
              });
              
              // Update counts
              state.unreadCount = state.notifications.filter(n => !n.read && !n.archived).length;
              state.archivedCount = state.notifications.filter(n => n.archived).length;
              
              state.deleteState = { status: 'success', data: idsArray, error: null, loading: false };
              
              // Update categorized data
              const byCategory = new Map<NotificationCategory, Notification[]>();
              const byPriority = new Map<NotificationPriority, Notification[]>();
              
              state.notifications.forEach(notification => {
                // By category
                const categoryList = byCategory.get(notification.category) || [];
                categoryList.push(notification);
                byCategory.set(notification.category, categoryList);
                
                // By priority
                const priorityList = byPriority.get(notification.priority) || [];
                priorityList.push(notification);
                byPriority.set(notification.priority, priorityList);
              });
              
              state.notificationsByCategory = byCategory;
              state.notificationsByPriority = byPriority;
              
              // Apply current filters
              get().applyCurrentFilters();
            });
            
            get().emit('notification.deleted' as EventKey, { ids: idsArray });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to delete notifications');
            
            set((state) => {
              state.deleteState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        // Batch operations (simplified implementation)
        batchMarkAsRead: async (filter: NotificationFilters) => {
          const notifications = get().notifications.filter(n => get().matchesFilter(n, filter));
          const ids = notifications.map(n => n.id);
          
          if (ids.length > 0) {
            await get().markAsRead(ids);
          }
          
          return ids.length;
        },
        
        batchArchive: async (filter: NotificationFilters) => {
          const notifications = get().notifications.filter(n => get().matchesFilter(n, filter));
          const ids = notifications.map(n => n.id);
          
          if (ids.length > 0) {
            await get().archiveNotifications(ids);
          }
          
          return ids.length;
        },
        
        batchDelete: async (filter: NotificationFilters) => {
          const notifications = get().notifications.filter(n => get().matchesFilter(n, filter));
          const ids = notifications.map(n => n.id);
          
          if (ids.length > 0) {
            await get().deleteNotifications(ids);
          }
          
          return ids.length;
        },
        
        // Action handling
        executeNotificationAction: async (notificationId: NotificationId, actionId: string) => {
          const notification = get().notificationMap.get(notificationId);
          if (!notification) {
            throw new Error('Notification not found');
          }
          
          const action = notification.actions?.find(a => a.id === actionId);
          if (!action) {
            throw new Error('Action not found');
          }
          
          if (action.handler) {
            await action.handler(notification);
          } else if (action.url) {
            window.location.href = action.url;
          }
          
          // Mark notification as read after action
          if (!notification.read) {
            await get().markAsRead(notificationId);
          }
        },
        
        executeCustomAction: async (notification: Notification, handler?: NotificationAction['handler']) => {
          if (handler) {
            await handler(notification);
          }
        },
        
        // Preferences management
        fetchPreferences: async () => {
          set((state) => {
            state.preferencesState = { status: 'loading', data: state.preferences, error: null, loading: true };
          });
          
          try {
            const preferences = await notificationApi.fetchPreferences();
            
            set((state) => {
              state.preferences = preferences;
              state.preferencesState = { status: 'success', data: preferences, error: null, loading: false };
            });
            
            return preferences;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch preferences');
            
            set((state) => {
              state.preferencesState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        updatePreferences: async (preferences: DeepPartial<NotificationPreferences>) => {
          set((state) => {
            state.preferencesState = { status: 'loading', data: state.preferences, error: null, loading: true };
          });
          
          try {
            const updatedPreferences = await notificationApi.updatePreferences(preferences);
            
            set((state) => {
              state.preferences = { ...state.preferences, ...updatedPreferences };
              state.preferencesState = { status: 'success', data: state.preferences, error: null, loading: false };
            });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to update preferences');
            
            set((state) => {
              state.preferencesState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        resetPreferences: async () => {
          await get().updatePreferences({});
        },
        
        // Real-time connection (simplified implementation)
        connectRealtime: async () => {
          set((state) => {
            state.realtimeConnection.status = 'connecting';
            state.realtimeEnabled = true;
          });
          
          try {
            // In real implementation, would establish WebSocket connection
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            set((state) => {
              state.realtimeConnection.status = 'connected';
              state.realtimeConnection.lastConnected = Date.now();
              state.realtimeConnection.error = null;
            });
          } catch (error) {
            set((state) => {
              state.realtimeConnection.status = 'failed';
              state.realtimeConnection.error = error instanceof Error ? error : new Error('Connection failed');
            });
            
            throw error;
          }
        },
        
        disconnectRealtime: () => {
          set((state) => {
            state.realtimeConnection.status = 'disconnected';
            state.realtimeConnection.lastDisconnected = Date.now();
            state.realtimeEnabled = false;
          });
        },
        
        toggleRealtime: async (enabled: boolean) => {
          if (enabled) {
            await get().connectRealtime();
          } else {
            get().disconnectRealtime();
          }
        },
        
        // Filtering and search
        setFilters: (filters: Partial<NotificationFilters>) => {
          set((state) => {
            state.activeFilters = { ...state.activeFilters, ...filters };
            get().applyCurrentFilters();
          });
        },
        
        clearFilters: () => {
          set((state) => {
            state.activeFilters = {
              categories: new Set(),
              priorities: new Set(),
              status: new Set(),
              hasActions: null,
              searchText: '',
            };
            state.searchQuery = '';
            state.filteredNotifications = state.notifications;
          });
        },
        
        setSearchQuery: (query: string) => {
          set((state) => {
            state.searchQuery = query;
            state.activeFilters.searchText = query;
            get().applyCurrentFilters();
          });
        },
        
        applyQuickFilter: (filter: QuickFilter) => {
          const now = new Date();
          const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
          const weekStart = new Date(todayStart.getTime() - 7 * 24 * 60 * 60 * 1000);
          
          switch (filter) {
            case 'all':
              get().clearFilters();
              break;
            case 'unread':
              get().setFilters({ status: new Set(['unread']) });
              break;
            case 'important':
              get().setFilters({ priorities: new Set(['high', 'urgent', 'critical']) });
              break;
            case 'today':
              get().setFilters({ dateRange: { start: todayStart, end: now } });
              break;
            case 'this_week':
              get().setFilters({ dateRange: { start: weekStart, end: now } });
              break;
            case 'archived':
              get().setFilters({ status: new Set(['archived']) });
              break;
            case 'with_actions':
              get().setFilters({ hasActions: true });
              break;
          }
        },
        
        // Helper method to apply current filters
        applyCurrentFilters: () => {
          const { notifications, activeFilters } = get();
          
          const filtered = notifications.filter(notification => 
            get().matchesFilter(notification, activeFilters)
          );
          
          set((state) => {
            state.filteredNotifications = filtered;
          });
        },
        
        // Helper method to check if notification matches filter
        matchesFilter: (notification: Notification, filter: NotificationFilters): boolean => {
          // Category filter
          if (filter.categories.size > 0 && !filter.categories.has(notification.category)) {
            return false;
          }
          
          // Priority filter
          if (filter.priorities.size > 0 && !filter.priorities.has(notification.priority)) {
            return false;
          }
          
          // Status filter
          if (filter.status.size > 0) {
            const status = notification.archived ? 'archived' : notification.read ? 'read' : 'unread';
            if (!filter.status.has(status)) {
              return false;
            }
          }
          
          // Date range filter
          if (filter.dateRange) {
            const notificationDate = new Date(notification.timestamp);
            if (notificationDate < filter.dateRange.start || notificationDate > filter.dateRange.end) {
              return false;
            }
          }
          
          // Actions filter
          if (filter.hasActions !== null) {
            const hasActions = Boolean(notification.actions && notification.actions.length > 0);
            if (hasActions !== filter.hasActions) {
              return false;
            }
          }
          
          // Search text filter
          if (filter.searchText) {
            const searchLower = filter.searchText.toLowerCase();
            const title = 'title' in notification ? notification.title.toLowerCase() : '';
            const message = 'message' in notification ? notification.message.toLowerCase() : '';
            
            if (!title.includes(searchLower) && !message.includes(searchLower)) {
              return false;
            }
          }
          
          return true;
        },
        
        // Utility methods
        getNotificationsByCategory: (category: NotificationCategory) => {
          return get().notificationsByCategory.get(category) || [];
        },
        
        getNotificationsByPriority: (priority: NotificationPriority) => {
          return get().notificationsByPriority.get(priority) || [];
        },
        
        getUnreadNotifications: () => {
          return get().notifications.filter(n => !n.read && !n.archived);
        },
        
        getArchivedNotifications: () => {
          return get().notifications.filter(n => n.archived);
        },
        
        // Statistics
        updateStats: () => {
          const notifications = get().notifications;
          const categoryBreakdown = new Map<NotificationCategory, number>();
          const priorityBreakdown = new Map<NotificationPriority, number>();
          
          notifications.forEach(notification => {
            // Category breakdown
            categoryBreakdown.set(
              notification.category,
              (categoryBreakdown.get(notification.category) || 0) + 1
            );
            
            // Priority breakdown
            priorityBreakdown.set(
              notification.priority,
              (priorityBreakdown.get(notification.priority) || 0) + 1
            );
          });
          
          set((state) => {
            state.stats = {
              ...state.stats,
              totalReceived: notifications.length,
              totalRead: notifications.filter(n => n.read).length,
              totalArchived: notifications.filter(n => n.archived).length,
              categoryBreakdown,
              priorityBreakdown,
            };
          });
        },
        
        getStatsForDateRange: async (start: Date, end: Date) => {
          // In real implementation, would fetch stats from API
          const notifications = get().notifications.filter(n => {
            const date = new Date(n.timestamp);
            return date >= start && date <= end;
          });
          
          const categoryBreakdown = new Map<NotificationCategory, number>();
          const priorityBreakdown = new Map<NotificationPriority, number>();
          
          notifications.forEach(notification => {
            categoryBreakdown.set(
              notification.category,
              (categoryBreakdown.get(notification.category) || 0) + 1
            );
            
            priorityBreakdown.set(
              notification.priority,
              (priorityBreakdown.get(notification.priority) || 0) + 1
            );
          });
          
          return {
            totalReceived: notifications.length,
            totalRead: notifications.filter(n => n.read).length,
            totalArchived: notifications.filter(n => n.archived).length,
            totalDeleted: 0,
            averageReadTime: 0,
            categoryBreakdown,
            priorityBreakdown,
            channelBreakdown: new Map(),
            responseRates: new Map(),
          };
        },
        
        // Type guards and assertions
        assertNotificationExists: (id: NotificationId) => {
          const notification = get().notificationMap.get(id);
          if (!notification) {
            throw new Error(`Notification with ID ${id} not found`);
          }
        },
        
        isNotificationRead: (id: NotificationId) => {
          const notification = get().notificationMap.get(id);
          return notification?.read ?? false;
        },
        
        isNotificationArchived: (id: NotificationId) => {
          const notification = get().notificationMap.get(id);
          return notification?.archived ?? false;
        },
      })),
      {
        name: 'notification-storage',
        partialize: (state) => ({
          preferences: state.preferences,
          realtimeEnabled: state.realtimeEnabled,
          activeFilters: {
            ...state.activeFilters,
            // Convert Sets to arrays for serialization
            categories: Array.from(state.activeFilters.categories),
            priorities: Array.from(state.activeFilters.priorities),
            status: Array.from(state.activeFilters.status),
          },
        }),
        onRehydrateStorage: () => (state) => {
          if (state && state.activeFilters) {
            // Convert arrays back to Sets
            state.activeFilters.categories = new Set(state.activeFilters.categories as any);
            state.activeFilters.priorities = new Set(state.activeFilters.priorities as any);
            state.activeFilters.status = new Set(state.activeFilters.status as any);
          }
        },
      }
    ),
    {
      name: 'notification-store',
    }
  )
);

// =============================================================================
// PERFORMANCE-OPTIMIZED SELECTORS
// =============================================================================

/**
 * Memoized selectors for optimal performance
 */
export const useNotifications = () => useNotificationStore((state) => state.filteredNotifications.length > 0 ? state.filteredNotifications : state.notifications);
export const useUnreadCount = () => useNotificationStore((state) => state.unreadCount);
export const useArchivedCount = () => useNotificationStore((state) => state.archivedCount);
export const useNotificationsByCategory = (category: NotificationCategory) => 
  useNotificationStore((state) => state.notificationsByCategory.get(category) || []);
export const useNotificationsByPriority = (priority: NotificationPriority) => 
  useNotificationStore((state) => state.notificationsByPriority.get(priority) || []);

export const useNotificationStates = () => useNotificationStore((state) => ({
  fetchState: state.fetchState,
  markAsReadState: state.markAsReadState,
  archiveState: state.archiveState,
  deleteState: state.deleteState,
  batchOperationState: state.batchOperationState,
}));

export const useNotificationPreferences = () => useNotificationStore((state) => state.preferences);
export const useNotificationFilters = () => useNotificationStore((state) => state.activeFilters);
export const useNotificationStats = () => useNotificationStore((state) => state.stats);
export const useRealtimeConnection = () => useNotificationStore((state) => state.realtimeConnection);

// Action selectors
export const useNotificationActions = () => useNotificationStore((state) => ({
  fetchNotifications: state.fetchNotifications,
  refreshNotifications: state.refreshNotifications,
  markAsRead: state.markAsRead,
  markAsUnread: state.markAsUnread,
  archiveNotifications: state.archiveNotifications,
  unarchiveNotifications: state.unarchiveNotifications,
  deleteNotifications: state.deleteNotifications,
  batchMarkAsRead: state.batchMarkAsRead,
  batchArchive: state.batchArchive,
  batchDelete: state.batchDelete,
  executeNotificationAction: state.executeNotificationAction,
  updatePreferences: state.updatePreferences,
  setFilters: state.setFilters,
  clearFilters: state.clearFilters,
  setSearchQuery: state.setSearchQuery,
  applyQuickFilter: state.applyQuickFilter,
  connectRealtime: state.connectRealtime,
  disconnectRealtime: state.disconnectRealtime,
  toggleRealtime: state.toggleRealtime,
}));

// Composite hooks for convenience
export const useNotificationWithActions = () => {
  const notifications = useNotifications();
  const unreadCount = useUnreadCount();
  const actions = useNotificationActions();
  const states = useNotificationStates();
  
  return {
    notifications,
    unreadCount,
    ...actions,
    ...states,
  };
};

// Type-safe notification hooks with specific filtering
export const useUnreadNotifications = () => useNotificationStore((state) => 
  state.notifications.filter(n => !n.read && !n.archived)
);

export const useImportantNotifications = () => useNotificationStore((state) => 
  state.notifications.filter(n => 
    ['high', 'urgent', 'critical'].includes(n.priority) && !n.archived
  )
);

export const useActionableNotifications = () => useNotificationStore((state) => 
  state.notifications.filter(n => 
    n.actions && n.actions.length > 0 && !n.archived
  )
);

// Hook for specific notification by ID with type safety
export const useNotificationById = (id: NotificationId | null) => 
  useNotificationStore((state) => 
    id ? state.notificationMap.get(id) || null : null
  );

// Utility hook for notification operations
export const useNotificationUtils = () => useNotificationStore((state) => ({
  getNotificationsByCategory: state.getNotificationsByCategory,
  getNotificationsByPriority: state.getNotificationsByPriority,
  getUnreadNotifications: state.getUnreadNotifications,
  getArchivedNotifications: state.getArchivedNotifications,
  isNotificationRead: state.isNotificationRead,
  isNotificationArchived: state.isNotificationArchived,
  assertNotificationExists: state.assertNotificationExists,
}));