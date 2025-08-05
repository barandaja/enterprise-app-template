/**
 * @fileoverview Preferences API Service
 * 
 * Enterprise-grade preferences service providing:
 * - Type-safe preference CRUD operations with validation
 * - Schema validation and migration support
 * - Backup and restore functionality with versioning
 * - Real-time synchronization across devices
 * - Conflict resolution with multiple strategies
 * - Preference groups and categories organization
 * - Encrypted storage for sensitive preferences
 * - Event-driven preference change notifications
 */

import { z } from 'zod';
import { apiClient } from './client';
import { PreferenceDataType } from './types';
import type {
  ApiResponse,
  PaginatedResponse,
  EnhancedApiRequestConfig,
  PreferenceValue,
  PreferenceDefinition,
  UserPreferenceEntry,
  PreferenceGroup,
  PreferenceBackup,
  PreferenceSyncConflict,
} from './types';

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Preference value validation schema
 */
const preferenceValueSchema = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.record(z.unknown()),
  z.array(z.unknown()),
  z.null(),
]);

/**
 * Preference definition schema
 */
const preferenceDefinitionSchema = z.object({
  key: z.string().min(1).max(100).regex(/^[a-zA-Z][a-zA-Z0-9._-]*$/, 'Invalid preference key format'),
  name: z.string().min(1).max(255),
  description: z.string().max(500).optional(),
  dataType: z.nativeEnum(PreferenceDataType),
  defaultValue: preferenceValueSchema,
  isRequired: z.boolean().default(false),
  isSecret: z.boolean().default(false),
  category: z.string().min(1).max(100),
  tags: z.array(z.string()).default([]),
});

/**
 * User preference entry schema
 */
const userPreferenceEntrySchema = z.object({
  key: z.string().min(1),
  value: preferenceValueSchema,
});

/**
 * Preference group schema
 */
const preferenceGroupSchema = z.object({
  category: z.string().min(1).max(100),
  name: z.string().min(1).max(255),
  description: z.string().max(500).optional(),
  order: z.number().int().min(0).default(0),
});

/**
 * Backup creation schema
 */
const createBackupSchema = z.object({
  version: z.string().min(1).max(50),
  metadata: z.object({
    deviceInfo: z.string().optional(),
    appVersion: z.string().optional(),
    reason: z.enum(['manual', 'auto', 'migration']),
  }),
});

/**
 * Sync conflict resolution schema
 */
const syncConflictResolutionSchema = z.object({
  conflicts: z.array(z.object({
    key: z.string(),
    resolution: z.enum(['local', 'remote', 'merge', 'manual']),
    resolvedValue: preferenceValueSchema.optional(),
  })),
});

// =============================================================================
// Type-Safe Preference Key System
// =============================================================================

/**
 * Well-known preference keys with type safety
 */
export const PREFERENCE_KEYS = {
  // UI Preferences
  THEME: 'ui.theme' as const,
  LANGUAGE: 'ui.language' as const,
  TIMEZONE: 'ui.timezone' as const,
  SIDEBAR_COLLAPSED: 'ui.sidebar.collapsed' as const,
  TABLE_PAGE_SIZE: 'ui.table.pageSize' as const,
  DATE_FORMAT: 'ui.dateFormat' as const,
  
  // Notification Preferences
  NOTIFICATIONS_EMAIL: 'notifications.email.enabled' as const,
  NOTIFICATIONS_PUSH: 'notifications.push.enabled' as const,
  NOTIFICATIONS_MARKETING: 'notifications.marketing.enabled' as const,
  NOTIFICATIONS_FREQUENCY: 'notifications.frequency' as const,
  
  // Privacy Preferences
  PRIVACY_PROFILE_VISIBLE: 'privacy.profile.visible' as const,
  PRIVACY_ANALYTICS: 'privacy.analytics.enabled' as const,
  PRIVACY_DATA_PROCESSING: 'privacy.dataProcessing.enabled' as const,
  
  // Security Preferences
  SECURITY_2FA_ENABLED: 'security.twoFactor.enabled' as const,
  SECURITY_SESSION_TIMEOUT: 'security.session.timeout' as const,
  SECURITY_LOGIN_ALERTS: 'security.login.alerts' as const,
  
  // Advanced Preferences
  DEVELOPER_MODE: 'advanced.developer.mode' as const,
  DEBUG_LOGGING: 'advanced.debug.logging' as const,
  EXPERIMENTAL_FEATURES: 'advanced.experimental.features' as const,
} as const;

/**
 * Preference key type
 */
export type PreferenceKey = typeof PREFERENCE_KEYS[keyof typeof PREFERENCE_KEYS] | string;

/**
 * Type-safe preference value mapping
 */
export interface PreferenceValueMap {
  [PREFERENCE_KEYS.THEME]: 'light' | 'dark' | 'system';
  [PREFERENCE_KEYS.LANGUAGE]: string;
  [PREFERENCE_KEYS.TIMEZONE]: string;
  [PREFERENCE_KEYS.SIDEBAR_COLLAPSED]: boolean;
  [PREFERENCE_KEYS.TABLE_PAGE_SIZE]: number;
  [PREFERENCE_KEYS.DATE_FORMAT]: string;
  [PREFERENCE_KEYS.NOTIFICATIONS_EMAIL]: boolean;
  [PREFERENCE_KEYS.NOTIFICATIONS_PUSH]: boolean;
  [PREFERENCE_KEYS.NOTIFICATIONS_MARKETING]: boolean;
  [PREFERENCE_KEYS.NOTIFICATIONS_FREQUENCY]: 'immediate' | 'hourly' | 'daily' | 'weekly';
  [PREFERENCE_KEYS.PRIVACY_PROFILE_VISIBLE]: boolean;
  [PREFERENCE_KEYS.PRIVACY_ANALYTICS]: boolean;
  [PREFERENCE_KEYS.PRIVACY_DATA_PROCESSING]: boolean;
  [PREFERENCE_KEYS.SECURITY_2FA_ENABLED]: boolean;
  [PREFERENCE_KEYS.SECURITY_SESSION_TIMEOUT]: number;
  [PREFERENCE_KEYS.SECURITY_LOGIN_ALERTS]: boolean;
  [PREFERENCE_KEYS.DEVELOPER_MODE]: boolean;
  [PREFERENCE_KEYS.DEBUG_LOGGING]: boolean;
  [PREFERENCE_KEYS.EXPERIMENTAL_FEATURES]: string[];
}

// =============================================================================
// Real-time Sync Manager
// =============================================================================

/**
 * Real-time preference synchronization manager
 */
class PreferenceSyncManager {
  private ws: WebSocket | null = null;
  private syncCallbacks = new Set<(changes: UserPreferenceEntry[]) => void>();
  private conflictCallbacks = new Set<(conflicts: PreferenceSyncConflict[]) => void>();
  private isConnected = false;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private lastSyncTimestamp: string | null = null;

  /**
   * Connect to real-time preference sync
   */
  async connect(userId: string): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      const wsUrl = this.buildWebSocketUrl(userId);
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[PreferenceSync] Connected');
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.requestSync();
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleSyncMessage(message);
        } catch (error) {
          console.error('[PreferenceSync] Failed to parse message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('[PreferenceSync] Disconnected');
        this.isConnected = false;
        this.scheduleReconnect(userId);
      };

      this.ws.onerror = (error) => {
        console.error('[PreferenceSync] Error:', error);
      };
    } catch (error) {
      console.error('[PreferenceSync] Connection failed:', error);
      this.scheduleReconnect(userId);
    }
  }

  /**
   * Disconnect from sync
   */
  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.isConnected = false;
    this.syncCallbacks.clear();
    this.conflictCallbacks.clear();
  }

  /**
   * Subscribe to preference changes
   */
  onSync(callback: (changes: UserPreferenceEntry[]) => void): () => void {
    this.syncCallbacks.add(callback);
    return () => this.syncCallbacks.delete(callback);
  }

  /**
   * Subscribe to sync conflicts
   */
  onConflict(callback: (conflicts: PreferenceSyncConflict[]) => void): () => void {
    this.conflictCallbacks.add(callback);
    return () => this.conflictCallbacks.delete(callback);
  }

  /**
   * Send preference changes to sync
   */
  sendChanges(changes: UserPreferenceEntry[]): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'preference.changes',
        payload: changes,
        timestamp: new Date().toISOString(),
      }));
    }
  }

  private buildWebSocketUrl(userId: string): string {
    const baseUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:3000';
    return `${baseUrl}/preferences/sync?userId=${userId}`;
  }

  private handleSyncMessage(message: any): void {
    switch (message.type) {
      case 'preference.sync':
        this.handlePreferenceSync(message.payload);
        break;
      case 'preference.conflicts':
        this.handleSyncConflicts(message.payload);
        break;
      case 'sync.ack':
        this.lastSyncTimestamp = message.timestamp;
        break;
      default:
        console.warn('[PreferenceSync] Unknown message type:', message.type);
    }
  }

  private handlePreferenceSync(changes: UserPreferenceEntry[]): void {
    this.syncCallbacks.forEach(callback => {
      try {
        callback(changes);
      } catch (error) {
        console.error('[PreferenceSync] Sync callback error:', error);
      }
    });
  }

  private handleSyncConflicts(conflicts: PreferenceSyncConflict[]): void {
    this.conflictCallbacks.forEach(callback => {
      try {
        callback(conflicts);
      } catch (error) {
        console.error('[PreferenceSync] Conflict callback error:', error);
      }
    });
  }

  private requestSync(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'sync.request',
        lastSyncTimestamp: this.lastSyncTimestamp,
      }));
    }
  }

  private scheduleReconnect(userId: string): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[PreferenceSync] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = 1000 * Math.pow(2, this.reconnectAttempts - 1);

    setTimeout(() => {
      console.log(`[PreferenceSync] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect(userId);
    }, delay);
  }
}

// =============================================================================
// Preferences Service Class
// =============================================================================

/**
 * Enterprise preferences service with advanced features
 */
export class PreferencesService {
  private readonly baseUrl = '/preferences';
  private readonly client = apiClient;
  private readonly syncManager = new PreferenceSyncManager();
  private readonly cache = new Map<string, { value: PreferenceValue; timestamp: number; ttl: number }>();
  private readonly CACHE_TTL = 300000; // 5 minutes

  // ===========================================================================
  // Type-Safe Preference Operations
  // ===========================================================================

  /**
   * Get preference value with type safety
   * 
   * @param key - Preference key
   * @param defaultValue - Default value if preference doesn't exist
   * @param config - Request configuration
   * @returns Promise resolving to preference value
   * 
   * @example
   * ```typescript
   * const theme = await preferencesService.get(PREFERENCE_KEYS.THEME, 'light');
   * const pageSize = await preferencesService.get(PREFERENCE_KEYS.TABLE_PAGE_SIZE, 20);
   * ```
   */
  async get<K extends keyof PreferenceValueMap>(
    key: K,
    defaultValue?: PreferenceValueMap[K],
    config: EnhancedApiRequestConfig = {}
  ): Promise<PreferenceValueMap[K]>;
  async get<T extends PreferenceValue>(
    key: string,
    defaultValue?: T,
    config: EnhancedApiRequestConfig = {}
  ): Promise<T>;
  async get<T extends PreferenceValue>(
    key: string,
    defaultValue?: T,
    config: EnhancedApiRequestConfig = {}
  ): Promise<T> {
    // Check cache first
    const cached = this.getCachedValue<T>(key);
    if (cached !== null) {
      return cached;
    }

    try {
      const response = await this.client.get<{ value: T }>(
        `${this.baseUrl}/${encodeURIComponent(key)}`,
        {
          ...config,
          cancelKey: `preference.get.${key}`,
          cache: {
            enabled: true,
            ttl: this.CACHE_TTL,
            key: `preference:${key}`,
          },
        }
      );

      if (response.success && response.data.value !== undefined) {
        const value = response.data.value;
        this.setCachedValue(key, value);
        return value;
      }
    } catch (error) {
      console.warn(`[Preferences] Failed to get preference '${key}':`, error);
    }

    // Return default value if preference doesn't exist or fetch failed
    return defaultValue as T;
  }

  /**
   * Set preference value with type safety
   * 
   * @param key - Preference key
   * @param value - Preference value
   * @param config - Request configuration
   * @returns Promise resolving to updated preference
   * 
   * @example
   * ```typescript
   * await preferencesService.set(PREFERENCE_KEYS.THEME, 'dark');
   * await preferencesService.set(PREFERENCE_KEYS.TABLE_PAGE_SIZE, 50);
   * ```
   */
  async set<K extends keyof PreferenceValueMap>(
    key: K,
    value: PreferenceValueMap[K],
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferenceEntry>>;
  async set<T extends PreferenceValue>(
    key: string,
    value: T,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferenceEntry>>;
  async set<T extends PreferenceValue>(
    key: string,
    value: T,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferenceEntry>> {
    const validatedEntry = userPreferenceEntrySchema.parse({ key, value });

    const response = await this.client.put<typeof validatedEntry, UserPreferenceEntry>(
      `${this.baseUrl}/${encodeURIComponent(key)}`,
      validatedEntry,
      {
        ...config,
        cancelKey: `preference.set.${key}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/preferences/${encodeURIComponent(key)}`],
        },
      }
    );

    if (response.success) {
      // Update cache
      this.setCachedValue(key, value);
      
      // Send to sync manager
      this.syncManager.sendChanges([response.data]);
    }

    return response;
  }

  /**
   * Set multiple preferences in batch
   * 
   * @param preferences - Key-value pairs of preferences to set
   * @param config - Request configuration
   * @returns Promise resolving to batch operation result
   */
  async setBatch(
    preferences: Record<string, PreferenceValue>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferenceEntry[]>> {
    const entries = Object.entries(preferences).map(([key, value]) => ({ key, value }));
    const validatedEntries = z.array(userPreferenceEntrySchema).parse(entries);

    const response = await this.client.patch<{ preferences: typeof validatedEntries }, UserPreferenceEntry[]>(
      `${this.baseUrl}/batch`,
      { preferences: validatedEntries },
      {
        ...config,
        cancelKey: 'preference.batch.set',
        cache: {
          enabled: false,
          invalidateOn: entries.map(entry => `GET:/preferences/${encodeURIComponent(entry.key)}`),
        },
      }
    );

    if (response.success) {
      // Update cache
      Object.entries(preferences).forEach(([key, value]) => {
        this.setCachedValue(key, value);
      });
      
      // Send to sync manager
      this.syncManager.sendChanges(response.data);
    }

    return response;
  }

  /**
   * Delete preference
   * 
   * @param key - Preference key
   * @param config - Request configuration
   * @returns Promise resolving to deletion confirmation
   */
  async delete(
    key: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    const response = await this.client.delete<void>(
      `${this.baseUrl}/${encodeURIComponent(key)}`,
      {
        ...config,
        cancelKey: `preference.delete.${key}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/preferences/${encodeURIComponent(key)}`],
        },
      }
    );

    if (response.success) {
      // Remove from cache
      this.cache.delete(key);
    }

    return response;
  }

  /**
   * Get all user preferences
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to user preferences
   */
  async getAll(
    params: {
      category?: string;
      includeSecrets?: boolean;
      tags?: string[];
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Record<string, PreferenceValue>>> {
    return this.client.get<Record<string, PreferenceValue>>(
      this.baseUrl,
      {
        ...config,
        params,
        cancelKey: 'preference.getAll',
        cache: {
          enabled: true,
          ttl: this.CACHE_TTL,
          key: `preferences:all:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Reset preferences to defaults
   * 
   * @param keys - Specific keys to reset (optional, resets all if not provided)
   * @param config - Request configuration
   * @returns Promise resolving to reset confirmation
   */
  async reset(
    keys?: string[],
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Record<string, PreferenceValue>>> {
    const response = await this.client.post<{ keys?: string[] }, Record<string, PreferenceValue>>(
      `${this.baseUrl}/reset`,
      { keys },
      {
        ...config,
        cancelKey: 'preference.reset',
        cache: {
          enabled: false,
          invalidateOn: keys 
            ? keys.map(key => `GET:/preferences/${encodeURIComponent(key)}`)
            : ['GET:/preferences'],
        },
      }
    );

    if (response.success) {
      // Clear cache
      if (keys) {
        keys.forEach(key => this.cache.delete(key));
      } else {
        this.cache.clear();
      }
    }

    return response;
  }

  // ===========================================================================
  // Schema and Definition Management
  // ===========================================================================

  /**
   * Get preference definitions/schema
   * 
   * @param category - Filter by category
   * @param config - Request configuration
   * @returns Promise resolving to preference definitions
   */
  async getDefinitions(
    category?: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PreferenceDefinition[]>> {
    return this.client.get<PreferenceDefinition[]>(
      `${this.baseUrl}/definitions`,
      {
        ...config,
        params: category ? { category } : {},
        cancelKey: `preference.definitions.${category || 'all'}`,
        cache: {
          enabled: true,
          ttl: 600000, // 10 minutes
          key: `preference:definitions:${category || 'all'}`,
        },
      }
    );
  }

  /**
   * Get preference groups
   * 
   * @param config - Request configuration
   * @returns Promise resolving to preference groups
   */
  async getGroups(
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PreferenceGroup[]>> {
    return this.client.get<PreferenceGroup[]>(
      `${this.baseUrl}/groups`,
      {
        ...config,
        cancelKey: 'preference.groups',
        cache: {
          enabled: true,
          ttl: 600000, // 10 minutes
          key: 'preference:groups',
        },
      }
    );
  }

  /**
   * Validate preference value against schema
   * 
   * @param key - Preference key
   * @param value - Value to validate
   * @param config - Request configuration
   * @returns Promise resolving to validation result
   */
  async validate(
    key: string,
    value: PreferenceValue,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{ valid: boolean; errors?: string[] }>> {
    return this.client.post<{ key: string; value: PreferenceValue }, { valid: boolean; errors?: string[] }>(
      `${this.baseUrl}/validate`,
      { key, value },
      {
        ...config,
        cancelKey: `preference.validate.${key}`,
      }
    );
  }

  // ===========================================================================
  // Backup and Restore
  // ===========================================================================

  /**
   * Create preference backup
   * 
   * @param data - Backup creation data
   * @param config - Request configuration
   * @returns Promise resolving to created backup
   */
  async createBackup(
    data: z.infer<typeof createBackupSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PreferenceBackup>> {
    const validatedData = createBackupSchema.parse(data);

    return this.client.post<typeof validatedData, PreferenceBackup>(
      `${this.baseUrl}/backups`,
      validatedData,
      {
        ...config,
        cancelKey: 'preference.backup.create',
      }
    );
  }

  /**
   * List preference backups
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to backup list
   */
  async listBackups(
    params: {
      page?: number;
      limit?: number;
      reason?: 'manual' | 'auto' | 'migration';
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<PreferenceBackup>>> {
    return this.client.get<PaginatedResponse<PreferenceBackup>>(
      `${this.baseUrl}/backups`,
      {
        ...config,
        params,
        cancelKey: 'preference.backup.list',
        cache: {
          enabled: true,
          ttl: 60000, // 1 minute
          key: `preference:backups:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Restore preferences from backup
   * 
   * @param backupId - Backup ID to restore from
   * @param options - Restore options
   * @param config - Request configuration
   * @returns Promise resolving to restore result
   */
  async restoreBackup(
    backupId: string,
    options: {
      mergeStrategy?: 'replace' | 'merge' | 'preserve';
      excludeKeys?: string[];
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{ restored: string[]; skipped: string[]; conflicts: string[] }>> {
    const response = await this.client.post<typeof options, { restored: string[]; skipped: string[]; conflicts: string[] }>(
      `${this.baseUrl}/backups/${backupId}/restore`,
      options,
      {
        ...config,
        cancelKey: `preference.backup.restore.${backupId}`,
        cache: {
          enabled: false,
          invalidateOn: ['GET:/preferences'],
        },
      }
    );

    if (response.success) {
      // Clear cache after restore
      this.cache.clear();
    }

    return response;
  }

  // ===========================================================================
  // Real-time Synchronization
  // ===========================================================================

  /**
   * Connect to real-time preference synchronization
   * 
   * @param userId - User ID for synchronization
   * @returns Promise resolving when connection is established
   */
  async connectSync(userId: string): Promise<void> {
    return this.syncManager.connect(userId);
  }

  /**
   * Disconnect from real-time synchronization
   */
  disconnectSync(): void {
    this.syncManager.disconnect();
  }

  /**
   * Subscribe to preference changes from other devices
   * 
   * @param callback - Callback function for preference changes
   * @returns Unsubscribe function
   */
  onSync(callback: (changes: UserPreferenceEntry[]) => void): () => void {
    return this.syncManager.onSync((changes) => {
      // Update local cache with synced changes
      changes.forEach(change => {
        this.setCachedValue(change.key, change.value);
      });
      
      callback(changes);
    });
  }

  /**
   * Subscribe to sync conflicts
   * 
   * @param callback - Callback function for conflicts
   * @returns Unsubscribe function
   */
  onConflict(callback: (conflicts: PreferenceSyncConflict[]) => void): () => void {
    return this.syncManager.onConflict(callback);
  }

  /**
   * Resolve sync conflicts
   * 
   * @param resolution - Conflict resolution data
   * @param config - Request configuration
   * @returns Promise resolving to resolution result
   */
  async resolveConflicts(
    resolution: z.infer<typeof syncConflictResolutionSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserPreferenceEntry[]>> {
    const validatedResolution = syncConflictResolutionSchema.parse(resolution);

    const response = await this.client.post<typeof validatedResolution, UserPreferenceEntry[]>(
      `${this.baseUrl}/sync/resolve-conflicts`,
      validatedResolution,
      {
        ...config,
        cancelKey: 'preference.sync.resolve',
        cache: {
          enabled: false,
          invalidateOn: validatedResolution.conflicts.map(c => `GET:/preferences/${encodeURIComponent(c.key)}`),
        },
      }
    );

    if (response.success) {
      // Update cache with resolved values
      response.data.forEach(entry => {
        this.setCachedValue(entry.key, entry.value);
      });
    }

    return response;
  }

  /**
   * Get sync status
   * 
   * @param config - Request configuration
   * @returns Promise resolving to sync status
   */
  async getSyncStatus(
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{
    lastSyncAt: string;
    pendingChanges: number;
    conflictCount: number;
    syncEnabled: boolean;
  }>> {
    return this.client.get(
      `${this.baseUrl}/sync/status`,
      {
        ...config,
        cancelKey: 'preference.sync.status',
        cache: {
          enabled: true,
          ttl: 30000, // 30 seconds
          key: 'preference:sync:status',
        },
      }
    );
  }

  // ===========================================================================
  // Cache Management
  // ===========================================================================

  /**
   * Get cached preference value
   */
  private getCachedValue<T extends PreferenceValue>(key: string): T | null {
    const cached = this.cache.get(key);
    if (cached && Date.now() - cached.timestamp < cached.ttl) {
      return cached.value as T;
    }
    
    // Remove expired cache entry
    if (cached) {
      this.cache.delete(key);
    }
    
    return null;
  }

  /**
   * Set cached preference value
   */
  private setCachedValue(key: string, value: PreferenceValue): void {
    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      ttl: this.CACHE_TTL,
    });
  }

  /**
   * Clear preference cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): {
    size: number;
    hitRate: number;
    memoryUsage: number;
  } {
    // This would be implemented with proper cache statistics tracking
    return {
      size: this.cache.size,
      hitRate: 0, // Would track hits vs misses
      memoryUsage: 0, // Would calculate memory usage
    };
  }
}

// Export singleton instance
export const preferencesService = new PreferencesService();

// Export validation schemas for external use
export {
  preferenceValueSchema,
  preferenceDefinitionSchema,
  userPreferenceEntrySchema,
  preferenceGroupSchema,
  createBackupSchema,
  syncConflictResolutionSchema,
};