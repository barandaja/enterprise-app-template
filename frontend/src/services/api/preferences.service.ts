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
import type {
  ApiResponse,
  ApiRequestConfig,
  PaginatedResponse,
  EnhancedApiRequestConfig,
  PreferenceValue,
  PreferenceDataType,
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
}\n\n// =============================================================================\n// Real-time Sync Manager\n// =============================================================================\n\n/**\n * Real-time preference synchronization manager\n */\nclass PreferenceSyncManager {\n  private ws: WebSocket | null = null;\n  private syncCallbacks = new Set<(changes: UserPreferenceEntry[]) => void>();\n  private conflictCallbacks = new Set<(conflicts: PreferenceSyncConflict[]) => void>();\n  private isConnected = false;\n  private reconnectAttempts = 0;\n  private maxReconnectAttempts = 5;\n  private lastSyncTimestamp: string | null = null;\n\n  /**\n   * Connect to real-time preference sync\n   */\n  async connect(userId: string): Promise<void> {\n    if (this.ws?.readyState === WebSocket.OPEN) {\n      return;\n    }\n\n    try {\n      const wsUrl = this.buildWebSocketUrl(userId);\n      this.ws = new WebSocket(wsUrl);\n\n      this.ws.onopen = () => {\n        console.log('[PreferenceSync] Connected');\n        this.isConnected = true;\n        this.reconnectAttempts = 0;\n        this.requestSync();\n      };\n\n      this.ws.onmessage = (event) => {\n        try {\n          const message = JSON.parse(event.data);\n          this.handleSyncMessage(message);\n        } catch (error) {\n          console.error('[PreferenceSync] Failed to parse message:', error);\n        }\n      };\n\n      this.ws.onclose = () => {\n        console.log('[PreferenceSync] Disconnected');\n        this.isConnected = false;\n        this.scheduleReconnect(userId);\n      };\n\n      this.ws.onerror = (error) => {\n        console.error('[PreferenceSync] Error:', error);\n      };\n    } catch (error) {\n      console.error('[PreferenceSync] Connection failed:', error);\n      this.scheduleReconnect(userId);\n    }\n  }\n\n  /**\n   * Disconnect from sync\n   */\n  disconnect(): void {\n    if (this.ws) {\n      this.ws.close();\n      this.ws = null;\n    }\n    this.isConnected = false;\n    this.syncCallbacks.clear();\n    this.conflictCallbacks.clear();\n  }\n\n  /**\n   * Subscribe to preference changes\n   */\n  onSync(callback: (changes: UserPreferenceEntry[]) => void): () => void {\n    this.syncCallbacks.add(callback);\n    return () => this.syncCallbacks.delete(callback);\n  }\n\n  /**\n   * Subscribe to sync conflicts\n   */\n  onConflict(callback: (conflicts: PreferenceSyncConflict[]) => void): () => void {\n    this.conflictCallbacks.add(callback);\n    return () => this.conflictCallbacks.delete(callback);\n  }\n\n  /**\n   * Send preference changes to sync\n   */\n  sendChanges(changes: UserPreferenceEntry[]): void {\n    if (this.ws?.readyState === WebSocket.OPEN) {\n      this.ws.send(JSON.stringify({\n        type: 'preference.changes',\n        payload: changes,\n        timestamp: new Date().toISOString(),\n      }));\n    }\n  }\n\n  private buildWebSocketUrl(userId: string): string {\n    const baseUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:3000';\n    return `${baseUrl}/preferences/sync?userId=${userId}`;\n  }\n\n  private handleSyncMessage(message: any): void {\n    switch (message.type) {\n      case 'preference.sync':\n        this.handlePreferenceSync(message.payload);\n        break;\n      case 'preference.conflicts':\n        this.handleSyncConflicts(message.payload);\n        break;\n      case 'sync.ack':\n        this.lastSyncTimestamp = message.timestamp;\n        break;\n      default:\n        console.warn('[PreferenceSync] Unknown message type:', message.type);\n    }\n  }\n\n  private handlePreferenceSync(changes: UserPreferenceEntry[]): void {\n    this.syncCallbacks.forEach(callback => {\n      try {\n        callback(changes);\n      } catch (error) {\n        console.error('[PreferenceSync] Sync callback error:', error);\n      }\n    });\n  }\n\n  private handleSyncConflicts(conflicts: PreferenceSyncConflict[]): void {\n    this.conflictCallbacks.forEach(callback => {\n      try {\n        callback(conflicts);\n      } catch (error) {\n        console.error('[PreferenceSync] Conflict callback error:', error);\n      }\n    });\n  }\n\n  private requestSync(): void {\n    if (this.ws?.readyState === WebSocket.OPEN) {\n      this.ws.send(JSON.stringify({\n        type: 'sync.request',\n        lastSyncTimestamp: this.lastSyncTimestamp,\n      }));\n    }\n  }\n\n  private scheduleReconnect(userId: string): void {\n    if (this.reconnectAttempts >= this.maxReconnectAttempts) {\n      console.error('[PreferenceSync] Max reconnect attempts reached');\n      return;\n    }\n\n    this.reconnectAttempts++;\n    const delay = 1000 * Math.pow(2, this.reconnectAttempts - 1);\n\n    setTimeout(() => {\n      console.log(`[PreferenceSync] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);\n      this.connect(userId);\n    }, delay);\n  }\n}\n\n// =============================================================================\n// Preferences Service Class\n// =============================================================================\n\n/**\n * Enterprise preferences service with advanced features\n */\nexport class PreferencesService {\n  private readonly baseUrl = '/preferences';\n  private readonly client = apiClient;\n  private readonly syncManager = new PreferenceSyncManager();\n  private readonly cache = new Map<string, { value: PreferenceValue; timestamp: number; ttl: number }>();\n  private readonly CACHE_TTL = 300000; // 5 minutes\n\n  // ===========================================================================\n  // Type-Safe Preference Operations\n  // ===========================================================================\n\n  /**\n   * Get preference value with type safety\n   * \n   * @param key - Preference key\n   * @param defaultValue - Default value if preference doesn't exist\n   * @param config - Request configuration\n   * @returns Promise resolving to preference value\n   * \n   * @example\n   * ```typescript\n   * const theme = await preferencesService.get(PREFERENCE_KEYS.THEME, 'light');\n   * const pageSize = await preferencesService.get(PREFERENCE_KEYS.TABLE_PAGE_SIZE, 20);\n   * ```\n   */\n  async get<K extends keyof PreferenceValueMap>(\n    key: K,\n    defaultValue?: PreferenceValueMap[K],\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<PreferenceValueMap[K]>;\n  async get<T extends PreferenceValue>(\n    key: string,\n    defaultValue?: T,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<T>;\n  async get<T extends PreferenceValue>(\n    key: string,\n    defaultValue?: T,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<T> {\n    // Check cache first\n    const cached = this.getCachedValue<T>(key);\n    if (cached !== null) {\n      return cached;\n    }\n\n    try {\n      const response = await this.client.get<{ value: T }>(\n        `${this.baseUrl}/${encodeURIComponent(key)}`,\n        {\n          ...config,\n          cancelKey: `preference.get.${key}`,\n          cache: {\n            enabled: true,\n            ttl: this.CACHE_TTL,\n            key: `preference:${key}`,\n          },\n        }\n      );\n\n      if (response.success && response.data.value !== undefined) {\n        const value = response.data.value;\n        this.setCachedValue(key, value);\n        return value;\n      }\n    } catch (error) {\n      console.warn(`[Preferences] Failed to get preference '${key}':`, error);\n    }\n\n    // Return default value if preference doesn't exist or fetch failed\n    return defaultValue as T;\n  }\n\n  /**\n   * Set preference value with type safety\n   * \n   * @param key - Preference key\n   * @param value - Preference value\n   * @param config - Request configuration\n   * @returns Promise resolving to updated preference\n   * \n   * @example\n   * ```typescript\n   * await preferencesService.set(PREFERENCE_KEYS.THEME, 'dark');\n   * await preferencesService.set(PREFERENCE_KEYS.TABLE_PAGE_SIZE, 50);\n   * ```\n   */\n  async set<K extends keyof PreferenceValueMap>(\n    key: K,\n    value: PreferenceValueMap[K],\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<UserPreferenceEntry>>;\n  async set<T extends PreferenceValue>(\n    key: string,\n    value: T,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<UserPreferenceEntry>>;\n  async set<T extends PreferenceValue>(\n    key: string,\n    value: T,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<UserPreferenceEntry>> {\n    const validatedEntry = userPreferenceEntrySchema.parse({ key, value });\n\n    const response = await this.client.put<typeof validatedEntry, UserPreferenceEntry>(\n      `${this.baseUrl}/${encodeURIComponent(key)}`,\n      validatedEntry,\n      {\n        ...config,\n        cancelKey: `preference.set.${key}`,\n        cache: {\n          enabled: false,\n          invalidateOn: [`GET:/preferences/${encodeURIComponent(key)}`],\n        },\n      }\n    );\n\n    if (response.success) {\n      // Update cache\n      this.setCachedValue(key, value);\n      \n      // Send to sync manager\n      this.syncManager.sendChanges([response.data]);\n    }\n\n    return response;\n  }\n\n  /**\n   * Set multiple preferences in batch\n   * \n   * @param preferences - Key-value pairs of preferences to set\n   * @param config - Request configuration\n   * @returns Promise resolving to batch operation result\n   */\n  async setBatch(\n    preferences: Record<string, PreferenceValue>,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<UserPreferenceEntry[]>> {\n    const entries = Object.entries(preferences).map(([key, value]) => ({ key, value }));\n    const validatedEntries = z.array(userPreferenceEntrySchema).parse(entries);\n\n    const response = await this.client.patch<{ preferences: typeof validatedEntries }, UserPreferenceEntry[]>(\n      `${this.baseUrl}/batch`,\n      { preferences: validatedEntries },\n      {\n        ...config,\n        cancelKey: 'preference.batch.set',\n        cache: {\n          enabled: false,\n          invalidateOn: entries.map(entry => `GET:/preferences/${encodeURIComponent(entry.key)}`),\n        },\n      }\n    );\n\n    if (response.success) {\n      // Update cache\n      Object.entries(preferences).forEach(([key, value]) => {\n        this.setCachedValue(key, value);\n      });\n      \n      // Send to sync manager\n      this.syncManager.sendChanges(response.data);\n    }\n\n    return response;\n  }\n\n  /**\n   * Delete preference\n   * \n   * @param key - Preference key\n   * @param config - Request configuration\n   * @returns Promise resolving to deletion confirmation\n   */\n  async delete(\n    key: string,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<void>> {\n    const response = await this.client.delete<void>(\n      `${this.baseUrl}/${encodeURIComponent(key)}`,\n      {\n        ...config,\n        cancelKey: `preference.delete.${key}`,\n        cache: {\n          enabled: false,\n          invalidateOn: [`GET:/preferences/${encodeURIComponent(key)}`],\n        },\n      }\n    );\n\n    if (response.success) {\n      // Remove from cache\n      this.cache.delete(key);\n    }\n\n    return response;\n  }\n\n  /**\n   * Get all user preferences\n   * \n   * @param params - Query parameters\n   * @param config - Request configuration\n   * @returns Promise resolving to user preferences\n   */\n  async getAll(\n    params: {\n      category?: string;\n      includeSecrets?: boolean;\n      tags?: string[];\n    } = {},\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<Record<string, PreferenceValue>>> {\n    return this.client.get<Record<string, PreferenceValue>>(\n      this.baseUrl,\n      {\n        ...config,\n        params,\n        cancelKey: 'preference.getAll',\n        cache: {\n          enabled: true,\n          ttl: this.CACHE_TTL,\n          key: `preferences:all:${JSON.stringify(params)}`,\n        },\n      }\n    );\n  }\n\n  /**\n   * Reset preferences to defaults\n   * \n   * @param keys - Specific keys to reset (optional, resets all if not provided)\n   * @param config - Request configuration\n   * @returns Promise resolving to reset confirmation\n   */\n  async reset(\n    keys?: string[],\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<Record<string, PreferenceValue>>> {\n    const response = await this.client.post<{ keys?: string[] }, Record<string, PreferenceValue>>(\n      `${this.baseUrl}/reset`,\n      { keys },\n      {\n        ...config,\n        cancelKey: 'preference.reset',\n        cache: {\n          enabled: false,\n          invalidateOn: keys \n            ? keys.map(key => `GET:/preferences/${encodeURIComponent(key)}`)\n            : ['GET:/preferences'],\n        },\n      }\n    );\n\n    if (response.success) {\n      // Clear cache\n      if (keys) {\n        keys.forEach(key => this.cache.delete(key));\n      } else {\n        this.cache.clear();\n      }\n    }\n\n    return response;\n  }\n\n  // ===========================================================================\n  // Schema and Definition Management\n  // ===========================================================================\n\n  /**\n   * Get preference definitions/schema\n   * \n   * @param category - Filter by category\n   * @param config - Request configuration\n   * @returns Promise resolving to preference definitions\n   */\n  async getDefinitions(\n    category?: string,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<PreferenceDefinition[]>> {\n    return this.client.get<PreferenceDefinition[]>(\n      `${this.baseUrl}/definitions`,\n      {\n        ...config,\n        params: category ? { category } : {},\n        cancelKey: `preference.definitions.${category || 'all'}`,\n        cache: {\n          enabled: true,\n          ttl: 600000, // 10 minutes\n          key: `preference:definitions:${category || 'all'}`,\n        },\n      }\n    );\n  }\n\n  /**\n   * Get preference groups\n   * \n   * @param config - Request configuration\n   * @returns Promise resolving to preference groups\n   */\n  async getGroups(\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<PreferenceGroup[]>> {\n    return this.client.get<PreferenceGroup[]>(\n      `${this.baseUrl}/groups`,\n      {\n        ...config,\n        cancelKey: 'preference.groups',\n        cache: {\n          enabled: true,\n          ttl: 600000, // 10 minutes\n          key: 'preference:groups',\n        },\n      }\n    );\n  }\n\n  /**\n   * Validate preference value against schema\n   * \n   * @param key - Preference key\n   * @param value - Value to validate\n   * @param config - Request configuration\n   * @returns Promise resolving to validation result\n   */\n  async validate(\n    key: string,\n    value: PreferenceValue,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<{ valid: boolean; errors?: string[] }>> {\n    return this.client.post<{ key: string; value: PreferenceValue }, { valid: boolean; errors?: string[] }>(\n      `${this.baseUrl}/validate`,\n      { key, value },\n      {\n        ...config,\n        cancelKey: `preference.validate.${key}`,\n      }\n    );\n  }\n\n  // ===========================================================================\n  // Backup and Restore\n  // ===========================================================================\n\n  /**\n   * Create preference backup\n   * \n   * @param data - Backup creation data\n   * @param config - Request configuration\n   * @returns Promise resolving to created backup\n   */\n  async createBackup(\n    data: z.infer<typeof createBackupSchema>,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<PreferenceBackup>> {\n    const validatedData = createBackupSchema.parse(data);\n\n    return this.client.post<typeof validatedData, PreferenceBackup>(\n      `${this.baseUrl}/backups`,\n      validatedData,\n      {\n        ...config,\n        cancelKey: 'preference.backup.create',\n      }\n    );\n  }\n\n  /**\n   * List preference backups\n   * \n   * @param params - Query parameters\n   * @param config - Request configuration\n   * @returns Promise resolving to backup list\n   */\n  async listBackups(\n    params: {\n      page?: number;\n      limit?: number;\n      reason?: 'manual' | 'auto' | 'migration';\n    } = {},\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<PaginatedResponse<PreferenceBackup>>> {\n    return this.client.get<PaginatedResponse<PreferenceBackup>>(\n      `${this.baseUrl}/backups`,\n      {\n        ...config,\n        params,\n        cancelKey: 'preference.backup.list',\n        cache: {\n          enabled: true,\n          ttl: 60000, // 1 minute\n          key: `preference:backups:${JSON.stringify(params)}`,\n        },\n      }\n    );\n  }\n\n  /**\n   * Restore preferences from backup\n   * \n   * @param backupId - Backup ID to restore from\n   * @param options - Restore options\n   * @param config - Request configuration\n   * @returns Promise resolving to restore result\n   */\n  async restoreBackup(\n    backupId: string,\n    options: {\n      mergeStrategy?: 'replace' | 'merge' | 'preserve';\n      excludeKeys?: string[];\n    } = {},\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<{ restored: string[]; skipped: string[]; conflicts: string[] }>> {\n    const response = await this.client.post<typeof options, { restored: string[]; skipped: string[]; conflicts: string[] }>(\n      `${this.baseUrl}/backups/${backupId}/restore`,\n      options,\n      {\n        ...config,\n        cancelKey: `preference.backup.restore.${backupId}`,\n        cache: {\n          enabled: false,\n          invalidateOn: ['GET:/preferences'],\n        },\n      }\n    );\n\n    if (response.success) {\n      // Clear cache after restore\n      this.cache.clear();\n    }\n\n    return response;\n  }\n\n  // ===========================================================================\n  // Real-time Synchronization\n  // ===========================================================================\n\n  /**\n   * Connect to real-time preference synchronization\n   * \n   * @param userId - User ID for synchronization\n   * @returns Promise resolving when connection is established\n   */\n  async connectSync(userId: string): Promise<void> {\n    return this.syncManager.connect(userId);\n  }\n\n  /**\n   * Disconnect from real-time synchronization\n   */\n  disconnectSync(): void {\n    this.syncManager.disconnect();\n  }\n\n  /**\n   * Subscribe to preference changes from other devices\n   * \n   * @param callback - Callback function for preference changes\n   * @returns Unsubscribe function\n   */\n  onSync(callback: (changes: UserPreferenceEntry[]) => void): () => void {\n    return this.syncManager.onSync((changes) => {\n      // Update local cache with synced changes\n      changes.forEach(change => {\n        this.setCachedValue(change.key, change.value);\n      });\n      \n      callback(changes);\n    });\n  }\n\n  /**\n   * Subscribe to sync conflicts\n   * \n   * @param callback - Callback function for conflicts\n   * @returns Unsubscribe function\n   */\n  onConflict(callback: (conflicts: PreferenceSyncConflict[]) => void): () => void {\n    return this.syncManager.onConflict(callback);\n  }\n\n  /**\n   * Resolve sync conflicts\n   * \n   * @param resolution - Conflict resolution data\n   * @param config - Request configuration\n   * @returns Promise resolving to resolution result\n   */\n  async resolveConflicts(\n    resolution: z.infer<typeof syncConflictResolutionSchema>,\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<UserPreferenceEntry[]>> {\n    const validatedResolution = syncConflictResolutionSchema.parse(resolution);\n\n    const response = await this.client.post<typeof validatedResolution, UserPreferenceEntry[]>(\n      `${this.baseUrl}/sync/resolve-conflicts`,\n      validatedResolution,\n      {\n        ...config,\n        cancelKey: 'preference.sync.resolve',\n        cache: {\n          enabled: false,\n          invalidateOn: validatedResolution.conflicts.map(c => `GET:/preferences/${encodeURIComponent(c.key)}`),\n        },\n      }\n    );\n\n    if (response.success) {\n      // Update cache with resolved values\n      response.data.forEach(entry => {\n        this.setCachedValue(entry.key, entry.value);\n      });\n    }\n\n    return response;\n  }\n\n  /**\n   * Get sync status\n   * \n   * @param config - Request configuration\n   * @returns Promise resolving to sync status\n   */\n  async getSyncStatus(\n    config: EnhancedApiRequestConfig = {}\n  ): Promise<ApiResponse<{\n    lastSyncAt: string;\n    pendingChanges: number;\n    conflictCount: number;\n    syncEnabled: boolean;\n  }>> {\n    return this.client.get(\n      `${this.baseUrl}/sync/status`,\n      {\n        ...config,\n        cancelKey: 'preference.sync.status',\n        cache: {\n          enabled: true,\n          ttl: 30000, // 30 seconds\n          key: 'preference:sync:status',\n        },\n      }\n    );\n  }\n\n  // ===========================================================================\n  // Cache Management\n  // ===========================================================================\n\n  /**\n   * Get cached preference value\n   */\n  private getCachedValue<T extends PreferenceValue>(key: string): T | null {\n    const cached = this.cache.get(key);\n    if (cached && Date.now() - cached.timestamp < cached.ttl) {\n      return cached.value as T;\n    }\n    \n    // Remove expired cache entry\n    if (cached) {\n      this.cache.delete(key);\n    }\n    \n    return null;\n  }\n\n  /**\n   * Set cached preference value\n   */\n  private setCachedValue(key: string, value: PreferenceValue): void {\n    this.cache.set(key, {\n      value,\n      timestamp: Date.now(),\n      ttl: this.CACHE_TTL,\n    });\n  }\n\n  /**\n   * Clear preference cache\n   */\n  clearCache(): void {\n    this.cache.clear();\n  }\n\n  /**\n   * Get cache statistics\n   */\n  getCacheStats(): {\n    size: number;\n    hitRate: number;\n    memoryUsage: number;\n  } {\n    // This would be implemented with proper cache statistics tracking\n    return {\n      size: this.cache.size,\n      hitRate: 0, // Would track hits vs misses\n      memoryUsage: 0, // Would calculate memory usage\n    };\n  }\n}\n\n// Export singleton instance\nexport const preferencesService = new PreferencesService();\n\n// Export validation schemas for external use\nexport {\n  preferenceValueSchema,\n  preferenceDefinitionSchema,\n  userPreferenceEntrySchema,\n  preferenceGroupSchema,\n  createBackupSchema,\n  syncConflictResolutionSchema,\n};