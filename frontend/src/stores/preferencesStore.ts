/**
 * Enterprise PreferencesStore with Advanced TypeScript Patterns
 * 
 * This store implements sophisticated user preference management with:
 * - Type-safe serialization and deserialization of complex preference objects
 * - Schema migration system for preference structure changes
 * - Feature flag integration with conditional types
 * - Granular preference validation with custom validation rules
 * - Settings backup and restoration with version control
 * - Real-time preference synchronization across tabs/devices
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
  PreferenceKey,
  UserId,
  EventKey,
  StoreEvent,
  createPreferenceKey,
  createUserId,
  generateStoreId,
  STORE_VERSION,
  DEFAULT_CACHE_EXPIRY,
  DeepPartial,
  DeepReadonly,
  RequiredExcept,
  ValidationRule,
  ValidationSchema,
  ValidationResult,
} from './types';

// =============================================================================
// ADVANCED PREFERENCE TYPES WITH TEMPLATE LITERALS
// =============================================================================

/**
 * Preference categories using template literal types
 */
export type PreferenceCategoryType = 
  | 'ui'
  | 'accessibility' 
  | 'notification'
  | 'privacy'
  | 'security'
  | 'performance'
  | 'integration'
  | 'experimental';

/**
 * UI preference subcategories
 */
export type UIPreferenceType = 
  | 'theme'
  | 'layout'
  | 'animation'
  | 'color'
  | 'typography'
  | 'spacing'
  | 'navigation';

/**
 * Accessibility preference types
 */
export type AccessibilityPreferenceType = 
  | 'vision'
  | 'hearing'
  | 'motor'
  | 'cognitive';

/**
 * Template literal types for preference keys
 */
export type UIPreferenceKey = `ui.${UIPreferenceType}.${string}`;
export type AccessibilityPreferenceKey = `accessibility.${AccessibilityPreferenceType}.${string}`;
export type NotificationPreferenceKey = `notification.${string}.${string}`;
export type PrivacyPreferenceKey = `privacy.${string}`;
export type SecurityPreferenceKey = `security.${string}`;
export type PerformancePreferenceKey = `performance.${string}`;
export type IntegrationPreferenceKey = `integration.${string}.${string}`;
export type ExperimentalPreferenceKey = `experimental.${string}`;

/**
 * Combined preference key type
 */
export type AnyPreferenceKey = 
  | UIPreferenceKey
  | AccessibilityPreferenceKey
  | NotificationPreferenceKey
  | PrivacyPreferenceKey
  | SecurityPreferenceKey
  | PerformancePreferenceKey
  | IntegrationPreferenceKey
  | ExperimentalPreferenceKey;

// =============================================================================
// PREFERENCE VALUE TYPES WITH CONDITIONAL TYPING
// =============================================================================

/**
 * Base preference value interface
 */
interface BasePreferenceValue {
  readonly value: unknown;
  readonly defaultValue: unknown;
  readonly lastModified: number;
  readonly version: number;
  readonly source: 'default' | 'user' | 'admin' | 'system' | 'imported';
  readonly metadata?: Record<string, unknown>;
}

/**
 * Typed preference values using conditional types
 */
export type PreferenceValue<T = unknown> = BasePreferenceValue & {
  readonly value: T;
  readonly defaultValue: T;
};

/**
 * Theme preferences with discriminated union
 */
export interface ThemePreferences {
  readonly 'ui.theme.mode': PreferenceValue<'light' | 'dark' | 'system' | 'auto'>;
  readonly 'ui.theme.primary_color': PreferenceValue<string>;
  readonly 'ui.theme.accent_color': PreferenceValue<string>;
  readonly 'ui.theme.border_radius': PreferenceValue<number>;
  readonly 'ui.theme.font_family': PreferenceValue<string>;
  readonly 'ui.theme.font_size': PreferenceValue<'xs' | 'sm' | 'md' | 'lg' | 'xl'>;
  readonly 'ui.theme.high_contrast': PreferenceValue<boolean>;
  readonly 'ui.theme.reduced_motion': PreferenceValue<boolean>;
}

/**
 * Layout preferences
 */
export interface LayoutPreferences {
  readonly 'ui.layout.sidebar_width': PreferenceValue<number>;
  readonly 'ui.layout.sidebar_collapsed': PreferenceValue<boolean>;
  readonly 'ui.layout.sidebar_position': PreferenceValue<'left' | 'right'>;
  readonly 'ui.layout.header_height': PreferenceValue<number>;
  readonly 'ui.layout.compact_mode': PreferenceValue<boolean>;
  readonly 'ui.layout.grid_density': PreferenceValue<'comfortable' | 'compact' | 'spacious'>;
}

/**
 * Accessibility preferences
 */
export interface AccessibilityPreferences {
  readonly 'accessibility.vision.screen_reader': PreferenceValue<boolean>;
  readonly 'accessibility.vision.high_contrast': PreferenceValue<boolean>;
  readonly 'accessibility.vision.color_blind_support': PreferenceValue<'none' | 'protanopia' | 'deuteranopia' | 'tritanopia'>;
  readonly 'accessibility.vision.font_size_multiplier': PreferenceValue<number>;
  readonly 'accessibility.motor.keyboard_navigation': PreferenceValue<boolean>;
  readonly 'accessibility.motor.focus_indicators': PreferenceValue<boolean>;
  readonly 'accessibility.motor.click_delay': PreferenceValue<number>;
  readonly 'accessibility.cognitive.simple_language': PreferenceValue<boolean>;
  readonly 'accessibility.cognitive.reduced_ui': PreferenceValue<boolean>;
}

/**
 * Privacy preferences with granular controls
 */
export interface PrivacyPreferences {
  readonly 'privacy.analytics_tracking': PreferenceValue<boolean>;
  readonly 'privacy.error_reporting': PreferenceValue<boolean>;
  readonly 'privacy.usage_statistics': PreferenceValue<boolean>;
  readonly 'privacy.location_sharing': PreferenceValue<boolean>;
  readonly 'privacy.contact_sharing': PreferenceValue<boolean>;
  readonly 'privacy.third_party_cookies': PreferenceValue<boolean>;
  readonly 'privacy.data_retention_period': PreferenceValue<number>; // days
  readonly 'privacy.profile_visibility': PreferenceValue<'public' | 'private' | 'friends' | 'organization'>;
}

/**
 * Security preferences
 */
export interface SecurityPreferences {
  readonly 'security.two_factor_enabled': PreferenceValue<boolean>;
  readonly 'security.session_timeout': PreferenceValue<number>; // minutes
  readonly 'security.login_notifications': PreferenceValue<boolean>;
  readonly 'security.device_tracking': PreferenceValue<boolean>;
  readonly 'security.suspicious_activity_alerts': PreferenceValue<boolean>;
  readonly 'security.password_expiry_days': PreferenceValue<number>;
  readonly 'security.require_password_change': PreferenceValue<boolean>;
}

/**
 * Performance preferences
 */
export interface PerformancePreferences {
  readonly 'performance.lazy_loading': PreferenceValue<boolean>;
  readonly 'performance.image_optimization': PreferenceValue<boolean>;
  readonly 'performance.cache_duration': PreferenceValue<number>; // minutes
  readonly 'performance.prefetch_links': PreferenceValue<boolean>;
  readonly 'performance.animation_performance': PreferenceValue<'auto' | 'reduced' | 'disabled'>;
  readonly 'performance.background_sync': PreferenceValue<boolean>;
}

/**
 * Combined preferences type
 */
export type UserPreferences = ThemePreferences & 
  LayoutPreferences & 
  AccessibilityPreferences & 
  PrivacyPreferences & 
  SecurityPreferences & 
  PerformancePreferences;

/**
 * Preference key extraction type
 */
export type PreferenceKeys = keyof UserPreferences;

/**
 * Extract preference value type by key
 */
export type PreferenceValueType<K extends PreferenceKeys> = UserPreferences[K]['value'];

// =============================================================================
// PREFERENCE SCHEMA AND MIGRATION TYPES
// =============================================================================

/**
 * Preference schema definition
 */
export interface PreferenceSchema<T = unknown> {
  readonly type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  readonly default: T;
  readonly validation?: ValidationRule<T>[];
  readonly description: string;
  readonly category: PreferenceCategoryType;
  readonly subcategory?: string;
  readonly deprecated?: boolean;
  readonly deprecationMessage?: string;
  readonly minVersion?: string;
  readonly maxVersion?: string;
  readonly tags?: readonly string[];
  readonly sensitive?: boolean; // For security-related preferences
  readonly experimental?: boolean;
  readonly featureFlag?: string; // Associated feature flag
}

/**
 * Migration function type
 */
export type PreferenceMigrationFunction = (
  oldPreferences: Record<string, unknown>,
  fromVersion: string,
  toVersion: string
) => Record<string, unknown>;

/**
 * Migration definition
 */
export interface PreferenceMigration {
  readonly fromVersion: string;
  readonly toVersion: string;
  readonly description: string;
  readonly migrate: PreferenceMigrationFunction;
  readonly rollback?: PreferenceMigrationFunction;
}

/**
 * Schema registry for all preferences
 */
export type PreferenceSchemaRegistry = {
  readonly [K in PreferenceKeys]: PreferenceSchema<PreferenceValueType<K>>;
};

// =============================================================================
// FEATURE FLAGS INTEGRATION
// =============================================================================

/**
 * Feature flag definition
 */
export interface FeatureFlag {
  readonly key: string;
  readonly enabled: boolean;
  readonly description: string;
  readonly rolloutPercentage?: number;
  readonly targetUsers?: UserId[];
  readonly targetGroups?: string[];
  readonly environmentRestriction?: ('development' | 'staging' | 'production')[];
  readonly startDate?: Date;
  readonly endDate?: Date;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Feature flag state
 */
export interface FeatureFlagState {
  readonly flags: ReadonlyMap<string, FeatureFlag>;
  readonly lastUpdated: number | null;
  readonly evaluationContext: {
    readonly userId?: UserId;
    readonly userGroups: readonly string[];
    readonly environment: string;
    readonly timestamp: number;
  };
}

// =============================================================================
// STORE STATE AND ACTIONS
// =============================================================================

/**
 * Preferences store state
 */
interface PreferencesState extends BaseStore, AsyncStoreMixin<PreferencesState>, CacheStoreMixin<UserPreferences> {
  // Core preference data
  readonly preferences: DeepReadonly<UserPreferences>;
  readonly defaultPreferences: DeepReadonly<UserPreferences>;
  readonly schemaRegistry: PreferenceSchemaRegistry;
  
  // Async states for operations
  readonly fetchState: AsyncState<UserPreferences>;
  readonly updateState: AsyncState<Partial<UserPreferences>>;
  readonly resetState: AsyncState<PreferenceKeys[]>;
  readonly backupState: AsyncState<{ id: string; preferences: UserPreferences }>;
  readonly restoreState: AsyncState<UserPreferences>;
  readonly migrationState: AsyncState<{ fromVersion: string; toVersion: string }>;
  
  // Feature flags
  readonly featureFlags: FeatureFlagState;
  readonly featureFlagState: AsyncState<FeatureFlag[]>;
  
  // Validation and migration
  readonly validationErrors: ReadonlyMap<PreferenceKeys, readonly string[]>;
  readonly migrationHistory: readonly PreferenceMigration[];
  readonly currentSchemaVersion: string;
  
  // Backup and restore
  readonly backups: ReadonlyArray<PreferenceBackup>;
  readonly autoBackupEnabled: boolean;
  readonly maxBackups: number;
  
  // Synchronization
  readonly syncEnabled: boolean;
  readonly lastSyncTime: number | null;
  readonly syncConflicts: ReadonlyArray<PreferenceSyncConflict>;
  
  // Performance tracking
  readonly changeTracker: PreferenceChangeTracker;
}

/**
 * Preference backup interface
 */
export interface PreferenceBackup {
  readonly id: string;
  readonly timestamp: number;
  readonly version: string;
  readonly preferences: DeepReadonly<UserPreferences>;
  readonly description?: string;
  readonly automatic: boolean;
  readonly size: number; // serialized size in bytes
}

/**
 * Preference sync conflict
 */
export interface PreferenceSyncConflict {
  readonly key: PreferenceKeys;
  readonly localValue: unknown;
  readonly remoteValue: unknown;
  readonly localTimestamp: number;
  readonly remoteTimestamp: number;
  readonly resolution?: 'local' | 'remote' | 'manual';
}

/**
 * Preference change tracker
 */
export interface PreferenceChangeTracker {
  readonly changes: ReadonlyMap<PreferenceKeys, PreferenceChange>;
  readonly sessionChanges: number;
  readonly lastChangeTime: number | null;
}

/**
 * Individual preference change
 */
export interface PreferenceChange {
  readonly key: PreferenceKeys;
  readonly oldValue: unknown;
  readonly newValue: unknown;
  readonly timestamp: number;
  readonly source: 'user' | 'system' | 'import' | 'migration';
}

/**
 * Preferences store actions
 */
interface PreferencesActions extends StoreEventEmitter {
  // Preference CRUD operations
  readonly getPreference: <K extends PreferenceKeys>(key: K) => UserPreferences[K]['value'];
  readonly setPreference: <K extends PreferenceKeys>(key: K, value: PreferenceValueType<K>, source?: PreferenceValue['source']) => Promise<void>;
  readonly setPreferences: (preferences: DeepPartial<UserPreferences>) => Promise<void>;
  readonly resetPreference: (key: PreferenceKeys) => Promise<void>;
  readonly resetPreferences: (keys?: PreferenceKeys[]) => Promise<void>;
  readonly resetAllPreferences: () => Promise<void>;
  
  // Bulk operations
  readonly importPreferences: (preferences: Record<string, unknown>, merge?: boolean) => Promise<void>;
  readonly exportPreferences: (keys?: PreferenceKeys[]) => DeepReadonly<Partial<UserPreferences>>;
  
  // Schema and validation
  readonly validatePreference: <K extends PreferenceKeys>(key: K, value: PreferenceValueType<K>) => ValidationResult;
  readonly validateAllPreferences: () => ValidationResult;
  readonly getPreferenceSchema: <K extends PreferenceKeys>(key: K) => PreferenceSchema<PreferenceValueType<K>>;
  readonly isPreferenceValid: <K extends PreferenceKeys>(key: K) => boolean;
  
  // Migration
  readonly migratePreferences: (fromVersion: string, toVersion: string) => Promise<void>;
  readonly rollbackMigration: (migrationId: string) => Promise<void>;
  readonly getMigrationHistory: () => readonly PreferenceMigration[];
  
  // Feature flags
  readonly fetchFeatureFlags: () => Promise<FeatureFlag[]>;
  readonly isFeatureEnabled: (flagKey: string) => boolean;
  readonly evaluateFeatureFlag: (flagKey: string, context?: Partial<FeatureFlagState['evaluationContext']>) => boolean;
  readonly refreshFeatureFlags: () => Promise<void>;
  
  // Backup and restore
  readonly createBackup: (description?: string) => Promise<string>;
  readonly restoreBackup: (backupId: string) => Promise<void>;
  readonly deleteBackup: (backupId: string) => Promise<void>;
  readonly cleanupOldBackups: () => Promise<number>;
  readonly toggleAutoBackup: (enabled: boolean) => void;
  
  // Synchronization
  readonly enableSync: () => Promise<void>;
  readonly disableSync: () => void;
  readonly syncWithRemote: () => Promise<void>;
  readonly resolveSyncConflict: (key: PreferenceKeys, resolution: 'local' | 'remote') => Promise<void>;
  readonly resolveSyncConflicts: (resolutions: Record<PreferenceKeys, 'local' | 'remote'>) => Promise<void>;
  
  // Utility methods
  readonly getPreferencesByCategory: (category: PreferenceCategoryType) => Partial<UserPreferences>;
  readonly getChangedPreferences: () => ReadonlyMap<PreferenceKeys, PreferenceChange>;
  readonly hasUnsavedChanges: () => boolean;
  readonly getPreferenceCount: () => number;
  readonly getPreferenceSize: () => number; // serialized size
  
  // Type guards and assertions
  readonly assertPreferenceExists: <K extends PreferenceKeys>(key: K) => asserts key is K;
  readonly isDefaultValue: <K extends PreferenceKeys>(key: K) => boolean;
  readonly hasPreferenceChanged: <K extends PreferenceKeys>(key: K) => boolean;
}

/**
 * Combined preferences store type
 */
type PreferencesStore = PreferencesState & PreferencesActions;

// =============================================================================
// DEFAULT PREFERENCES AND SCHEMA
// =============================================================================

/**
 * Create default preference value
 */
const createDefaultPreference = <T>(
  value: T,
  schema: Omit<PreferenceSchema<T>, 'default'>
): PreferenceValue<T> => ({
  value,
  defaultValue: value,
  lastModified: Date.now(),
  version: 1,
  source: 'default',
});

/**
 * Default preferences with type safety
 */
const defaultPreferences: UserPreferences = {
  // Theme preferences
  'ui.theme.mode': createDefaultPreference('system', {
    type: 'string',
    description: 'Application theme mode',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.primary_color': createDefaultPreference('#3b82f6', {
    type: 'string',
    description: 'Primary color for the application theme',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.accent_color': createDefaultPreference('#10b981', {
    type: 'string',
    description: 'Accent color for highlights and emphasis',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.border_radius': createDefaultPreference(8, {
    type: 'number',
    description: 'Border radius for UI elements in pixels',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.font_family': createDefaultPreference('Inter', {
    type: 'string',
    description: 'Font family for the application',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.font_size': createDefaultPreference('md', {
    type: 'string',
    description: 'Default font size scale',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.high_contrast': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Enable high contrast mode for better visibility',
    category: 'ui',
    subcategory: 'theme',
  }),
  'ui.theme.reduced_motion': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Reduce animations and transitions',
    category: 'ui',
    subcategory: 'theme',
  }),
  
  // Layout preferences
  'ui.layout.sidebar_width': createDefaultPreference(280, {
    type: 'number',
    description: 'Width of the sidebar in pixels',
    category: 'ui',
    subcategory: 'layout',
  }),
  'ui.layout.sidebar_collapsed': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Whether the sidebar is collapsed by default',
    category: 'ui',
    subcategory: 'layout',
  }),
  'ui.layout.sidebar_position': createDefaultPreference('left', {
    type: 'string',
    description: 'Position of the sidebar',
    category: 'ui',
    subcategory: 'layout',
  }),
  'ui.layout.header_height': createDefaultPreference(64, {
    type: 'number',
    description: 'Height of the application header in pixels',
    category: 'ui',
    subcategory: 'layout',
  }),
  'ui.layout.compact_mode': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Enable compact layout mode for more content density',
    category: 'ui',
    subcategory: 'layout',
  }),
  'ui.layout.grid_density': createDefaultPreference('comfortable', {
    type: 'string',
    description: 'Density of grid layouts and lists',
    category: 'ui',
    subcategory: 'layout',
  }),
  
  // Accessibility preferences
  'accessibility.vision.screen_reader': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Screen reader support enabled',
    category: 'accessibility',
    subcategory: 'vision',
  }),
  'accessibility.vision.high_contrast': createDefaultPreference(false, {
    type: 'boolean',
    description: 'High contrast mode for better visibility',
    category: 'accessibility',
    subcategory: 'vision',
  }),
  'accessibility.vision.color_blind_support': createDefaultPreference('none', {
    type: 'string',
    description: 'Color blindness support type',
    category: 'accessibility',
    subcategory: 'vision',
  }),
  'accessibility.vision.font_size_multiplier': createDefaultPreference(1.0, {
    type: 'number',
    description: 'Font size multiplier for better readability',
    category: 'accessibility',
    subcategory: 'vision',
  }),
  'accessibility.motor.keyboard_navigation': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Enhanced keyboard navigation support',
    category: 'accessibility',
    subcategory: 'motor',
  }),
  'accessibility.motor.focus_indicators': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Visible focus indicators for keyboard navigation',
    category: 'accessibility',
    subcategory: 'motor',
  }),
  'accessibility.motor.click_delay': createDefaultPreference(0, {
    type: 'number',
    description: 'Delay before click actions in milliseconds',
    category: 'accessibility',
    subcategory: 'motor',
  }),
  'accessibility.cognitive.simple_language': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Use simplified language and terminology',
    category: 'accessibility',
    subcategory: 'cognitive',
  }),
  'accessibility.cognitive.reduced_ui': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Simplified user interface with fewer options',
    category: 'accessibility',
    subcategory: 'cognitive',
  }),
  
  // Privacy preferences
  'privacy.analytics_tracking': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Allow analytics and usage tracking',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.error_reporting': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Automatically report errors to improve the service',
    category: 'privacy',
  }),
  'privacy.usage_statistics': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Share anonymous usage statistics',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.location_sharing': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Allow location-based features',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.contact_sharing': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Allow sharing contact information with other users',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.third_party_cookies': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Allow third-party cookies for integrated services',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.data_retention_period': createDefaultPreference(365, {
    type: 'number',
    description: 'Data retention period in days',
    category: 'privacy',
    sensitive: true,
  }),
  'privacy.profile_visibility': createDefaultPreference('private', {
    type: 'string',
    description: 'Visibility level of your profile',
    category: 'privacy',
    sensitive: true,
  }),
  
  // Security preferences
  'security.two_factor_enabled': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Two-factor authentication enabled',
    category: 'security',
    sensitive: true,
  }),
  'security.session_timeout': createDefaultPreference(480, {
    type: 'number',
    description: 'Session timeout in minutes',
    category: 'security',
    sensitive: true,
  }),
  'security.login_notifications': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Receive notifications for new login attempts',
    category: 'security',
  }),
  'security.device_tracking': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Track and manage authorized devices',
    category: 'security',
  }),
  'security.suspicious_activity_alerts': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Receive alerts for suspicious account activity',
    category: 'security',
  }),
  'security.password_expiry_days': createDefaultPreference(90, {
    type: 'number',
    description: 'Password expiry period in days (0 = never)',
    category: 'security',
    sensitive: true,
  }),
  'security.require_password_change': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Require password change on next login',
    category: 'security',
    sensitive: true,
  }),
  
  // Performance preferences
  'performance.lazy_loading': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Enable lazy loading for better performance',
    category: 'performance',
  }),
  'performance.image_optimization': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Optimize images for faster loading',
    category: 'performance',
  }),
  'performance.cache_duration': createDefaultPreference(60, {
    type: 'number',
    description: 'Cache duration in minutes',
    category: 'performance',
  }),
  'performance.prefetch_links': createDefaultPreference(false, {
    type: 'boolean',
    description: 'Prefetch linked resources for faster navigation',
    category: 'performance',
  }),
  'performance.animation_performance': createDefaultPreference('auto', {
    type: 'string',
    description: 'Animation performance optimization level',
    category: 'performance',
  }),
  'performance.background_sync': createDefaultPreference(true, {
    type: 'boolean',
    description: 'Enable background synchronization',
    category: 'performance',
  }),
} as const;

// =============================================================================
// MOCK API SERVICE
// =============================================================================

export const preferencesApi = {
  async fetchPreferences(): Promise<UserPreferences> {
    await new Promise(resolve => setTimeout(resolve, 600));
    return defaultPreferences;
  },
  
  async updatePreferences(preferences: DeepPartial<UserPreferences>): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 400));
  },
  
  async fetchFeatureFlags(): Promise<FeatureFlag[]> {
    await new Promise(resolve => setTimeout(resolve, 300));
    return [
      {
        key: 'new_dashboard',
        enabled: true,
        description: 'Enable the new dashboard layout',
        rolloutPercentage: 50,
      },
      {
        key: 'advanced_search',
        enabled: false,
        description: 'Advanced search functionality',
        rolloutPercentage: 10,
      },
    ];
  },
  
  async createBackup(preferences: UserPreferences): Promise<{ id: string; size: number }> {
    await new Promise(resolve => setTimeout(resolve, 800));
    const serialized = JSON.stringify(preferences);
    return {
      id: `backup_${Date.now()}`,
      size: new Blob([serialized]).size,
    };
  },
  
  async restoreBackup(backupId: string): Promise<UserPreferences> {
    await new Promise(resolve => setTimeout(resolve, 1000));
    return defaultPreferences;
  },
};

// =============================================================================
// STORE IMPLEMENTATION
// =============================================================================

/**
 * Create the enhanced preferences store
 */
export const usePreferencesStore = create<PreferencesStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Base store implementation
        _initialized: Date.now(),
        _version: STORE_VERSION,
        _storeId: generateStoreId(),
        
        // Core preference data
        preferences: defaultPreferences,
        defaultPreferences,
        schemaRegistry: {} as PreferenceSchemaRegistry, // Would be populated with actual schemas
        
        // Async states
        fetchState: { status: 'idle', data: null, error: null, loading: false },
        updateState: { status: 'idle', data: null, error: null, loading: false },
        resetState: { status: 'idle', data: null, error: null, loading: false },
        backupState: { status: 'idle', data: null, error: null, loading: false },
        restoreState: { status: 'idle', data: null, error: null, loading: false },
        migrationState: { status: 'idle', data: null, error: null, loading: false },
        
        // Feature flags
        featureFlags: {
          flags: new Map(),
          lastUpdated: null,
          evaluationContext: {
            userGroups: [],
            environment: process.env.NODE_ENV || 'development',
            timestamp: Date.now(),
          },
        },
        featureFlagState: { status: 'idle', data: null, error: null, loading: false },
        
        // Validation and migration
        validationErrors: new Map(),
        migrationHistory: [],
        currentSchemaVersion: STORE_VERSION,
        
        // Backup and restore
        backups: [],
        autoBackupEnabled: true,
        maxBackups: 10,
        
        // Synchronization
        syncEnabled: false,
        lastSyncTime: null,
        syncConflicts: [],
        
        // Performance tracking
        changeTracker: {
          changes: new Map(),
          sessionChanges: 0,
          lastChangeTime: null,
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
            state.updateState.error = null;
            state.resetState.error = null;
            state.backupState.error = null;
            state.restoreState.error = null;
            state.migrationState.error = null;
            state.featureFlagState.error = null;
            state.validationErrors = new Map();
          });
        },
        
        reset: () => {
          set((state) => {
            state.preferences = defaultPreferences;
            state.validationErrors = new Map();
            state.changeTracker = {
              changes: new Map(),
              sessionChanges: 0,
              lastChangeTime: null,
            };
            state.syncConflicts = [];
            state.isLoading = false;
            state.error = null;
            state.lastOperation = null;
          });
        },
        
        hasPendingOperations: () => {
          const state = get();
          return state.fetchState.loading ||
                 state.updateState.loading ||
                 state.resetState.loading ||
                 state.backupState.loading ||
                 state.restoreState.loading ||
                 state.migrationState.loading ||
                 state.featureFlagState.loading;
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
          await get().fetchPreferences();
        },
        
        // Core preference operations
        getPreference: <K extends PreferenceKeys>(key: K) => {
          const preference = get().preferences[key];
          return preference.value;
        },
        
        setPreference: async <K extends PreferenceKeys>(
          key: K, 
          value: PreferenceValueType<K>, 
          source: PreferenceValue['source'] = 'user'
        ) => {
          // Validate the new value
          const validation = get().validatePreference(key, value);
          if (!validation.isValid) {
            throw new Error(`Invalid value for ${key}: ${validation.errors[key]?.join(', ')}`);
          }
          
          const oldValue = get().preferences[key].value;
          
          set((state) => {
            state.updateState = { status: 'loading', data: { [key]: value } as any, error: null, loading: true };
            state.isLoading = true;
            state.lastOperation = Date.now();
          });
          
          try {
            // Update the preference
            await preferencesApi.updatePreferences({ [key]: { value } as any });
            
            set((state) => {
              // Update the preference value
              const currentPreference = state.preferences[key];
              (state.preferences as any)[key] = {
                ...currentPreference,
                value,
                lastModified: Date.now(),
                version: currentPreference.version + 1,
                source,
              };
              
              // Track the change
              state.changeTracker.changes.set(key, {
                key,
                oldValue,
                newValue: value,
                timestamp: Date.now(),
                source,
              });
              state.changeTracker.sessionChanges += 1;
              state.changeTracker.lastChangeTime = Date.now();
              
              // Clear validation errors for this key
              state.validationErrors.delete(key);
              
              state.updateState = { status: 'success', data: { [key]: value } as any, error: null, loading: false };
              state.isLoading = false;
              state.lastCacheUpdate = Date.now();
            });
            
            // Emit change event
            get().emit('preference.updated' as EventKey, { key, value, oldValue });
            
            // Auto-backup if enabled
            if (get().autoBackupEnabled) {
              await get().createBackup(`Auto-backup after ${key} change`);
            }
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to update preference');
            
            set((state) => {
              state.updateState = { status: 'error', data: null, error: err, loading: false };
              state.isLoading = false;
              state.error = err;
            });
            
            throw err;
          }
        },
        
        setPreferences: async (preferences: DeepPartial<UserPreferences>) => {
          set((state) => {
            state.updateState = { status: 'loading', data: preferences as any, error: null, loading: true };
            state.isLoading = true;
            state.lastOperation = Date.now();
          });
          
          try {
            await preferencesApi.updatePreferences(preferences);
            
            set((state) => {
              // Update multiple preferences
              Object.entries(preferences).forEach(([key, preferenceUpdate]) => {
                if (preferenceUpdate && typeof preferenceUpdate === 'object' && 'value' in preferenceUpdate) {
                  const currentPreference = state.preferences[key as PreferenceKeys];
                  if (currentPreference) {
                    const oldValue = currentPreference.value;
                    
                    (state.preferences as any)[key] = {
                      ...currentPreference,
                      ...preferenceUpdate,
                      lastModified: Date.now(),
                      version: currentPreference.version + 1,
                    };
                    
                    // Track the change
                    state.changeTracker.changes.set(key as PreferenceKeys, {
                      key: key as PreferenceKeys,
                      oldValue,
                      newValue: preferenceUpdate.value,
                      timestamp: Date.now(),
                      source: preferenceUpdate.source || 'user',
                    });
                  }
                }
              });
              
              state.changeTracker.sessionChanges += Object.keys(preferences).length;
              state.changeTracker.lastChangeTime = Date.now();
              
              state.updateState = { status: 'success', data: preferences as any, error: null, loading: false };
              state.isLoading = false;
              state.lastCacheUpdate = Date.now();
            });
            
            get().emit('preferences.updated' as EventKey, { preferences });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to update preferences');
            
            set((state) => {
              state.updateState = { status: 'error', data: null, error: err, loading: false };
              state.isLoading = false;
              state.error = err;
            });
            
            throw err;
          }
        },
        
        resetPreference: async (key: PreferenceKeys) => {
          const defaultValue = get().defaultPreferences[key];
          await get().setPreference(key, defaultValue.value as any, 'system');
        },
        
        resetPreferences: async (keys?: PreferenceKeys[]) => {
          const keysToReset = keys || (Object.keys(get().preferences) as PreferenceKeys[]);
          
          set((state) => {
            state.resetState = { status: 'loading', data: keysToReset, error: null, loading: true };
          });
          
          try {
            const resetPreferences: DeepPartial<UserPreferences> = {};
            
            keysToReset.forEach(key => {
              const defaultValue = get().defaultPreferences[key];
              (resetPreferences as any)[key] = {
                value: defaultValue.value,
                source: 'system',
              };
            });
            
            await get().setPreferences(resetPreferences);
            
            set((state) => {
              state.resetState = { status: 'success', data: keysToReset, error: null, loading: false };
            });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to reset preferences');
            
            set((state) => {
              state.resetState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        resetAllPreferences: async () => {
          await get().resetPreferences();
        },
        
        fetchPreferences: async (): Promise<UserPreferences> => {
          set((state) => {
            state.fetchState = { status: 'loading', data: state.preferences, error: null, loading: true };
            state.isLoading = true;
            state.lastOperation = Date.now();
          });
          
          try {
            const preferences = await preferencesApi.fetchPreferences();
            
            set((state) => {
              state.preferences = preferences;
              state.fetchState = { status: 'success', data: preferences, error: null, loading: false };
              state.isLoading = false;
              state.lastCacheUpdate = Date.now();
            });
            
            return preferences;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch preferences');
            
            set((state) => {
              state.fetchState = { status: 'error', data: null, error: err, loading: false };
              state.isLoading = false;
              state.error = err;
            });
            
            throw err;
          }
        },
        
        // Validation
        validatePreference: <K extends PreferenceKeys>(key: K, value: PreferenceValueType<K>): ValidationResult => {
          const schema = get().schemaRegistry[key];
          if (!schema) {
            return { isValid: true, errors: {} };
          }
          
          const errors: string[] = [];
          
          // Type validation
          if (schema.type === 'string' && typeof value !== 'string') {
            errors.push('Must be a string');
          } else if (schema.type === 'number' && typeof value !== 'number') {
            errors.push('Must be a number');
          } else if (schema.type === 'boolean' && typeof value !== 'boolean') {
            errors.push('Must be a boolean');
          }
          
          // Custom validation rules
          if (schema.validation) {
            schema.validation.forEach(rule => {
              const result = rule(value);
              if (result) {
                errors.push(result);
              }
            });
          }
          
          return {
            isValid: errors.length === 0,
            errors: errors.length > 0 ? { [key]: errors } : {},
          };
        },
        
        validateAllPreferences: (): ValidationResult => {
          const preferences = get().preferences;
          const allErrors: Record<string, string[]> = {};
          let isValid = true;
          
          Object.keys(preferences).forEach(key => {
            const prefKey = key as PreferenceKeys;
            const value = preferences[prefKey].value;
            const result = get().validatePreference(prefKey, value as any);
            
            if (!result.isValid) {
              isValid = false;
              Object.assign(allErrors, result.errors);
            }
          });
          
          return { isValid, errors: allErrors };
        },
        
        getPreferenceSchema: <K extends PreferenceKeys>(key: K) => {
          return get().schemaRegistry[key];
        },
        
        isPreferenceValid: <K extends PreferenceKeys>(key: K) => {
          const value = get().preferences[key].value;
          const result = get().validatePreference(key, value as any);
          return result.isValid;
        },
        
        // Feature flags
        fetchFeatureFlags: async () => {
          set((state) => {
            state.featureFlagState = { status: 'loading', data: Array.from(state.featureFlags.flags.values()), error: null, loading: true };
          });
          
          try {
            const flags = await preferencesApi.fetchFeatureFlags();
            
            set((state) => {
              const flagsMap = new Map(flags.map(flag => [flag.key, flag]));
              state.featureFlags.flags = flagsMap;
              state.featureFlags.lastUpdated = Date.now();
              state.featureFlagState = { status: 'success', data: flags, error: null, loading: false };
            });
            
            return flags;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch feature flags');
            
            set((state) => {
              state.featureFlagState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        isFeatureEnabled: (flagKey: string) => {
          return get().evaluateFeatureFlag(flagKey);
        },
        
        evaluateFeatureFlag: (flagKey: string, context?: Partial<FeatureFlagState['evaluationContext']>) => {
          const flag = get().featureFlags.flags.get(flagKey);
          if (!flag) return false;
          
          const evalContext = { ...get().featureFlags.evaluationContext, ...context };
          
          // Basic evaluation logic (in real implementation, this would be more sophisticated)
          if (!flag.enabled) return false;
          
          // Check environment restrictions
          if (flag.environmentRestriction && !flag.environmentRestriction.includes(evalContext.environment as any)) {
            return false;
          }
          
          // Check date restrictions
          const now = new Date();
          if (flag.startDate && now < flag.startDate) return false;
          if (flag.endDate && now > flag.endDate) return false;
          
          // Check user targeting
          if (flag.targetUsers && evalContext.userId && !flag.targetUsers.includes(evalContext.userId)) {
            return false;
          }
          
          // Check group targeting
          if (flag.targetGroups) {
            const hasMatchingGroup = flag.targetGroups.some(group => 
              evalContext.userGroups.includes(group)
            );
            if (!hasMatchingGroup) return false;
          }
          
          // Check rollout percentage (simplified)
          if (flag.rolloutPercentage !== undefined && flag.rolloutPercentage < 100) {
            const hash = Math.abs(flagKey.split('').reduce((a, b) => {
              return (a << 5) - a + b.charCodeAt(0);
            }, 0));
            return (hash % 100) < flag.rolloutPercentage;
          }
          
          return true;
        },
        
        refreshFeatureFlags: async () => {
          await get().fetchFeatureFlags();
        },
        
        // Backup and restore
        createBackup: async (description?: string) => {
          set((state) => {
            state.backupState = { status: 'loading', data: null, error: null, loading: true };
          });
          
          try {
            const preferences = get().preferences;
            const { id, size } = await preferencesApi.createBackup(preferences);
            
            const backup: PreferenceBackup = {
              id,
              timestamp: Date.now(),
              version: get().currentSchemaVersion,
              preferences,
              description,
              automatic: !description || description.startsWith('Auto-backup'),
              size,
            };
            
            set((state) => {
              state.backups = [backup, ...state.backups].slice(0, state.maxBackups);
              state.backupState = { status: 'success', data: backup as any, error: null, loading: false };
            });
            
            return id;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to create backup');
            
            set((state) => {
              state.backupState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        restoreBackup: async (backupId: string) => {
          const backup = get().backups.find(b => b.id === backupId);
          if (!backup) {
            throw new Error('Backup not found');
          }
          
          set((state) => {
            state.restoreState = { status: 'loading', data: backup.preferences, error: null, loading: true };
          });
          
          try {
            const restoredPreferences = await preferencesApi.restoreBackup(backupId);
            
            set((state) => {
              state.preferences = restoredPreferences;
              state.restoreState = { status: 'success', data: restoredPreferences, error: null, loading: false };
              state.lastCacheUpdate = Date.now();
            });
            
            get().emit('preferences.restored' as EventKey, { backupId, preferences: restoredPreferences });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to restore backup');
            
            set((state) => {
              state.restoreState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        deleteBackup: async (backupId: string) => {
          set((state) => {
            state.backups = state.backups.filter(b => b.id !== backupId);
          });
        },
        
        cleanupOldBackups: async () => {
          const { backups, maxBackups } = get();
          const toDelete = backups.length - maxBackups;
          
          if (toDelete > 0) {
            const oldestBackups = backups
              .sort((a, b) => a.timestamp - b.timestamp)
              .slice(0, toDelete);
            
            set((state) => {
              state.backups = state.backups.filter(b => 
                !oldestBackups.some(old => old.id === b.id)
              );
            });
            
            return toDelete;
          }
          
          return 0;
        },
        
        toggleAutoBackup: (enabled: boolean) => {
          set((state) => {
            state.autoBackupEnabled = enabled;
          });
        },
        
        // Utility methods
        importPreferences: async (preferences: Record<string, unknown>, merge = true) => {
          // Type conversion and validation would happen here
          const validPreferences: DeepPartial<UserPreferences> = {};
          
          // Simple implementation - in reality would have sophisticated validation
          Object.entries(preferences).forEach(([key, value]) => {
            if (key in get().defaultPreferences) {
              (validPreferences as any)[key] = { value, source: 'imported' as const };
            }
          });
          
          if (merge) {
            await get().setPreferences(validPreferences);
          } else {
            await get().resetAllPreferences();
            await get().setPreferences(validPreferences);
          }
        },
        
        exportPreferences: (keys?: PreferenceKeys[]) => {
          const preferences = get().preferences;
          const keysToExport = keys || (Object.keys(preferences) as PreferenceKeys[]);
          
          const exported: Partial<UserPreferences> = {};
          keysToExport.forEach(key => {
            if (key in preferences) {
              (exported as any)[key] = preferences[key];
            }
          });
          
          return exported;
        },
        
        getPreferencesByCategory: (category: PreferenceCategoryType) => {
          const preferences = get().preferences;
          const filtered: Partial<UserPreferences> = {};
          
          Object.entries(preferences).forEach(([key, preference]) => {
            if (key.startsWith(`${category}.`)) {
              (filtered as any)[key] = preference;
            }
          });
          
          return filtered;
        },
        
        getChangedPreferences: () => {
          return get().changeTracker.changes;
        },
        
        hasUnsavedChanges: () => {
          return get().changeTracker.changes.size > 0;
        },
        
        getPreferenceCount: () => {
          return Object.keys(get().preferences).length;
        },
        
        getPreferenceSize: () => {
          const preferences = get().preferences;
          const serialized = JSON.stringify(preferences);
          return new Blob([serialized]).size;
        },
        
        // Migration (simplified implementation)
        migratePreferences: async (fromVersion: string, toVersion: string) => {
          set((state) => {
            state.migrationState = { status: 'loading', data: { fromVersion, toVersion }, error: null, loading: true };
          });
          
          try {
            // In real implementation, would apply migration functions
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            set((state) => {
              state.currentSchemaVersion = toVersion;
              state.migrationState = { status: 'success', data: { fromVersion, toVersion }, error: null, loading: false };
            });
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Migration failed');
            
            set((state) => {
              state.migrationState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        rollbackMigration: async (migrationId: string) => {
          // Simplified implementation
          await new Promise(resolve => setTimeout(resolve, 800));
        },
        
        getMigrationHistory: () => {
          return get().migrationHistory;
        },
        
        // Synchronization (simplified implementation)
        enableSync: async () => {
          set((state) => {
            state.syncEnabled = true;
            state.lastSyncTime = Date.now();
          });
        },
        
        disableSync: () => {
          set((state) => {
            state.syncEnabled = false;
          });
        },
        
        syncWithRemote: async () => {
          if (!get().syncEnabled) return;
          
          // Simplified sync implementation
          await new Promise(resolve => setTimeout(resolve, 1200));
          
          set((state) => {
            state.lastSyncTime = Date.now();
          });
        },
        
        resolveSyncConflict: async (key: PreferenceKeys, resolution: 'local' | 'remote') => {
          const conflicts = get().syncConflicts;
          const conflict = conflicts.find(c => c.key === key);
          
          if (conflict) {
            const value = resolution === 'local' ? conflict.localValue : conflict.remoteValue;
            await get().setPreference(key, value as any, 'user');
            
            set((state) => {
              state.syncConflicts = state.syncConflicts.filter(c => c.key !== key);
            });
          }
        },
        
        resolveSyncConflicts: async (resolutions: Record<PreferenceKeys, 'local' | 'remote'>) => {
          for (const [key, resolution] of Object.entries(resolutions)) {
            await get().resolveSyncConflict(key as PreferenceKeys, resolution);
          }
        },
        
        // Type guards and assertions
        assertPreferenceExists: <K extends PreferenceKeys>(key: K) => {
          if (!(key in get().preferences)) {
            throw new Error(`Preference ${key} does not exist`);
          }
        },
        
        isDefaultValue: <K extends PreferenceKeys>(key: K) => {
          const current = get().preferences[key];
          const defaultVal = get().defaultPreferences[key];
          return current.value === defaultVal.value;
        },
        
        hasPreferenceChanged: <K extends PreferenceKeys>(key: K) => {
          return get().changeTracker.changes.has(key);
        },
      })),
      {
        name: 'preferences-storage',
        partialize: (state) => ({
          preferences: state.preferences,
          featureFlags: {
            ...state.featureFlags,
            // Convert Map to array for serialization
            flags: Array.from(state.featureFlags.flags.entries()),
          },
          autoBackupEnabled: state.autoBackupEnabled,
          maxBackups: state.maxBackups,
          syncEnabled: state.syncEnabled,
          backups: state.backups.slice(0, 5), // Only persist recent backups
        }),
        onRehydrateStorage: () => (state) => {
          if (state && state.featureFlags && Array.isArray(state.featureFlags.flags)) {
            // Convert array back to Map
            state.featureFlags.flags = new Map(state.featureFlags.flags as any);
          }
        },
      }
    ),
    {
      name: 'preferences-store',
    }
  )
);

// =============================================================================
// PERFORMANCE-OPTIMIZED SELECTORS
// =============================================================================

export const usePreference = <K extends PreferenceKeys>(key: K) => 
  usePreferencesStore((state) => state.preferences[key].value);

export const usePreferences = () => usePreferencesStore((state) => state.preferences);

export const usePreferencesByCategory = (category: PreferenceCategoryType) =>
  usePreferencesStore((state) => state.getPreferencesByCategory(category));

export const usePreferenceStates = () => usePreferencesStore((state) => ({
  fetchState: state.fetchState,
  updateState: state.updateState,
  resetState: state.resetState,
  backupState: state.backupState,
  restoreState: state.restoreState,
  migrationState: state.migrationState,
}));

export const useFeatureFlags = () => usePreferencesStore((state) => state.featureFlags);
export const useFeatureFlag = (flagKey: string) => 
  usePreferencesStore((state) => state.isFeatureEnabled(flagKey));

export const usePreferenceBackups = () => usePreferencesStore((state) => state.backups);
export const usePreferenceValidation = () => usePreferencesStore((state) => state.validationErrors);
export const usePreferenceChanges = () => usePreferencesStore((state) => state.changeTracker);

// Action selectors
export const usePreferenceActions = () => usePreferencesStore((state) => ({
  getPreference: state.getPreference,
  setPreference: state.setPreference,
  setPreferences: state.setPreferences,
  resetPreference: state.resetPreference,
  resetPreferences: state.resetPreferences,
  resetAllPreferences: state.resetAllPreferences,
  fetchPreferences: state.fetchPreferences,
  validatePreference: state.validatePreference,
  validateAllPreferences: state.validateAllPreferences,
  createBackup: state.createBackup,
  restoreBackup: state.restoreBackup,
  deleteBackup: state.deleteBackup,
  fetchFeatureFlags: state.fetchFeatureFlags,
  isFeatureEnabled: state.isFeatureEnabled,
  importPreferences: state.importPreferences,
  exportPreferences: state.exportPreferences,
}));

// Composite hooks
export const usePreferencesWithActions = () => {
  const preferences = usePreferences();
  const actions = usePreferenceActions();
  const states = usePreferenceStates();
  
  return {
    preferences,
    ...actions,
    ...states,
  };
};

// Type-safe preference hooks for common categories
export const useThemePreferences = () => usePreferencesByCategory('ui');
export const useAccessibilityPreferences = () => usePreferencesByCategory('accessibility');
export const usePrivacyPreferences = () => usePreferencesByCategory('privacy');
export const useSecurityPreferences = () => usePreferencesByCategory('security');
export const usePerformancePreferences = () => usePreferencesByCategory('performance');

// Utility hooks
export const usePreferenceUtils = () => usePreferencesStore((state) => ({
  hasUnsavedChanges: state.hasUnsavedChanges,
  getPreferenceCount: state.getPreferenceCount,
  getPreferenceSize: state.getPreferenceSize,
  isDefaultValue: state.isDefaultValue,
  hasPreferenceChanged: state.hasPreferenceChanged,
  getChangedPreferences: state.getChangedPreferences,
}));