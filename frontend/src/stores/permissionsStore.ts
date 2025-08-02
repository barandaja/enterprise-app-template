/**
 * Enterprise PermissionsStore with Advanced TypeScript Patterns
 * 
 * This store implements sophisticated Role-Based Access Control (RBAC) with:
 * - Advanced TypeScript patterns for type-safe permission checking
 * - Hierarchical role and permission structures with recursive types
 * - Dynamic permission evaluation with conditional types
 * - Permission caching and refresh mechanisms with performance optimization
 * - Temporal permissions with time-based access control
 * - Context-aware permissions based on resources and conditions
 * - Audit logging for permission checks and changes
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
  PermissionId,
  UserId,
  EventKey,
  StoreEvent,
  NestedPermissions,
  ResourceAction,
  ResourceType,
  PermissionKey,
  createPermissionId,
  createUserId,
  generateStoreId,
  STORE_VERSION,
  DEFAULT_CACHE_EXPIRY,
  DeepReadonly,
  DeepPartial,
  RequiredExcept,
} from './types';

// =============================================================================
// ADVANCED PERMISSION TYPES WITH TEMPLATE LITERALS
// =============================================================================

/**
 * Permission actions using template literal types
 */
export type PermissionAction = ResourceAction | 'execute' | 'approve' | 'reject' | 'assign' | 'unassign' | 'grant' | 'revoke';

/**
 * Resource types for permission system
 */
export type PermissionResourceType = ResourceType | 'role' | 'permission' | 'organization' | 'team' | 'project' | 'document' | 'report';

/**
 * Advanced permission key with template literals
 */
export type AdvancedPermissionKey = `${PermissionResourceType}.${PermissionAction}` | `${PermissionResourceType}.${PermissionAction}.${string}`;

/**
 * Permission scopes for context-aware permissions
 */
export type PermissionScope = 'global' | 'organization' | 'team' | 'project' | 'personal';

/**
 * Permission contexts with conditional types
 */
export type PermissionContext<T extends PermissionScope = PermissionScope> = T extends 'global'
  ? { scope: 'global' }
  : T extends 'organization'
  ? { scope: 'organization'; organizationId: string }
  : T extends 'team'
  ? { scope: 'team'; teamId: string; organizationId?: string }
  : T extends 'project'
  ? { scope: 'project'; projectId: string; teamId?: string; organizationId?: string }
  : T extends 'personal'
  ? { scope: 'personal'; userId: UserId }
  : { scope: PermissionScope; [key: string]: unknown };

// =============================================================================
// ROLE-BASED ACCESS CONTROL TYPES
// =============================================================================

/**
 * Base permission interface
 */
export interface BasePermission {
  readonly id: PermissionId;
  readonly key: AdvancedPermissionKey;
  readonly name: string;
  readonly description: string;
  readonly category: string;
  readonly scope: PermissionScope;
  readonly resource?: string;
  readonly action?: PermissionAction;
  readonly metadata?: Record<string, unknown>;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * Conditional permission with dynamic evaluation
 */
export interface ConditionalPermission extends BasePermission {
  readonly type: 'conditional';
  readonly conditions: PermissionCondition[];
  readonly operator: 'AND' | 'OR';
}

/**
 * Time-based permission with temporal access control
 */
export interface TemporalPermission extends BasePermission {
  readonly type: 'temporal';
  readonly validFrom?: Date;
  readonly validUntil?: Date;
  readonly schedule?: PermissionSchedule;
  readonly timezone?: string;
}

/**
 * Resource-specific permission with context awareness
 */
export interface ResourcePermission extends BasePermission {
  readonly type: 'resource';
  readonly resourceType: PermissionResourceType;
  readonly resourceId?: string;
  readonly resourceFilter?: PermissionResourceFilter;
  readonly inherited?: boolean;
  readonly inheritanceSource?: PermissionId;
}

/**
 * Dynamic permission with runtime evaluation
 */
export interface DynamicPermission extends BasePermission {
  readonly type: 'dynamic';
  readonly evaluator: PermissionEvaluator;
  readonly dependencies: AdvancedPermissionKey[];
  readonly cachePolicy: PermissionCachePolicy;
}

/**
 * Discriminated union of all permission types
 */
export type Permission = ConditionalPermission | TemporalPermission | ResourcePermission | DynamicPermission;

/**
 * Permission condition for conditional permissions
 */
export interface PermissionCondition {
  readonly field: string;
  readonly operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'greater_than' | 'less_than' | 'in' | 'not_in' | 'exists' | 'not_exists';
  readonly value: unknown;
  readonly contextPath?: string;
}

/**
 * Permission schedule for temporal permissions
 */
export interface PermissionSchedule {
  readonly type: 'recurring' | 'one_time';
  readonly pattern?: 'daily' | 'weekly' | 'monthly';
  readonly daysOfWeek?: number[]; // 0-6, Sunday=0
  readonly daysOfMonth?: number[]; // 1-31
  readonly timeRanges?: Array<{
    start: string; // HH:mm format
    end: string;   // HH:mm format
  }>;
  readonly exceptions?: Date[];
}

/**
 * Resource filter for resource-specific permissions
 */
export interface PermissionResourceFilter {
  readonly includePatterns?: string[];
  readonly excludePatterns?: string[];
  readonly attributes?: Record<string, unknown>;
  readonly tags?: string[];
}

/**
 * Permission evaluator function for dynamic permissions
 */
export type PermissionEvaluator = (
  context: PermissionEvaluationContext
) => boolean | Promise<boolean>;

/**
 * Permission cache policy
 */
export interface PermissionCachePolicy {
  readonly ttl: number; // milliseconds
  readonly invalidateOn: string[]; // events that invalidate cache
  readonly shared: boolean; // shared across users
}

// =============================================================================
// ROLE SYSTEM WITH HIERARCHICAL STRUCTURE
// =============================================================================

/**
 * Base role interface
 */
export interface BaseRole {
  readonly id: string;
  readonly name: string;
  readonly description: string;
  readonly scope: PermissionScope;
  readonly permissions: ReadonlyArray<PermissionId>;
  readonly metadata?: Record<string, unknown>;
  readonly createdAt: number;
  readonly updatedAt: number;
}

/**
 * Hierarchical role with inheritance
 */
export interface HierarchicalRole extends BaseRole {
  readonly type: 'hierarchical';
  readonly parentRoles: ReadonlyArray<string>;
  readonly childRoles: ReadonlyArray<string>;
  readonly inheritanceType: 'additive' | 'restrictive' | 'override';
  readonly level: number;
}

/**
 * Contextual role with scope-specific behavior
 */
export interface ContextualRole extends BaseRole {
  readonly type: 'contextual';
  readonly contextRequirements: PermissionContext[];
  readonly contextPermissions: ReadonlyMap<string, ReadonlyArray<PermissionId>>;
}

/**
 * Template role for role templates
 */
export interface TemplateRole extends BaseRole {
  readonly type: 'template';
  readonly templateId: string;
  readonly variables: Record<string, unknown>;
  readonly instantiationRules: RoleInstantiationRule[];
}

/**
 * Discriminated union of all role types
 */
export type Role = HierarchicalRole | ContextualRole | TemplateRole;

/**
 * Role instantiation rule
 */
export interface RoleInstantiationRule {
  readonly condition: string;
  readonly permissionModifications: Array<{
    action: 'add' | 'remove' | 'modify';
    permissionId: PermissionId;
    context?: PermissionContext;
  }>;
}

// =============================================================================
// PERMISSION EVALUATION SYSTEM
// =============================================================================

/**
 * Permission evaluation context
 */
export interface PermissionEvaluationContext {
  readonly user: {
    readonly id: UserId;
    readonly roles: ReadonlyArray<string>;
    readonly attributes: Record<string, unknown>;
    readonly groups: ReadonlyArray<string>;
  };
  readonly resource?: {
    readonly type: PermissionResourceType;
    readonly id: string;
    readonly attributes: Record<string, unknown>;
    readonly owner?: UserId;
    readonly tags: ReadonlyArray<string>;
  };
  readonly environment: {
    readonly timestamp: number;
    readonly location?: string;
    readonly ipAddress?: string;
    readonly userAgent?: string;
    readonly sessionId?: string;
  };
  readonly request?: {
    readonly action: PermissionAction;
    readonly parameters: Record<string, unknown>;
    readonly headers: Record<string, string>;
  };
}

/**
 * Permission evaluation result
 */
export interface PermissionEvaluationResult {
  readonly allowed: boolean;
  readonly reason: string;
  readonly matchedPermissions: ReadonlyArray<PermissionId>;
  readonly failedConditions: ReadonlyArray<string>;
  readonly evaluationTime: number;
  readonly cached: boolean;
  readonly context: PermissionEvaluationContext;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Permission check request
 */
export interface PermissionCheckRequest {
  readonly permission: AdvancedPermissionKey;
  readonly context?: Partial<PermissionEvaluationContext>;
  readonly options?: PermissionCheckOptions;
}

/**
 * Permission check options
 */
export interface PermissionCheckOptions {
  readonly useCache: boolean;
  readonly includeReason: boolean;
  readonly auditLog: boolean;
  readonly timeout: number;
  readonly fallbackToDefault: boolean;
}

// =============================================================================
// PERMISSION AUDIT AND LOGGING
// =============================================================================

/**
 * Permission audit log entry
 */
export interface PermissionAuditEntry {
  readonly id: string;
  readonly timestamp: number;
  readonly userId: UserId;
  readonly sessionId?: string;
  readonly action: 'check' | 'grant' | 'revoke' | 'modify' | 'delete';
  readonly permission: AdvancedPermissionKey;
  readonly resource?: {
    readonly type: PermissionResourceType;
    readonly id: string;
  };
  readonly result: 'granted' | 'denied' | 'error';
  readonly reason: string;
  readonly context: Partial<PermissionEvaluationContext>;
  readonly metadata?: Record<string, unknown>;
}

/**
 * Permission audit filter
 */
export interface PermissionAuditFilter {
  readonly startDate?: Date;
  readonly endDate?: Date;
  readonly userId?: UserId;
  readonly actions?: ReadonlyArray<PermissionAuditEntry['action']>;
  readonly permissions?: ReadonlyArray<AdvancedPermissionKey>;
  readonly results?: ReadonlyArray<PermissionAuditEntry['result']>;
  readonly resourceTypes?: ReadonlyArray<PermissionResourceType>;
}

// =============================================================================
// STORE STATE AND ACTIONS
// =============================================================================

/**
 * Permissions store state
 */
interface PermissionsState extends BaseStore, AsyncStoreMixin<PermissionsState>, CacheStoreMixin<Permission[]> {
  // Core permission data
  readonly permissions: ReadonlyMap<PermissionId, Permission>;
  readonly roles: ReadonlyMap<string, Role>;
  readonly userRoles: ReadonlyMap<UserId, ReadonlyArray<string>>;
  readonly userPermissions: ReadonlyMap<UserId, ReadonlyArray<PermissionId>>;
  
  // Hierarchical data structures
  readonly permissionHierarchy: NestedPermissions<PermissionId>;
  readonly roleHierarchy: ReadonlyMap<string, ReadonlyArray<string>>;
  
  // Async states for operations
  readonly fetchPermissionsState: AsyncState<Permission[]>;
  readonly fetchRolesState: AsyncState<Role[]>;
  readonly fetchUserPermissionsState: AsyncState<{ userId: UserId; permissions: PermissionId[] }>;
  readonly grantPermissionState: AsyncState<{ userId: UserId; permissionId: PermissionId }>;
  readonly revokePermissionState: AsyncState<{ userId: UserId; permissionId: PermissionId }>;
  readonly evaluatePermissionState: AsyncState<PermissionEvaluationResult>;
  
  // Evaluation cache
  readonly evaluationCache: ReadonlyMap<string, CachedPermissionResult>;
  readonly cacheStats: PermissionCacheStats;
  
  // Audit logging
  readonly auditLog: ReadonlyArray<PermissionAuditEntry>;
  readonly auditLogEnabled: boolean;
  readonly maxAuditEntries: number;
  
  // Performance tracking
  readonly evaluationStats: PermissionEvaluationStats;
  readonly slowEvaluationThreshold: number;
  
  // Current evaluation context
  readonly currentContext: Partial<PermissionEvaluationContext>;
}

/**
 * Cached permission result
 */
export interface CachedPermissionResult {
  readonly key: string;
  readonly result: PermissionEvaluationResult;
  readonly timestamp: number;
  readonly ttl: number;
  readonly hitCount: number;
}

/**
 * Permission cache statistics
 */
export interface PermissionCacheStats {
  readonly hits: number;
  readonly misses: number;
  readonly evictions: number;
  readonly totalEvaluations: number;
  readonly averageEvaluationTime: number;
  readonly cacheSize: number;
  readonly maxCacheSize: number;
}

/**
 * Permission evaluation statistics
 */
export interface PermissionEvaluationStats {
  readonly totalEvaluations: number;
  readonly fastEvaluations: number;
  readonly slowEvaluations: number;
  readonly cachedEvaluations: number;
  readonly failedEvaluations: number;
  readonly averageEvaluationTime: number;
  readonly maxEvaluationTime: number;
  readonly evaluationsByPermission: ReadonlyMap<AdvancedPermissionKey, number>;
  readonly evaluationsByUser: ReadonlyMap<UserId, number>;
}

/**
 * Permissions store actions
 */
interface PermissionsActions extends StoreEventEmitter {
  // Permission CRUD operations
  readonly fetchPermissions: () => Promise<Permission[]>;
  readonly fetchRoles: () => Promise<Role[]>;
  readonly fetchUserPermissions: (userId: UserId) => Promise<PermissionId[]>;
  readonly createPermission: (permission: Omit<Permission, 'id' | 'createdAt' | 'updatedAt'>) => Promise<PermissionId>;
  readonly updatePermission: (id: PermissionId, updates: Partial<Permission>) => Promise<void>;
  readonly deletePermission: (id: PermissionId) => Promise<void>;
  
  // Role management
  readonly createRole: (role: Omit<Role, 'id' | 'createdAt' | 'updatedAt'>) => Promise<string>;
  readonly updateRole: (id: string, updates: Partial<Role>) => Promise<void>;
  readonly deleteRole: (id: string) => Promise<void>;
  readonly assignRole: (userId: UserId, roleId: string) => Promise<void>;
  readonly unassignRole: (userId: UserId, roleId: string) => Promise<void>;
  
  // Permission granting and revoking
  readonly grantPermission: (userId: UserId, permissionId: PermissionId, context?: PermissionContext) => Promise<void>;
  readonly revokePermission: (userId: UserId, permissionId: PermissionId, context?: PermissionContext) => Promise<void>;
  readonly grantPermissions: (userId: UserId, permissionIds: PermissionId[], context?: PermissionContext) => Promise<void>;
  readonly revokePermissions: (userId: UserId, permissionIds: PermissionId[], context?: PermissionContext) => Promise<void>;
  
  // Permission evaluation
  readonly hasPermission: (permission: AdvancedPermissionKey, context?: Partial<PermissionEvaluationContext>) => Promise<boolean>;
  readonly checkPermission: (request: PermissionCheckRequest) => Promise<PermissionEvaluationResult>;
  readonly checkPermissions: (requests: PermissionCheckRequest[]) => Promise<PermissionEvaluationResult[]>;
  readonly evaluatePermission: (permission: Permission, context: PermissionEvaluationContext) => Promise<boolean>;
  
  // Bulk operations
  readonly hasPermissions: (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => Promise<boolean[]>;
  readonly hasAnyPermission: (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => Promise<boolean>;
  readonly hasAllPermissions: (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => Promise<boolean>;
  
  // Context-aware permission checking
  readonly hasPermissionInContext: <T extends PermissionScope>(
    permission: AdvancedPermissionKey,
    context: PermissionContext<T>
  ) => Promise<boolean>;
  readonly getPermissionsForResource: (resourceType: PermissionResourceType, resourceId: string) => Promise<AdvancedPermissionKey[]>;
  readonly getUserPermissionsInContext: (userId: UserId, context: PermissionContext) => Promise<AdvancedPermissionKey[]>;
  
  // Role-based queries
  readonly getUserRoles: (userId: UserId) => ReadonlyArray<string>;
  readonly getRolePermissions: (roleId: string) => ReadonlyArray<PermissionId>;
  readonly getEffectivePermissions: (userId: UserId) => Promise<ReadonlyArray<PermissionId>>;
  readonly getRoleHierarchy: (roleId: string) => ReadonlyArray<string>;
  
  // Temporal permission handling
  readonly checkTemporalPermission: (permission: TemporalPermission, context: PermissionEvaluationContext) => boolean;
  readonly getActiveTemporalPermissions: (userId: UserId, timestamp?: number) => ReadonlyArray<PermissionId>;
  readonly schedulePermissionExpiry: (permissionId: PermissionId, expiryDate: Date) => Promise<void>;
  
  // Cache management
  readonly clearPermissionCache: (pattern?: string) => void;
  readonly refreshPermissionCache: () => Promise<void>;
  readonly getCacheStats: () => PermissionCacheStats;
  readonly optimizeCache: () => Promise<void>;
  
  // Audit and logging
  readonly getAuditLog: (filter?: PermissionAuditFilter) => ReadonlyArray<PermissionAuditEntry>;
  readonly clearAuditLog: () => void;
  readonly exportAuditLog: (filter?: PermissionAuditFilter) => Promise<Blob>;
  readonly toggleAuditLogging: (enabled: boolean) => void;
  
  // Context management
  readonly setEvaluationContext: (context: Partial<PermissionEvaluationContext>) => void;
  readonly updateEvaluationContext: (updates: Partial<PermissionEvaluationContext>) => void;
  readonly clearEvaluationContext: () => void;
  
  // Utility methods
  readonly getPermissionsByCategory: (category: string) => ReadonlyArray<Permission>;
  readonly getPermissionsByScope: (scope: PermissionScope) => ReadonlyArray<Permission>;
  readonly searchPermissions: (query: string) => ReadonlyArray<Permission>;
  readonly validatePermissionKey: (key: string) => key is AdvancedPermissionKey;
  readonly getPermissionStats: () => PermissionEvaluationStats;
  
  // Type guards and assertions
  readonly assertPermissionExists: (id: PermissionId) => asserts this is PermissionsStore & { permissions: Map<PermissionId, Permission> };
  readonly assertUserHasPermission: (userId: UserId, permission: AdvancedPermissionKey) => Promise<void>;
  readonly isTemporalPermission: (permission: Permission) => permission is TemporalPermission;
  readonly isConditionalPermission: (permission: Permission) => permission is ConditionalPermission;
  readonly isResourcePermission: (permission: Permission) => permission is ResourcePermission;
  readonly isDynamicPermission: (permission: Permission) => permission is DynamicPermission;
}

/**
 * Combined permissions store type
 */
type PermissionsStore = PermissionsState & PermissionsActions;

// =============================================================================
// MOCK API SERVICE
// =============================================================================

const permissionsApi = {
  async fetchPermissions(): Promise<Permission[]> {
    await new Promise(resolve => setTimeout(resolve, 800));
    
    return [
      {
        id: createPermissionId('perm_1'),
        key: 'user.read',
        name: 'Read Users',
        description: 'Permission to read user information',
        category: 'user_management',
        scope: 'global',
        type: 'resource',
        resourceType: 'user',
        createdAt: Date.now() - 86400000,
        updatedAt: Date.now() - 86400000,
      },
      {
        id: createPermissionId('perm_2'),
        key: 'user.create',
        name: 'Create Users',
        description: 'Permission to create new users',
        category: 'user_management',
        scope: 'organization',
        type: 'conditional',
        conditions: [
          {
            field: 'user.role',
            operator: 'in',
            value: ['admin', 'manager'],
          },
        ],
        operator: 'AND',
        createdAt: Date.now() - 86400000,
        updatedAt: Date.now() - 86400000,
      },
    ] as Permission[];
  },
  
  async fetchRoles(): Promise<Role[]> {
    await new Promise(resolve => setTimeout(resolve, 600));
    
    return [
      {
        id: 'role_admin',
        name: 'Administrator',
        description: 'Full system access',
        scope: 'global',
        type: 'hierarchical',
        permissions: [createPermissionId('perm_1'), createPermissionId('perm_2')],
        parentRoles: [],
        childRoles: ['role_manager'],
        inheritanceType: 'additive',
        level: 0,
        createdAt: Date.now() - 86400000,
        updatedAt: Date.now() - 86400000,
      },
      {
        id: 'role_manager',
        name: 'Manager',
        description: 'Team management access',
        scope: 'team',
        type: 'hierarchical',
        permissions: [createPermissionId('perm_1')],
        parentRoles: ['role_admin'],
        childRoles: ['role_user'],
        inheritanceType: 'additive',
        level: 1,
        createdAt: Date.now() - 86400000,
        updatedAt: Date.now() - 86400000,
      },
    ] as Role[];
  },
  
  async fetchUserPermissions(userId: UserId): Promise<PermissionId[]> {
    await new Promise(resolve => setTimeout(resolve, 400));
    return [createPermissionId('perm_1')];
  },
  
  async grantPermission(userId: UserId, permissionId: PermissionId): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 300));
  },
  
  async revokePermission(userId: UserId, permissionId: PermissionId): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, 300));
  },
  
  async evaluatePermission(permissionId: PermissionId, context: PermissionEvaluationContext): Promise<PermissionEvaluationResult> {
    await new Promise(resolve => setTimeout(resolve, 200));
    
    return {
      allowed: true,
      reason: 'Permission granted by role assignment',
      matchedPermissions: [permissionId],
      failedConditions: [],
      evaluationTime: 150,
      cached: false,
      context,
    };
  },
};

// =============================================================================
// PERMISSION EVALUATION UTILITIES
// =============================================================================

/**
 * Create cache key for permission evaluation
 */
const createCacheKey = (permission: AdvancedPermissionKey, context: Partial<PermissionEvaluationContext>): string => {
  const contextStr = JSON.stringify({
    userId: context.user?.id,
    resourceType: context.resource?.type,
    resourceId: context.resource?.id,
    action: context.request?.action,
  });
  return `${permission}:${btoa(contextStr)}`;
};

/**
 * Check if temporal permission is currently active
 */
const isTemporalPermissionActive = (permission: TemporalPermission, timestamp: number = Date.now()): boolean => {
  const now = new Date(timestamp);
  
  // Check validity period
  if (permission.validFrom && now < permission.validFrom) {
    return false;
  }
  
  if (permission.validUntil && now > permission.validUntil) {
    return false;
  }
  
  // Check schedule if present
  if (permission.schedule) {
    return isScheduleActive(permission.schedule, now, permission.timezone);
  }
  
  return true;
};

/**
 * Check if schedule is currently active
 */
const isScheduleActive = (schedule: PermissionSchedule, date: Date, timezone?: string): boolean => {
  const targetDate = timezone ? new Date(date.toLocaleString('en-US', { timeZone: timezone })) : date;
  
  // Check exceptions
  if (schedule.exceptions?.some(exception => 
    exception.toDateString() === targetDate.toDateString()
  )) {
    return false;
  }
  
  // Check recurring patterns
  if (schedule.pattern === 'daily') {
    return checkTimeRanges(schedule.timeRanges, targetDate);
  } else if (schedule.pattern === 'weekly' && schedule.daysOfWeek) {
    const dayOfWeek = targetDate.getDay();
    if (!schedule.daysOfWeek.includes(dayOfWeek)) {
      return false;
    }
    return checkTimeRanges(schedule.timeRanges, targetDate);
  } else if (schedule.pattern === 'monthly' && schedule.daysOfMonth) {
    const dayOfMonth = targetDate.getDate();
    if (!schedule.daysOfMonth.includes(dayOfMonth)) {
      return false;
    }
    return checkTimeRanges(schedule.timeRanges, targetDate);
  }
  
  return true;
};

/**
 * Check if current time falls within allowed time ranges
 */
const checkTimeRanges = (timeRanges: PermissionSchedule['timeRanges'], date: Date): boolean => {
  if (!timeRanges || timeRanges.length === 0) {
    return true;
  }
  
  const currentTime = date.getHours() * 60 + date.getMinutes();
  
  return timeRanges.some(range => {
    const [startHour, startMin] = range.start.split(':').map(Number);
    const [endHour, endMin] = range.end.split(':').map(Number);
    
    const startTime = startHour * 60 + startMin;
    const endTime = endHour * 60 + endMin;
    
    return currentTime >= startTime && currentTime <= endTime;
  });
};

/**
 * Evaluate conditional permission
 */
const evaluateConditions = (conditions: PermissionCondition[], context: PermissionEvaluationContext, operator: 'AND' | 'OR'): boolean => {
  const results = conditions.map(condition => evaluateCondition(condition, context));
  
  return operator === 'AND' ? results.every(Boolean) : results.some(Boolean);
};

/**
 * Evaluate single condition
 */
const evaluateCondition = (condition: PermissionCondition, context: PermissionEvaluationContext): boolean => {
  const { field, operator, value, contextPath } = condition;
  
  // Extract field value from context
  const fieldValue = getNestedValue(context, contextPath ? `${contextPath}.${field}` : field);
  
  switch (operator) {
    case 'equals':
      return fieldValue === value;
    case 'not_equals':
      return fieldValue !== value;
    case 'contains':
      return Array.isArray(fieldValue) ? fieldValue.includes(value) : String(fieldValue).includes(String(value));
    case 'not_contains':
      return Array.isArray(fieldValue) ? !fieldValue.includes(value) : !String(fieldValue).includes(String(value));
    case 'greater_than':
      return Number(fieldValue) > Number(value);
    case 'less_than':
      return Number(fieldValue) < Number(value);
    case 'in':
      return Array.isArray(value) ? value.includes(fieldValue) : false;
    case 'not_in':
      return Array.isArray(value) ? !value.includes(fieldValue) : true;
    case 'exists':
      return fieldValue !== undefined && fieldValue !== null;
    case 'not_exists':
      return fieldValue === undefined || fieldValue === null;
    default:
      return false;
  }
};

/**
 * Get nested value from object using dot notation
 */
const getNestedValue = (obj: any, path: string): unknown => {
  return path.split('.').reduce((current, key) => current?.[key], obj);
};

// =============================================================================
// STORE IMPLEMENTATION
// =============================================================================

/**
 * Create the enhanced permissions store
 */
export const usePermissionsStore = create<PermissionsStore>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Base store implementation
        _initialized: Date.now(),
        _version: STORE_VERSION,
        _storeId: generateStoreId(),
        
        // Core permission data
        permissions: new Map(),
        roles: new Map(),
        userRoles: new Map(),
        userPermissions: new Map(),
        
        // Hierarchical structures
        permissionHierarchy: {},
        roleHierarchy: new Map(),
        
        // Async states
        fetchPermissionsState: { status: 'idle', data: null, error: null, loading: false },
        fetchRolesState: { status: 'idle', data: null, error: null, loading: false },
        fetchUserPermissionsState: { status: 'idle', data: null, error: null, loading: false },
        grantPermissionState: { status: 'idle', data: null, error: null, loading: false },
        revokePermissionState: { status: 'idle', data: null, error: null, loading: false },
        evaluatePermissionState: { status: 'idle', data: null, error: null, loading: false },
        
        // Evaluation cache
        evaluationCache: new Map(),
        cacheStats: {
          hits: 0,
          misses: 0,
          evictions: 0,
          totalEvaluations: 0,
          averageEvaluationTime: 0,
          cacheSize: 0,
          maxCacheSize: 1000,
        },
        
        // Audit logging
        auditLog: [],
        auditLogEnabled: true,
        maxAuditEntries: 10000,
        
        // Performance tracking
        evaluationStats: {
          totalEvaluations: 0,
          fastEvaluations: 0,
          slowEvaluations: 0,
          cachedEvaluations: 0,
          failedEvaluations: 0,
          averageEvaluationTime: 0,
          maxEvaluationTime: 0,
          evaluationsByPermission: new Map(),
          evaluationsByUser: new Map(),
        },
        slowEvaluationThreshold: 100, // milliseconds
        
        // Current context
        currentContext: {
          environment: {
            timestamp: Date.now(),
          },
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
            state.fetchPermissionsState.error = null;
            state.fetchRolesState.error = null;
            state.fetchUserPermissionsState.error = null;
            state.grantPermissionState.error = null;
            state.revokePermissionState.error = null;
            state.evaluatePermissionState.error = null;
          });
        },
        
        reset: () => {
          set((state) => {
            state.permissions = new Map();
            state.roles = new Map();
            state.userRoles = new Map();
            state.userPermissions = new Map();
            state.permissionHierarchy = {};
            state.roleHierarchy = new Map();
            state.evaluationCache = new Map();
            state.auditLog = [];
            state.isLoading = false;
            state.error = null;
            state.lastOperation = null;
          });
        },
        
        hasPendingOperations: () => {
          const state = get();
          return state.fetchPermissionsState.loading ||
                 state.fetchRolesState.loading ||
                 state.fetchUserPermissionsState.loading ||
                 state.grantPermissionState.loading ||
                 state.revokePermissionState.loading ||
                 state.evaluatePermissionState.loading;
        },
        
        isCacheValid: () => {
          const { lastCacheUpdate, cacheExpiry } = get();
          if (!lastCacheUpdate) return false;
          return Date.now() - lastCacheUpdate < cacheExpiry;
        },
        
        invalidateCache: () => {
          set((state) => {
            state.lastCacheUpdate = null;
            state.evaluationCache = new Map();
          });
        },
        
        refreshCache: async () => {
          await get().fetchPermissions();
          await get().fetchRoles();
        },
        
        // Core permission operations
        fetchPermissions: async () => {
          set((state) => {
            state.fetchPermissionsState = { status: 'loading', data: Array.from(state.permissions.values()), error: null, loading: true };
            state.isLoading = true;
            state.lastOperation = Date.now();
          });
          
          try {
            const permissions = await permissionsApi.fetchPermissions();
            
            set((state) => {
              state.permissions = new Map(permissions.map(p => [p.id, p]));
              state.fetchPermissionsState = { status: 'success', data: permissions, error: null, loading: false };
              state.isLoading = false;
              state.lastCacheUpdate = Date.now();
            });
            
            get().emit('permissions.fetched' as EventKey, { count: permissions.length });
            
            return permissions;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch permissions');
            
            set((state) => {
              state.fetchPermissionsState = { status: 'error', data: null, error: err, loading: false };
              state.isLoading = false;
              state.error = err;
            });
            
            throw err;
          }
        },
        
        fetchRoles: async () => {
          set((state) => {
            state.fetchRolesState = { status: 'loading', data: Array.from(state.roles.values()), error: null, loading: true };
          });
          
          try {
            const roles = await permissionsApi.fetchRoles();
            
            set((state) => {
              state.roles = new Map(roles.map(r => [r.id, r]));
              
              // Build role hierarchy
              const hierarchy = new Map<string, string[]>();
              roles.forEach(role => {
                if ('childRoles' in role) {
                  hierarchy.set(role.id, role.childRoles as string[]);
                }
              });
              state.roleHierarchy = hierarchy;
              
              state.fetchRolesState = { status: 'success', data: roles, error: null, loading: false };
            });
            
            return roles;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch roles');
            
            set((state) => {
              state.fetchRolesState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        fetchUserPermissions: async (userId: UserId) => {
          set((state) => {
            state.fetchUserPermissionsState = { status: 'loading', data: { userId, permissions: [] }, error: null, loading: true };
          });
          
          try {
            const permissions = await permissionsApi.fetchUserPermissions(userId);
            
            set((state) => {
              state.userPermissions.set(userId, permissions);
              state.fetchUserPermissionsState = { status: 'success', data: { userId, permissions }, error: null, loading: false };
            });
            
            return permissions;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to fetch user permissions');
            
            set((state) => {
              state.fetchUserPermissionsState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        // Permission evaluation
        hasPermission: async (permission: AdvancedPermissionKey, context?: Partial<PermissionEvaluationContext>) => {
          const result = await get().checkPermission({
            permission,
            context,
            options: {
              useCache: true,
              includeReason: false,
              auditLog: false,
              timeout: 5000,
              fallbackToDefault: true,
            },
          });
          
          return result.allowed;
        },
        
        checkPermission: async (request: PermissionCheckRequest) => {
          const startTime = Date.now();
          const { permission, context = {}, options = {} } = request;
          
          // Merge with current context
          const evaluationContext: PermissionEvaluationContext = {
            user: context.user || { id: createUserId('unknown'), roles: [], attributes: {}, groups: [] },
            resource: context.resource,
            environment: { ...get().currentContext.environment, ...context.environment, timestamp: Date.now() },
            request: context.request,
          };
          
          // Check cache first
          const cacheKey = createCacheKey(permission, context);
          if (options.useCache !== false) {
            const cached = get().evaluationCache.get(cacheKey);
            if (cached && (Date.now() - cached.timestamp) < cached.ttl) {
              set((state) => {
                state.cacheStats.hits += 1;
                state.evaluationStats.cachedEvaluations += 1;
              });
              
              return {
                ...cached.result,
                cached: true,
                evaluationTime: Date.now() - startTime,
              };
            }
          }
          
          set((state) => {
            state.evaluatePermissionState = { status: 'loading', data: null, error: null, loading: true };
            state.cacheStats.misses += 1;
          });
          
          try {
            // Find matching permissions
            const matchingPermissions = Array.from(get().permissions.values()).filter(p => p.key === permission);
            
            if (matchingPermissions.length === 0) {
              const result: PermissionEvaluationResult = {
                allowed: false,
                reason: 'Permission not found',
                matchedPermissions: [],
                failedConditions: ['Permission does not exist'],
                evaluationTime: Date.now() - startTime,
                cached: false,
                context: evaluationContext,
              };
              
              get().logAuditEntry('check', permission, 'denied', result.reason, evaluationContext);
              
              return result;
            }
            
            // Evaluate each matching permission
            let allowed = false;
            const matchedPermissions: PermissionId[] = [];
            const failedConditions: string[] = [];
            
            for (const perm of matchingPermissions) {
              const permissionAllowed = await get().evaluatePermission(perm, evaluationContext);
              
              if (permissionAllowed) {
                allowed = true;
                matchedPermissions.push(perm.id);
              } else {
                failedConditions.push(`Permission ${perm.id} evaluation failed`);
              }
            }
            
            const evaluationTime = Date.now() - startTime;
            
            const result: PermissionEvaluationResult = {
              allowed,
              reason: allowed ? 'Permission granted' : 'Permission denied',
              matchedPermissions,
              failedConditions,
              evaluationTime,
              cached: false,
              context: evaluationContext,
            };
            
            // Cache the result
            if (options.useCache !== false) {
              const cachedResult: CachedPermissionResult = {
                key: cacheKey,
                result,
                timestamp: Date.now(),
                ttl: 5 * 60 * 1000, // 5 minutes
                hitCount: 0,
              };
              
              set((state) => {
                state.evaluationCache.set(cacheKey, cachedResult);
                state.cacheStats.cacheSize = state.evaluationCache.size;
              });
            }
            
            // Update statistics
            set((state) => {
              state.evaluationStats.totalEvaluations += 1;
              if (evaluationTime < state.slowEvaluationThreshold) {
                state.evaluationStats.fastEvaluations += 1;
              } else {
                state.evaluationStats.slowEvaluations += 1;
              }
              
              state.evaluationStats.averageEvaluationTime = 
                (state.evaluationStats.averageEvaluationTime * (state.evaluationStats.totalEvaluations - 1) + evaluationTime) / 
                state.evaluationStats.totalEvaluations;
              
              if (evaluationTime > state.evaluationStats.maxEvaluationTime) {
                state.evaluationStats.maxEvaluationTime = evaluationTime;
              }
              
              // Update permission-specific stats
              const permissionCount = state.evaluationStats.evaluationsByPermission.get(permission) || 0;
              state.evaluationStats.evaluationsByPermission.set(permission, permissionCount + 1);
              
              // Update user-specific stats
              const userCount = state.evaluationStats.evaluationsByUser.get(evaluationContext.user.id) || 0;
              state.evaluationStats.evaluationsByUser.set(evaluationContext.user.id, userCount + 1);
              
              state.evaluatePermissionState = { status: 'success', data: result, error: null, loading: false };
            });
            
            // Audit logging
            if (options.auditLog !== false && get().auditLogEnabled) {
              get().logAuditEntry('check', permission, allowed ? 'granted' : 'denied', result.reason, evaluationContext);
            }
            
            return result;
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Permission evaluation failed');
            const evaluationTime = Date.now() - startTime;
            
            set((state) => {
              state.evaluatePermissionState = { status: 'error', data: null, error: err, loading: false };
              state.evaluationStats.failedEvaluations += 1;
            });
            
            const result: PermissionEvaluationResult = {
              allowed: false,
              reason: err.message,
              matchedPermissions: [],
              failedConditions: [err.message],
              evaluationTime,
              cached: false,
              context: evaluationContext,
            };
            
            get().logAuditEntry('check', permission, 'error', err.message, evaluationContext);
            
            return result;
          }
        },
        
        evaluatePermission: async (permission: Permission, context: PermissionEvaluationContext) => {
          switch (permission.type) {
            case 'conditional':
              return evaluateConditions(permission.conditions, context, permission.operator);
              
            case 'temporal':
              return isTemporalPermissionActive(permission, context.environment.timestamp);
              
            case 'resource':
              // Check if user has permission for this specific resource
              if (permission.resourceId && context.resource) {
                return permission.resourceId === context.resource.id;
              }
              return true; // Allow if no specific resource restriction
              
            case 'dynamic':
              // Dynamic permissions would use their evaluator function
              return await permission.evaluator(context);
              
            default:
              return true; // Default allow for base permissions
          }
        },
        
        // Bulk operations
        hasPermissions: async (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => {
          const results = await Promise.all(
            permissions.map(permission => get().hasPermission(permission, context))
          );
          return results;
        },
        
        hasAnyPermission: async (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => {
          const results = await get().hasPermissions(permissions, context);
          return results.some(Boolean);
        },
        
        hasAllPermissions: async (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => {
          const results = await get().hasPermissions(permissions, context);
          return results.every(Boolean);
        },
        
        checkPermissions: async (requests: PermissionCheckRequest[]) => {
          return Promise.all(requests.map(request => get().checkPermission(request)));
        },
        
        // Role management
        createRole: async (role: Omit<Role, 'id' | 'createdAt' | 'updatedAt'>) => {
          const id = `role_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
          const newRole: Role = {
            ...role,
            id,
            createdAt: Date.now(),
            updatedAt: Date.now(),
          } as Role;
          
          set((state) => {
            state.roles.set(id, newRole);
          });
          
          return id;
        },
        
        updateRole: async (id: string, updates: Partial<Role>) => {
          set((state) => {
            const role = state.roles.get(id);
            if (role) {
              state.roles.set(id, { ...role, ...updates, updatedAt: Date.now() });
            }
          });
        },
        
        deleteRole: async (id: string) => {
          set((state) => {
            state.roles.delete(id);
            
            // Remove role from user assignments
            state.userRoles.forEach((roles, userId) => {
              const filteredRoles = roles.filter(roleId => roleId !== id);
              if (filteredRoles.length !== roles.length) {
                state.userRoles.set(userId, filteredRoles);
              }
            });
          });
        },
        
        assignRole: async (userId: UserId, roleId: string) => {
          set((state) => {
            const currentRoles = state.userRoles.get(userId) || [];
            if (!currentRoles.includes(roleId)) {
              state.userRoles.set(userId, [...currentRoles, roleId]);
            }
          });
        },
        
        unassignRole: async (userId: UserId, roleId: string) => {
          set((state) => {
            const currentRoles = state.userRoles.get(userId) || [];
            const filteredRoles = currentRoles.filter(id => id !== roleId);
            state.userRoles.set(userId, filteredRoles);
          });
        },
        
        // Permission granting/revoking
        grantPermission: async (userId: UserId, permissionId: PermissionId, context?: PermissionContext) => {
          set((state) => {
            state.grantPermissionState = { status: 'loading', data: { userId, permissionId }, error: null, loading: true };
          });
          
          try {
            await permissionsApi.grantPermission(userId, permissionId);
            
            set((state) => {
              const currentPermissions = state.userPermissions.get(userId) || [];
              if (!currentPermissions.includes(permissionId)) {
                state.userPermissions.set(userId, [...currentPermissions, permissionId]);
              }
              
              state.grantPermissionState = { status: 'success', data: { userId, permissionId }, error: null, loading: false };
            });
            
            get().logAuditEntry('grant', permissionId.toString() as AdvancedPermissionKey, 'granted', 'Permission granted to user', { user: { id: userId, roles: [], attributes: {}, groups: [] } } as any);
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to grant permission');
            
            set((state) => {
              state.grantPermissionState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        revokePermission: async (userId: UserId, permissionId: PermissionId, context?: PermissionContext) => {
          set((state) => {
            state.revokePermissionState = { status: 'loading', data: { userId, permissionId }, error: null, loading: true };
          });
          
          try {
            await permissionsApi.revokePermission(userId, permissionId);
            
            set((state) => {
              const currentPermissions = state.userPermissions.get(userId) || [];
              const filteredPermissions = currentPermissions.filter(id => id !== permissionId);
              state.userPermissions.set(userId, filteredPermissions);
              
              state.revokePermissionState = { status: 'success', data: { userId, permissionId }, error: null, loading: false };
            });
            
            get().logAuditEntry('revoke', permissionId.toString() as AdvancedPermissionKey, 'granted', 'Permission revoked from user', { user: { id: userId, roles: [], attributes: {}, groups: [] } } as any);
          } catch (error) {
            const err = error instanceof Error ? error : new Error('Failed to revoke permission');
            
            set((state) => {
              state.revokePermissionState = { status: 'error', data: null, error: err, loading: false };
            });
            
            throw err;
          }
        },
        
        grantPermissions: async (userId: UserId, permissionIds: PermissionId[], context?: PermissionContext) => {
          await Promise.all(permissionIds.map(id => get().grantPermission(userId, id, context)));
        },
        
        revokePermissions: async (userId: UserId, permissionIds: PermissionId[], context?: PermissionContext) => {
          await Promise.all(permissionIds.map(id => get().revokePermission(userId, id, context)));
        },
        
        // Query methods
        getUserRoles: (userId: UserId) => {
          return get().userRoles.get(userId) || [];
        },
        
        getRolePermissions: (roleId: string) => {
          const role = get().roles.get(roleId);
          return role ? role.permissions : [];
        },
        
        getEffectivePermissions: async (userId: UserId) => {
          const userRoles = get().getUserRoles(userId);
          const directPermissions = get().userPermissions.get(userId) || [];
          
          const rolePermissions: PermissionId[] = [];
          userRoles.forEach(roleId => {
            const permissions = get().getRolePermissions(roleId);
            rolePermissions.push(...permissions);
          });
          
          // Combine and deduplicate
          const allPermissions = [...new Set([...directPermissions, ...rolePermissions])];
          return allPermissions;
        },
        
        getRoleHierarchy: (roleId: string) => {
          return get().roleHierarchy.get(roleId) || [];
        },
        
        // Temporal permission handling
        checkTemporalPermission: (permission: TemporalPermission, context: PermissionEvaluationContext) => {
          return isTemporalPermissionActive(permission, context.environment.timestamp);
        },
        
        getActiveTemporalPermissions: (userId: UserId, timestamp = Date.now()) => {
          const userPermissions = get().userPermissions.get(userId) || [];
          const activePermissions: PermissionId[] = [];
          
          userPermissions.forEach(permissionId => {
            const permission = get().permissions.get(permissionId);
            if (permission && get().isTemporalPermission(permission)) {
              if (isTemporalPermissionActive(permission, timestamp)) {
                activePermissions.push(permissionId);
              }
            }
          });
          
          return activePermissions;
        },
        
        schedulePermissionExpiry: async (permissionId: PermissionId, expiryDate: Date) => {
          // In real implementation, would schedule background job
          setTimeout(() => {
            // Auto-revoke permission logic would go here
            console.log(`Permission ${permissionId} expired at ${expiryDate}`);
          }, expiryDate.getTime() - Date.now());
        },
        
        // Context-aware methods
        hasPermissionInContext: async <T extends PermissionScope>(
          permission: AdvancedPermissionKey,
          context: PermissionContext<T>
        ) => {
          return get().hasPermission(permission, { 
            environment: { ...get().currentContext.environment },
            // Context would be properly mapped based on scope
          });
        },
        
        getPermissionsForResource: async (resourceType: PermissionResourceType, resourceId: string) => {
          const permissions = Array.from(get().permissions.values())
            .filter(p => 
              get().isResourcePermission(p) && 
              p.resourceType === resourceType && 
              (!p.resourceId || p.resourceId === resourceId)
            )
            .map(p => p.key);
          
          return permissions;
        },
        
        getUserPermissionsInContext: async (userId: UserId, context: PermissionContext) => {
          const userPermissions = await get().getEffectivePermissions(userId);
          const contextPermissions: AdvancedPermissionKey[] = [];
          
          for (const permissionId of userPermissions) {
            const permission = get().permissions.get(permissionId);
            if (permission) {
              // Check if permission applies to this context
              const evaluationContext: PermissionEvaluationContext = {
                user: { id: userId, roles: get().getUserRoles(userId), attributes: {}, groups: [] },
                environment: { timestamp: Date.now() },
              };
              
              const allowed = await get().evaluatePermission(permission, evaluationContext);
              if (allowed) {
                contextPermissions.push(permission.key);
              }
            }
          }
          
          return contextPermissions;
        },
        
        // Cache management
        clearPermissionCache: (pattern?: string) => {
          set((state) => {
            if (pattern) {
              // Clear cache entries matching pattern
              const keysToDelete: string[] = [];
              state.evaluationCache.forEach((_, key) => {
                if (key.includes(pattern)) {
                  keysToDelete.push(key);
                }
              });
              keysToDelete.forEach(key => state.evaluationCache.delete(key));
            } else {
              state.evaluationCache.clear();
            }
            
            state.cacheStats.cacheSize = state.evaluationCache.size;
          });
        },
        
        refreshPermissionCache: async () => {
          get().clearPermissionCache();
          await get().refreshCache();
        },
        
        getCacheStats: () => {
          return get().cacheStats;
        },
        
        optimizeCache: async () => {
          const cache = get().evaluationCache;
          const now = Date.now();
          let evicted = 0;
          
          // Remove expired entries
          cache.forEach((entry, key) => {
            if ((now - entry.timestamp) > entry.ttl) {
              cache.delete(key);
              evicted++;
            }
          });
          
          set((state) => {
            state.cacheStats.evictions += evicted;
            state.cacheStats.cacheSize = cache.size;
          });
        },
        
        // Audit logging
        logAuditEntry: (
          action: PermissionAuditEntry['action'],
          permission: AdvancedPermissionKey,
          result: PermissionAuditEntry['result'],
          reason: string,
          context: Partial<PermissionEvaluationContext>
        ) => {
          if (!get().auditLogEnabled) return;
          
          const entry: PermissionAuditEntry = {
            id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: Date.now(),
            userId: context.user?.id || createUserId('unknown'),
            sessionId: context.environment?.sessionId,
            action,
            permission,
            resource: context.resource ? {
              type: context.resource.type,
              id: context.resource.id,
            } : undefined,
            result,
            reason,
            context,
          };
          
          set((state) => {
            state.auditLog = [entry, ...state.auditLog].slice(0, state.maxAuditEntries);
          });
        },
        
        getAuditLog: (filter?: PermissionAuditFilter) => {
          let log = get().auditLog;
          
          if (filter) {
            log = log.filter(entry => {
              if (filter.startDate && new Date(entry.timestamp) < filter.startDate) return false;
              if (filter.endDate && new Date(entry.timestamp) > filter.endDate) return false;
              if (filter.userId && entry.userId !== filter.userId) return false;
              if (filter.actions && !filter.actions.includes(entry.action)) return false;
              if (filter.permissions && !filter.permissions.includes(entry.permission)) return false;
              if (filter.results && !filter.results.includes(entry.result)) return false;
              if (filter.resourceTypes && entry.resource && !filter.resourceTypes.includes(entry.resource.type)) return false;
              
              return true;
            });
          }
          
          return log;
        },
        
        clearAuditLog: () => {
          set((state) => {
            state.auditLog = [];
          });
        },
        
        exportAuditLog: async (filter?: PermissionAuditFilter) => {
          const log = get().getAuditLog(filter);
          const csv = [
            'Timestamp,User ID,Action,Permission,Resource Type,Resource ID,Result,Reason',
            ...log.map(entry => [
              new Date(entry.timestamp).toISOString(),
              entry.userId,
              entry.action,
              entry.permission,
              entry.resource?.type || '',
              entry.resource?.id || '',
              entry.result,
              entry.reason.replace(/,/g, ';'), // Escape commas
            ].join(','))
          ].join('\n');
          
          return new Blob([csv], { type: 'text/csv' });
        },
        
        toggleAuditLogging: (enabled: boolean) => {
          set((state) => {
            state.auditLogEnabled = enabled;
          });
        },
        
        // Context management
        setEvaluationContext: (context: Partial<PermissionEvaluationContext>) => {
          set((state) => {
            state.currentContext = context;
          });
        },
        
        updateEvaluationContext: (updates: Partial<PermissionEvaluationContext>) => {
          set((state) => {
            state.currentContext = { ...state.currentContext, ...updates };
          });
        },
        
        clearEvaluationContext: () => {
          set((state) => {
            state.currentContext = {
              environment: {
                timestamp: Date.now(),
              },
            };
          });
        },
        
        // Utility methods
        createPermission: async (permission: Omit<Permission, 'id' | 'createdAt' | 'updatedAt'>) => {
          const id = createPermissionId(`perm_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`);
          const newPermission: Permission = {
            ...permission,
            id,
            createdAt: Date.now(),
            updatedAt: Date.now(),
          } as Permission;
          
          set((state) => {
            state.permissions.set(id, newPermission);
          });
          
          return id;
        },
        
        updatePermission: async (id: PermissionId, updates: Partial<Permission>) => {
          set((state) => {
            const permission = state.permissions.get(id);
            if (permission) {
              state.permissions.set(id, { ...permission, ...updates, updatedAt: Date.now() } as Permission);
            }
          });
        },
        
        deletePermission: async (id: PermissionId) => {
          set((state) => {
            state.permissions.delete(id);
            
            // Remove from user permissions
            state.userPermissions.forEach((permissions, userId) => {
              const filteredPermissions = permissions.filter(permId => permId !== id);
              if (filteredPermissions.length !== permissions.length) {
                state.userPermissions.set(userId, filteredPermissions);
              }
            });
            
            // Remove from roles
            state.roles.forEach((role, roleId) => {
              const filteredPermissions = role.permissions.filter(permId => permId !== id);
              if (filteredPermissions.length !== role.permissions.length) {
                const updatedRole = { ...role, permissions: filteredPermissions, updatedAt: Date.now() };
                state.roles.set(roleId, updatedRole as Role);
              }
            });
          });
        },
        
        getPermissionsByCategory: (category: string) => {
          return Array.from(get().permissions.values()).filter(p => p.category === category);
        },
        
        getPermissionsByScope: (scope: PermissionScope) => {
          return Array.from(get().permissions.values()).filter(p => p.scope === scope);
        },
        
        searchPermissions: (query: string) => {
          const lowerQuery = query.toLowerCase();
          return Array.from(get().permissions.values()).filter(p => 
            p.name.toLowerCase().includes(lowerQuery) ||
            p.description.toLowerCase().includes(lowerQuery) ||
            p.key.toLowerCase().includes(lowerQuery)
          );
        },
        
        validatePermissionKey: (key: string): key is AdvancedPermissionKey => {
          // Simple validation - in real implementation would be more sophisticated
          return key.includes('.') && key.split('.').length >= 2;
        },
        
        getPermissionStats: () => {
          return get().evaluationStats;
        },
        
        // Type guards and assertions
        assertPermissionExists: (id: PermissionId) => {
          if (!get().permissions.has(id)) {
            throw new Error(`Permission ${id} does not exist`);
          }
        },
        
        assertUserHasPermission: async (userId: UserId, permission: AdvancedPermissionKey) => {
          const hasPermission = await get().hasPermission(permission, {
            user: { id: userId, roles: get().getUserRoles(userId), attributes: {}, groups: [] }
          });
          
          if (!hasPermission) {
            throw new Error(`User ${userId} does not have permission ${permission}`);
          }
        },
        
        isTemporalPermission: (permission: Permission): permission is TemporalPermission => {
          return permission.type === 'temporal';
        },
        
        isConditionalPermission: (permission: Permission): permission is ConditionalPermission => {
          return permission.type === 'conditional';
        },
        
        isResourcePermission: (permission: Permission): permission is ResourcePermission => {
          return permission.type === 'resource';
        },
        
        isDynamicPermission: (permission: Permission): permission is DynamicPermission => {
          return permission.type === 'dynamic';
        },
      })),
      {
        name: 'permissions-storage',
        partialize: (state) => ({
          // Persist core data structures (serializable maps converted to arrays)
          permissions: Array.from(state.permissions.entries()),
          roles: Array.from(state.roles.entries()),
          userRoles: Array.from(state.userRoles.entries()),
          userPermissions: Array.from(state.userPermissions.entries()),
          roleHierarchy: Array.from(state.roleHierarchy.entries()),
          auditLogEnabled: state.auditLogEnabled,
          maxAuditEntries: state.maxAuditEntries,
          currentContext: state.currentContext,
        }),
        onRehydrateStorage: () => (state) => {
          if (state) {
            // Convert arrays back to Maps
            if (Array.isArray(state.permissions)) {
              state.permissions = new Map(state.permissions as any);
            }
            if (Array.isArray(state.roles)) {
              state.roles = new Map(state.roles as any);
            }
            if (Array.isArray(state.userRoles)) {
              state.userRoles = new Map(state.userRoles as any);
            }
            if (Array.isArray(state.userPermissions)) {
              state.userPermissions = new Map(state.userPermissions as any);
            }
            if (Array.isArray(state.roleHierarchy)) {
              state.roleHierarchy = new Map(state.roleHierarchy as any);
            }
          }
        },
      }
    ),
    {
      name: 'permissions-store',
    }
  )
);

// =============================================================================
// PERFORMANCE-OPTIMIZED SELECTORS
// =============================================================================

export const usePermissions = () => usePermissionsStore((state) => Array.from(state.permissions.values()));
export const useRoles = () => usePermissionsStore((state) => Array.from(state.roles.values()));
export const useUserRoles = (userId: UserId) => usePermissionsStore((state) => state.userRoles.get(userId) || []);
export const useUserPermissions = (userId: UserId) => usePermissionsStore((state) => state.userPermissions.get(userId) || []);

export const usePermissionsByCategory = (category: string) => 
  usePermissionsStore((state) => state.getPermissionsByCategory(category));

export const usePermissionsByScope = (scope: PermissionScope) => 
  usePermissionsStore((state) => state.getPermissionsByScope(scope));

export const usePermissionStates = () => usePermissionsStore((state) => ({
  fetchPermissionsState: state.fetchPermissionsState,
  fetchRolesState: state.fetchRolesState,
  fetchUserPermissionsState: state.fetchUserPermissionsState,
  grantPermissionState: state.grantPermissionState,
  revokePermissionState: state.revokePermissionState,
  evaluatePermissionState: state.evaluatePermissionState,
}));

export const usePermissionCache = () => usePermissionsStore((state) => ({
  cacheStats: state.cacheStats,
  evaluationStats: state.evaluationStats,
}));

export const useAuditLog = (filter?: PermissionAuditFilter) => 
  usePermissionsStore((state) => state.getAuditLog(filter));

// Action selectors
export const usePermissionActions = () => usePermissionsStore((state) => ({
  fetchPermissions: state.fetchPermissions,
  fetchRoles: state.fetchRoles,
  fetchUserPermissions: state.fetchUserPermissions,
  hasPermission: state.hasPermission,
  checkPermission: state.checkPermission,
  checkPermissions: state.checkPermissions,
  hasPermissions: state.hasPermissions,
  hasAnyPermission: state.hasAnyPermission,
  hasAllPermissions: state.hasAllPermissions,
  grantPermission: state.grantPermission,
  revokePermission: state.revokePermission,
  grantPermissions: state.grantPermissions,
  revokePermissions: state.revokePermissions,
  assignRole: state.assignRole,
  unassignRole: state.unassignRole,
  createRole: state.createRole,
  updateRole: state.updateRole,
  deleteRole: state.deleteRole,
  clearPermissionCache: state.clearPermissionCache,
  refreshPermissionCache: state.refreshPermissionCache,
}));

// Composite hooks
export const usePermissionsWithActions = () => {
  const permissions = usePermissions();
  const actions = usePermissionActions();
  const states = usePermissionStates();
  
  return {
    permissions,
    ...actions,
    ...states,
  };
};

// Type-safe permission hooks
export const useHasPermission = (permission: AdvancedPermissionKey, context?: Partial<PermissionEvaluationContext>) => {
  const [hasPermission, setHasPermission] = React.useState<boolean | null>(null);
  const checkPermission = usePermissionsStore((state) => state.hasPermission);
  
  React.useEffect(() => {
    checkPermission(permission, context).then(setHasPermission);
  }, [permission, context, checkPermission]);
  
  return hasPermission;
};

// Hook for checking multiple permissions
export const useHasPermissions = (permissions: AdvancedPermissionKey[], context?: Partial<PermissionEvaluationContext>) => {
  const [permissionResults, setPermissionResults] = React.useState<boolean[] | null>(null);
  const checkPermissions = usePermissionsStore((state) => state.hasPermissions);
  
  React.useEffect(() => {
    checkPermissions(permissions, context).then(setPermissionResults);
  }, [permissions, context, checkPermissions]);
  
  return permissionResults;
};

// Role-based hooks
export const useUserRole = (userId: UserId, roleId: string) => {
  const userRoles = useUserRoles(userId);
  return userRoles.includes(roleId);
};

export const useEffectivePermissions = (userId: UserId) => {
  const [effectivePermissions, setEffectivePermissions] = React.useState<ReadonlyArray<PermissionId>>([]);
  const getEffectivePermissions = usePermissionsStore((state) => state.getEffectivePermissions);
  
  React.useEffect(() => {
    getEffectivePermissions(userId).then(setEffectivePermissions);
  }, [userId, getEffectivePermissions]);
  
  return effectivePermissions;
};

// Utility hooks
export const usePermissionUtils = () => usePermissionsStore((state) => ({
  validatePermissionKey: state.validatePermissionKey,
  searchPermissions: state.searchPermissions,
  getPermissionStats: state.getPermissionStats,
  isTemporalPermission: state.isTemporalPermission,
  isConditionalPermission: state.isConditionalPermission,
  isResourcePermission: state.isResourcePermission,
  isDynamicPermission: state.isDynamicPermission,
}));