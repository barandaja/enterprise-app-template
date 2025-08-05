/**
 * @fileoverview Permissions API Service
 * 
 * Enterprise-grade permissions service providing:
 * - RBAC operations with type-safe permission keys
 * - Role management with hierarchical structures
 * - Permission checking with context awareness
 * - Audit logging for permission changes
 * - Policy-based access control (PBAC)
 * - Permission caching and optimization
 * - Real-time permission updates
 * - Bulk operations for enterprise scalability
 */

import { z } from 'zod';
import { apiClient } from './client';
import type {
  ApiResponse,
  ApiRequestConfig,
  PaginatedResponse,
  EnhancedApiRequestConfig,
  Permission,
  Role,
  UserRoleAssignment,
  PermissionCheckRequest,
  PermissionCheckResult,
  PermissionAuditLog,
  PermissionResource,
  PermissionAction,
  PermissionScope,
} from './types';

// =============================================================================
// Well-Known Permissions System
// =============================================================================

/**
 * Well-known permission resources
 */
export const RESOURCES = {
  USER: 'user' as const,
  ROLE: 'role' as const,
  PERMISSION: 'permission' as const,
  NOTIFICATION: 'notification' as const,
  PREFERENCE: 'preference' as const,
  AUDIT: 'audit' as const,
  SYSTEM: 'system' as const,
  ORGANIZATION: 'organization' as const,
  TEAM: 'team' as const,
  PROJECT: 'project' as const,
  DOCUMENT: 'document' as const,
  REPORT: 'report' as const,
} as const;

/**
 * Well-known permission actions
 */
export const ACTIONS = {
  CREATE: 'create' as const,
  READ: 'read' as const,
  UPDATE: 'update' as const,
  DELETE: 'delete' as const,
  LIST: 'list' as const,
  EXECUTE: 'execute' as const,
  MANAGE: 'manage' as const,
  APPROVE: 'approve' as const,
  PUBLISH: 'publish' as const,
  EXPORT: 'export' as const,
  IMPORT: 'import' as const,
  SHARE: 'share' as const,
} as const;

/**
 * Common permission combinations
 */
export const PERMISSION_SETS = {
  // Basic CRUD
  FULL_ACCESS: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.DELETE, ACTIONS.LIST] as const,
  READ_ONLY: [ACTIONS.READ, ACTIONS.LIST] as const,
  EDITOR: [ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.LIST] as const,
  CREATOR: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.LIST] as const,
  
  // Administrative
  ADMIN: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.DELETE, ACTIONS.LIST, ACTIONS.MANAGE] as const,
  MODERATOR: [ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.LIST, ACTIONS.APPROVE] as const,
  
  // Content management
  PUBLISHER: [ACTIONS.CREATE, ACTIONS.READ, ACTIONS.UPDATE, ACTIONS.PUBLISH, ACTIONS.LIST] as const,
  REVIEWER: [ACTIONS.READ, ACTIONS.APPROVE, ACTIONS.LIST] as const,
} as const;

/**
 * System roles with predefined permissions
 */
export const SYSTEM_ROLES = {
  SUPER_ADMIN: 'system.super_admin' as const,
  ADMIN: 'system.admin' as const,
  MODERATOR: 'system.moderator' as const,
  USER: 'system.user' as const,
  GUEST: 'system.guest' as const,
} as const;

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Permission scope validation schema
 */
const permissionScopeSchema = z.object({
  type: z.enum(['global', 'organization', 'team', 'user', 'resource']),
  value: z.string().optional(),
  conditions: z.record(z.unknown()).optional(),
});

/**
 * Permission creation schema
 */
export const createPermissionSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(500).optional(),
  resource: z.string().min(1).max(100),
  action: z.string().min(1).max(100),
  scope: permissionScopeSchema,
  conditions: z.record(z.unknown()).optional(),
});

/**
 * Role creation schema
 */
export const createRoleSchema = z.object({
  name: z.string().min(1).max(255),
  description: z.string().max(500).optional(),
  permissions: z.array(z.string()).default([]), // Permission IDs
  parentRoleId: z.string().optional(),
  metadata: z.object({
    level: z.number().int().min(0).default(0),
    priority: z.number().int().min(0).default(0),
    tags: z.array(z.string()).default([]),
  }).default({}),
});

/**
 * Role assignment schema
 */
export const assignRoleSchema = z.object({
  userId: z.string().min(1),
  roleId: z.string().min(1),
  scope: permissionScopeSchema.optional(),
  expiresAt: z.string().datetime().optional(),
});

/**
 * Permission check schema
 */
export const permissionCheckSchema = z.object({
  userId: z.string().min(1),
  resource: z.string().min(1),
  action: z.string().min(1),
  scope: permissionScopeSchema.optional(),
  context: z.record(z.unknown()).optional(),
});

/**
 * Bulk permission check schema
 */
export const bulkPermissionCheckSchema = z.object({
  userId: z.string().min(1),
  checks: z.array(z.object({
    resource: z.string().min(1),
    action: z.string().min(1),
    scope: permissionScopeSchema.optional(),
    context: z.record(z.unknown()).optional(),
  })),
});

// =============================================================================
// Permission Policy Engine
// =============================================================================

/**
 * Policy condition evaluator
 */
interface PolicyCondition {
  field: string;
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte' | 'in' | 'not_in' | 'contains' | 'starts_with' | 'ends_with';
  value: unknown;
}

/**
 * Policy rule definition
 */
interface PolicyRule {
  id: string;
  name: string;
  description?: string;
  resource: PermissionResource;
  action: PermissionAction;
  effect: 'allow' | 'deny';
  conditions: PolicyCondition[];
  priority: number;
}

/**
 * Policy evaluation context
 */
interface PolicyContext {
  user: {
    id: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  resource: {
    type: PermissionResource;
    id?: string;
    attributes: Record<string, unknown>;
  };
  environment: {
    time: string;
    ipAddress?: string;
    userAgent?: string;
    location?: string;
  };
  request: {
    action: PermissionAction;
    parameters: Record<string, unknown>;
  };
}

/**
 * Policy evaluation result
 */
interface PolicyEvaluationResult {
  decision: 'allow' | 'deny' | 'not_applicable';
  matchedRules: PolicyRule[];
  reason: string;
  metadata: Record<string, unknown>;
}

/**
 * Client-side policy evaluator (for caching and quick checks)
 */
class PolicyEvaluator {
  private rules: PolicyRule[] = [];

  /**
   * Load policy rules
   */
  loadRules(rules: PolicyRule[]): void {
    this.rules = rules.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Evaluate permission request against policies
   */
  evaluate(context: PolicyContext): PolicyEvaluationResult {
    const matchedRules: PolicyRule[] = [];
    
    for (const rule of this.rules) {
      if (this.matchesRule(rule, context)) {
        matchedRules.push(rule);
        
        // First matching rule determines the decision
        return {
          decision: rule.effect,
          matchedRules: [rule],
          reason: `Matched rule: ${rule.name}`,
          metadata: { ruleId: rule.id, priority: rule.priority },
        };
      }
    }

    return {
      decision: 'not_applicable',
      matchedRules: [],
      reason: 'No matching policy rules found',
      metadata: {},
    };
  }

  /**
   * Check if a rule matches the context
   */
  private matchesRule(rule: PolicyRule, context: PolicyContext): boolean {
    // Check resource and action match
    if (rule.resource !== context.resource.type || rule.action !== context.request.action) {
      return false;
    }

    // Evaluate conditions
    return rule.conditions.every(condition => this.evaluateCondition(condition, context));
  }

  /**
   * Evaluate a single condition
   */
  private evaluateCondition(condition: PolicyCondition, context: PolicyContext): boolean {
    const fieldValue = this.getFieldValue(condition.field, context);
    
    switch (condition.operator) {
      case 'eq':
        return fieldValue === condition.value;
      case 'ne':
        return fieldValue !== condition.value;
      case 'gt':
        return typeof fieldValue === 'number' && typeof condition.value === 'number' && fieldValue > condition.value;
      case 'gte':
        return typeof fieldValue === 'number' && typeof condition.value === 'number' && fieldValue >= condition.value;
      case 'lt':
        return typeof fieldValue === 'number' && typeof condition.value === 'number' && fieldValue < condition.value;
      case 'lte':
        return typeof fieldValue === 'number' && typeof condition.value === 'number' && fieldValue <= condition.value;
      case 'in':
        return Array.isArray(condition.value) && condition.value.includes(fieldValue);
      case 'not_in':
        return Array.isArray(condition.value) && !condition.value.includes(fieldValue);
      case 'contains':
        return typeof fieldValue === 'string' && typeof condition.value === 'string' && fieldValue.includes(condition.value);
      case 'starts_with':
        return typeof fieldValue === 'string' && typeof condition.value === 'string' && fieldValue.startsWith(condition.value);
      case 'ends_with':
        return typeof fieldValue === 'string' && typeof condition.value === 'string' && fieldValue.endsWith(condition.value);
      default:
        return false;
    }
  }

  /**
   * Get field value from context using dot notation
   */
  private getFieldValue(field: string, context: PolicyContext): unknown {
    const parts = field.split('.');
    let value: any = context;
    
    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }
    
    return value;
  }
}

// =============================================================================
// Permission Cache Manager
// =============================================================================

/**
 * Permission cache entry
 */
interface PermissionCacheEntry {
  result: PermissionCheckResult;
  timestamp: number;
  ttl: number;
}

/**
 * Permission cache manager with intelligent invalidation
 */
class PermissionCache {
  private cache = new Map<string, PermissionCacheEntry>();
  private userRoleCache = new Map<string, { roles: string[]; timestamp: number }>();
  private defaultTTL = 300000; // 5 minutes
  private roleTTL = 600000; // 10 minutes

  /**
   * Get cached permission result
   */
  get(userId: string, resource: string, action: string, scope?: PermissionScope): PermissionCheckResult | null {
    const key = this.generateKey(userId, resource, action, scope);
    const entry = this.cache.get(key);
    
    if (entry && Date.now() - entry.timestamp < entry.ttl) {
      return entry.result;
    }
    
    // Remove expired entry
    if (entry) {
      this.cache.delete(key);
    }
    
    return null;
  }

  /**
   * Set cached permission result
   */
  set(
    userId: string,
    resource: string,
    action: string,
    result: PermissionCheckResult,
    scope?: PermissionScope,
    ttl?: number
  ): void {
    const key = this.generateKey(userId, resource, action, scope);
    this.cache.set(key, {
      result,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL,
    });
  }

  /**
   * Invalidate cache for specific user
   */
  invalidateUser(userId: string): void {
    const keysToDelete = Array.from(this.cache.keys()).filter(key => key.startsWith(`${userId}:`));
    keysToDelete.forEach(key => this.cache.delete(key));
    this.userRoleCache.delete(userId);
  }

  /**
   * Invalidate cache for specific resource
   */
  invalidateResource(resource: string): void {
    const keysToDelete = Array.from(this.cache.keys()).filter(key => key.includes(`:${resource}:`));
    keysToDelete.forEach(key => this.cache.delete(key));
  }

  /**
   * Clear all cache
   */
  clear(): void {
    this.cache.clear();
    this.userRoleCache.clear();
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; hitRate: number; memoryUsage: number } {
    // This would be implemented with proper statistics tracking
    return {
      size: this.cache.size,
      hitRate: 0, // Would track hits vs misses
      memoryUsage: 0, // Would calculate memory usage
    };
  }

  /**
   * Generate cache key
   */
  private generateKey(userId: string, resource: string, action: string, scope?: PermissionScope): string {
    const scopeKey = scope ? `${scope.type}:${scope.value || ''}` : 'global';
    return `${userId}:${resource}:${action}:${scopeKey}`;
  }
}

// =============================================================================
// Permissions Service Class
// =============================================================================

/**
 * Enterprise permissions service with advanced RBAC features
 */
export class PermissionsService {
  private readonly baseUrl = '/permissions';
  private readonly client = apiClient;
  private readonly cache = new PermissionCache();
  private readonly policyEvaluator = new PolicyEvaluator();
  private ws: WebSocket | null = null;

  // ===========================================================================
  // Permission Management
  // ===========================================================================

  /**
   * Create a new permission
   * 
   * @param data - Permission creation data
   * @param config - Request configuration
   * @returns Promise resolving to created permission
   * 
   * @example
   * ```typescript
   * const permission = await permissionsService.createPermission({
   *   name: 'Edit User Profile',
   *   resource: 'user',
   *   action: 'update',
   *   scope: { type: 'user', value: 'self' }
   * });
   * ```
   */
  async createPermission(
    data: z.infer<typeof createPermissionSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Permission>> {
    const validatedData = createPermissionSchema.parse(data);

    return this.client.post<typeof validatedData, Permission>(
      `${this.baseUrl}`,
      validatedData,
      {
        ...config,
        cancelKey: 'permission.create',
        cache: { enabled: false },
      }
    );
  }

  /**
   * Get permission by ID
   * 
   * @param id - Permission ID
   * @param config - Request configuration
   * @returns Promise resolving to permission
   */
  async getPermission(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Permission>> {
    return this.client.get<Permission>(
      `${this.baseUrl}/${id}`,
      {
        ...config,
        cancelKey: `permission.get.${id}`,
        cache: {
          enabled: true,
          ttl: 600000, // 10 minutes
          key: `permission:${id}`,
        },
      }
    );
  }

  /**
   * List permissions
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated permissions
   */
  async listPermissions(
    params: {
      page?: number;
      limit?: number;
      resource?: PermissionResource;
      action?: PermissionAction;
      scope?: string;
      search?: string;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<Permission>>> {
    return this.client.get<PaginatedResponse<Permission>>(
      this.baseUrl,
      {
        ...config,
        params,
        cancelKey: 'permission.list',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `permissions:list:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Update permission
   * 
   * @param id - Permission ID
   * @param data - Update data
   * @param config - Request configuration
   * @returns Promise resolving to updated permission
   */
  async updatePermission(
    id: string,
    data: Partial<z.infer<typeof createPermissionSchema>>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Permission>> {
    return this.client.patch<typeof data, Permission>(
      `${this.baseUrl}/${id}`,
      data,
      {
        ...config,
        cancelKey: `permission.update.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/permissions/${id}`, 'GET:/permissions'],
        },
      }
    );
  }

  /**
   * Delete permission
   * 
   * @param id - Permission ID
   * @param config - Request configuration
   * @returns Promise resolving to deletion confirmation
   */
  async deletePermission(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    const response = await this.client.delete<void>(
      `${this.baseUrl}/${id}`,
      {
        ...config,
        cancelKey: `permission.delete.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/permissions/${id}`, 'GET:/permissions'],
        },
      }
    );

    if (response.success) {
      // Invalidate cache since permissions changed
      this.cache.clear();
    }

    return response;
  }

  // ===========================================================================
  // Role Management
  // ===========================================================================

  /**
   * Create a new role
   * 
   * @param data - Role creation data
   * @param config - Request configuration
   * @returns Promise resolving to created role
   * 
   * @example
   * ```typescript
   * const role = await permissionsService.createRole({
   *   name: 'Content Editor',
   *   description: 'Can create and edit content',
   *   permissions: ['perm1', 'perm2'],
   *   metadata: { level: 1, priority: 10 }
   * });
   * ```
   */
  async createRole(
    data: z.infer<typeof createRoleSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Role>> {
    const validatedData = createRoleSchema.parse(data);

    return this.client.post<typeof validatedData, Role>(
      `${this.baseUrl}/roles`,
      validatedData,
      {
        ...config,
        cancelKey: 'role.create',
        cache: { enabled: false },
      }
    );
  }

  /**
   * Get role by ID
   * 
   * @param id - Role ID
   * @param config - Request configuration
   * @returns Promise resolving to role
   */
  async getRole(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Role>> {
    return this.client.get<Role>(
      `${this.baseUrl}/roles/${id}`,
      {
        ...config,
        cancelKey: `role.get.${id}`,
        cache: {
          enabled: true,
          ttl: 600000, // 10 minutes
          key: `role:${id}`,
        },
      }
    );
  }

  /**
   * List roles
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated roles
   */
  async listRoles(
    params: {
      page?: number;
      limit?: number;
      parentRoleId?: string;
      isActive?: boolean;
      search?: string;
      includePermissions?: boolean;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<Role>>> {
    return this.client.get<PaginatedResponse<Role>>(
      `${this.baseUrl}/roles`,
      {
        ...config,
        params,
        cancelKey: 'role.list',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `roles:list:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Update role
   * 
   * @param id - Role ID
   * @param data - Update data
   * @param config - Request configuration
   * @returns Promise resolving to updated role
   */
  async updateRole(
    id: string,
    data: Partial<z.infer<typeof createRoleSchema>>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<Role>> {
    const response = await this.client.patch<typeof data, Role>(
      `${this.baseUrl}/roles/${id}`,
      data,
      {
        ...config,
        cancelKey: `role.update.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/permissions/roles/${id}`, 'GET:/permissions/roles'],
        },
      }
    );

    if (response.success) {
      // Invalidate permission cache since role changed
      this.cache.clear();
    }

    return response;
  }

  /**
   * Delete role
   * 
   * @param id - Role ID
   * @param config - Request configuration
   * @returns Promise resolving to deletion confirmation
   */
  async deleteRole(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    const response = await this.client.delete<void>(
      `${this.baseUrl}/roles/${id}`,
      {
        ...config,
        cancelKey: `role.delete.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/permissions/roles/${id}`, 'GET:/permissions/roles'],
        },
      }
    );

    if (response.success) {
      // Invalidate cache since roles changed
      this.cache.clear();
    }

    return response;
  }

  // ===========================================================================
  // Role Assignment Management
  // ===========================================================================

  /**
   * Assign role to user
   * 
   * @param data - Role assignment data
   * @param config - Request configuration
   * @returns Promise resolving to role assignment
   */
  async assignRole(
    data: z.infer<typeof assignRoleSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserRoleAssignment>> {
    const validatedData = assignRoleSchema.parse(data);

    const response = await this.client.post<typeof validatedData, UserRoleAssignment>(
      `${this.baseUrl}/assignments`,
      validatedData,
      {
        ...config,
        cancelKey: `role.assign.${data.userId}.${data.roleId}`,
        cache: { enabled: false },
      }
    );

    if (response.success) {
      // Invalidate user's permission cache
      this.cache.invalidateUser(data.userId);
    }

    return response;
  }

  /**
   * Revoke role from user
   * 
   * @param assignmentId - Role assignment ID
   * @param config - Request configuration
   * @returns Promise resolving to revocation confirmation
   */
  async revokeRole(
    assignmentId: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    const response = await this.client.delete<void>(
      `${this.baseUrl}/assignments/${assignmentId}`,
      {
        ...config,
        cancelKey: `role.revoke.${assignmentId}`,
        cache: { enabled: false },
      }
    );

    if (response.success) {
      // Would need to know userId to invalidate specific user cache
      // For now, clear all cache
      this.cache.clear();
    }

    return response;
  }

  /**
   * Get user's role assignments
   * 
   * @param userId - User ID
   * @param config - Request configuration
   * @returns Promise resolving to user's role assignments
   */
  async getUserRoles(
    userId: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<UserRoleAssignment[]>> {
    return this.client.get<UserRoleAssignment[]>(
      `${this.baseUrl}/users/${userId}/roles`,
      {
        ...config,
        cancelKey: `user.roles.${userId}`,
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `user:roles:${userId}`,
        },
      }
    );
  }

  /**
   * Get role assignments
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated role assignments
   */
  async getRoleAssignments(
    params: {
      page?: number;
      limit?: number;
      userId?: string;
      roleId?: string;
      isActive?: boolean;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<UserRoleAssignment>>> {
    return this.client.get<PaginatedResponse<UserRoleAssignment>>(
      `${this.baseUrl}/assignments`,
      {
        ...config,
        params,
        cancelKey: 'role.assignments',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `assignments:${JSON.stringify(params)}`,
        },
      }
    );
  }

  // ===========================================================================
  // Permission Checking
  // ===========================================================================

  /**
   * Check if user has permission
   * 
   * @param request - Permission check request
   * @param config - Request configuration
   * @returns Promise resolving to permission check result
   * 
   * @example
   * ```typescript
   * const canEdit = await permissionsService.hasPermission({
   *   userId: 'user123',
   *   resource: 'document',
   *   action: 'update',
   *   scope: { type: 'resource', value: 'doc456' }
   * });
   * 
   * if (canEdit.success && canEdit.data.granted) {
   *   // User can edit the document
   * }
   * ```
   */
  async hasPermission(
    request: z.infer<typeof permissionCheckSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PermissionCheckResult>> {
    const validatedRequest = permissionCheckSchema.parse(request);

    // Check cache first
    const cached = this.cache.get(
      validatedRequest.userId,
      validatedRequest.resource,
      validatedRequest.action,
      validatedRequest.scope
    );

    if (cached) {
      return {
        success: true,
        data: cached,
        meta: {
          timestamp: new Date().toISOString(),
          requestId: crypto.randomUUID(),
          cached: true,
        },
      };
    }

    const response = await this.client.post<typeof validatedRequest, PermissionCheckResult>(
      `${this.baseUrl}/check`,
      validatedRequest,
      {
        ...config,
        cancelKey: `permission.check.${validatedRequest.userId}`,
      }
    );

    if (response.success) {
      // Cache the result
      this.cache.set(
        validatedRequest.userId,
        validatedRequest.resource,
        validatedRequest.action,
        response.data,
        validatedRequest.scope
      );
    }

    return response;
  }

  /**
   * Check multiple permissions in batch
   * 
   * @param request - Bulk permission check request
   * @param config - Request configuration
   * @returns Promise resolving to bulk permission check results
   */
  async hasPermissionsBulk(
    request: z.infer<typeof bulkPermissionCheckSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PermissionCheckResult[]>> {
    const validatedRequest = bulkPermissionCheckSchema.parse(request);

    return this.client.post<typeof validatedRequest, PermissionCheckResult[]>(
      `${this.baseUrl}/check/bulk`,
      validatedRequest,
      {
        ...config,
        cancelKey: `permission.check.bulk.${validatedRequest.userId}`,
      }
    );
  }

  /**
   * Get effective permissions for user
   * 
   * @param userId - User ID
   * @param scope - Optional scope filter
   * @param config - Request configuration
   * @returns Promise resolving to user's effective permissions
   */
  async getEffectivePermissions(
    userId: string,
    scope?: PermissionScope,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{
    permissions: Permission[];
    roles: Role[];
    inheritedFrom: Record<string, string[]>; // permission ID -> role IDs
  }>> {
    return this.client.get(
      `${this.baseUrl}/users/${userId}/effective`,
      {
        ...config,
        params: scope ? { scope: JSON.stringify(scope) } : {},
        cancelKey: `permission.effective.${userId}`,
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `effective:${userId}:${JSON.stringify(scope)}`,
        },
      }
    );
  }

  // ===========================================================================
  // Utility Methods
  // ===========================================================================

  /**
   * Check permission with caching (synchronous)
   * 
   * @param userId - User ID
   * @param resource - Resource type
   * @param action - Action type
   * @param scope - Optional scope
   * @returns Cached permission result or null
   */
  checkCached(
    userId: string,
    resource: PermissionResource,
    action: PermissionAction,
    scope?: PermissionScope
  ): PermissionCheckResult | null {
    return this.cache.get(userId, resource, action, scope);
  }

  /**
   * Preload permissions for user (for caching)
   * 
   * @param userId - User ID
   * @param permissions - Permissions to preload
   * @param config - Request configuration
   * @returns Promise resolving to preloaded permissions
   */
  async preloadPermissions(
    userId: string,
    permissions: Array<{ resource: PermissionResource; action: PermissionAction; scope?: PermissionScope }>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PermissionCheckResult[]>> {
    const bulkRequest = {
      userId,
      checks: permissions,
    };

    const response = await this.hasPermissionsBulk(bulkRequest, config);

    if (response.success) {
      // Cache all results
      response.data.forEach((result, index) => {
        const perm = permissions[index];
        this.cache.set(userId, perm.resource, perm.action, result, perm.scope);
      });
    }

    return response;
  }

  /**
   * Clear permission cache
   * 
   * @param userId - Optional user ID to clear specific user cache
   */
  clearCache(userId?: string): void {
    if (userId) {
      this.cache.invalidateUser(userId);
    } else {
      this.cache.clear();
    }
  }

  /**
   * Get cache statistics
   */
  getCacheStats(): { size: number; hitRate: number; memoryUsage: number } {
    return this.cache.getStats();
  }

  // ===========================================================================
  // Audit and Monitoring
  // ===========================================================================

  /**
   * Get permission audit logs
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated audit logs
   */
  async getAuditLogs(
    params: {
      page?: number;
      limit?: number;
      userId?: string;
      resource?: PermissionResource;
      action?: string;
      dateFrom?: string;
      dateTo?: string;
      result?: boolean;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<PermissionAuditLog>>> {
    return this.client.get<PaginatedResponse<PermissionAuditLog>>(
      `${this.baseUrl}/audit`,
      {
        ...config,
        params,
        cancelKey: 'permission.audit',
        cache: {
          enabled: true,
          ttl: 60000, // 1 minute
          key: `audit:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Get permission usage statistics
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to usage statistics
   */
  async getUsageStats(
    params: {
      dateFrom?: string;
      dateTo?: string;
      groupBy?: 'user' | 'resource' | 'action' | 'day' | 'week' | 'month';
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{
    totalChecks: number;
    grantedChecks: number;
    deniedChecks: number;
    grantRate: number;
    byResource: Record<PermissionResource, number>;
    byAction: Record<PermissionAction, number>;
    timeline: Array<{ date: string; checks: number; granted: number; denied: number }>;
  }>> {
    return this.client.get(
      `${this.baseUrl}/stats/usage`,
      {
        ...config,
        params,
        cancelKey: 'permission.stats.usage',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `stats:usage:${JSON.stringify(params)}`,
        },
      }
    );
  }

  // ===========================================================================
  // Real-time Updates
  // ===========================================================================

  /**
   * Connect to real-time permission updates
   * 
   * @param userId - User ID for personalized updates
   * @returns Promise resolving when connection is established
   */
  async connectRealtime(userId: string): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    const wsUrl = `${import.meta.env.VITE_WS_URL || 'ws://localhost:3000'}/permissions/ws?userId=${userId}`;
    this.ws = new WebSocket(wsUrl);

    return new Promise((resolve, reject) => {
      if (!this.ws) {
        reject(new Error('Failed to create WebSocket'));
        return;
      }

      this.ws.onopen = () => {
        console.log('[PermissionWS] Connected');
        resolve();
      };

      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.handleRealtimeMessage(message);
        } catch (error) {
          console.error('[PermissionWS] Failed to parse message:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('[PermissionWS] Error:', error);
        reject(error);
      };

      this.ws.onclose = () => {
        console.log('[PermissionWS] Disconnected');
      };
    });
  }

  /**
   * Disconnect from real-time updates
   */
  disconnectRealtime(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Handle real-time permission messages
   */
  private handleRealtimeMessage(message: any): void {
    switch (message.type) {
      case 'permission.granted':
      case 'permission.revoked':
      case 'role.assigned':
      case 'role.revoked':
        // Invalidate affected user's cache
        if (message.userId) {
          this.cache.invalidateUser(message.userId);
        }
        break;
      case 'permission.updated':
      case 'role.updated':
        // Invalidate all cache since permissions/roles changed
        this.cache.clear();
        break;
      default:
        console.warn('[PermissionWS] Unknown message type:', message.type);
    }
  }

  /**
   * Get real-time connection status
   */
  get isRealtimeConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

// Export singleton instance
export const permissionsService = new PermissionsService();