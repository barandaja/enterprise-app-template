/**
 * @fileoverview Notification API Service
 * 
 * Enterprise-grade notification service providing:
 * - CRUD operations for notifications with full typing
 * - Batch operations with progress tracking
 * - Real-time subscription management with WebSocket
 * - Preference management with type-safe keys
 * - Template management and rendering
 * - Delivery status tracking across channels
 * - Advanced querying with type-safe builders
 */

import { z } from 'zod';
import { apiClient } from './client';
import type {
  ApiResponse,
  ApiRequestConfig,
  PaginatedResponse,
  EnhancedApiRequestConfig,
  QueryBuilder,
  BaseNotification,
  NotificationWithStatus,
  NotificationTemplate,
  NotificationSubscription,
  BatchNotificationRequest,
  BatchOperationResult,
  NotificationEvent,
  NotificationType,
  NotificationPriority,
  NotificationChannel,
} from './types';

// =============================================================================
// Validation Schemas
// =============================================================================

/**
 * Notification creation schema
 */
const createNotificationSchema = z.object({
  userId: z.string().min(1, 'User ID is required'),
  type: z.nativeEnum(NotificationType),
  priority: z.nativeEnum(NotificationPriority).default(NotificationPriority.NORMAL),
  title: z.string().min(1, 'Title is required').max(255, 'Title too long'),
  message: z.string().min(1, 'Message is required').max(2000, 'Message too long'),
  data: z.record(z.unknown()).optional(),
  channels: z.array(z.nativeEnum(NotificationChannel)).min(1, 'At least one channel required'),
  actionUrl: z.string().url().optional(),
  actionText: z.string().max(50).optional(),
  expiresAt: z.string().datetime().optional(),
});

/**
 * Notification update schema
 */
const updateNotificationSchema = z.object({
  title: z.string().min(1).max(255).optional(),
  message: z.string().min(1).max(2000).optional(),
  data: z.record(z.unknown()).optional(),
  actionUrl: z.string().url().optional(),
  actionText: z.string().max(50).optional(),
  expiresAt: z.string().datetime().optional(),
  isRead: z.boolean().optional(),
  isArchived: z.boolean().optional(),
});

/**
 * Subscription preferences schema
 */
const subscriptionPreferencesSchema = z.object({
  channels: z.record(
    z.nativeEnum(NotificationChannel),
    z.object({
      enabled: z.boolean(),
      types: z.array(z.nativeEnum(NotificationType)),
      quietHours: z.object({
        start: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
        end: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/),
        timezone: z.string(),
      }).optional(),
    })
  ).partial(),
  globalSettings: z.object({
    enabled: z.boolean(),
    allowMarketing: z.boolean(),
    allowSystem: z.boolean(),
    frequency: z.enum(['immediate', 'hourly', 'daily', 'weekly']),
  }),
});

/**
 * Template creation schema
 */
const createTemplateSchema = z.object({
  name: z.string().min(1, 'Template name is required').max(100),
  type: z.nativeEnum(NotificationType),
  subject: z.string().min(1, 'Subject is required').max(255),
  htmlContent: z.string().min(1, 'HTML content is required'),
  textContent: z.string().min(1, 'Text content is required'),
  variables: z.array(z.string()).default([]),
});

// =============================================================================
// Type-Safe Query Builder Implementation
// =============================================================================

/**
 * Notification-specific query builder
 */
class NotificationQueryBuilder implements QueryBuilder<BaseNotification> {
  private filters: Array<{ field: string; operator: string; value: unknown }> = [];
  private sortBy?: { field: string; direction: 'asc' | 'desc' };
  private limitValue?: number;
  private offsetValue?: number;

  where<K extends keyof BaseNotification>(
    field: K,
    operator: '=' | '!=' | '>' | '>=' | '<' | '<=' | 'like' | 'ilike' | 'in' | 'not_in',
    value: BaseNotification[K]
  ): this {
    this.filters.push({ field: field as string, operator, value });
    return this;
  }

  whereIn<K extends keyof BaseNotification>(field: K, values: BaseNotification[K][]): this {
    this.filters.push({ field: field as string, operator: 'in', value: values });
    return this;
  }

  whereBetween<K extends keyof BaseNotification>(
    field: K,
    min: BaseNotification[K],
    max: BaseNotification[K]
  ): this {
    this.filters.push({ field: field as string, operator: '>=', value: min });
    this.filters.push({ field: field as string, operator: '<=', value: max });
    return this;
  }

  orderBy<K extends keyof BaseNotification>(field: K, direction: 'asc' | 'desc' = 'desc'): this {
    this.sortBy = { field: field as string, direction };
    return this;
  }

  limit(count: number): this {
    this.limitValue = count;
    return this;
  }

  offset(count: number): this {
    this.offsetValue = count;
    return this;
  }

  page(number: number, size = 20): this {
    this.limitValue = size;
    this.offsetValue = (number - 1) * size;
    return this;
  }

  build() {
    const params: Record<string, unknown> = {};

    if (this.filters.length > 0) {
      params.filters = this.filters;
    }

    if (this.sortBy) {
      params.sortBy = this.sortBy.field;
      params.sortOrder = this.sortBy.direction;
    }

    if (this.limitValue !== undefined) {
      params.limit = this.limitValue;
    }

    if (this.offsetValue !== undefined) {
      params.offset = this.offsetValue;
    }

    return params;
  }
}

// =============================================================================
// WebSocket Connection Manager
// =============================================================================

/**
 * Real-time notification connection manager
 */
class NotificationWebSocketManager {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private eventHandlers = new Map<string, Set<(event: NotificationEvent) => void>>();
  private isConnecting = false;

  /**
   * Connect to WebSocket for real-time notifications
   */
  async connect(userId: string): Promise<void> {
    if (this.ws?.readyState === WebSocket.OPEN || this.isConnecting) {
      return;
    }

    this.isConnecting = true;

    try {
      const wsUrl = this.buildWebSocketUrl(userId);
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[NotificationWS] Connected');
        this.reconnectAttempts = 0;
        this.isConnecting = false;
      };

      this.ws.onmessage = (event) => {
        try {
          const notificationEvent: NotificationEvent = JSON.parse(event.data);
          this.handleNotificationEvent(notificationEvent);
        } catch (error) {
          console.error('[NotificationWS] Failed to parse message:', error);
        }
      };

      this.ws.onclose = () => {
        console.log('[NotificationWS] Disconnected');
        this.isConnecting = false;
        this.scheduleReconnect(userId);
      };

      this.ws.onerror = (error) => {
        console.error('[NotificationWS] Error:', error);
        this.isConnecting = false;
      };
    } catch (error) {
      console.error('[NotificationWS] Connection failed:', error);
      this.isConnecting = false;
      this.scheduleReconnect(userId);
    }
  }

  /**
   * Disconnect from WebSocket
   */
  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.eventHandlers.clear();
    this.reconnectAttempts = 0;
  }

  /**
   * Subscribe to notification events
   */
  subscribe(
    eventType: NotificationEvent['type'],
    handler: (event: NotificationEvent) => void
  ): () => void {
    if (!this.eventHandlers.has(eventType)) {
      this.eventHandlers.set(eventType, new Set());
    }
    
    this.eventHandlers.get(eventType)!.add(handler);

    return () => {
      this.eventHandlers.get(eventType)?.delete(handler);
    };
  }

  /**
   * Get connection status
   */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  private buildWebSocketUrl(userId: string): string {
    const baseUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:3000';
    return `${baseUrl}/notifications/ws?userId=${userId}`;
  }

  private handleNotificationEvent(event: NotificationEvent): void {
    const handlers = this.eventHandlers.get(event.type);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(event);
        } catch (error) {
          console.error('[NotificationWS] Handler error:', error);
        }
      });
    }
  }

  private scheduleReconnect(userId: string): void {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('[NotificationWS] Max reconnect attempts reached');
      return;
    }

    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);

    setTimeout(() => {
      console.log(`[NotificationWS] Reconnecting... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      this.connect(userId);
    }, delay);
  }
}

// =============================================================================
// Notification Service Class
// =============================================================================

/**
 * Enterprise notification service with advanced features
 */
export class NotificationService {
  private readonly baseUrl = '/notifications';
  private readonly client = apiClient;
  private readonly wsManager = new NotificationWebSocketManager();

  // ===========================================================================
  // CRUD Operations
  // ===========================================================================

  /**
   * Create a new notification
   * 
   * @param data - Notification creation data
   * @param config - Request configuration
   * @returns Promise resolving to created notification
   * 
   * @example
   * ```typescript
   * const notification = await notificationService.create({
   *   userId: 'user123',
   *   type: NotificationType.INFO,
   *   priority: NotificationPriority.HIGH,
   *   title: 'Welcome!',
   *   message: 'Welcome to our platform',
   *   channels: [NotificationChannel.IN_APP, NotificationChannel.EMAIL]
   * });
   * ```
   */
  async create(
    data: z.infer<typeof createNotificationSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BaseNotification>> {
    const validatedData = createNotificationSchema.parse(data);

    return this.client.post<typeof validatedData, BaseNotification>(
      this.baseUrl,
      validatedData,
      {
        ...config,
        cancelKey: 'notification.create',
        cache: { enabled: false }, // Don't cache create operations
      }
    );
  }

  /**
   * Get notification by ID
   * 
   * @param id - Notification ID
   * @param config - Request configuration
   * @returns Promise resolving to notification with delivery status
   */
  async getById(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<NotificationWithStatus>> {
    return this.client.get<NotificationWithStatus>(
      `${this.baseUrl}/${id}`,
      {
        ...config,
        cancelKey: `notification.get.${id}`,
        cache: {
          enabled: true,
          ttl: 30000, // 30 seconds
          key: `notification:${id}`,
        },
      }
    );
  }

  /**
   * Update notification
   * 
   * @param id - Notification ID
   * @param data - Update data
   * @param config - Request configuration
   * @returns Promise resolving to updated notification
   */
  async update(
    id: string,
    data: z.infer<typeof updateNotificationSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BaseNotification>> {
    const validatedData = updateNotificationSchema.parse(data);

    return this.client.patch<typeof validatedData, BaseNotification>(
      `${this.baseUrl}/${id}`,
      validatedData,
      {
        ...config,
        cancelKey: `notification.update.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/notifications/${id}`, 'GET:/notifications'],
        },
      }
    );
  }

  /**
   * Delete notification
   * 
   * @param id - Notification ID
   * @param config - Request configuration
   * @returns Promise resolving to deletion confirmation
   */
  async delete(
    id: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<void>> {
    return this.client.delete<void>(
      `${this.baseUrl}/${id}`,
      {
        ...config,
        cancelKey: `notification.delete.${id}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/notifications/${id}`, 'GET:/notifications'],
        },
      }
    );
  }

  /**
   * List notifications with advanced querying
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated notifications
   * 
   * @example
   * ```typescript
   * const notifications = await notificationService.list({
   *   page: 1,
   *   limit: 20,
   *   filters: { isRead: false, type: 'info' }
   * });
   * ```
   */
  async list(
    params: {
      page?: number;
      limit?: number;
      sortBy?: keyof BaseNotification;
      sortOrder?: 'asc' | 'desc';
      filters?: Partial<BaseNotification>;
      userId?: string;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<BaseNotification>>> {
    return this.client.get<PaginatedResponse<BaseNotification>>(
      this.baseUrl,
      {
        ...config,
        params,
        cancelKey: 'notification.list',
        cache: {
          enabled: true,
          ttl: 60000, // 1 minute
          key: `notifications:list:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Create type-safe query builder
   * 
   * @returns Query builder instance
   * 
   * @example
   * ```typescript
   * const notifications = await notificationService
   *   .query()
   *   .where('type', '=', NotificationType.INFO)
   *   .where('isRead', '=', false)
   *   .orderBy('createdAt', 'desc')
   *   .page(1, 10)
   *   .execute();
   * ```
   */
  query(): NotificationQueryBuilder & { execute: () => Promise<ApiResponse<PaginatedResponse<BaseNotification>>> } {
    const builder = new NotificationQueryBuilder();
    
    return {
      ...builder,
      execute: async () => {
        const params = builder.build();
        return this.list(params);
      },
    };
  }

  // ===========================================================================
  // Batch Operations
  // ===========================================================================

  /**
   * Create multiple notifications in batch
   * 
   * @param request - Batch creation request
   * @param config - Request configuration
   * @returns Promise resolving to batch operation result
   */
  async createBatch(
    request: BatchNotificationRequest,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BatchOperationResult<BaseNotification>>> {
    return this.client.post<BatchNotificationRequest, BatchOperationResult<BaseNotification>>(
      `${this.baseUrl}/batch`,
      request,
      {
        ...config,
        cancelKey: 'notification.batch.create',
        timeout: 60000, // Extended timeout for batch operations
      }
    );
  }

  /**
   * Mark multiple notifications as read
   * 
   * @param ids - Notification IDs
   * @param config - Request configuration
   * @returns Promise resolving to batch operation result
   */
  async markAsReadBatch(
    ids: string[],
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BatchOperationResult<BaseNotification>>> {
    return this.client.patch<{ ids: string[] }, BatchOperationResult<BaseNotification>>(
      `${this.baseUrl}/batch/read`,
      { ids },
      {
        ...config,
        cancelKey: 'notification.batch.read',
      }
    );
  }

  /**
   * Archive multiple notifications
   * 
   * @param ids - Notification IDs
   * @param config - Request configuration
   * @returns Promise resolving to batch operation result
   */
  async archiveBatch(
    ids: string[],
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BatchOperationResult<BaseNotification>>> {
    return this.client.patch<{ ids: string[] }, BatchOperationResult<BaseNotification>>(
      `${this.baseUrl}/batch/archive`,
      { ids },
      {
        ...config,
        cancelKey: 'notification.batch.archive',
      }
    );
  }

  /**
   * Delete multiple notifications
   * 
   * @param ids - Notification IDs
   * @param config - Request configuration
   * @returns Promise resolving to batch operation result
   */
  async deleteBatch(
    ids: string[],
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<BatchOperationResult<void>>> {
    return this.client.delete<BatchOperationResult<void>>(
      `${this.baseUrl}/batch`,
      {
        ...config,
        data: { ids },
        cancelKey: 'notification.batch.delete',
      }
    );
  }

  // ===========================================================================
  // Subscription Management
  // ===========================================================================

  /**
   * Get user's notification subscription preferences
   * 
   * @param userId - User ID
   * @param config - Request configuration
   * @returns Promise resolving to subscription preferences
   */
  async getSubscriptions(
    userId: string,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<NotificationSubscription>> {
    return this.client.get<NotificationSubscription>(
      `${this.baseUrl}/subscriptions/${userId}`,
      {
        ...config,
        cancelKey: `notification.subscriptions.${userId}`,
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `notification:subscriptions:${userId}`,
        },
      }
    );
  }

  /**
   * Update user's notification subscription preferences
   * 
   * @param userId - User ID
   * @param preferences - Updated preferences
   * @param config - Request configuration
   * @returns Promise resolving to updated preferences
   */
  async updateSubscriptions(
    userId: string,
    preferences: z.infer<typeof subscriptionPreferencesSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<NotificationSubscription>> {
    const validatedPreferences = subscriptionPreferencesSchema.parse(preferences);

    return this.client.patch<typeof validatedPreferences, NotificationSubscription>(
      `${this.baseUrl}/subscriptions/${userId}`,
      validatedPreferences,
      {
        ...config,
        cancelKey: `notification.subscriptions.update.${userId}`,
        cache: {
          enabled: false,
          invalidateOn: [`GET:/notifications/subscriptions/${userId}`],
        },
      }
    );
  }

  // ===========================================================================
  // Template Management
  // ===========================================================================

  /**
   * Create notification template
   * 
   * @param data - Template creation data
   * @param config - Request configuration
   * @returns Promise resolving to created template
   */
  async createTemplate(
    data: z.infer<typeof createTemplateSchema>,
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<NotificationTemplate>> {
    const validatedData = createTemplateSchema.parse(data);

    return this.client.post<typeof validatedData, NotificationTemplate>(
      `${this.baseUrl}/templates`,
      validatedData,
      {
        ...config,
        cancelKey: 'notification.template.create',
      }
    );
  }

  /**
   * List notification templates
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to paginated templates
   */
  async listTemplates(
    params: {
      page?: number;
      limit?: number;
      type?: NotificationType;
      isActive?: boolean;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<PaginatedResponse<NotificationTemplate>>> {
    return this.client.get<PaginatedResponse<NotificationTemplate>>(
      `${this.baseUrl}/templates`,
      {
        ...config,
        params,
        cancelKey: 'notification.template.list',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `notification:templates:${JSON.stringify(params)}`,
        },
      }
    );
  }

  // ===========================================================================
  // Real-time Features
  // ===========================================================================

  /**
   * Connect to real-time notification feed
   * 
   * @param userId - User ID for the connection
   * @returns Promise resolving when connection is established
   */
  async connectRealtime(userId: string): Promise<void> {
    return this.wsManager.connect(userId);
  }

  /**
   * Disconnect from real-time notification feed
   */
  disconnectRealtime(): void {
    this.wsManager.disconnect();
  }

  /**
   * Subscribe to real-time notification events
   * 
   * @param eventType - Type of events to subscribe to
   * @param handler - Event handler function
   * @returns Unsubscribe function
   * 
   * @example
   * ```typescript
   * const unsubscribe = notificationService.onNotificationEvent(
   *   'notification.created',
   *   (event) => {
   *     console.log('New notification:', event.payload);
   *   }
   * );
   * 
   * // Later...
   * unsubscribe();
   * ```
   */
  onNotificationEvent(
    eventType: NotificationEvent['type'],
    handler: (event: NotificationEvent) => void
  ): () => void {
    return this.wsManager.subscribe(eventType, handler);
  }

  /**
   * Get real-time connection status
   */
  get isRealtimeConnected(): boolean {
    return this.wsManager.isConnected;
  }

  // ===========================================================================
  // Analytics and Metrics
  // ===========================================================================

  /**
   * Get notification delivery statistics
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to delivery statistics
   */
  async getDeliveryStats(
    params: {
      userId?: string;
      dateFrom?: string;
      dateTo?: string;
      channel?: NotificationChannel;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{
    totalSent: number;
    totalDelivered: number;
    totalFailed: number;
    deliveryRate: number;
    byChannel: Record<NotificationChannel, {
      sent: number;
      delivered: number;
      failed: number;
      rate: number;
    }>;
  }>> {
    return this.client.get(
      `${this.baseUrl}/analytics/delivery`,
      {
        ...config,
        params,
        cancelKey: 'notification.analytics.delivery',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `notification:analytics:delivery:${JSON.stringify(params)}`,
        },
      }
    );
  }

  /**
   * Get user engagement statistics
   * 
   * @param params - Query parameters
   * @param config - Request configuration
   * @returns Promise resolving to engagement statistics
   */
  async getEngagementStats(
    params: {
      userId?: string;
      dateFrom?: string;
      dateTo?: string;
      type?: NotificationType;
    } = {},
    config: EnhancedApiRequestConfig = {}
  ): Promise<ApiResponse<{
    totalNotifications: number;
    readNotifications: number;
    clickedNotifications: number;
    readRate: number;
    clickRate: number;
    byType: Record<NotificationType, {
      total: number;
      read: number;
      clicked: number;
      readRate: number;
      clickRate: number;
    }>;
  }>> {
    return this.client.get(
      `${this.baseUrl}/analytics/engagement`,
      {
        ...config,
        params,
        cancelKey: 'notification.analytics.engagement',
        cache: {
          enabled: true,
          ttl: 300000, // 5 minutes
          key: `notification:analytics:engagement:${JSON.stringify(params)}`,
        },
      }
    );
  }
}

// Export singleton instance
export const notificationService = new NotificationService();

// Export validation schemas for external use
export {
  createNotificationSchema,
  updateNotificationSchema,
  subscriptionPreferencesSchema,
  createTemplateSchema,
};

// Export query builder for advanced usage
export { NotificationQueryBuilder };