/**
 * Comprehensive audit logging system for compliance (GDPR, HIPAA, SOC2)
 * Tracks all security-relevant events and user actions
 */

/**
 * Event types for audit logging
 */
export enum AuditEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'auth.login.success',
  LOGIN_FAILURE = 'auth.login.failure',
  LOGOUT = 'auth.logout',
  SESSION_TIMEOUT = 'auth.session.timeout',
  PASSWORD_CHANGE = 'auth.password.change',
  PASSWORD_RESET = 'auth.password.reset',
  MFA_ENABLED = 'auth.mfa.enabled',
  MFA_DISABLED = 'auth.mfa.disabled',
  TOKEN_REFRESH = 'auth.token.refresh',

  // Access Control Events
  ACCESS_GRANTED = 'access.granted',
  ACCESS_DENIED = 'access.denied',
  PERMISSION_CHANGED = 'access.permission.changed',
  ROLE_CHANGED = 'access.role.changed',

  // Data Events (GDPR/HIPAA)
  DATA_VIEW = 'data.view',
  DATA_CREATE = 'data.create',
  DATA_UPDATE = 'data.update',
  DATA_DELETE = 'data.delete',
  DATA_EXPORT = 'data.export',
  DATA_DOWNLOAD = 'data.download',
  PHI_ACCESS = 'data.phi.access', // HIPAA specific
  PII_ACCESS = 'data.pii.access', // GDPR specific

  // User Actions
  PROFILE_UPDATE = 'user.profile.update',
  SETTINGS_CHANGE = 'user.settings.change',
  CONSENT_GIVEN = 'user.consent.given',
  CONSENT_WITHDRAWN = 'user.consent.withdrawn',

  // Security Events
  SECURITY_ALERT = 'security.alert',
  SUSPICIOUS_ACTIVITY = 'security.suspicious',
  RATE_LIMIT_EXCEEDED = 'security.rate_limit',
  INVALID_INPUT = 'security.invalid_input',
  XSS_ATTEMPT = 'security.xss_attempt',
  SQL_INJECTION_ATTEMPT = 'security.sql_injection',
  CSRF_ATTEMPT = 'security.csrf_attempt',

  // System Events
  SYSTEM_ERROR = 'system.error',
  API_ERROR = 'system.api.error',
  CONFIGURATION_CHANGE = 'system.config.change',
}

/**
 * Severity levels for audit events
 */
export enum AuditSeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical',
}

/**
 * Audit event interface
 */
export interface AuditEvent {
  id: string;
  timestamp: string;
  type: AuditEventType;
  severity: AuditSeverity;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  resource?: string;
  action?: string;
  result: 'success' | 'failure';
  details?: Record<string, any>;
  metadata?: {
    component?: string;
    method?: string;
    duration?: number;
    errorCode?: string;
    errorMessage?: string;
  };
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  endpoint?: string;
  batchSize?: number;
  flushInterval?: number;
  enableConsoleLog?: boolean;
  enableLocalStorage?: boolean;
  maxLocalEvents?: number;
  includeSensitiveData?: boolean;
  complianceMode?: 'GDPR' | 'HIPAA' | 'SOC2' | 'ALL';
}

/**
 * Main audit logger class
 */
export class AuditLogger {
  private static instance: AuditLogger;
  private config: Required<AuditLoggerConfig>;
  private eventQueue: AuditEvent[] = [];
  private flushTimer?: NodeJS.Timeout;
  private sessionId: string;

  private constructor(config: AuditLoggerConfig = {}) {
    this.config = {
      endpoint: config.endpoint || '/api/audit/events',
      batchSize: config.batchSize || 50,
      flushInterval: config.flushInterval || 5000,
      enableConsoleLog: config.enableConsoleLog ?? false,
      enableLocalStorage: config.enableLocalStorage ?? true,
      maxLocalEvents: config.maxLocalEvents || 1000,
      includeSensitiveData: config.includeSensitiveData ?? false,
      complianceMode: config.complianceMode || 'ALL',
    };

    this.sessionId = this.generateSessionId();
    this.setupAutoFlush();
    this.setupUnloadHandler();
  }

  /**
   * Get singleton instance
   */
  static getInstance(config?: AuditLoggerConfig): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger(config);
    }
    return AuditLogger.instance;
  }

  /**
   * Log an audit event
   */
  log(
    type: AuditEventType,
    details: {
      severity?: AuditSeverity;
      userId?: string;
      resource?: string;
      action?: string;
      result?: 'success' | 'failure';
      details?: Record<string, any>;
      metadata?: Record<string, any>;
    } = {}
  ): void {
    const event: AuditEvent = {
      id: this.generateEventId(),
      timestamp: new Date().toISOString(),
      type,
      severity: details.severity || this.getDefaultSeverity(type),
      sessionId: this.sessionId,
      userId: details.userId || this.getCurrentUserId(),
      ipAddress: this.getClientIP(),
      userAgent: navigator.userAgent,
      resource: details.resource,
      action: details.action,
      result: details.result || 'success',
      details: this.sanitizeDetails(details.details),
      metadata: details.metadata,
    };

    // Apply compliance filters
    const filteredEvent = this.applyComplianceFilters(event);

    // Console logging for development
    if (this.config.enableConsoleLog) {
      console.log(`[AUDIT] ${event.type}`, filteredEvent);
    }

    // Add to queue
    this.eventQueue.push(filteredEvent);

    // Store locally if enabled
    if (this.config.enableLocalStorage) {
      this.storeLocally(filteredEvent);
    }

    // Flush if batch size reached
    if (this.eventQueue.length >= this.config.batchSize) {
      this.flush();
    }
  }

  /**
   * Log security event
   */
  logSecurity(
    type: AuditEventType,
    threat: string,
    details?: Record<string, any>
  ): void {
    this.log(type, {
      severity: AuditSeverity.WARNING,
      result: 'failure',
      details: {
        threat,
        ...details,
      },
      metadata: {
        component: 'security',
      },
    });
  }

  /**
   * Log data access event (GDPR/HIPAA)
   */
  logDataAccess(
    resource: string,
    action: 'view' | 'create' | 'update' | 'delete' | 'export',
    dataType: 'PII' | 'PHI' | 'sensitive' | 'general',
    details?: Record<string, any>
  ): void {
    const eventType = dataType === 'PHI' 
      ? AuditEventType.PHI_ACCESS 
      : dataType === 'PII' 
      ? AuditEventType.PII_ACCESS 
      : AuditEventType.DATA_VIEW;

    this.log(eventType, {
      severity: AuditSeverity.INFO,
      resource,
      action,
      details: {
        dataType,
        ...details,
      },
    });
  }

  /**
   * Log consent event (GDPR)
   */
  logConsent(
    action: 'given' | 'withdrawn',
    consentType: string,
    details?: Record<string, any>
  ): void {
    this.log(
      action === 'given' 
        ? AuditEventType.CONSENT_GIVEN 
        : AuditEventType.CONSENT_WITHDRAWN,
      {
        severity: AuditSeverity.INFO,
        details: {
          consentType,
          timestamp: new Date().toISOString(),
          ...details,
        },
      }
    );
  }

  /**
   * Flush events to backend
   */
  async flush(): Promise<void> {
    if (this.eventQueue.length === 0) return;

    const events = [...this.eventQueue];
    this.eventQueue = [];

    try {
      const response = await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ events }),
      });

      if (!response.ok) {
        throw new Error(`Failed to send audit events: ${response.statusText}`);
      }
    } catch (error) {
      console.error('Failed to flush audit events:', error);
      // Re-queue events for retry
      this.eventQueue.unshift(...events);
      
      // Store failed events locally
      if (this.config.enableLocalStorage) {
        events.forEach(event => this.storeLocally(event, true));
      }
    }
  }

  /**
   * Get audit trail for a user
   */
  async getUserAuditTrail(
    userId: string,
    options: {
      startDate?: Date;
      endDate?: Date;
      eventTypes?: AuditEventType[];
      limit?: number;
    } = {}
  ): Promise<AuditEvent[]> {
    const params = new URLSearchParams({
      userId,
      ...(options.startDate && { startDate: options.startDate.toISOString() }),
      ...(options.endDate && { endDate: options.endDate.toISOString() }),
      ...(options.eventTypes && { eventTypes: options.eventTypes.join(',') }),
      ...(options.limit && { limit: options.limit.toString() }),
    });

    const response = await fetch(`${this.config.endpoint}?${params}`);
    if (!response.ok) {
      throw new Error('Failed to fetch audit trail');
    }

    return response.json();
  }

  /**
   * Private helper methods
   */
  private generateEventId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }

  private generateSessionId(): string {
    return `session-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  }

  private getCurrentUserId(): string | undefined {
    // This should be implemented to get the current user ID from your auth system
    // For example: return authStore.getState().user?.id;
    return undefined;
  }

  private getClientIP(): string | undefined {
    // Client-side IP detection is limited
    // This would typically be handled server-side
    return undefined;
  }

  private getDefaultSeverity(type: AuditEventType): AuditSeverity {
    if (type.includes('failure') || type.includes('denied')) {
      return AuditSeverity.WARNING;
    }
    if (type.includes('error') || type.includes('attack')) {
      return AuditSeverity.ERROR;
    }
    return AuditSeverity.INFO;
  }

  private sanitizeDetails(details?: Record<string, any>): Record<string, any> | undefined {
    if (!details || this.config.includeSensitiveData) {
      return details;
    }

    // Remove sensitive fields based on compliance mode
    const sensitiveFields = this.getSensitiveFields();
    const sanitized: Record<string, any> = {};

    for (const [key, value] of Object.entries(details)) {
      if (!sensitiveFields.includes(key.toLowerCase())) {
        sanitized[key] = value;
      } else {
        sanitized[key] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  private getSensitiveFields(): string[] {
    const baseFields = ['password', 'token', 'secret', 'key', 'auth'];
    
    switch (this.config.complianceMode) {
      case 'GDPR':
        return [...baseFields, 'email', 'name', 'address', 'phone', 'ip'];
      case 'HIPAA':
        return [...baseFields, 'ssn', 'mrn', 'diagnosis', 'treatment', 'medication'];
      case 'SOC2':
        return [...baseFields, 'creditcard', 'cvv', 'account'];
      case 'ALL':
      default:
        return [...baseFields, 'email', 'name', 'address', 'phone', 'ip', 
                'ssn', 'mrn', 'diagnosis', 'treatment', 'medication',
                'creditcard', 'cvv', 'account'];
    }
  }

  private applyComplianceFilters(event: AuditEvent): AuditEvent {
    // Apply compliance-specific filters
    const filtered = { ...event };

    // GDPR: Anonymize IP after 90 days
    if (this.config.complianceMode === 'GDPR' || this.config.complianceMode === 'ALL') {
      // This would be handled server-side in production
    }

    // HIPAA: Ensure minimum necessary principle
    if (this.config.complianceMode === 'HIPAA' || this.config.complianceMode === 'ALL') {
      if (event.type === AuditEventType.PHI_ACCESS && event.details) {
        filtered.details = {
          accessType: event.details.accessType,
          recordId: event.details.recordId,
          // Remove actual PHI data
        };
      }
    }

    return filtered;
  }

  private setupAutoFlush(): void {
    this.flushTimer = setInterval(() => {
      this.flush();
    }, this.config.flushInterval);
  }

  private setupUnloadHandler(): void {
    window.addEventListener('beforeunload', () => {
      // Use sendBeacon for reliability
      if (this.eventQueue.length > 0 && navigator.sendBeacon) {
        const data = JSON.stringify({ events: this.eventQueue });
        navigator.sendBeacon(this.config.endpoint, data);
      }
    });
  }

  private storeLocally(event: AuditEvent, isFailedFlush = false): void {
    try {
      const key = isFailedFlush ? 'audit_events_failed' : 'audit_events';
      const stored = localStorage.getItem(key);
      const events: AuditEvent[] = stored ? JSON.parse(stored) : [];
      
      events.push(event);
      
      // Limit stored events
      if (events.length > this.config.maxLocalEvents) {
        events.splice(0, events.length - this.config.maxLocalEvents);
      }
      
      localStorage.setItem(key, JSON.stringify(events));
    } catch (error) {
      console.error('Failed to store audit event locally:', error);
    }
  }

  /**
   * Cleanup and shutdown
   */
  shutdown(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
    this.flush();
  }
}

// Export singleton instance
export const auditLogger = AuditLogger.getInstance();

/**
 * React hook for audit logging
 */
export function useAuditLog() {
  const logger = AuditLogger.getInstance();

  return {
    log: logger.log.bind(logger),
    logSecurity: logger.logSecurity.bind(logger),
    logDataAccess: logger.logDataAccess.bind(logger),
    logConsent: logger.logConsent.bind(logger),
    getUserAuditTrail: logger.getUserAuditTrail.bind(logger),
  };
}

/**
 * Audit log viewer component props
 */
export interface AuditLogViewerProps {
  userId?: string;
  eventTypes?: AuditEventType[];
  startDate?: Date;
  endDate?: Date;
  limit?: number;
}

/**
 * Format audit event for display
 */
export function formatAuditEvent(event: AuditEvent): {
  icon: string;
  color: string;
  title: string;
  description: string;
} {
  const formatMap: Record<string, { icon: string; color: string; title: string }> = {
    [AuditEventType.LOGIN_SUCCESS]: { icon: '🔓', color: 'green', title: 'Login Success' },
    [AuditEventType.LOGIN_FAILURE]: { icon: '🔒', color: 'red', title: 'Login Failed' },
    [AuditEventType.DATA_ACCESS]: { icon: '👁️', color: 'blue', title: 'Data Accessed' },
    [AuditEventType.SECURITY_ALERT]: { icon: '🚨', color: 'red', title: 'Security Alert' },
    // Add more mappings as needed
  };

  const format = formatMap[event.type] || { 
    icon: '📝', 
    color: 'gray', 
    title: event.type 
  };

  return {
    ...format,
    description: `${event.resource || 'System'} - ${event.result}`,
  };
}