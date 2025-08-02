/**
 * Security Monitoring and Alerting System
 * Real-time security event detection and reporting
 */

import { initializeSecurityMonitoring as initializeHeaders } from './headers';

/**
 * Security event types
 */
export enum SecurityEventType {
  // Authentication events
  LOGIN_SUCCESS = 'auth.login.success',
  LOGIN_FAILURE = 'auth.login.failure',
  LOGOUT = 'auth.logout',
  TOKEN_REFRESH_SUCCESS = 'auth.token.refresh.success',
  TOKEN_REFRESH_FAILURE = 'auth.token.refresh.failure',
  SESSION_EXPIRED = 'auth.session.expired',
  
  // Security violations
  CSRF_VIOLATION = 'security.csrf.violation',
  CSP_VIOLATION = 'security.csp.violation',
  XSS_ATTEMPT = 'security.xss.attempt',
  INJECTION_ATTEMPT = 'security.injection.attempt',
  
  // Access control
  UNAUTHORIZED_ACCESS = 'access.unauthorized',
  PERMISSION_DENIED = 'access.permission.denied',
  RATE_LIMIT_EXCEEDED = 'access.rate.limit.exceeded',
  
  // Data security
  DATA_ENCRYPTION_FAILURE = 'data.encryption.failure',
  DATA_DECRYPTION_FAILURE = 'data.decryption.failure',
  KEY_ROTATION = 'data.key.rotation',
  
  // System security
  MIXED_CONTENT = 'system.mixed.content',
  INSECURE_CONTEXT = 'system.insecure.context',
  STORAGE_TAMPERING = 'system.storage.tampering',
  
  // User behavior
  SUSPICIOUS_ACTIVITY = 'behavior.suspicious',
  MULTIPLE_FAILED_ATTEMPTS = 'behavior.multiple.failures',
  CONCURRENT_SESSIONS = 'behavior.concurrent.sessions'
}

/**
 * Security event severity levels
 */
export enum SecuritySeverity {
  INFO = 'info',
  WARNING = 'warning',
  ERROR = 'error',
  CRITICAL = 'critical'
}

/**
 * Security event interface
 */
export interface SecurityEvent {
  id: string;
  type: SecurityEventType;
  severity: SecuritySeverity;
  timestamp: number;
  message: string;
  details?: any;
  userId?: string;
  sessionId?: string;
  ipAddress?: string;
  userAgent?: string;
  url?: string;
  stackTrace?: string;
}

/**
 * Security monitoring configuration
 */
export interface SecurityMonitoringConfig {
  /** Enable real-time monitoring */
  enabled?: boolean;
  /** Monitoring endpoint URL */
  endpoint?: string;
  /** Batch size for event reporting */
  batchSize?: number;
  /** Batch interval in milliseconds */
  batchInterval?: number;
  /** Enable console logging */
  enableConsoleLogging?: boolean;
  /** Custom event handler */
  customHandler?: (event: SecurityEvent) => void;
  /** Events to monitor */
  monitoredEvents?: SecurityEventType[];
}

/**
 * Security alert rule
 */
export interface SecurityAlertRule {
  id: string;
  name: string;
  description: string;
  condition: (event: SecurityEvent) => boolean;
  action: (event: SecurityEvent) => void;
  cooldown?: number; // Milliseconds between alerts
  lastTriggered?: number;
}

/**
 * Security Monitoring System
 */
export class SecurityMonitor {
  private config: Required<SecurityMonitoringConfig>;
  private eventQueue: SecurityEvent[] = [];
  private batchTimer: ReturnType<typeof setTimeout> | null = null;
  private alertRules = new Map<string, SecurityAlertRule>();
  private eventListeners = new Map<SecurityEventType, Set<(event: SecurityEvent) => void>>();
  private sessionId: string;
  private isInitialized = false;

  constructor(config: SecurityMonitoringConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      endpoint: config.endpoint ?? '/api/security/events',
      batchSize: config.batchSize ?? 10,
      batchInterval: config.batchInterval ?? 5000,
      enableConsoleLogging: config.enableConsoleLogging ?? process.env.NODE_ENV === 'development',
      customHandler: config.customHandler ?? null,
      monitoredEvents: config.monitoredEvents ?? Object.values(SecurityEventType)
    };
    
    this.sessionId = this.generateSessionId();
  }

  /**
   * Initialize the security monitoring system
   */
  initialize(): void {
    if (this.isInitialized) return;
    
    // Initialize header monitoring
    initializeHeaders();
    
    // Set up global error handler
    this.setupGlobalErrorHandler();
    
    // Monitor authentication events
    this.monitorAuthEvents();
    
    // Monitor security violations
    this.monitorSecurityViolations();
    
    // Monitor storage events
    this.monitorStorageEvents();
    
    // Set up default alert rules
    this.setupDefaultAlertRules();
    
    // Start batch processing
    if (this.config.enabled) {
      this.startBatchProcessing();
    }
    
    this.isInitialized = true;
    
    // Log initialization
    this.logEvent({
      type: SecurityEventType.LOGIN_SUCCESS,
      severity: SecuritySeverity.INFO,
      message: 'Security monitoring initialized'
    });
  }

  /**
   * Log a security event
   */
  logEvent(event: Partial<SecurityEvent>): void {
    if (!this.config.enabled) return;

    const fullEvent: SecurityEvent = {
      id: this.generateEventId(),
      timestamp: Date.now(),
      sessionId: this.sessionId,
      userAgent: navigator.userAgent,
      url: window.location.href,
      ...event,
      type: event.type!,
      severity: event.severity!,
      message: event.message!
    };

    // Check if this event type is monitored
    if (!this.config.monitoredEvents.includes(fullEvent.type)) {
      return;
    }

    // Console logging
    if (this.config.enableConsoleLogging) {
      this.consoleLog(fullEvent);
    }

    // Custom handler
    if (this.config.customHandler) {
      try {
        this.config.customHandler(fullEvent);
      } catch (error) {
        console.error('Custom security handler error:', error);
      }
    }

    // Add to queue
    this.eventQueue.push(fullEvent);

    // Check alert rules
    this.checkAlertRules(fullEvent);

    // Notify listeners
    this.notifyListeners(fullEvent);

    // Flush if batch size reached
    if (this.eventQueue.length >= this.config.batchSize) {
      this.flushEvents();
    }
  }

  /**
   * Add an alert rule
   */
  addAlertRule(rule: SecurityAlertRule): void {
    this.alertRules.set(rule.id, rule);
  }

  /**
   * Remove an alert rule
   */
  removeAlertRule(ruleId: string): void {
    this.alertRules.delete(ruleId);
  }

  /**
   * Subscribe to specific event types
   */
  on(eventType: SecurityEventType, handler: (event: SecurityEvent) => void): () => void {
    if (!this.eventListeners.has(eventType)) {
      this.eventListeners.set(eventType, new Set());
    }
    
    this.eventListeners.get(eventType)!.add(handler);
    
    return () => {
      this.eventListeners.get(eventType)?.delete(handler);
    };
  }

  /**
   * Get security metrics
   */
  getMetrics(): {
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsBySeverity: Record<string, number>;
    recentEvents: SecurityEvent[];
  } {
    const eventsByType: Record<string, number> = {};
    const eventsBySeverity: Record<string, number> = {};
    
    for (const event of this.eventQueue) {
      eventsByType[event.type] = (eventsByType[event.type] || 0) + 1;
      eventsBySeverity[event.severity] = (eventsBySeverity[event.severity] || 0) + 1;
    }
    
    return {
      totalEvents: this.eventQueue.length,
      eventsByType,
      eventsBySeverity,
      recentEvents: this.eventQueue.slice(-10)
    };
  }

  /**
   * Setup global error handler
   */
  private setupGlobalErrorHandler(): void {
    window.addEventListener('error', (event) => {
      // Check for XSS patterns
      if (this.isXSSAttempt(event.message)) {
        this.logEvent({
          type: SecurityEventType.XSS_ATTEMPT,
          severity: SecuritySeverity.CRITICAL,
          message: 'Potential XSS attempt detected',
          details: {
            errorMessage: event.message,
            source: event.filename,
            line: event.lineno,
            column: event.colno
          }
        });
      }
    });

    // Monitor unhandled promise rejections
    window.addEventListener('unhandledrejection', (event) => {
      this.logEvent({
        type: SecurityEventType.LOGIN_FAILURE,
        severity: SecuritySeverity.WARNING,
        message: 'Unhandled promise rejection',
        details: {
          reason: event.reason
        }
      });
    });
  }

  /**
   * Monitor authentication events
   */
  private monitorAuthEvents(): void {
    // Listen for custom auth events
    window.addEventListener('auth:login:success', (event: any) => {
      this.logEvent({
        type: SecurityEventType.LOGIN_SUCCESS,
        severity: SecuritySeverity.INFO,
        message: 'User logged in successfully',
        userId: event.detail?.userId
      });
    });

    window.addEventListener('auth:login:failure', (event: any) => {
      this.logEvent({
        type: SecurityEventType.LOGIN_FAILURE,
        severity: SecuritySeverity.WARNING,
        message: 'Login attempt failed',
        details: event.detail
      });
    });

    window.addEventListener('auth:logout', (event: any) => {
      this.logEvent({
        type: SecurityEventType.LOGOUT,
        severity: SecuritySeverity.INFO,
        message: 'User logged out',
        userId: event.detail?.userId
      });
    });

    window.addEventListener('auth:token:refresh:failure', () => {
      this.logEvent({
        type: SecurityEventType.TOKEN_REFRESH_FAILURE,
        severity: SecuritySeverity.ERROR,
        message: 'Token refresh failed'
      });
    });
  }

  /**
   * Monitor security violations
   */
  private monitorSecurityViolations(): void {
    // CSP violations (already handled in headers.ts)
    document.addEventListener('securitypolicyviolation', (event) => {
      this.logEvent({
        type: SecurityEventType.CSP_VIOLATION,
        severity: SecuritySeverity.WARNING,
        message: `CSP violation: ${event.violatedDirective}`,
        details: {
          blockedURI: event.blockedURI,
          violatedDirective: event.violatedDirective,
          originalPolicy: event.originalPolicy
        }
      });
    });
  }

  /**
   * Monitor storage events
   */
  private monitorStorageEvents(): void {
    // Create monitored storage wrappers using Proxy
    const createMonitoredStorage = (storage: Storage): Storage => {
      return new Proxy(storage, {
        get(target, prop) {
          if (prop === 'setItem') {
            return function(key: string, value: string) {
              // Check for suspicious patterns
              if (securityMonitor.isSuspiciousStorageKey(key) || securityMonitor.isSuspiciousValue(value)) {
                securityMonitor.logEvent({
                  type: SecurityEventType.STORAGE_TAMPERING,
                  severity: SecuritySeverity.WARNING,
                  message: 'Suspicious storage activity detected',
                  details: { key, valueLength: value.length }
                });
              }
              return target.setItem(key, value);
            };
          }
          
          if (prop === 'removeItem') {
            return function(key: string) {
              // Log removal of security-critical keys
              if (securityMonitor.isSecurityKey(key)) {
                securityMonitor.logEvent({
                  type: SecurityEventType.STORAGE_TAMPERING,
                  severity: SecuritySeverity.WARNING,
                  message: 'Security-critical key removed from storage',
                  details: { key }
                });
              }
              return target.removeItem(key);
            };
          }
          
          // Pass through other properties/methods
          return Reflect.get(target, prop);
        }
      });
    };
    
    // Replace global storage objects with monitored versions
    try {
      Object.defineProperty(window, 'localStorage', {
        value: createMonitoredStorage(window.localStorage),
        writable: false,
        configurable: false
      });
      
      Object.defineProperty(window, 'sessionStorage', {
        value: createMonitoredStorage(window.sessionStorage),
        writable: false,
        configurable: false
      });
    } catch (error) {
      // Some browsers may not allow redefining storage objects
      this.log('Failed to set up storage monitoring', error);
    }
  }

  /**
   * Setup default alert rules
   */
  private setupDefaultAlertRules(): void {
    // Multiple failed login attempts
    this.addAlertRule({
      id: 'multiple-failures',
      name: 'Multiple Failed Login Attempts',
      description: 'Alert on multiple failed login attempts',
      condition: (event) => event.type === SecurityEventType.LOGIN_FAILURE,
      action: (event) => {
        // Count recent failures
        const recentFailures = this.eventQueue.filter(e => 
          e.type === SecurityEventType.LOGIN_FAILURE &&
          e.timestamp > Date.now() - 5 * 60 * 1000 // Last 5 minutes
        );
        
        if (recentFailures.length >= 3) {
          this.logEvent({
            type: SecurityEventType.MULTIPLE_FAILED_ATTEMPTS,
            severity: SecuritySeverity.WARNING,
            message: `${recentFailures.length} failed login attempts in the last 5 minutes`,
            details: { attempts: recentFailures.length }
          });
        }
      }
    });

    // Critical security violations
    this.addAlertRule({
      id: 'critical-violations',
      name: 'Critical Security Violations',
      description: 'Alert on critical security events',
      condition: (event) => event.severity === SecuritySeverity.CRITICAL,
      action: (event) => {
        console.error('🚨 CRITICAL SECURITY EVENT:', event);
        // In production, this would send to monitoring service
      },
      cooldown: 60000 // 1 minute cooldown
    });
  }

  /**
   * Check if string contains XSS patterns
   */
  private isXSSAttempt(str: string): boolean {
    const xssPatterns = [
      /<script[^>]*>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i,
      /eval\s*\(/i,
      /expression\s*\(/i
    ];
    
    return xssPatterns.some(pattern => pattern.test(str));
  }

  /**
   * Check if storage key is suspicious
   */
  private isSuspiciousStorageKey(key: string): boolean {
    const suspiciousPatterns = [
      /^__proto__$/,
      /^constructor$/,
      /prototype/i,
      /\$\{.*\}/,
      /<script/i
    ];
    
    return suspiciousPatterns.some(pattern => pattern.test(key));
  }

  /**
   * Check if value is suspicious
   */
  private isSuspiciousValue(value: string): boolean {
    return this.isXSSAttempt(value) || value.length > 1024 * 1024; // 1MB limit
  }

  /**
   * Check if key is security-critical
   */
  private isSecurityKey(key: string): boolean {
    const securityKeys = [
      'auth_token',
      'refresh_token',
      'csrf_token',
      'session_id',
      'user_credentials'
    ];
    
    return securityKeys.some(k => key.includes(k));
  }

  /**
   * Check alert rules
   */
  private checkAlertRules(event: SecurityEvent): void {
    for (const rule of this.alertRules.values()) {
      // Check cooldown
      if (rule.cooldown && rule.lastTriggered) {
        if (Date.now() - rule.lastTriggered < rule.cooldown) {
          continue;
        }
      }
      
      // Check condition
      if (rule.condition(event)) {
        try {
          rule.action(event);
          rule.lastTriggered = Date.now();
        } catch (error) {
          console.error(`Alert rule ${rule.id} error:`, error);
        }
      }
    }
  }

  /**
   * Notify event listeners
   */
  private notifyListeners(event: SecurityEvent): void {
    const listeners = this.eventListeners.get(event.type);
    if (listeners) {
      listeners.forEach(handler => {
        try {
          handler(event);
        } catch (error) {
          console.error('Event listener error:', error);
        }
      });
    }
  }

  /**
   * Start batch processing
   */
  private startBatchProcessing(): void {
    this.batchTimer = setInterval(() => {
      if (this.eventQueue.length > 0) {
        this.flushEvents();
      }
    }, this.config.batchInterval);
  }

  /**
   * Flush events to server
   */
  private async flushEvents(): Promise<void> {
    if (this.eventQueue.length === 0) return;
    
    const events = [...this.eventQueue];
    this.eventQueue = [];
    
    try {
      await fetch(this.config.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ events })
      });
    } catch (error) {
      console.error('Failed to send security events:', error);
      // Re-queue events on failure
      this.eventQueue.unshift(...events);
    }
  }

  /**
   * Console log event
   */
  private consoleLog(event: SecurityEvent): void {
    const emoji = {
      [SecuritySeverity.INFO]: 'ℹ️',
      [SecuritySeverity.WARNING]: '⚠️',
      [SecuritySeverity.ERROR]: '❌',
      [SecuritySeverity.CRITICAL]: '🚨'
    };
    
    const color = {
      [SecuritySeverity.INFO]: 'color: blue',
      [SecuritySeverity.WARNING]: 'color: orange',
      [SecuritySeverity.ERROR]: 'color: red',
      [SecuritySeverity.CRITICAL]: 'color: red; font-weight: bold'
    };
    
    console.log(
      `%c${emoji[event.severity]} [Security] ${event.message}`,
      color[event.severity],
      {
        type: event.type,
        severity: event.severity,
        details: event.details,
        timestamp: new Date(event.timestamp).toISOString()
      }
    );
  }

  /**
   * Generate session ID
   */
  private generateSessionId(): string {
    return `session_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Generate event ID
   */
  private generateEventId(): string {
    return `event_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }

  /**
   * Clean up resources
   */
  dispose(): void {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
    
    // Flush remaining events
    this.flushEvents();
    
    this.alertRules.clear();
    this.eventListeners.clear();
    this.eventQueue = [];
  }
}

// Create singleton instance
export const securityMonitor = new SecurityMonitor();

// Initialize on load
if (typeof window !== 'undefined') {
  // Wait for DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      securityMonitor.initialize();
    });
  } else {
    securityMonitor.initialize();
  }
}

// Export convenience functions
export function logSecurityEvent(event: Partial<SecurityEvent>): void {
  securityMonitor.logEvent(event);
}

export function onSecurityEvent(
  eventType: SecurityEventType,
  handler: (event: SecurityEvent) => void
): () => void {
  return securityMonitor.on(eventType, handler);
}