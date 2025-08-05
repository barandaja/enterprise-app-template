"""
Audit logging model for comprehensive compliance tracking.
Implements GDPR, HIPAA, and SOC2 compliant audit trails.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, ForeignKey, 
    Boolean, Index, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import structlog

from .base import BaseModel
from .encryption import EncryptedField
from ..core.config import settings

logger = structlog.get_logger()


class AuditEventType(str, Enum):
    """Audit event types for categorization."""
    
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    
    # Authorization events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    
    # Data access events
    DATA_READ = "data_read"
    DATA_CREATE = "data_create"
    DATA_UPDATE = "data_update"
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"
    
    # Administrative events
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    USER_ACTIVATED = "user_activated"
    USER_DEACTIVATED = "user_deactivated"
    
    # System events
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    CONFIG_CHANGE = "config_change"
    BACKUP_CREATED = "backup_created"
    
    # Security events
    SECURITY_ALERT = "security_alert"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    
    # Token events
    TOKEN_CREATED = "token_created"
    TOKEN_REFRESHED = "token_refreshed"
    
    # Session events
    SESSION_CREATED = "session_created"
    SESSION_ENDED = "session_ended"
    
    # Compliance events
    GDPR_DATA_REQUEST = "gdpr_data_request"
    GDPR_DATA_DELETE = "gdpr_data_delete"
    GDPR_DATA_ACCESS = "gdpr_data_access"
    GDPR_CONSENT_UPDATE = "gdpr_consent_update"
    HIPAA_ACCESS = "hipaa_access"
    SOC2_CONTROL_CHECK = "soc2_control_check"
    
    # System events (additional)
    SYSTEM_ERROR = "system_error"
    
    # Permission events (additional)
    PERMISSION_REVOKED = "permission_revoked"
    
    @classmethod
    def _missing_(cls, value):
        """Handle missing enum values for backward compatibility."""
        if isinstance(value, str):
            # Convert uppercase to lowercase for backward compatibility
            value_lower = value.lower()
            for member in cls:
                if member.value == value_lower:
                    return member
            # If no match found, try to find by name (case-insensitive)
            for member in cls:
                if member.name.lower() == value_lower:
                    return member
        return None


class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @classmethod
    def _missing_(cls, value):
        """Handle missing enum values for backward compatibility."""
        if isinstance(value, str):
            # Convert uppercase to lowercase for backward compatibility
            value_lower = value.lower()
            for member in cls:
                if member.value == value_lower:
                    return member
            # If no match found, try to find by name (case-insensitive)
            for member in cls:
                if member.name.lower() == value_lower:
                    return member
        return None


class AuditLog(BaseModel):
    """Comprehensive audit log model for compliance tracking."""
    
    __tablename__ = 'audit_log'
    
    # Event identification
    event_type = Column(SQLEnum(AuditEventType, values_callable=lambda x: [e.value for e in x]), nullable=False, index=True)
    event_id = Column(String(128), unique=True, nullable=False, index=True)  # UUID for tracing
    correlation_id = Column(String(128), nullable=True, index=True)  # For tracing related events
    
    # Event metadata
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    severity = Column(SQLEnum(AuditSeverity, values_callable=lambda x: [e.value for e in x]), default=AuditSeverity.LOW, nullable=False)
    
    # User and session context
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    impersonator_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)  # For impersonation
    
    # Request context
    ip_address = Column(String(45), nullable=True, index=True)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    request_method = Column(String(10), nullable=True)
    request_path = Column(String(500), nullable=True)
    request_id = Column(String(128), nullable=True, index=True)
    
    # Resource information
    resource_type = Column(String(100), nullable=True, index=True)  # e.g., 'user', 'role'
    resource_id = Column(String(100), nullable=True, index=True)    # Resource identifier
    resource_name = Column(String(255), nullable=True)             # Human-readable name
    
    # Event details
    action = Column(String(100), nullable=False, index=True)        # Action performed
    description = Column(Text, nullable=False)                     # Human-readable description
    event_data = EncryptedField("json", nullable=True)            # Additional event data (encrypted)
    
    # Result information
    success = Column(Boolean, nullable=False, index=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Compliance flags
    pii_accessed = Column(Boolean, default=False, nullable=False, index=True)
    gdpr_relevant = Column(Boolean, default=False, nullable=False, index=True)
    hipaa_relevant = Column(Boolean, default=False, nullable=False, index=True)
    
    # Technical details
    execution_time_ms = Column(Integer, nullable=True)  # Request processing time
    response_status = Column(Integer, nullable=True)    # HTTP status code
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id], back_populates="audit_logs")
    impersonator_user = relationship("User", foreign_keys=[impersonator_user_id])
    
    __table_args__ = (
        Index('idx_audit_user_timestamp', 'user_id', 'timestamp'),
        Index('idx_audit_event_timestamp', 'event_type', 'timestamp'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
        Index('idx_audit_compliance', 'gdpr_relevant', 'hipaa_relevant'),
        Index('idx_audit_security', 'severity', 'success'),
    )
    
    @classmethod
    async def create_audit_log(
        cls,
        db: AsyncSession,
        event_type: AuditEventType,
        action: str,
        description: str,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        success: bool = True,
        severity: AuditSeverity = AuditSeverity.LOW,
        event_data: Optional[Dict[str, Any]] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        correlation_id: Optional[str] = None,
        pii_accessed: bool = False,
        execution_time_ms: Optional[int] = None,
        **kwargs
    ) -> Optional['AuditLog']:
        """Create a new audit log entry with error handling bypass."""
        import uuid
        
        try:
            # Determine compliance relevance
            gdpr_relevant = pii_accessed or event_type in [
                AuditEventType.GDPR_DATA_REQUEST,
                AuditEventType.GDPR_DATA_DELETE,
                AuditEventType.DATA_EXPORT
            ]
            
            hipaa_relevant = (
                pii_accessed or 
                settings.HIPAA_COMPLIANT_MODE and 
                event_type in [
                    AuditEventType.DATA_READ,
                    AuditEventType.DATA_CREATE,
                    AuditEventType.DATA_UPDATE,
                    AuditEventType.DATA_DELETE,
                    AuditEventType.HIPAA_ACCESS
                ]
            )
            
            audit_log = cls(
                event_type=event_type,
                event_id=str(uuid.uuid4()),
                correlation_id=correlation_id,
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource_type=resource_type,
                resource_id=resource_id,
                resource_name=resource_name,
                action=action,
                description=description,
                event_data=event_data or {},
                success=success,
                severity=severity,
                error_code=error_code,
                error_message=error_message,
                pii_accessed=pii_accessed,
                gdpr_relevant=gdpr_relevant,
                hipaa_relevant=hipaa_relevant,
                execution_time_ms=execution_time_ms,
                **kwargs
            )
            
            return await audit_log.save(db)
            
        except Exception as e:
            # Log the actual error details for debugging
            logger.error(
                "Audit logging failed - this indicates a database or schema issue",
                event_type=event_type.value if hasattr(event_type, 'value') else str(event_type),
                action=action,
                description=description,
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__
            )
            
            # Re-raise the original exception instead of masking it
            # This will help identify the real underlying issue
            raise
    
    @classmethod
    async def get_user_audit_trail(
        cls,
        db: AsyncSession,
        user_id: int,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        limit: int = 100
    ) -> List['AuditLog']:
        """Get audit trail for a specific user."""
        query = select(cls).where(cls.user_id == user_id)
        
        if start_date:
            query = query.where(cls.timestamp >= start_date)
        
        if end_date:
            query = query.where(cls.timestamp <= end_date)
        
        if event_types:
            query = query.where(cls.event_type.in_(event_types))
        
        query = query.order_by(cls.timestamp.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def get_security_events(
        cls,
        db: AsyncSession,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None,
        limit: int = 100
    ) -> List['AuditLog']:
        """Get security-related audit events."""
        security_events = [
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.ACCOUNT_LOCKED,
            AuditEventType.PERMISSION_DENIED,
            AuditEventType.SECURITY_ALERT,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.UNAUTHORIZED_ACCESS
        ]
        
        query = select(cls).where(cls.event_type.in_(security_events))
        
        if start_date:
            query = query.where(cls.timestamp >= start_date)
        
        if end_date:
            query = query.where(cls.timestamp <= end_date)
        
        if severity:
            query = query.where(cls.severity == severity)
        
        query = query.order_by(cls.timestamp.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def get_compliance_events(
        cls,
        db: AsyncSession,
        compliance_type: str,  # 'gdpr' or 'hipaa'
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List['AuditLog']:
        """Get compliance-related audit events."""
        if compliance_type.lower() == 'gdpr':
            query = select(cls).where(cls.gdpr_relevant == True)
        elif compliance_type.lower() == 'hipaa':
            query = select(cls).where(cls.hipaa_relevant == True)
        else:
            raise ValueError("compliance_type must be 'gdpr' or 'hipaa'")
        
        if start_date:
            query = query.where(cls.timestamp >= start_date)
        
        if end_date:
            query = query.where(cls.timestamp <= end_date)
        
        query = query.order_by(cls.timestamp.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def cleanup_old_logs(
        cls,
        db: AsyncSession,
        retention_days: int = None
    ) -> int:
        """Clean up old audit logs based on retention policy."""
        retention_days = retention_days or settings.GDPR_DATA_RETENTION_DAYS
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # Only delete non-critical logs older than retention period
        old_logs = await db.execute(
            select(cls).where(
                cls.timestamp < cutoff_date,
                cls.severity.in_([AuditSeverity.LOW, AuditSeverity.MEDIUM])
            )
        )
        
        count = 0
        for log in old_logs.scalars():
            await log.delete(db, hard_delete=True)
            count += 1
        
        logger.info("Cleaned up old audit logs", count=count, cutoff_date=cutoff_date)
        return count
    
    def to_dict(self, exclude: Optional[set] = None) -> Dict[str, Any]:
        """Convert audit log to dictionary for API responses."""
        exclude = exclude or set()
        data = super().to_dict(exclude)
        
        # Add computed fields
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        
        return data
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, event_type={self.event_type}, user_id={self.user_id})>"


class AuditLogger:
    """Service for creating audit log entries."""
    
    def __init__(self):
        self.logger = structlog.get_logger("audit")
    
    async def log_auth_event(
        self,
        db: AsyncSession,
        event_type: AuditEventType,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        description: str = "",
        **kwargs
    ) -> Optional[AuditLog]:
        """Log authentication-related events."""
        severity = AuditSeverity.MEDIUM if not success else AuditSeverity.LOW
        
        return await AuditLog.create_audit_log(
            db=db,
            event_type=event_type,
            action="authentication",
            description=description,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            success=success,
            severity=severity,
            **kwargs
        )
    
    async def log_data_access(
        self,
        db: AsyncSession,
        action: str,
        resource_type: str,
        resource_id: str,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        pii_accessed: bool = False,
        success: bool = True,
        description: str = "",
        **kwargs
    ) -> Optional[AuditLog]:
        """Log data access events."""
        event_type = getattr(AuditEventType, f"DATA_{action.upper()}", AuditEventType.DATA_READ)
        severity = AuditSeverity.MEDIUM if pii_accessed else AuditSeverity.LOW
        
        return await AuditLog.create_audit_log(
            db=db,
            event_type=event_type,
            action=action,
            description=description,
            user_id=user_id,
            session_id=session_id,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            severity=severity,
            pii_accessed=pii_accessed,
            **kwargs
        )
    
    async def log_security_event(
        self,
        db: AsyncSession,
        event_type: AuditEventType,
        description: str,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        severity: AuditSeverity = AuditSeverity.HIGH,
        **kwargs
    ) -> Optional[AuditLog]:
        """Log security-related events."""
        return await AuditLog.create_audit_log(
            db=db,
            event_type=event_type,
            action="security_check",
            description=description,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            success=False,  # Security events are typically failures
            severity=severity,
            **kwargs
        )