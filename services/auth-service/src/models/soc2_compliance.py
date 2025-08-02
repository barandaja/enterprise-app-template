"""
SOC2 Compliance models for incident response, anomaly detection, vendor access management,
and change management tracking. Implements the five Trust Service Criteria.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, 
    Text, Index, Enum as SQLEnum, UniqueConstraint, JSON, Float
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import structlog
import uuid

from .base import BaseModel
from .encryption import EncryptedField

logger = structlog.get_logger()


class TrustServiceCriteria(str, Enum):
    """SOC2 Trust Service Criteria."""
    
    SECURITY = "security"                    # Common Criteria (CC)
    AVAILABILITY = "availability"            # Additional Criteria (A)
    PROCESSING_INTEGRITY = "processing_integrity"  # Additional Criteria (PI)
    CONFIDENTIALITY = "confidentiality"      # Additional Criteria (C)
    PRIVACY = "privacy"                      # Additional Criteria (P)


class IncidentSeverity(str, Enum):
    """Incident severity levels for SOC2 compliance."""
    
    LOW = "low"                             # Low impact, minimal disruption
    MEDIUM = "medium"                       # Medium impact, some disruption
    HIGH = "high"                           # High impact, significant disruption
    CRITICAL = "critical"                   # Critical impact, major disruption


class IncidentStatus(str, Enum):
    """Incident response status."""
    
    OPEN = "open"                           # Incident reported and open
    IN_PROGRESS = "in_progress"             # Investigation/remediation in progress
    ESCALATED = "escalated"                 # Escalated to higher level
    RESOLVED = "resolved"                   # Incident resolved
    CLOSED = "closed"                       # Incident closed and documented
    REOPENED = "reopened"                   # Previously closed, now reopened


class IncidentCategory(str, Enum):
    """Categories of security incidents."""
    
    SECURITY_BREACH = "security_breach"      # Data breach or security compromise
    UNAUTHORIZED_ACCESS = "unauthorized_access"  # Unauthorized system access
    SYSTEM_OUTAGE = "system_outage"         # System availability issues
    DATA_LOSS = "data_loss"                 # Data loss or corruption
    MALWARE = "malware"                     # Malware detection
    PHISHING = "phishing"                   # Phishing attempts
    POLICY_VIOLATION = "policy_violation"    # Security policy violations
    VULNERABILITY = "vulnerability"          # Security vulnerability
    PERFORMANCE = "performance"             # Performance degradation
    COMPLIANCE = "compliance"               # Compliance violations
    OTHER = "other"                         # Other incidents


class AnomalyType(str, Enum):
    """Types of security anomalies detected."""
    
    LOGIN_ANOMALY = "login_anomaly"         # Unusual login patterns
    ACCESS_PATTERN = "access_pattern"       # Unusual access patterns
    DATA_VOLUME = "data_volume"             # Unusual data access volume
    TIME_PATTERN = "time_pattern"           # Access outside normal hours
    LOCATION_ANOMALY = "location_anomaly"   # Access from unusual locations
    PERMISSION_ESCALATION = "permission_escalation"  # Privilege escalation
    FAILED_ATTEMPTS = "failed_attempts"     # Multiple failed attempts
    RESOURCE_USAGE = "resource_usage"       # Unusual resource usage
    NETWORK_TRAFFIC = "network_traffic"     # Unusual network patterns
    SYSTEM_BEHAVIOR = "system_behavior"     # Unusual system behavior


class ChangeType(str, Enum):
    """Types of changes for change management."""
    
    STANDARD = "standard"                   # Pre-approved standard changes
    NORMAL = "normal"                       # Normal changes requiring approval
    EMERGENCY = "emergency"                 # Emergency changes
    CONFIGURATION = "configuration"         # Configuration changes
    ACCESS_CONTROL = "access_control"       # Access control changes
    SECURITY_POLICY = "security_policy"     # Security policy changes
    SYSTEM_UPDATE = "system_update"         # System updates/patches
    USER_MANAGEMENT = "user_management"     # User account changes
    ROLE_PERMISSION = "role_permission"     # Role/permission changes
    DATA_SCHEMA = "data_schema"             # Database schema changes


class ChangeStatus(str, Enum):
    """Status of change requests."""
    
    REQUESTED = "requested"                 # Change requested
    APPROVED = "approved"                   # Change approved
    REJECTED = "rejected"                   # Change rejected
    IN_PROGRESS = "in_progress"             # Change implementation in progress
    COMPLETED = "completed"                 # Change completed successfully
    FAILED = "failed"                       # Change implementation failed
    ROLLED_BACK = "rolled_back"             # Change rolled back
    UNDER_REVIEW = "under_review"           # Change under review


class VendorAccessLevel(str, Enum):
    """Vendor access levels."""
    
    NO_ACCESS = "no_access"                 # No system access
    LIMITED = "limited"                     # Limited read-only access
    STANDARD = "standard"                   # Standard operational access
    ELEVATED = "elevated"                   # Elevated administrative access
    FULL_ADMIN = "full_admin"               # Full administrative access


class SecurityIncident(BaseModel):
    """Security incident tracking for SOC2 compliance."""
    
    __tablename__ = 'security_incident'
    
    # Incident identification
    incident_id = Column(String(128), unique=True, nullable=False, index=True)
    incident_number = Column(String(50), unique=True, nullable=False, index=True)
    
    # Incident classification
    category = Column(SQLEnum(IncidentCategory), nullable=False, index=True)
    severity = Column(SQLEnum(IncidentSeverity), nullable=False, index=True)
    trust_criteria_affected = Column(JSON, nullable=False)  # List of affected criteria
    
    # Incident details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    
    # Timeline
    detected_at = Column(DateTime(timezone=True), nullable=False, index=True)
    reported_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    
    # Status tracking
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False, index=True)
    
    # Impact assessment
    systems_affected = Column(JSON, nullable=True)  # List of affected systems
    users_affected_count = Column(Integer, nullable=True)
    data_affected = Column(Boolean, default=False, nullable=False)
    customer_impact = Column(Boolean, default=False, nullable=False)
    
    # Response team
    reported_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    assigned_to_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    incident_commander_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Root cause and resolution
    root_cause = Column(Text, nullable=True)
    resolution_summary = Column(Text, nullable=True)
    corrective_actions = Column(JSON, nullable=True)  # List of corrective actions
    
    # External reporting
    external_reporting_required = Column(Boolean, default=False, nullable=False)
    regulatory_notification_sent = Column(Boolean, default=False, nullable=False)
    customer_notification_sent = Column(Boolean, default=False, nullable=False)
    
    # Evidence and documentation (encrypted)
    evidence_collected = EncryptedField("json", nullable=True)
    incident_notes = EncryptedField("json", nullable=True)  # Chronological notes
    
    # Relationships
    reported_by_user = relationship("User", foreign_keys=[reported_by_user_id])
    assigned_to_user = relationship("User", foreign_keys=[assigned_to_user_id])
    incident_commander = relationship("User", foreign_keys=[incident_commander_id])
    
    __table_args__ = (
        Index('idx_incident_category_severity', 'category', 'severity'),
        Index('idx_incident_status_detected', 'status', 'detected_at'),
        Index('idx_incident_assigned', 'assigned_to_user_id', 'status'),
    )
    
    @classmethod
    async def create_incident(
        cls,
        db: AsyncSession,
        category: IncidentCategory,
        severity: IncidentSeverity,
        title: str,
        description: str,
        trust_criteria_affected: List[str],
        detected_at: Optional[datetime] = None,
        reported_by_user_id: Optional[int] = None,
        **kwargs
    ) -> 'SecurityIncident':
        """Create a new security incident."""
        # Generate incident number
        incident_count = await db.execute(
            select(cls).where(cls.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0))
        )
        daily_count = len(incident_count.scalars().all()) + 1
        incident_number = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{daily_count:04d}"
        
        incident = cls(
            incident_id=str(uuid.uuid4()),
            incident_number=incident_number,
            category=category,
            severity=severity,
            title=title,
            description=description,
            trust_criteria_affected=trust_criteria_affected,
            detected_at=detected_at or datetime.utcnow(),
            reported_by_user_id=reported_by_user_id,
            **kwargs
        )
        
        return await incident.save(db)
    
    @classmethod
    async def get_open_incidents(cls, db: AsyncSession) -> List['SecurityIncident']:
        """Get all open incidents."""
        query = select(cls).where(
            cls.status.in_([IncidentStatus.OPEN, IncidentStatus.IN_PROGRESS, IncidentStatus.ESCALATED])
        ).order_by(cls.severity.desc(), cls.detected_at.desc())
        
        result = await db.execute(query)
        return result.scalars().all()
    
    async def acknowledge(self, db: AsyncSession, user_id: int) -> None:
        """Acknowledge the incident."""
        self.acknowledged_at = datetime.utcnow()
        self.assigned_to_user_id = user_id
        self.status = IncidentStatus.IN_PROGRESS
        await self.save(db)
    
    async def resolve(
        self, 
        db: AsyncSession, 
        resolution_summary: str,
        root_cause: Optional[str] = None,
        corrective_actions: Optional[List[str]] = None
    ) -> None:
        """Resolve the incident."""
        self.resolved_at = datetime.utcnow()
        self.status = IncidentStatus.RESOLVED
        self.resolution_summary = resolution_summary
        self.root_cause = root_cause
        self.corrective_actions = corrective_actions or []
        await self.save(db)
    
    def get_response_time_minutes(self) -> Optional[int]:
        """Get incident response time in minutes."""
        if not self.acknowledged_at:
            return None
        
        return int((self.acknowledged_at - self.reported_at).total_seconds() / 60)
    
    def get_resolution_time_hours(self) -> Optional[float]:
        """Get incident resolution time in hours."""
        if not self.resolved_at:
            return None
        
        return (self.resolved_at - self.reported_at).total_seconds() / 3600


class SecurityAnomaly(BaseModel):
    """Security anomaly detection for proactive monitoring."""
    
    __tablename__ = 'security_anomaly'
    
    # Anomaly identification
    anomaly_id = Column(String(128), unique=True, nullable=False, index=True)
    anomaly_type = Column(SQLEnum(AnomalyType), nullable=False, index=True)
    
    # Detection details
    detected_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    detection_source = Column(String(100), nullable=False)  # System/service that detected anomaly
    confidence_score = Column(Float, nullable=False)  # 0.0 to 1.0 confidence level
    
    # Subject information
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True, index=True)
    
    # Anomaly details
    description = Column(Text, nullable=False)
    baseline_behavior = Column(JSON, nullable=True)  # Normal behavior pattern
    anomalous_behavior = Column(JSON, nullable=False)  # Detected anomalous behavior
    
    # Risk assessment
    risk_score = Column(Float, nullable=False)  # 0.0 to 10.0 risk score
    potential_impact = Column(String(100), nullable=False)  # Description of potential impact
    
    # Response status
    investigated = Column(Boolean, default=False, nullable=False)
    false_positive = Column(Boolean, default=False, nullable=False)
    incident_created = Column(Boolean, default=False, nullable=False)
    security_incident_id = Column(String(128), ForeignKey('security_incident.incident_id'), nullable=True)
    
    # Investigation details
    investigated_at = Column(DateTime(timezone=True), nullable=True)
    investigated_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    investigation_notes = Column(Text, nullable=True)
    
    # Raw data (encrypted)
    raw_event_data = EncryptedField("json", nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    investigated_by_user = relationship("User", foreign_keys=[investigated_by_user_id])
    security_incident = relationship("SecurityIncident")
    
    __table_args__ = (
        Index('idx_anomaly_type_detected', 'anomaly_type', 'detected_at'),
        Index('idx_anomaly_user_detected', 'user_id', 'detected_at'),
        Index('idx_anomaly_risk_score', 'risk_score'),
        Index('idx_anomaly_investigation', 'investigated', 'detected_at'),
    )
    
    @classmethod
    async def create_anomaly(
        cls,
        db: AsyncSession,
        anomaly_type: AnomalyType,
        description: str,
        anomalous_behavior: Dict[str, Any],
        confidence_score: float,
        risk_score: float,
        potential_impact: str,
        detection_source: str,
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        baseline_behavior: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> 'SecurityAnomaly':
        """Create a new security anomaly."""
        anomaly = cls(
            anomaly_id=str(uuid.uuid4()),
            anomaly_type=anomaly_type,
            description=description,
            anomalous_behavior=anomalous_behavior,
            confidence_score=confidence_score,
            risk_score=risk_score,
            potential_impact=potential_impact,
            detection_source=detection_source,
            user_id=user_id,
            session_id=session_id,
            ip_address=ip_address,
            baseline_behavior=baseline_behavior,
            **kwargs
        )
        
        return await anomaly.save(db)
    
    @classmethod
    async def get_high_risk_anomalies(
        cls, 
        db: AsyncSession, 
        risk_threshold: float = 7.0,
        limit: int = 100
    ) -> List['SecurityAnomaly']:
        """Get high-risk anomalies requiring investigation."""
        query = select(cls).where(
            cls.risk_score >= risk_threshold,
            cls.investigated == False
        ).order_by(cls.risk_score.desc(), cls.detected_at.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    async def mark_investigated(
        self,
        db: AsyncSession,
        investigated_by_user_id: int,
        investigation_notes: Optional[str] = None,
        false_positive: bool = False
    ) -> None:
        """Mark anomaly as investigated."""
        self.investigated = True
        self.investigated_at = datetime.utcnow()
        self.investigated_by_user_id = investigated_by_user_id
        self.investigation_notes = investigation_notes
        self.false_positive = false_positive
        
        await self.save(db)


class VendorAccess(BaseModel):
    """Vendor access management for SOC2 compliance."""
    
    __tablename__ = 'vendor_access'
    
    # Access identification
    access_id = Column(String(128), unique=True, nullable=False, index=True)
    vendor_name = Column(String(255), nullable=False, index=True)
    vendor_contact_email = EncryptedField("string", nullable=False)
    
    # Access details
    access_level = Column(SQLEnum(VendorAccessLevel), nullable=False, index=True)
    systems_accessed = Column(JSON, nullable=False)  # List of systems/services
    access_purpose = Column(Text, nullable=False)
    business_justification = Column(Text, nullable=False)
    
    # Time constraints
    access_start_date = Column(DateTime(timezone=True), nullable=False, index=True)
    access_end_date = Column(DateTime(timezone=True), nullable=False, index=True)
    last_accessed = Column(DateTime(timezone=True), nullable=True)
    
    # Approval workflow
    requested_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    approved_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    
    # Status tracking
    is_active = Column(Boolean, default=False, nullable=False, index=True)
    is_revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    revocation_reason = Column(Text, nullable=True)
    
    # Security requirements
    mfa_required = Column(Boolean, default=True, nullable=False)
    vpn_required = Column(Boolean, default=True, nullable=False)
    ip_restrictions = Column(JSON, nullable=True)  # List of allowed IP ranges
    
    # Monitoring and compliance
    activity_monitored = Column(Boolean, default=True, nullable=False)
    data_access_logged = Column(Boolean, default=True, nullable=False)
    compliance_reviewed = Column(Boolean, default=False, nullable=False)
    
    # Additional metadata (encrypted)
    vendor_metadata = EncryptedField("json", nullable=True)
    access_credentials = EncryptedField("json", nullable=True)  # If managed credentials
    
    # Relationships
    requested_by_user = relationship("User", foreign_keys=[requested_by_user_id])
    approved_by_user = relationship("User", foreign_keys=[approved_by_user_id])
    revoked_by_user = relationship("User", foreign_keys=[revoked_by_user_id])
    
    __table_args__ = (
        Index('idx_vendor_access_dates', 'access_start_date', 'access_end_date'),
        Index('idx_vendor_access_status', 'is_active', 'is_revoked'),
        Index('idx_vendor_access_level', 'access_level', 'is_active'),
    )
    
    @classmethod
    async def create_vendor_access(
        cls,
        db: AsyncSession,
        vendor_name: str,
        vendor_contact_email: str,
        access_level: VendorAccessLevel,
        systems_accessed: List[str],
        access_purpose: str,
        business_justification: str,
        access_start_date: datetime,
        access_end_date: datetime,
        requested_by_user_id: int,
        **kwargs
    ) -> 'VendorAccess':
        """Create new vendor access request."""
        vendor_access = cls(
            access_id=str(uuid.uuid4()),
            vendor_name=vendor_name,
            vendor_contact_email=vendor_contact_email,
            access_level=access_level,
            systems_accessed=systems_accessed,
            access_purpose=access_purpose,
            business_justification=business_justification,
            access_start_date=access_start_date,
            access_end_date=access_end_date,
            requested_by_user_id=requested_by_user_id,
            **kwargs
        )
        
        return await vendor_access.save(db)
    
    @classmethod
    async def get_active_vendor_access(cls, db: AsyncSession) -> List['VendorAccess']:
        """Get all active vendor access grants."""
        now = datetime.utcnow()
        query = select(cls).where(
            cls.is_active == True,
            cls.is_revoked == False,
            cls.access_start_date <= now,
            cls.access_end_date > now
        ).order_by(cls.access_end_date)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def get_expiring_access(
        cls, 
        db: AsyncSession, 
        days_ahead: int = 7
    ) -> List['VendorAccess']:
        """Get vendor access expiring within specified days."""
        now = datetime.utcnow()
        expiry_threshold = now + timedelta(days=days_ahead)
        
        query = select(cls).where(
            cls.is_active == True,
            cls.is_revoked == False,
            cls.access_end_date <= expiry_threshold,
            cls.access_end_date > now
        ).order_by(cls.access_end_date)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    async def approve_access(
        self,
        db: AsyncSession,
        approved_by_user_id: int
    ) -> None:
        """Approve vendor access request."""
        self.approved_by_user_id = approved_by_user_id
        self.approved_at = datetime.utcnow()
        self.is_active = True
        
        await self.save(db)
    
    async def revoke_access(
        self,
        db: AsyncSession,
        revoked_by_user_id: int,
        revocation_reason: Optional[str] = None
    ) -> None:
        """Revoke vendor access."""
        self.is_revoked = True
        self.revoked_at = datetime.utcnow()
        self.revoked_by_user_id = revoked_by_user_id
        self.revocation_reason = revocation_reason
        self.is_active = False
        
        await self.save(db)
    
    def is_expired(self) -> bool:
        """Check if vendor access has expired."""
        return datetime.utcnow() > self.access_end_date


class ChangeManagement(BaseModel):
    """Change management tracking for SOC2 compliance."""
    
    __tablename__ = 'change_management'
    
    # Change identification
    change_id = Column(String(128), unique=True, nullable=False, index=True)
    change_number = Column(String(50), unique=True, nullable=False, index=True)
    
    # Change classification
    change_type = Column(SQLEnum(ChangeType), nullable=False, index=True)
    risk_level = Column(String(20), nullable=False, default="medium")  # low, medium, high, critical
    
    # Change details
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    business_justification = Column(Text, nullable=False)
    
    # Systems and impact
    systems_affected = Column(JSON, nullable=False)  # List of affected systems
    trust_criteria_impact = Column(JSON, nullable=False)  # SOC2 criteria impacted
    estimated_downtime_minutes = Column(Integer, nullable=True)
    
    # Timing
    requested_implementation_date = Column(DateTime(timezone=True), nullable=False)
    actual_implementation_date = Column(DateTime(timezone=True), nullable=True)
    completion_date = Column(DateTime(timezone=True), nullable=True)
    
    # Status tracking
    status = Column(SQLEnum(ChangeStatus), default=ChangeStatus.REQUESTED, nullable=False, index=True)
    
    # Personnel
    requested_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
    approved_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    implemented_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Review and approval
    approval_required = Column(Boolean, default=True, nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    
    # Implementation details
    implementation_steps = Column(JSON, nullable=False)  # List of implementation steps
    rollback_plan = Column(Text, nullable=False)
    testing_plan = Column(Text, nullable=True)
    
    # Results and verification
    implementation_successful = Column(Boolean, nullable=True)
    verification_completed = Column(Boolean, default=False, nullable=False)
    verification_notes = Column(Text, nullable=True)
    
    # Documentation (encrypted)
    change_documentation = EncryptedField("json", nullable=True)
    implementation_log = EncryptedField("json", nullable=True)
    
    # Relationships
    requested_by_user = relationship("User", foreign_keys=[requested_by_user_id])
    approved_by_user = relationship("User", foreign_keys=[approved_by_user_id])
    implemented_by_user = relationship("User", foreign_keys=[implemented_by_user_id])
    
    __table_args__ = (
        Index('idx_change_type_status', 'change_type', 'status'),
        Index('idx_change_implementation_date', 'requested_implementation_date'),
        Index('idx_change_risk_level', 'risk_level', 'status'),
    )
    
    @classmethod
    async def create_change_request(
        cls,
        db: AsyncSession,
        change_type: ChangeType,
        title: str,
        description: str,
        business_justification: str,
        systems_affected: List[str],
        trust_criteria_impact: List[str],
        requested_implementation_date: datetime,
        implementation_steps: List[str],
        rollback_plan: str,
        requested_by_user_id: int,
        risk_level: str = "medium",
        **kwargs
    ) -> 'ChangeManagement':
        """Create a new change request."""
        # Generate change number
        change_count = await db.execute(
            select(cls).where(cls.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0))
        )
        daily_count = len(change_count.scalars().all()) + 1
        change_number = f"CHG-{datetime.utcnow().strftime('%Y%m%d')}-{daily_count:04d}"
        
        change_request = cls(
            change_id=str(uuid.uuid4()),
            change_number=change_number,
            change_type=change_type,
            title=title,
            description=description,
            business_justification=business_justification,
            systems_affected=systems_affected,
            trust_criteria_impact=trust_criteria_impact,
            requested_implementation_date=requested_implementation_date,
            implementation_steps=implementation_steps,
            rollback_plan=rollback_plan,
            requested_by_user_id=requested_by_user_id,
            risk_level=risk_level,
            **kwargs
        )
        
        return await change_request.save(db)
    
    async def approve_change(
        self,
        db: AsyncSession,
        approved_by_user_id: int
    ) -> None:
        """Approve the change request."""
        self.approved_by_user_id = approved_by_user_id
        self.approved_at = datetime.utcnow()
        self.status = ChangeStatus.APPROVED
        
        await self.save(db)
    
    async def reject_change(
        self,
        db: AsyncSession,
        rejection_reason: str
    ) -> None:
        """Reject the change request."""
        self.status = ChangeStatus.REJECTED
        self.rejection_reason = rejection_reason
        
        await self.save(db)
    
    async def start_implementation(
        self,
        db: AsyncSession,
        implemented_by_user_id: int
    ) -> None:
        """Start change implementation."""
        self.status = ChangeStatus.IN_PROGRESS
        self.implemented_by_user_id = implemented_by_user_id
        self.actual_implementation_date = datetime.utcnow()
        
        await self.save(db)
    
    async def complete_change(
        self,
        db: AsyncSession,
        implementation_successful: bool,
        verification_notes: Optional[str] = None
    ) -> None:
        """Complete the change implementation."""
        self.completion_date = datetime.utcnow()
        self.implementation_successful = implementation_successful
        self.verification_notes = verification_notes
        self.verification_completed = True
        
        if implementation_successful:
            self.status = ChangeStatus.COMPLETED
        else:
            self.status = ChangeStatus.FAILED
        
        await self.save(db)


class ComplianceControl(BaseModel):
    """SOC2 compliance control tracking and effectiveness monitoring."""
    
    __tablename__ = 'compliance_control'
    
    # Control identification
    control_id = Column(String(128), unique=True, nullable=False, index=True)
    control_number = Column(String(50), unique=True, nullable=False, index=True)
    
    # Control classification
    trust_criteria = Column(SQLEnum(TrustServiceCriteria), nullable=False, index=True)
    control_category = Column(String(100), nullable=False, index=True)
    
    # Control details
    control_title = Column(String(255), nullable=False)
    control_description = Column(Text, nullable=False)
    control_objective = Column(Text, nullable=False)
    
    # Implementation
    is_implemented = Column(Boolean, default=False, nullable=False)
    implementation_date = Column(DateTime(timezone=True), nullable=True)
    implementation_status = Column(String(50), nullable=False, default="not_started")
    
    # Testing and monitoring
    testing_frequency = Column(String(50), nullable=False)  # daily, weekly, monthly, quarterly, annually
    last_tested_date = Column(DateTime(timezone=True), nullable=True, index=True)
    next_test_due_date = Column(DateTime(timezone=True), nullable=True, index=True)
    
    # Effectiveness
    is_effective = Column(Boolean, nullable=True)
    effectiveness_rating = Column(String(20), nullable=True)  # effective, needs_improvement, ineffective
    deficiency_identified = Column(Boolean, default=False, nullable=False)
    
    # Ownership and responsibility
    control_owner_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    reviewer_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Documentation (encrypted)
    control_procedures = EncryptedField("json", nullable=True)
    evidence_requirements = Column(JSON, nullable=True)  # List of required evidence
    testing_procedures = Column(JSON, nullable=True)
    
    # Relationships
    control_owner = relationship("User", foreign_keys=[control_owner_user_id])
    reviewer = relationship("User", foreign_keys=[reviewer_user_id])
    
    __table_args__ = (
        Index('idx_control_criteria', 'trust_criteria', 'is_implemented'),
        Index('idx_control_testing', 'next_test_due_date', 'is_implemented'),
        Index('idx_control_effectiveness', 'is_effective', 'deficiency_identified'),
    )
    
    @classmethod
    async def create_control(
        cls,
        db: AsyncSession,
        control_number: str,
        trust_criteria: TrustServiceCriteria,
        control_category: str,
        control_title: str,
        control_description: str,
        control_objective: str,
        testing_frequency: str,
        control_owner_user_id: Optional[int] = None,
        **kwargs
    ) -> 'ComplianceControl':
        """Create a new compliance control."""
        control = cls(
            control_id=str(uuid.uuid4()),
            control_number=control_number,
            trust_criteria=trust_criteria,
            control_category=control_category,
            control_title=control_title,
            control_description=control_description,
            control_objective=control_objective,
            testing_frequency=testing_frequency,
            control_owner_user_id=control_owner_user_id,
            **kwargs
        )
        
        return await control.save(db)
    
    @classmethod
    async def get_controls_due_for_testing(
        cls, 
        db: AsyncSession,
        days_ahead: int = 7
    ) -> List['ComplianceControl']:
        """Get controls due for testing within specified days."""
        now = datetime.utcnow()
        due_threshold = now + timedelta(days=days_ahead)
        
        query = select(cls).where(
            cls.is_implemented == True,
            cls.next_test_due_date <= due_threshold
        ).order_by(cls.next_test_due_date)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    async def mark_tested(
        self,
        db: AsyncSession,
        is_effective: bool,
        effectiveness_rating: str,
        reviewer_user_id: int,
        next_test_date: Optional[datetime] = None
    ) -> None:
        """Mark control as tested and update effectiveness."""
        self.last_tested_date = datetime.utcnow()
        self.is_effective = is_effective
        self.effectiveness_rating = effectiveness_rating
        self.reviewer_user_id = reviewer_user_id
        self.deficiency_identified = not is_effective
        
        if next_test_date:
            self.next_test_due_date = next_test_date
        else:
            # Calculate next test date based on frequency
            frequency_days = {
                'daily': 1,
                'weekly': 7,
                'monthly': 30,
                'quarterly': 90,
                'annually': 365
            }
            days = frequency_days.get(self.testing_frequency, 90)
            self.next_test_due_date = datetime.utcnow() + timedelta(days=days)
        
        await self.save(db)