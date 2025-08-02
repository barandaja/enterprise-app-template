"""
HIPAA Compliance models for tracking PHI access, BAA agreements, and emergency access procedures.
Implements enhanced audit trail and strict access controls for healthcare data.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, 
    Text, Index, Enum as SQLEnum, UniqueConstraint, JSON
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import structlog
import uuid

from .base import BaseModel
from .encryption import EncryptedField

logger = structlog.get_logger()


class PHICategory(str, Enum):
    """Categories of Protected Health Information."""
    
    DEMOGRAPHIC = "demographic"              # Names, addresses, birth dates
    FINANCIAL = "financial"                  # Account numbers, payment info
    MEDICAL_RECORD_NUMBER = "medical_record_number"
    HEALTH_PLAN_NUMBER = "health_plan_number"
    BIOMETRIC = "biometric"                  # Fingerprints, voiceprints
    PHOTO = "photo"                          # Full face photos
    CONTACT = "contact"                      # Phone, email, fax
    DEVICE_IDENTIFIER = "device_identifier"  # Device serial numbers
    WEB_URL = "web_url"                      # Web URLs
    IP_ADDRESS = "ip_address"                # Internet Protocol addresses
    MEDICAL_DATA = "medical_data"            # Medical records, lab results
    INSURANCE = "insurance"                  # Insurance information
    OTHER = "other"                          # Other PHI not categorized


class AccessPurpose(str, Enum):
    """Purpose of PHI access under HIPAA."""
    
    TREATMENT = "treatment"                  # Healthcare treatment
    PAYMENT = "payment"                      # Healthcare payment operations
    OPERATIONS = "operations"                # Healthcare operations
    RESEARCH = "research"                    # Research with authorization
    PUBLIC_HEALTH = "public_health"          # Public health activities
    EMERGENCY = "emergency"                  # Emergency situations
    LEGAL = "legal"                          # Legal proceedings
    AUDIT = "audit"                          # Internal audit
    ADMINISTRATIVE = "administrative"        # Administrative purposes
    MINIMUM_NECESSARY = "minimum_necessary"  # Minimum necessary standard


class EmergencyAccessType(str, Enum):
    """Types of emergency access procedures."""
    
    BREAK_GLASS = "break_glass"              # Break-glass emergency access
    LIFE_THREATENING = "life_threatening"    # Life-threatening emergency
    CLINICAL_EMERGENCY = "clinical_emergency" # Clinical emergency
    SYSTEM_OUTAGE = "system_outage"          # System outage emergency
    DISASTER_RECOVERY = "disaster_recovery"  # Disaster recovery
    SECURITY_INCIDENT = "security_incident"  # Security incident response


class BAAAgreementStatus(str, Enum):
    """Status of Business Associate Agreements."""
    
    ACTIVE = "active"                        # Agreement is active
    PENDING = "pending"                      # Agreement pending approval
    EXPIRED = "expired"                      # Agreement has expired
    TERMINATED = "terminated"                # Agreement terminated
    SUSPENDED = "suspended"                  # Agreement suspended
    UNDER_REVIEW = "under_review"            # Agreement under review


class PHIAccessLog(BaseModel):
    """Enhanced audit log for Protected Health Information access."""
    
    __tablename__ = 'phi_access_log'
    
    # Access identification
    access_id = Column(String(128), unique=True, nullable=False, index=True)  # UUID
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    
    # PHI details
    phi_category = Column(SQLEnum(PHICategory), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)  # e.g., 'patient', 'medical_record'
    resource_id = Column(String(100), nullable=False, index=True)
    resource_description = Column(Text, nullable=True)
    
    # Access details
    access_timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    access_purpose = Column(SQLEnum(AccessPurpose), nullable=False, index=True)
    access_method = Column(String(50), nullable=False)  # 'web', 'api', 'mobile', etc.
    action_performed = Column(String(50), nullable=False, index=True)  # 'read', 'create', 'update', 'delete'
    
    # Justification and authorization
    access_justification = Column(Text, nullable=False)  # Required justification
    minimum_necessary_applied = Column(Boolean, default=True, nullable=False)
    authorization_id = Column(String(128), nullable=True)  # Patient authorization reference
    
    # Request context (encrypted)
    ip_address = Column(String(45), nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    request_headers = EncryptedField("json", nullable=True)
    
    # Data accessed (encrypted metadata)
    phi_fields_accessed = EncryptedField("json", nullable=True)  # List of specific PHI fields
    data_volume = Column(Integer, nullable=True)  # Number of records accessed
    
    # Patient information (if applicable)
    patient_id = Column(String(100), nullable=True, index=True)
    patient_mrn = EncryptedField("string", nullable=True)  # Medical Record Number
    
    # System information
    application_name = Column(String(100), nullable=True)
    module_name = Column(String(100), nullable=True)
    
    # Result and errors
    access_successful = Column(Boolean, nullable=False, index=True)
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Audit trail
    created_by_system = Column(String(100), nullable=False, default="auth-service")
    correlation_id = Column(String(128), nullable=True, index=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        Index('idx_phi_access_user_timestamp', 'user_id', 'access_timestamp'),
        Index('idx_phi_access_resource', 'resource_type', 'resource_id'),
        Index('idx_phi_access_patient', 'patient_id', 'access_timestamp'),
        Index('idx_phi_access_purpose', 'access_purpose', 'access_timestamp'),
        Index('idx_phi_access_category', 'phi_category', 'access_timestamp'),
    )
    
    @classmethod
    async def create_phi_access_log(
        cls,
        db: AsyncSession,
        user_id: int,
        phi_category: PHICategory,
        resource_type: str,
        resource_id: str,
        access_purpose: AccessPurpose,
        access_method: str,
        action_performed: str,
        access_justification: str,
        session_id: Optional[str] = None,
        patient_id: Optional[str] = None,
        patient_mrn: Optional[str] = None,
        phi_fields_accessed: Optional[List[str]] = None,
        data_volume: Optional[int] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        authorization_id: Optional[str] = None,
        minimum_necessary_applied: bool = True,
        access_successful: bool = True,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None,
        **kwargs
    ) -> 'PHIAccessLog':
        """Create a new PHI access log entry."""
        access_log = cls(
            access_id=str(uuid.uuid4()),
            user_id=user_id,
            session_id=session_id,
            phi_category=phi_category,
            resource_type=resource_type,
            resource_id=resource_id,
            access_purpose=access_purpose,
            access_method=access_method,
            action_performed=action_performed,
            access_justification=access_justification,
            patient_id=patient_id,
            patient_mrn=patient_mrn,
            phi_fields_accessed=phi_fields_accessed or [],
            data_volume=data_volume,
            ip_address=ip_address,
            user_agent=user_agent,
            authorization_id=authorization_id,
            minimum_necessary_applied=minimum_necessary_applied,
            access_successful=access_successful,
            error_code=error_code,
            error_message=error_message,
            **kwargs
        )
        
        return await access_log.save(db)
    
    @classmethod
    async def get_phi_access_history(
        cls,
        db: AsyncSession,
        user_id: Optional[int] = None,
        patient_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List['PHIAccessLog']:
        """Get PHI access history with filters."""
        query = select(cls)
        
        if user_id:
            query = query.where(cls.user_id == user_id)
        
        if patient_id:
            query = query.where(cls.patient_id == patient_id)
        
        if resource_type:
            query = query.where(cls.resource_type == resource_type)
        
        if start_date:
            query = query.where(cls.access_timestamp >= start_date)
        
        if end_date:
            query = query.where(cls.access_timestamp <= end_date)
        
        query = query.order_by(cls.access_timestamp.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()


class BusinessAssociateAgreement(BaseModel):
    """Business Associate Agreement tracking for HIPAA compliance."""
    
    __tablename__ = 'business_associate_agreement'
    
    # Agreement identification
    agreement_id = Column(String(128), unique=True, nullable=False, index=True)
    agreement_number = Column(String(100), nullable=True, index=True)
    
    # Business Associate information
    business_associate_name = Column(String(255), nullable=False, index=True)
    business_associate_contact = EncryptedField("json", nullable=True)  # Contact information
    business_associate_type = Column(String(100), nullable=False)  # 'vendor', 'contractor', 'consultant'
    
    # Agreement details
    agreement_title = Column(String(255), nullable=False)
    agreement_description = Column(Text, nullable=True)
    covered_services = Column(JSON, nullable=False)  # List of services covered
    phi_categories_covered = Column(JSON, nullable=False)  # List of PHI categories
    
    # Dates and status
    effective_date = Column(DateTime(timezone=True), nullable=False, index=True)
    expiration_date = Column(DateTime(timezone=True), nullable=False, index=True)
    termination_date = Column(DateTime(timezone=True), nullable=True)
    status = Column(SQLEnum(BAAAgreementStatus), default=BAAAgreementStatus.ACTIVE, nullable=False, index=True)
    
    # Compliance requirements
    security_requirements = Column(JSON, nullable=True)  # Specific security requirements
    audit_requirements = Column(JSON, nullable=True)    # Audit and reporting requirements
    data_return_requirements = Column(Text, nullable=True)  # Data return/destruction requirements
    
    # Incident response
    incident_notification_timeframe = Column(Integer, nullable=True)  # Hours for incident notification
    breach_notification_procedure = Column(Text, nullable=True)
    
    # Management information
    signed_by_covered_entity = Column(String(255), nullable=True)
    signed_by_business_associate = Column(String(255), nullable=True)
    signed_date = Column(DateTime(timezone=True), nullable=True)
    approved_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Document management (encrypted)
    agreement_document_path = EncryptedField("string", nullable=True)
    additional_documents = EncryptedField("json", nullable=True)
    
    # Relationships
    approved_by_user = relationship("User")
    
    __table_args__ = (
        Index('idx_baa_status_expiration', 'status', 'expiration_date'),
        Index('idx_baa_business_associate', 'business_associate_name'),
        Index('idx_baa_effective_dates', 'effective_date', 'expiration_date'),
    )
    
    @classmethod
    async def create_baa(
        cls,
        db: AsyncSession,
        business_associate_name: str,
        agreement_title: str,
        covered_services: List[str],
        phi_categories_covered: List[str],
        effective_date: datetime,
        expiration_date: datetime,
        business_associate_type: str = "vendor",
        **kwargs
    ) -> 'BusinessAssociateAgreement':
        """Create a new Business Associate Agreement."""
        baa = cls(
            agreement_id=str(uuid.uuid4()),
            business_associate_name=business_associate_name,
            business_associate_type=business_associate_type,
            agreement_title=agreement_title,
            covered_services=covered_services,
            phi_categories_covered=phi_categories_covered,
            effective_date=effective_date,
            expiration_date=expiration_date,
            **kwargs
        )
        
        return await baa.save(db)
    
    @classmethod
    async def get_active_agreements(cls, db: AsyncSession) -> List['BusinessAssociateAgreement']:
        """Get all active BAA agreements."""
        now = datetime.utcnow()
        query = select(cls).where(
            cls.status == BAAAgreementStatus.ACTIVE,
            cls.effective_date <= now,
            cls.expiration_date > now
        ).order_by(cls.expiration_date)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def get_expiring_agreements(
        cls, 
        db: AsyncSession, 
        days_ahead: int = 30
    ) -> List['BusinessAssociateAgreement']:
        """Get agreements expiring within specified days."""
        now = datetime.utcnow()
        expiry_threshold = now + timedelta(days=days_ahead)
        
        query = select(cls).where(
            cls.status == BAAAgreementStatus.ACTIVE,
            cls.expiration_date <= expiry_threshold,
            cls.expiration_date > now
        ).order_by(cls.expiration_date)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    def is_active(self) -> bool:
        """Check if agreement is currently active."""
        now = datetime.utcnow()
        return (
            self.status == BAAAgreementStatus.ACTIVE and
            self.effective_date <= now and
            self.expiration_date > now and
            not self.termination_date
        )
    
    def days_until_expiration(self) -> int:
        """Get number of days until expiration."""
        if not self.expiration_date:
            return -1
        
        now = datetime.utcnow()
        if self.expiration_date <= now:
            return 0
        
        return (self.expiration_date - now).days


class EmergencyAccess(BaseModel):
    """Emergency access procedures and break-glass functionality."""
    
    __tablename__ = 'emergency_access'
    
    # Emergency access identification
    emergency_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False, index=True)
    session_id = Column(String(128), nullable=True, index=True)
    
    # Emergency details
    emergency_type = Column(SQLEnum(EmergencyAccessType), nullable=False, index=True)
    emergency_justification = Column(Text, nullable=False)
    emergency_start_time = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False, index=True)
    emergency_end_time = Column(DateTime(timezone=True), nullable=True)
    
    # Authorization and approval
    authorized_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    authorization_code = Column(String(128), nullable=True)  # Emergency authorization code
    approval_required = Column(Boolean, default=True, nullable=False)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    approved_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Patient and resource information
    patient_id = Column(String(100), nullable=True, index=True)
    patient_mrn = EncryptedField("string", nullable=True)
    affected_resources = Column(JSON, nullable=True)  # List of resources accessed
    
    # Context information
    location = Column(String(255), nullable=True)  # Physical location
    department = Column(String(100), nullable=True)
    clinical_context = Column(Text, nullable=True)
    
    # System information
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    access_method = Column(String(50), nullable=False, default="web")
    
    # Status tracking
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    terminated_at = Column(DateTime(timezone=True), nullable=True)
    terminated_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    termination_reason = Column(Text, nullable=True)
    
    # Audit and review
    review_required = Column(Boolean, default=True, nullable=False)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    reviewed_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    review_notes = Column(Text, nullable=True)
    
    # Additional metadata (encrypted)
    emergency_metadata = EncryptedField("json", nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    authorized_by_user = relationship("User", foreign_keys=[authorized_by_user_id])
    approved_by_user = relationship("User", foreign_keys=[approved_by_user_id])
    terminated_by_user = relationship("User", foreign_keys=[terminated_by_user_id])
    reviewed_by_user = relationship("User", foreign_keys=[reviewed_by_user_id])
    
    __table_args__ = (
        Index('idx_emergency_access_user_time', 'user_id', 'emergency_start_time'),
        Index('idx_emergency_access_type', 'emergency_type', 'emergency_start_time'),
        Index('idx_emergency_access_patient', 'patient_id', 'emergency_start_time'),
        Index('idx_emergency_access_active', 'is_active', 'emergency_start_time'),
    )
    
    @classmethod
    async def create_emergency_access(
        cls,
        db: AsyncSession,
        user_id: int,
        emergency_type: EmergencyAccessType,
        emergency_justification: str,
        patient_id: Optional[str] = None,
        patient_mrn: Optional[str] = None,
        location: Optional[str] = None,
        department: Optional[str] = None,
        clinical_context: Optional[str] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        **kwargs
    ) -> 'EmergencyAccess':
        """Create a new emergency access record."""
        emergency_access = cls(
            emergency_id=str(uuid.uuid4()),
            user_id=user_id,
            session_id=session_id,
            emergency_type=emergency_type,
            emergency_justification=emergency_justification,
            patient_id=patient_id,
            patient_mrn=patient_mrn,
            location=location,
            department=department,
            clinical_context=clinical_context,
            ip_address=ip_address,
            user_agent=user_agent,
            **kwargs
        )
        
        return await emergency_access.save(db)
    
    @classmethod
    async def get_active_emergency_sessions(
        cls,
        db: AsyncSession,
        user_id: Optional[int] = None
    ) -> List['EmergencyAccess']:
        """Get active emergency access sessions."""
        query = select(cls).where(
            cls.is_active == True,
            cls.emergency_end_time.is_(None)
        )
        
        if user_id:
            query = query.where(cls.user_id == user_id)
        
        query = query.order_by(cls.emergency_start_time.desc())
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def get_pending_reviews(cls, db: AsyncSession) -> List['EmergencyAccess']:
        """Get emergency accesses pending review."""
        query = select(cls).where(
            cls.review_required == True,
            cls.reviewed_at.is_(None),
            cls.is_active == False
        ).order_by(cls.emergency_start_time.desc())
        
        result = await db.execute(query)
        return result.scalars().all()
    
    async def terminate_emergency_access(
        self,
        db: AsyncSession,
        terminated_by_user_id: int,
        termination_reason: Optional[str] = None
    ) -> None:
        """Terminate the emergency access session."""
        self.is_active = False
        self.terminated_at = datetime.utcnow()
        self.terminated_by_user_id = terminated_by_user_id
        self.termination_reason = termination_reason
        self.emergency_end_time = datetime.utcnow()
        
        await self.save(db)
    
    async def approve_emergency_access(
        self,
        db: AsyncSession,
        approved_by_user_id: int
    ) -> None:
        """Approve the emergency access request."""
        self.approved_at = datetime.utcnow()
        self.approved_by_user_id = approved_by_user_id
        
        await self.save(db)
    
    async def complete_review(
        self,
        db: AsyncSession,
        reviewed_by_user_id: int,
        review_notes: Optional[str] = None
    ) -> None:
        """Complete the emergency access review."""
        self.reviewed_at = datetime.utcnow()
        self.reviewed_by_user_id = reviewed_by_user_id
        self.review_notes = review_notes
        
        await self.save(db)
    
    def is_expired(self, max_duration_hours: int = 24) -> bool:
        """Check if emergency access has exceeded maximum duration."""
        if not self.emergency_start_time:
            return False
        
        max_duration = timedelta(hours=max_duration_hours)
        return datetime.utcnow() - self.emergency_start_time > max_duration
    
    def get_duration_minutes(self) -> int:
        """Get the duration of emergency access in minutes."""
        start_time = self.emergency_start_time
        end_time = self.emergency_end_time or datetime.utcnow()
        
        return int((end_time - start_time).total_seconds() / 60)


class HIPAASessionContext(BaseModel):
    """Enhanced session context for HIPAA compliance with automatic timeout."""
    
    __tablename__ = 'hipaa_session_context'
    
    # Session identification
    session_id = Column(String(128), ForeignKey('user_session.session_id'), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=False, index=True)
    
    # HIPAA-specific context
    phi_access_level = Column(String(50), nullable=False, default="none")  # 'none', 'limited', 'full'
    current_patient_context = Column(String(100), nullable=True, index=True)
    department_context = Column(String(100), nullable=True)
    role_context = Column(String(100), nullable=True)
    
    # Timeout management
    last_phi_access = Column(DateTime(timezone=True), nullable=True, index=True)
    phi_session_timeout_minutes = Column(Integer, default=15, nullable=False)  # 15-minute timeout for PHI
    warning_issued_at = Column(DateTime(timezone=True), nullable=True)
    
    # Emergency access
    emergency_access_active = Column(Boolean, default=False, nullable=False)
    emergency_access_id = Column(String(128), ForeignKey('emergency_access.emergency_id'), nullable=True)
    
    # Audit context
    access_justification_required = Column(Boolean, default=True, nullable=False)
    minimum_necessary_enforced = Column(Boolean, default=True, nullable=False)
    
    # Session metadata (encrypted)
    session_metadata = EncryptedField("json", nullable=True)
    
    # Relationships
    user = relationship("User")
    emergency_access = relationship("EmergencyAccess")
    
    __table_args__ = (
        Index('idx_hipaa_session_user', 'user_id'),
        Index('idx_hipaa_session_patient', 'current_patient_context'),
        Index('idx_hipaa_session_phi_access', 'last_phi_access'),
    )
    
    @classmethod
    async def create_hipaa_session(
        cls,
        db: AsyncSession,
        session_id: str,
        user_id: int,
        phi_access_level: str = "none",
        department_context: Optional[str] = None,
        role_context: Optional[str] = None,
        phi_session_timeout_minutes: int = 15
    ) -> 'HIPAASessionContext':
        """Create a new HIPAA session context."""
        hipaa_session = cls(
            session_id=session_id,
            user_id=user_id,
            phi_access_level=phi_access_level,
            department_context=department_context,
            role_context=role_context,
            phi_session_timeout_minutes=phi_session_timeout_minutes
        )
        
        return await hipaa_session.save(db)
    
    async def update_phi_access(
        self,
        db: AsyncSession,
        phi_access_level: str,
        patient_context: Optional[str] = None
    ) -> None:
        """Update PHI access level and patient context."""
        self.phi_access_level = phi_access_level
        self.current_patient_context = patient_context
        self.last_phi_access = datetime.utcnow()
        self.warning_issued_at = None  # Reset warning
        
        await self.save(db)
    
    def is_phi_session_expired(self) -> bool:
        """Check if PHI session has expired due to inactivity."""
        if not self.last_phi_access:
            return False
        
        timeout = timedelta(minutes=self.phi_session_timeout_minutes)
        return datetime.utcnow() - self.last_phi_access > timeout
    
    def should_issue_timeout_warning(self, warning_minutes_before: int = 2) -> bool:
        """Check if timeout warning should be issued."""
        if not self.last_phi_access or self.warning_issued_at:
            return False
        
        timeout = timedelta(minutes=self.phi_session_timeout_minutes)
        warning_time = timeout - timedelta(minutes=warning_minutes_before)
        
        return datetime.utcnow() - self.last_phi_access > warning_time
    
    async def issue_timeout_warning(self, db: AsyncSession) -> None:
        """Issue timeout warning to user."""
        self.warning_issued_at = datetime.utcnow()
        await self.save(db)
    
    async def extend_phi_session(self, db: AsyncSession) -> None:
        """Extend PHI session by updating last access time."""
        self.last_phi_access = datetime.utcnow()
        self.warning_issued_at = None
        await self.save(db)