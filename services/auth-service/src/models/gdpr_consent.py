"""
GDPR Consent Management models for tracking granular user consent.
Implements consent versioning, history, and withdrawal mechanisms.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, 
    Text, Index, Enum as SQLEnum, UniqueConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import structlog

from .base import BaseModel
from .encryption import EncryptedField

logger = structlog.get_logger()


class ConsentType(str, Enum):
    """Types of consent that can be granted or withdrawn."""
    
    DATA_PROCESSING = "data_processing"          # Basic data processing consent
    MARKETING_EMAIL = "marketing_email"          # Email marketing consent
    MARKETING_SMS = "marketing_sms"              # SMS marketing consent
    THIRD_PARTY_SHARING = "third_party_sharing"  # Third-party data sharing
    ANALYTICS = "analytics"                      # Analytics and tracking
    COOKIES_FUNCTIONAL = "cookies_functional"    # Functional cookies
    COOKIES_ANALYTICS = "cookies_analytics"      # Analytics cookies
    COOKIES_MARKETING = "cookies_marketing"      # Marketing cookies
    PROFILING = "profiling"                      # Automated profiling
    PERSONALIZATION = "personalization"         # Content personalization


class ConsentStatus(str, Enum):
    """Status of consent."""
    
    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    PENDING = "pending"      # Awaiting user decision
    EXPIRED = "expired"      # Consent has expired


class ConsentLegalBasis(str, Enum):
    """Legal basis for data processing under GDPR."""
    
    CONSENT = "consent"                    # Article 6(1)(a) - User consent
    CONTRACT = "contract"                  # Article 6(1)(b) - Contract performance
    LEGAL_OBLIGATION = "legal_obligation"  # Article 6(1)(c) - Legal obligation
    VITAL_INTERESTS = "vital_interests"    # Article 6(1)(d) - Vital interests
    PUBLIC_TASK = "public_task"           # Article 6(1)(e) - Public task
    LEGITIMATE_INTERESTS = "legitimate_interests"  # Article 6(1)(f) - Legitimate interests


class ConsentVersion(BaseModel):
    """Consent version model for tracking consent text changes."""
    
    __tablename__ = 'consent_version'
    
    version_number = Column(String(20), nullable=False, index=True)  # e.g., "1.0", "1.1"
    consent_type = Column(SQLEnum(ConsentType), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    consent_text = Column(Text, nullable=False)  # Full consent text
    legal_basis = Column(SQLEnum(ConsentLegalBasis), nullable=False)
    
    # Version metadata
    effective_from = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    effective_until = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Admin metadata
    created_by_user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    
    # Relationships
    created_by_user = relationship("User", foreign_keys=[created_by_user_id])
    user_consents = relationship("UserConsent", back_populates="consent_version")
    
    __table_args__ = (
        UniqueConstraint('consent_type', 'version_number', name='uq_consent_version'),
        Index('idx_consent_version_active', 'consent_type', 'is_active'),
        Index('idx_consent_version_effective', 'effective_from', 'effective_until'),
    )
    
    @classmethod
    async def get_active_version(
        cls, 
        db: AsyncSession, 
        consent_type: ConsentType
    ) -> Optional['ConsentVersion']:
        """Get the active version for a consent type."""
        now = datetime.utcnow()
        query = select(cls).where(
            cls.consent_type == consent_type,
            cls.is_active == True,
            cls.effective_from <= now,
            (cls.effective_until.is_(None) | (cls.effective_until > now))
        ).order_by(cls.effective_from.desc())
        
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def create_version(
        cls,
        db: AsyncSession,
        consent_type: ConsentType,
        version_number: str,
        title: str,
        description: str,
        consent_text: str,
        legal_basis: ConsentLegalBasis,
        created_by_user_id: Optional[int] = None,
        effective_from: Optional[datetime] = None
    ) -> 'ConsentVersion':
        """Create a new consent version."""
        # Deactivate previous version
        prev_version = await cls.get_active_version(db, consent_type)
        if prev_version:
            prev_version.is_active = False
            prev_version.effective_until = effective_from or datetime.utcnow()
            await prev_version.save(db)
        
        version = cls(
            consent_type=consent_type,
            version_number=version_number,
            title=title,
            description=description,
            consent_text=consent_text,
            legal_basis=legal_basis,
            created_by_user_id=created_by_user_id,
            effective_from=effective_from or datetime.utcnow()
        )
        
        return await version.save(db)


class UserConsent(BaseModel):
    """User consent records with full audit trail."""
    
    __tablename__ = 'user_consent'
    
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    consent_version_id = Column(
        Integer, 
        ForeignKey('consent_version.id', ondelete='CASCADE'), 
        nullable=False, 
        index=True
    )
    
    # Consent details
    status = Column(SQLEnum(ConsentStatus), nullable=False, default=ConsentStatus.PENDING)
    granted_at = Column(DateTime(timezone=True), nullable=True)
    withdrawn_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # For time-limited consent
    
    # Request context
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    user_agent = Column(Text, nullable=True)
    consent_method = Column(String(50), nullable=True)  # 'web_form', 'api', 'email', etc.
    
    # Additional metadata (encrypted)
    consent_metadata = EncryptedField("json", nullable=True)  # Additional context
    withdrawal_reason = Column(Text, nullable=True)
    
    # Relationships
    user = relationship("User")
    consent_version = relationship("ConsentVersion", back_populates="user_consents")
    
    __table_args__ = (
        UniqueConstraint('user_id', 'consent_version_id', name='uq_user_consent_version'),
        Index('idx_user_consent_status', 'user_id', 'status'),
        Index('idx_user_consent_type_status', 'status'),
        Index('idx_user_consent_expiry', 'expires_at'),
    )
    
    @classmethod
    async def get_user_consent(
        cls,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType
    ) -> Optional['UserConsent']:
        """Get current user consent for a specific type."""
        # Get active consent version
        consent_version = await ConsentVersion.get_active_version(db, consent_type)
        if not consent_version:
            return None
        
        query = select(cls).where(
            cls.user_id == user_id,
            cls.consent_version_id == consent_version.id
        ).order_by(cls.created_at.desc())
        
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod 
    async def get_user_consents(
        cls,
        db: AsyncSession,
        user_id: int,
        consent_types: Optional[List[ConsentType]] = None
    ) -> List['UserConsent']:
        """Get all current user consents."""
        # First get all active consent versions
        query = select(ConsentVersion).where(
            ConsentVersion.is_active == True
        )
        
        if consent_types:
            query = query.where(ConsentVersion.consent_type.in_(consent_types))
        
        result = await db.execute(query)
        active_versions = result.scalars().all()
        
        # Get user consents for active versions
        version_ids = [v.id for v in active_versions]
        
        consent_query = select(cls).where(
            cls.user_id == user_id,
            cls.consent_version_id.in_(version_ids)
        ).order_by(cls.created_at.desc())
        
        result = await db.execute(consent_query)
        return result.scalars().all()
    
    @classmethod
    async def grant_consent(
        cls,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        consent_method: str = 'web_form',
        expires_at: Optional[datetime] = None,
        consent_metadata: Optional[Dict[str, Any]] = None
    ) -> 'UserConsent':
        """Grant consent for a user."""
        # Get active consent version
        consent_version = await ConsentVersion.get_active_version(db, consent_type)
        if not consent_version:
            raise ValueError(f"No active consent version found for {consent_type}")
        
        # Check if consent already exists
        existing_consent = await cls.get_user_consent(db, user_id, consent_type)
        
        if existing_consent:
            # Update existing consent
            existing_consent.status = ConsentStatus.GRANTED
            existing_consent.granted_at = datetime.utcnow()
            existing_consent.withdrawn_at = None
            existing_consent.expires_at = expires_at
            existing_consent.ip_address = ip_address
            existing_consent.user_agent = user_agent
            existing_consent.consent_method = consent_method
            existing_consent.consent_metadata = consent_metadata or {}
            
            return await existing_consent.save(db)
        else:
            # Create new consent
            consent = cls(
                user_id=user_id,
                consent_version_id=consent_version.id,
                status=ConsentStatus.GRANTED,
                granted_at=datetime.utcnow(),
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                consent_method=consent_method,
                consent_metadata=consent_metadata or {}
            )
            
            return await consent.save(db)
    
    @classmethod
    async def withdraw_consent(
        cls,
        db: AsyncSession,
        user_id: int,
        consent_type: ConsentType,
        withdrawal_reason: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional['UserConsent']:
        """Withdraw consent for a user."""
        consent = await cls.get_user_consent(db, user_id, consent_type)
        
        if consent:
            consent.status = ConsentStatus.WITHDRAWN
            consent.withdrawn_at = datetime.utcnow()
            consent.withdrawal_reason = withdrawal_reason
            consent.ip_address = ip_address
            consent.user_agent = user_agent
            
            return await consent.save(db)
        
        return None
    
    @classmethod
    async def get_consent_history(
        cls,
        db: AsyncSession,
        user_id: int,
        consent_type: Optional[ConsentType] = None,
        limit: int = 100
    ) -> List['UserConsent']:
        """Get consent history for a user."""
        query = select(cls).where(cls.user_id == user_id)
        
        if consent_type:
            # Get all versions for this consent type
            version_query = select(ConsentVersion).where(
                ConsentVersion.consent_type == consent_type
            )
            version_result = await db.execute(version_query)
            version_ids = [v.id for v in version_result.scalars().all()]
            
            query = query.where(cls.consent_version_id.in_(version_ids))
        
        query = query.order_by(cls.created_at.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    def is_valid(self) -> bool:
        """Check if consent is currently valid."""
        if self.status != ConsentStatus.GRANTED:
            return False
        
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        
        if self.withdrawn_at:
            return False
        
        return True
    
    def is_expired(self) -> bool:
        """Check if consent has expired."""
        return (
            self.expires_at is not None and 
            datetime.utcnow() > self.expires_at
        )
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        data = super().to_dict()
        
        # Add computed fields
        data['status'] = self.status.value
        data['is_valid'] = self.is_valid()
        data['is_expired'] = self.is_expired()
        
        if hasattr(self, 'consent_version') and self.consent_version:
            data['consent_type'] = self.consent_version.consent_type.value
            data['consent_title'] = self.consent_version.title
            data['consent_description'] = self.consent_version.description
            data['legal_basis'] = self.consent_version.legal_basis.value
            data['version_number'] = self.consent_version.version_number
        
        if not include_sensitive:
            # Remove sensitive fields from public API
            data.pop('ip_address', None)
            data.pop('user_agent', None)
            data.pop('consent_metadata', None)
        
        return data