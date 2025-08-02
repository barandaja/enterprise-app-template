"""
User session model for secure session management with Redis backing.
Implements comprehensive session tracking and security features.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import json
import secrets
import structlog

from .base import BaseModel
from .encryption import EncryptedField
from ..core.config import settings

logger = structlog.get_logger()


class UserSession(BaseModel):
    """User session model for tracking active sessions."""
    
    __tablename__ = 'user_session'
    
    # Session identification
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    refresh_token_id = Column(String(128), unique=True, nullable=True, index=True)
    
    # User association
    user_id = Column(Integer, ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
    # Session metadata
    device_info = EncryptedField("json", nullable=True)  # Device fingerprint
    user_agent = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 support
    location_data = EncryptedField("json", nullable=True)  # GeoIP data
    
    # Session lifecycle
    started_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    last_activity_at = Column(DateTime(timezone=True), default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    ended_at = Column(DateTime(timezone=True), nullable=True)
    
    # Session state
    is_active = Column(Boolean, default=True, nullable=False)
    is_mobile = Column(Boolean, default=False, nullable=False)
    is_trusted_device = Column(Boolean, default=False, nullable=False)
    
    # Security flags
    requires_mfa = Column(Boolean, default=False, nullable=False)
    mfa_completed = Column(Boolean, default=False, nullable=False)
    suspicious_activity = Column(Boolean, default=False, nullable=False)
    
    # Additional session data
    session_data = EncryptedField("json", nullable=True)  # Additional session context
    
    # Relationships
    user = relationship("User", back_populates="sessions")
    
    __table_args__ = (
        Index('idx_session_user_id', 'user_id'),
        Index('idx_session_active', 'is_active'),
        Index('idx_session_expires', 'expires_at'),
        Index('idx_session_last_activity', 'last_activity_at'),
    )
    
    @classmethod
    async def create_session(
        cls,
        db: AsyncSession,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        location_data: Optional[Dict[str, Any]] = None,
        session_lifetime: Optional[int] = None
    ) -> 'UserSession':
        """Create a new user session."""
        session_id = secrets.token_urlsafe(64)
        refresh_token_id = secrets.token_urlsafe(32)
        
        lifetime = session_lifetime or settings.SESSION_LIFETIME_SECONDS
        expires_at = datetime.utcnow() + timedelta(seconds=lifetime)
        
        # Detect if mobile device
        is_mobile = False
        if user_agent:
            mobile_keywords = ['mobile', 'android', 'iphone', 'ipad', 'tablet']
            is_mobile = any(keyword in user_agent.lower() for keyword in mobile_keywords)
        
        session = cls(
            session_id=session_id,
            refresh_token_id=refresh_token_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info or {},
            location_data=location_data or {},
            expires_at=expires_at,
            is_mobile=is_mobile
        )
        
        return await session.save(db)
    
    @classmethod
    async def get_by_session_id(
        cls, 
        db: AsyncSession, 
        session_id: str
    ) -> Optional['UserSession']:
        """Get session by session ID."""
        query = select(cls).where(
            cls.session_id == session_id,
            cls.is_active == True,
            cls.is_deleted == False
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_by_refresh_token_id(
        cls, 
        db: AsyncSession, 
        refresh_token_id: str
    ) -> Optional['UserSession']:
        """Get session by refresh token ID."""
        query = select(cls).where(
            cls.refresh_token_id == refresh_token_id,
            cls.is_active == True,
            cls.is_deleted == False
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    @classmethod
    async def get_active_sessions_for_user(
        cls,
        db: AsyncSession,
        user_id: int,
        limit: int = 10
    ) -> list['UserSession']:
        """Get active sessions for a user."""
        query = select(cls).where(
            cls.user_id == user_id,
            cls.is_active == True,
            cls.is_deleted == False
        ).order_by(cls.last_activity_at.desc()).limit(limit)
        
        result = await db.execute(query)
        return result.scalars().all()
    
    @classmethod
    async def cleanup_expired_sessions(cls, db: AsyncSession) -> int:
        """Clean up expired sessions."""
        expired_sessions = await db.execute(
            select(cls).where(
                cls.expires_at < datetime.utcnow(),
                cls.is_active == True
            )
        )
        
        count = 0
        for session in expired_sessions.scalars():
            await session.end_session(db, reason="expired")
            count += 1
        
        logger.info("Cleaned up expired sessions", count=count)
        return count
    
    async def update_activity(self, db: AsyncSession) -> None:
        """Update last activity timestamp."""
        self.last_activity_at = datetime.utcnow()
        await self.save(db)
    
    async def extend_session(
        self, 
        db: AsyncSession, 
        additional_seconds: int = None
    ) -> None:
        """Extend session expiration time."""
        if additional_seconds is None:
            additional_seconds = settings.SESSION_LIFETIME_SECONDS
        
        self.expires_at = datetime.utcnow() + timedelta(seconds=additional_seconds)
        await self.update_activity(db)
    
    async def end_session(
        self, 
        db: AsyncSession, 
        reason: str = "logout"
    ) -> None:
        """End the session."""
        self.is_active = False
        self.ended_at = datetime.utcnow()
        
        # Store end reason in session data
        session_data = self.session_data or {}
        session_data['end_reason'] = reason
        session_data['ended_at'] = datetime.utcnow().isoformat()
        self.session_data = session_data
        
        await self.save(db)
        
        logger.info(
            "Session ended",
            session_id=self.session_id,
            user_id=self.user_id,
            reason=reason
        )
    
    async def mark_suspicious(
        self, 
        db: AsyncSession, 
        reason: str = "security_check"
    ) -> None:
        """Mark session as suspicious."""
        self.suspicious_activity = True
        
        session_data = self.session_data or {}
        session_data['suspicious_reason'] = reason
        session_data['marked_suspicious_at'] = datetime.utcnow().isoformat()
        self.session_data = session_data
        
        await self.save(db)
        
        logger.warning(
            "Session marked as suspicious",
            session_id=self.session_id,
            user_id=self.user_id,
            reason=reason
        )
    
    async def rotate_tokens(self, db: AsyncSession) -> str:
        """Rotate session and refresh tokens."""
        old_refresh_token_id = self.refresh_token_id
        self.refresh_token_id = secrets.token_urlsafe(32)
        
        # Update activity and extend session
        await self.update_activity(db)
        
        logger.info(
            "Session tokens rotated",
            session_id=self.session_id,
            user_id=self.user_id,
            old_refresh_token_id=old_refresh_token_id
        )
        
        return self.refresh_token_id
    
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        return self.is_active and not self.is_expired() and not self.is_deleted
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get session information for API responses."""
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "last_activity_at": self.last_activity_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
            "is_mobile": self.is_mobile,
            "is_trusted_device": self.is_trusted_device,
            "location": self.location_data or {},
            "device_info": {
                "browser": self.device_info.get("browser") if self.device_info else None,
                "os": self.device_info.get("os") if self.device_info else None,
                "device_type": "mobile" if self.is_mobile else "desktop"
            }
        }
    
    def __repr__(self) -> str:
        return f"<UserSession(id={self.id}, user_id={self.user_id}, active={self.is_active})>"


class SessionManager:
    """Manages user sessions with Redis backing for performance."""
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    async def cache_session(self, session: UserSession) -> None:
        """Cache session data in Redis for fast lookup."""
        session_key = f"session:{session.session_id}"
        session_data = {
            "user_id": session.user_id,
            "expires_at": session.expires_at.isoformat(),
            "is_active": session.is_active,
            "requires_mfa": session.requires_mfa,
            "mfa_completed": session.mfa_completed
        }
        
        # Cache for session lifetime
        ttl = int((session.expires_at - datetime.utcnow()).total_seconds())
        if ttl > 0:
            await self.redis.setex(
                session_key, 
                ttl, 
                json.dumps(session_data)
            )
    
    async def get_cached_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data from Redis cache."""
        session_key = f"session:{session_id}"
        cached_data = await self.redis.get(session_key)
        
        if cached_data:
            return json.loads(cached_data)
        
        return None
    
    async def invalidate_session(self, session_id: str) -> None:
        """Remove session from Redis cache."""
        session_key = f"session:{session_id}"
        await self.redis.delete(session_key)
    
    async def invalidate_user_sessions(self, user_id: int) -> None:
        """Invalidate all sessions for a user."""
        pattern = f"session:*"
        async for key in self.redis.scan_iter(match=pattern):
            cached_data = await self.redis.get(key)
            if cached_data:
                session_data = json.loads(cached_data)
                if session_data.get("user_id") == user_id:
                    await self.redis.delete(key)