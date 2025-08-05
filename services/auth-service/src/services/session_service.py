"""
Session management service with Redis backing and comprehensive security features.
Implements session lifecycle management, validation, and cleanup.
"""
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import HTTPException, status
import structlog

from ..models.user import User
from ..models.session import UserSession, SessionManager
from ..models.audit import AuditEventType, AuditLogger
from ..core.redis import get_cache_service
from ..core.config import settings

logger = structlog.get_logger()


class SessionService:
    """Comprehensive session management service."""
    
    def __init__(self):
        self.cache_service = get_cache_service()
        self.session_manager = SessionManager(self.cache_service.redis)
        self.audit_logger = AuditLogger()
    
    async def create_session(
        self,
        db: AsyncSession,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
        location_data: Optional[Dict[str, Any]] = None,
        remember_me: bool = False
    ) -> UserSession:
        """
        Create a new user session with comprehensive tracking.
        
        Args:
            db: Database session
            user: User object
            ip_address: Client IP address
            user_agent: User agent string
            device_info: Device fingerprint information
            location_data: GeoIP location data
            remember_me: Whether to extend session lifetime
        
        Returns:
            Created session object
        """
        try:
            # Determine session lifetime
            session_lifetime = settings.SESSION_LIFETIME_SECONDS
            if remember_me:
                session_lifetime *= 7  # Extend for "remember me"
            
            # Create session
            session = await UserSession.create_session(
                db=db,
                user_id=user.id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info or {},
                location_data=location_data or {},
                session_lifetime=session_lifetime
            )
            
            # Cache session for fast lookup
            await self.session_manager.cache_session(session)
            
            # Log session creation
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=user.id,
                session_id=session.session_id,
                ip_address=ip_address,
                success=True,
                description=f"Session created for user {user.id}",
                event_data={
                    "device_info": device_info,
                    "location": location_data,
                    "remember_me": remember_me
                }
            )
            
            logger.info(
                "Session created successfully",
                user_id=user.id,
                session_id=session.session_id,
                ip_address=ip_address
            )
            
            return session
        
        except Exception as e:
            logger.error("Session creation failed", user_id=user.id, error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create session"
            )
    
    async def get_session(
        self,
        db: AsyncSession,
        session_id: str,
        validate: bool = True
    ) -> Optional[UserSession]:
        """
        Get session by ID with optional validation.
        
        Args:
            db: Database session
            session_id: Session identifier
            validate: Whether to validate session is active and not expired
        
        Returns:
            Session object if found and valid
        """
        try:
            # Try cache first
            cached_session = await self.session_manager.get_cached_session(session_id)
            if cached_session and not validate:
                # For non-validated requests, return cached data
                # In production, you'd reconstruct the UserSession object
                pass
            
            # Get from database
            session = await UserSession.get_by_session_id(db, session_id)
            
            if not session:
                return None
            
            if validate and not session.is_valid():
                # Session is invalid (expired or inactive)
                await self.end_session(db, session_id, reason="expired")
                return None
            
            return session
        
        except Exception as e:
            logger.error("Failed to get session", session_id=session_id, error=str(e))
            return None
    
    async def validate_session(
        self,
        db: AsyncSession,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[UserSession]:
        """
        Validate session with security checks.
        
        Args:
            db: Database session
            session_id: Session identifier
            ip_address: Current IP address for validation
            user_agent: Current user agent for validation
        
        Returns:
            Valid session object or None
        """
        try:
            session = await self.get_session(db, session_id, validate=True)
            if not session:
                return None
            
            # Security validations
            security_violations = []
            
            # IP address validation (if configured)
            if settings.ENFORCE_IP_VALIDATION and ip_address:
                if session.ip_address and session.ip_address != ip_address:
                    security_violations.append("IP address mismatch")
            
            # User agent validation (basic check)
            if user_agent and session.user_agent:
                # Simple user agent change detection
                if len(session.user_agent) > 0 and session.user_agent != user_agent:
                    # Allow minor user agent changes (updates, etc.)
                    # This is a simplified check - production would be more sophisticated
                    pass
            
            # Check for suspicious activity flags
            if session.suspicious_activity:
                security_violations.append("Session marked as suspicious")
            
            if security_violations:
                # Mark session as suspicious and potentially end it
                await session.mark_suspicious(
                    db, 
                    reason=f"Security validation failed: {', '.join(security_violations)}"
                )
                
                # Log security event
                await self.audit_logger.log_security_event(
                    db=db,
                    event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
                    description=f"Session security validation failed: {', '.join(security_violations)}",
                    user_id=session.user_id,
                    session_id=session_id,
                    ip_address=ip_address,
                    severity=AuditSeverity.HIGH
                )
                
                # End session if critical violations
                if "IP address mismatch" in security_violations:
                    await self.end_session(db, session_id, reason="security_violation")
                    return None
            
            # Update last activity
            await session.update_activity(db)
            
            return session
        
        except Exception as e:
            logger.error("Session validation failed", session_id=session_id, error=str(e))
            return None
    
    async def refresh_session(
        self,
        db: AsyncSession,
        refresh_token_id: str,
        ip_address: Optional[str] = None
    ) -> Optional[UserSession]:
        """
        Refresh session using refresh token.
        
        Args:
            db: Database session
            refresh_token_id: Refresh token identifier
            ip_address: Client IP address
        
        Returns:
            Refreshed session object
        """
        try:
            # Get session by refresh token
            session = await UserSession.get_by_refresh_token_id(db, refresh_token_id)
            if not session or not session.is_valid():
                logger.info("Invalid or expired refresh token", refresh_token_id=refresh_token_id)
                return None
            
            logger.info("Found valid session for refresh", session_id=session.session_id, user_id=session.user_id)
            
            # Rotate tokens for security
            old_refresh_token_id = session.refresh_token_id
            logger.info("Rotating session tokens", session_id=session.session_id)
            new_refresh_token_id = await session.rotate_tokens(db)
            
            # Extend session if needed
            if session.expires_at - datetime.now(timezone.utc) < timedelta(hours=1):
                logger.info("Extending session expiration", session_id=session.session_id)
                await session.extend_session(db)
            
            # Update cache - do this before audit logging to avoid cache inconsistency
            logger.info("Updating session cache", session_id=session.session_id)
            await self.session_manager.cache_session(session)
            
            # Log token refresh - this is where the error likely occurs
            logger.info("Creating audit log for session refresh", session_id=session.session_id)
            try:
                await self.audit_logger.log_auth_event(
                    db=db,
                    event_type=AuditEventType.LOGIN_SUCCESS,
                    user_id=session.user_id,
                    session_id=session.session_id,
                    ip_address=ip_address,
                    success=True,
                    description="Session refreshed via refresh token",
                    event_data={
                        "old_refresh_token_id": old_refresh_token_id,
                        "new_refresh_token_id": new_refresh_token_id
                    }
                )
                logger.info("Audit log created successfully for session refresh")
            except Exception as audit_error:
                logger.error(
                    "Audit logging failed during session refresh",
                    session_id=session.session_id,
                    user_id=session.user_id,
                    audit_error=str(audit_error),
                    audit_error_type=type(audit_error).__name__
                )
                # Re-raise the audit error to surface the real issue
                raise audit_error
            
            logger.info(
                "Session refreshed successfully",
                user_id=session.user_id,
                session_id=session.session_id
            )
            
            return session
        
        except Exception as e:
            logger.error(
                "Session refresh failed", 
                refresh_token_id=refresh_token_id, 
                error=str(e),
                error_type=type(e).__name__
            )
            # Import traceback for full error details
            import traceback
            logger.error("Session refresh full traceback", traceback=traceback.format_exc())
            raise  # Re-raise the error instead of returning None
    
    async def end_session(
        self,
        db: AsyncSession,
        session_id: str,
        reason: str = "logout",
        ended_by_user_id: Optional[int] = None
    ) -> bool:
        """
        End a user session.
        
        Args:
            db: Database session
            session_id: Session identifier
            reason: Reason for ending session
            ended_by_user_id: ID of user ending the session (for admin actions)
        
        Returns:
            True if session ended successfully
        """
        try:
            session = await UserSession.get_by_session_id(db, session_id)
            if not session:
                return False
            
            # End session
            await session.end_session(db, reason=reason)
            
            # Remove from cache
            await self.session_manager.invalidate_session(session_id)
            
            # Log session end
            event_type = AuditEventType.LOGOUT
            if reason == "expired":
                event_type = AuditEventType.LOGIN_FAILURE  # Use for expired sessions
            elif reason == "security_violation":
                event_type = AuditEventType.SECURITY_ALERT
            
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=event_type,
                user_id=session.user_id,
                session_id=session_id,
                ip_address=session.ip_address,
                success=True,
                description=f"Session ended: {reason}",
                event_data={
                    "reason": reason,
                    "ended_by_user_id": ended_by_user_id
                }
            )
            
            logger.info(
                "Session ended successfully",
                user_id=session.user_id,
                session_id=session_id,
                reason=reason
            )
            
            return True
        
        except Exception as e:
            logger.error("Failed to end session", session_id=session_id, error=str(e))
            return False
    
    async def end_all_user_sessions(
        self,
        db: AsyncSession,
        user_id: int,
        except_session_id: Optional[str] = None,
        reason: str = "admin_action"
    ) -> int:
        """
        End all sessions for a user.
        
        Args:
            db: Database session
            user_id: User ID
            except_session_id: Session ID to exclude from termination
            reason: Reason for ending sessions
        
        Returns:
            Number of sessions ended
        """
        try:
            # Get all active sessions for user
            active_sessions = await UserSession.get_active_sessions_for_user(db, user_id)
            
            ended_count = 0
            for session in active_sessions:
                if except_session_id and session.session_id == except_session_id:
                    continue
                
                await session.end_session(db, reason=reason)
                await self.session_manager.invalidate_session(session.session_id)
                ended_count += 1
            
            # Invalidate all cached sessions for user
            await self.session_manager.invalidate_user_sessions(user_id)
            
            # Log bulk session termination
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.LOGOUT,
                user_id=user_id,
                success=True,
                description=f"All user sessions ended: {reason}",
                event_data={
                    "reason": reason,
                    "sessions_ended": ended_count,
                    "except_session_id": except_session_id
                }
            )
            
            logger.info(
                "All user sessions ended",
                user_id=user_id,
                sessions_ended=ended_count,
                reason=reason
            )
            
            return ended_count
        
        except Exception as e:
            logger.error("Failed to end all user sessions", user_id=user_id, error=str(e))
            return 0
    
    async def get_user_sessions(
        self,
        db: AsyncSession,
        user_id: int,
        active_only: bool = True,
        limit: int = 10
    ) -> List[UserSession]:
        """Get sessions for a user."""
        try:
            if active_only:
                return await UserSession.get_active_sessions_for_user(db, user_id, limit)
            else:
                # Get all sessions (would need additional query implementation)
                return await UserSession.get_active_sessions_for_user(db, user_id, limit)
        
        except Exception as e:
            logger.error("Failed to get user sessions", user_id=user_id, error=str(e))
            return []
    
    async def cleanup_expired_sessions(self, db: AsyncSession) -> int:
        """Clean up expired sessions."""
        try:
            count = await UserSession.cleanup_expired_sessions(db)
            
            if count > 0:
                logger.info("Expired sessions cleaned up", count=count)
            
            return count
        
        except Exception as e:
            logger.error("Failed to cleanup expired sessions", error=str(e))
            return 0
    
    async def get_session_analytics(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get session analytics for monitoring and reporting.
        
        Args:
            db: Database session
            user_id: Optional user ID to filter by
            start_date: Start date for analytics
            end_date: End date for analytics
        
        Returns:
            Analytics data dictionary
        """
        try:
            # This would be implemented based on specific analytics requirements
            # For now, return basic structure
            analytics = {
                "total_sessions": 0,
                "active_sessions": 0,
                "expired_sessions": 0,
                "suspicious_sessions": 0,
                "mobile_sessions": 0,
                "desktop_sessions": 0,
                "average_session_duration": 0,
                "unique_users": 0,
                "unique_ip_addresses": 0
            }
            
            # Implementation would include database queries to populate these metrics
            
            return analytics
        
        except Exception as e:
            logger.error("Failed to get session analytics", error=str(e))
            return {}
    
    async def mark_device_as_trusted(
        self,
        db: AsyncSession,
        session_id: str,
        user_id: int
    ) -> bool:
        """Mark device as trusted for the user."""
        try:
            session = await self.get_session(db, session_id)
            if not session or session.user_id != user_id:
                return False
            
            session.is_trusted_device = True
            await session.save(db)
            
            # Update cache
            await self.session_manager.cache_session(session)
            
            # Log trusted device
            await self.audit_logger.log_auth_event(
                db=db,
                event_type=AuditEventType.LOGIN_SUCCESS,
                user_id=user_id,
                session_id=session_id,
                success=True,
                description="Device marked as trusted"
            )
            
            logger.info("Device marked as trusted", user_id=user_id, session_id=session_id)
            return True
        
        except Exception as e:
            logger.error("Failed to mark device as trusted", session_id=session_id, error=str(e))
            return False