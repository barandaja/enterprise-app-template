"""
GDPR Data Deletion Service for Right to be Forgotten (Article 17).
Implements comprehensive data deletion across all tables with audit logging.
"""
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from enum import Enum
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy import text, delete
from fastapi import HTTPException, status
import structlog

from ..models.user import User
from ..models.session import UserSession
from ..models.audit import AuditLog, AuditEventType, AuditSeverity, AuditLogger
from ..models.gdpr_consent import UserConsent
from ..core.config import settings

logger = structlog.get_logger()


class DeletionReason(str, Enum):
    """Reasons for data deletion."""
    
    USER_REQUEST = "user_request"           # User-initiated deletion request
    ADMIN_REQUEST = "admin_request"         # Admin-initiated deletion
    RETENTION_EXPIRY = "retention_expiry"   # Automatic deletion after retention period
    ACCOUNT_CLOSURE = "account_closure"     # Account closure
    GDPR_ARTICLE_17 = "gdpr_article_17"    # Right to be forgotten


class DeletionScope(str, Enum):
    """Scope of data deletion."""
    
    FULL_DELETION = "full_deletion"         # Complete data removal
    ANONYMIZATION = "anonymization"         # Anonymize but keep statistics
    MINIMAL_RETENTION = "minimal_retention" # Keep only legally required data


class DeletionStatus(str, Enum):
    """Status of deletion request."""
    
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class GDPRDeletionService:
    """Comprehensive data deletion service for GDPR compliance."""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.retention_days = getattr(settings, 'GDPR_DATA_RETENTION_DAYS', 2555)  # 7 years default
        self.min_audit_retention_days = getattr(settings, 'MIN_AUDIT_RETENTION_DAYS', 365)  # 1 year minimum
    
    async def request_data_deletion(
        self,
        db: AsyncSession,
        user_id: int,
        deletion_reason: DeletionReason,
        deletion_scope: DeletionScope = DeletionScope.FULL_DELETION,
        requested_by_user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        justification: Optional[str] = None,
        scheduled_for: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Request data deletion for a user.
        
        Args:
            db: Database session
            user_id: User whose data should be deleted
            deletion_reason: Reason for deletion
            deletion_scope: Scope of deletion
            requested_by_user_id: User making the request (for admin requests)
            ip_address: IP address of requester
            justification: Justification for deletion
            scheduled_for: When to execute the deletion (immediate if None)
            
        Returns:
            Dict with deletion request information
        """
        try:
            # Validate user exists
            user = await User.get_by_id(db, user_id)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Validate requester permissions
            requester_id = requested_by_user_id or user_id
            if requester_id != user_id:
                # Admin request - validate permissions
                requester = await User.get_by_id(db, requester_id)
                if not requester or not requester.is_superuser:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions for deletion request"
                    )
            
            # Check if user has already been deleted or is in deletion process
            if user.is_deleted:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User data has already been deleted"
                )
            
            deletion_request_id = f"del_{user_id}_{int(datetime.utcnow().timestamp())}"
            
            # Log deletion request
            await self.audit_logger.log_data_access(
                db=db,
                action="request_deletion",
                resource_type="user_data",
                resource_id=str(user_id),
                user_id=requester_id,
                ip_address=ip_address,
                success=True,
                description=f"Data deletion requested: {deletion_reason.value}",
                event_data={
                    'deletion_request_id': deletion_request_id,
                    'deletion_reason': deletion_reason.value,
                    'deletion_scope': deletion_scope.value,
                    'justification': justification,
                    'scheduled_for': scheduled_for.isoformat() if scheduled_for else None
                },
                pii_accessed=True
            )
            
            # Execute deletion immediately or schedule it
            if scheduled_for is None or scheduled_for <= datetime.utcnow():
                # Execute immediately
                deletion_result = await self._execute_deletion(
                    db=db,
                    user_id=user_id,
                    deletion_reason=deletion_reason,
                    deletion_scope=deletion_scope,
                    requested_by_user_id=requester_id,
                    deletion_request_id=deletion_request_id
                )
                
                return {
                    'deletion_request_id': deletion_request_id,
                    'status': DeletionStatus.COMPLETED,
                    'executed_at': datetime.utcnow().isoformat(),
                    'deletion_result': deletion_result
                }
            else:
                # Schedule for later (in a real implementation, this would use a job queue)
                logger.info(
                    "Deletion scheduled for future execution",
                    deletion_request_id=deletion_request_id,
                    user_id=user_id,
                    scheduled_for=scheduled_for
                )
                
                return {
                    'deletion_request_id': deletion_request_id,
                    'status': DeletionStatus.PENDING,
                    'scheduled_for': scheduled_for.isoformat(),
                    'message': 'Deletion request has been scheduled'
                }
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error("Failed to request data deletion", error=str(e), user_id=user_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to process deletion request"
            )
    
    async def _execute_deletion(
        self,
        db: AsyncSession,
        user_id: int,
        deletion_reason: DeletionReason,
        deletion_scope: DeletionScope,
        requested_by_user_id: int,
        deletion_request_id: str
    ) -> Dict[str, Any]:
        """Execute the actual data deletion."""
        try:
            logger.info(
                "Starting data deletion execution",
                deletion_request_id=deletion_request_id,
                user_id=user_id,
                scope=deletion_scope.value
            )
            
            deletion_result = {
                'user_id': user_id,
                'deletion_request_id': deletion_request_id,
                'deletion_scope': deletion_scope.value,
                'deletion_reason': deletion_reason.value,
                'started_at': datetime.utcnow().isoformat(),
                'deleted_records': {},
                'anonymized_records': {},
                'retained_records': {},
                'errors': []
            }
            
            if deletion_scope == DeletionScope.FULL_DELETION:
                deletion_result = await self._full_deletion(db, user_id, deletion_result)
            elif deletion_scope == DeletionScope.ANONYMIZATION:
                deletion_result = await self._anonymize_user_data(db, user_id, deletion_result)
            elif deletion_scope == DeletionScope.MINIMAL_RETENTION:
                deletion_result = await self._minimal_retention_deletion(db, user_id, deletion_result)
            
            deletion_result['completed_at'] = datetime.utcnow().isoformat()
            deletion_result['success'] = len(deletion_result['errors']) == 0
            
            # Create final audit log entry
            await self.audit_logger.log_data_access(
                db=db,
                action="execute_deletion",
                resource_type="user_data",
                resource_id=str(user_id),
                user_id=requested_by_user_id,
                success=deletion_result['success'],
                description=f"Data deletion executed: {deletion_scope.value}",
                event_data=deletion_result,
                pii_accessed=True
            )
            
            logger.info(
                "Data deletion execution completed",
                deletion_request_id=deletion_request_id,
                user_id=user_id,
                success=deletion_result['success']
            )
            
            return deletion_result
            
        except Exception as e:
            logger.error("Failed to execute deletion", error=str(e), user_id=user_id)
            deletion_result['errors'].append(f"Execution failed: {str(e)}")
            deletion_result['success'] = False
            deletion_result['completed_at'] = datetime.utcnow().isoformat()
            return deletion_result
    
    async def _full_deletion(
        self,
        db: AsyncSession,
        user_id: int,
        deletion_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform full deletion of user data."""
        try:
            # 1. Delete user sessions
            session_count = await self._delete_user_sessions(db, user_id)
            deletion_result['deleted_records']['user_sessions'] = session_count
            
            # 2. Delete user consents
            consent_count = await self._delete_user_consents(db, user_id)
            deletion_result['deleted_records']['user_consents'] = consent_count
            
            # 3. Anonymize or delete audit logs (keep minimal for compliance)
            audit_result = await self._handle_audit_logs(db, user_id, delete_old=True)
            deletion_result['deleted_records']['audit_logs'] = audit_result['deleted']
            deletion_result['anonymized_records']['audit_logs'] = audit_result['anonymized']
            deletion_result['retained_records']['audit_logs'] = audit_result['retained']
            
            # 4. Delete user roles associations
            role_count = await self._delete_user_roles(db, user_id)
            deletion_result['deleted_records']['user_roles'] = role_count
            
            # 5. Finally, delete the user record itself (soft delete with anonymization)
            user_deleted = await self._delete_user_record(db, user_id)
            deletion_result['deleted_records']['user'] = 1 if user_deleted else 0
            
            return deletion_result
            
        except Exception as e:
            deletion_result['errors'].append(f"Full deletion error: {str(e)}")
            return deletion_result bre_
    
    async def _anonymize_user_data(
        self,
        db: AsyncSession,
        user_id: int,
        deletion_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Anonymize user data while keeping statistical information."""
        try:
            # Get user record
            user = await User.get_by_id(db, user_id)
            if not user:
                deletion_result['errors'].append("User not found for anonymization")
                return deletion_result
            
            # Anonymize PII fields
            anonymous_id = f"anon_user_{user_id}_{int(datetime.utcnow().timestamp())}"
            
            user.email = f"{anonymous_id}@anonymized.local"
            user.first_name = "Anonymized"
            user.last_name = "User"
            user.phone_number = None
            user.profile_data = {"anonymized": True, "anonymized_at": datetime.utcnow().isoformat()}
            user.preferences = {"anonymized": True}
            user.is_deleted = True
            user.deleted_at = datetime.utcnow()
            
            await user.save(db)
            deletion_result['anonymized_records']['user'] = 1
            
            # Keep sessions and audit logs but anonymize IP addresses
            await self._anonymize_user_sessions(db, user_id)
            session_count = await db.scalar(select(UserSession).where(UserSession.user_id == user_id).count())
            deletion_result['anonymized_records']['user_sessions'] = session_count or 0
            
            # Anonymize audit logs
            await self._anonymize_audit_logs(db, user_id)
            audit_count = await db.scalar(select(AuditLog).where(AuditLog.user_id == user_id).count())
            deletion_result['anonymized_records']['audit_logs'] = audit_count or 0
            
            # Delete consents (no statistical value)
            consent_count = await self._delete_user_consents(db, user_id)
            deletion_result['deleted_records']['user_consents'] = consent_count
            
            return deletion_result
            
        except Exception as e:
            deletion_result['errors'].append(f"Anonymization error: {str(e)}")
            return deletion_result
    
    async def _minimal_retention_deletion(
        self,
        db: AsyncSession,
        user_id: int,
        deletion_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Delete user data but retain minimal information for legal compliance."""
        try:
            # Keep user record with minimal information
            user = await User.get_by_id(db, user_id)
            if user:
                # Clear PII but keep account structure for legal/audit purposes
                user.email = f"deleted_user_{user_id}@deleted.local"
                user.first_name = None
                user.last_name = None
                user.phone_number = None
                user.profile_data = None
                user.preferences = None
                user.is_active = False
                user.is_deleted = True
                user.deleted_at = datetime.utcnow()
                
                await user.save(db)
                deletion_result['retained_records']['user'] = 1
            
            # Delete sessions (not needed for compliance)
            session_count = await self._delete_user_sessions(db, user_id)
            deletion_result['deleted_records']['user_sessions'] = session_count
            
            # Delete consents (fulfilled their purpose)
            consent_count = await self._delete_user_consents(db, user_id)
            deletion_result['deleted_records']['user_consents'] = consent_count
            
            # Keep critical audit logs, delete routine ones
            audit_result = await self._handle_audit_logs(db, user_id, delete_old=True, keep_critical=True)
            deletion_result['deleted_records']['audit_logs'] = audit_result['deleted']
            deletion_result['retained_records']['audit_logs'] = audit_result['retained']
            
            return deletion_result
            
        except Exception as e:
            deletion_result['errors'].append(f"Minimal retention error: {str(e)}")
            return deletion_result
    
    async def _delete_user_sessions(self, db: AsyncSession, user_id: int) -> int:
        """Delete all user sessions."""
        try:
            # Get count before deletion
            count_query = select(UserSession).where(UserSession.user_id == user_id, UserSession.is_deleted == False)
            count_result = await db.execute(count_query)
            sessions = count_result.scalars().all()
            count = len(sessions)
            
            # Soft delete sessions
            for session in sessions:
                session.is_deleted = True
                session.deleted_at = datetime.utcnow()
                await session.save(db)
            
            return count
            
        except Exception as e:
            logger.error("Failed to delete user sessions", error=str(e), user_id=user_id)
            return 0
    
    async def _delete_user_consents(self, db: AsyncSession, user_id: int) -> int:
        """Delete all user consents."""
        try:
            # Get count before deletion
            count_query = select(UserConsent).where(UserConsent.user_id == user_id, UserConsent.is_deleted == False)
            count_result = await db.execute(count_query)
            consents = count_result.scalars().all()
            count = len(consents)
            
            # Soft delete consents
            for consent in consents:
                consent.is_deleted = True
                consent.deleted_at = datetime.utcnow()
                await consent.save(db)
            
            return count
            
        except Exception as e:
            logger.error("Failed to delete user consents", error=str(e), user_id=user_id)
            return 0
    
    async def _delete_user_roles(self, db: AsyncSession, user_id: int) -> int:
        """Delete user role associations."""
        try:
            user = await User.get_by_id(db, user_id)
            if user:
                role_count = len(user.roles)
                user.roles.clear()
                await user.save(db)
                return role_count
            return 0
            
        except Exception as e:
            logger.error("Failed to delete user roles", error=str(e), user_id=user_id)
            return 0
    
    async def _handle_audit_logs(
        self, 
        db: AsyncSession, 
        user_id: int, 
        delete_old: bool = True,
        keep_critical: bool = False
    ) -> Dict[str, int]:
        """Handle audit logs according to retention policy."""
        try:
            result = {'deleted': 0, 'anonymized': 0, 'retained': 0}
            
            # Get all audit logs for user
            query = select(AuditLog).where(AuditLog.user_id == user_id)
            audit_result = await db.execute(query)
            audit_logs = audit_result.scalars().all()
            
            cutoff_date = datetime.utcnow() - timedelta(days=self.min_audit_retention_days)
            critical_events = [
                AuditEventType.LOGIN_SUCCESS,
                AuditEventType.LOGIN_FAILURE,
                AuditEventType.PASSWORD_CHANGE,
                AuditEventType.GDPR_DATA_REQUEST,
                AuditEventType.GDPR_DATA_DELETE
            ]
            
            for log in audit_logs:
                if keep_critical and log.event_type in critical_events:
                    # Keep critical logs but anonymize
                    log.ip_address = "0.0.0.0"
                    log.user_agent = "anonymized"
                    log.event_data = {"anonymized": True}
                    await log.save(db)
                    result['anonymized'] += 1
                elif delete_old and log.timestamp < cutoff_date:
                    # Delete old logs
                    await log.delete(db, hard_delete=True)
                    result['deleted'] += 1
                else:
                    # Retain recent logs
                    result['retained'] += 1
            
            return result
            
        except Exception as e:
            logger.error("Failed to handle audit logs", error=str(e), user_id=user_id)
            return {'deleted': 0, 'anonymized': 0, 'retained': 0}
    
    async def _delete_user_record(self, db: AsyncSession, user_id: int) -> bool:
        """Soft delete and anonymize user record."""
        try:
            user = await User.get_by_id(db, user_id)
            if user:
                # Anonymize PII and soft delete
                anonymous_email = f"deleted_{user_id}_{int(datetime.utcnow().timestamp())}@deleted.local"
                
                user.email = anonymous_email
                user.email_hash = User._hash_email(anonymous_email)
                user.first_name = None
                user.last_name = None
                user.phone_number = None
                user.profile_data = None
                user.preferences = None
                user.is_active = False
                user.is_deleted = True
                user.deleted_at = datetime.utcnow()
                
                await user.save(db)
                return True
            return False
            
        except Exception as e:
            logger.error("Failed to delete user record", error=str(e), user_id=user_id)
            return False
    
    async def _anonymize_user_sessions(self, db: AsyncSession, user_id: int) -> int:
        """Anonymize user sessions."""
        try:
            query = select(UserSession).where(UserSession.user_id == user_id)
            result = await db.execute(query)
            sessions = result.scalars().all()
            
            count = 0
            for session in sessions:
                session.ip_address = "0.0.0.0"
                session.user_agent = "anonymized"
                session.device_info = {"anonymized": True}
                session.location_data = {"anonymized": True}
                await session.save(db)
                count += 1
            
            return count
            
        except Exception as e:
            logger.error("Failed to anonymize user sessions", error=str(e), user_id=user_id)
            return 0
    
    async def _anonymize_audit_logs(self, db: AsyncSession, user_id: int) -> int:
        """Anonymize audit logs."""
        try:
            query = select(AuditLog).where(AuditLog.user_id == user_id)
            result = await db.execute(query)
            audit_logs = result.scalars().all()
            
            count = 0
            for log in audit_logs:
                log.ip_address = "0.0.0.0"
                log.user_agent = "anonymized"
                if log.event_data:
                    log.event_data = {"anonymized": True, "original_event_type": log.event_type.value}
                await log.save(db)
                count += 1
            
            return count
            
        except Exception as e:
            logger.error("Failed to anonymize audit logs", error=str(e), user_id=user_id)
            return 0
    
    async def schedule_retention_cleanup(self, db: AsyncSession) -> Dict[str, Any]:
        """
        Schedule cleanup of data that has exceeded retention period.
        Should be run as a periodic task.
        """
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
            
            # Find users with expired retention
            query = select(User).where(
                User.data_retention_until < datetime.utcnow(),
                User.is_deleted == False,
                User.is_active == False  # Only inactive users
            )
            
            result = await db.execute(query)
            expired_users = result.scalars().all()
            
            cleanup_results = []
            
            for user in expired_users:
                try:
                    deletion_result = await self.request_data_deletion(
                        db=db,
                        user_id=user.id,
                        deletion_reason=DeletionReason.RETENTION_EXPIRY,
                        deletion_scope=DeletionScope.MINIMAL_RETENTION,
                        requested_by_user_id=None,  # System request
                        justification="Automatic cleanup after data retention period"
                    )
                    
                    cleanup_results.append({
                        'user_id': user.id,
                        'status': 'scheduled',
                        'deletion_request_id': deletion_result.get('deletion_request_id')
                    })
                    
                except Exception as e:
                    cleanup_results.append({
                        'user_id': user.id,
                        'status': 'failed',
                        'error': str(e)
                    })
            
            logger.info(
                "Retention cleanup scheduled",
                total_users=len(expired_users),
                successful=len([r for r in cleanup_results if r['status'] == 'scheduled']),
                failed=len([r for r in cleanup_results if r['status'] == 'failed'])
            )
            
            return {
                'cutoff_date': cutoff_date.isoformat(),
                'total_users_processed': len(expired_users),
                'cleanup_results': cleanup_results
            }
            
        except Exception as e:
            logger.error("Failed to schedule retention cleanup", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to schedule retention cleanup"
            )