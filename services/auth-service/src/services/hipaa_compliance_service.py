"""
HIPAA Compliance Service implementing enhanced PHI protection, audit trails,
and emergency access procedures.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import structlog
import asyncio
from contextlib import asynccontextmanager

from ..models.hipaa_compliance import (
    PHIAccessLog, BusinessAssociateAgreement, EmergencyAccess, HIPAASessionContext,
    PHICategory, AccessPurpose, EmergencyAccessType, BAAAgreementStatus
)
from ..models.audit import AuditLog, AuditEventType, AuditSeverity
from ..models.user import User
from ..core.config import settings

logger = structlog.get_logger()


class HIPAAComplianceService:
    """Service for HIPAA compliance operations."""
    
    def __init__(self):
        self.logger = structlog.get_logger("hipaa_compliance")
        self.phi_session_timeout_minutes = getattr(settings, 'HIPAA_PHI_SESSION_TIMEOUT_MINUTES', 15)
        self.emergency_access_max_hours = getattr(settings, 'HIPAA_EMERGENCY_ACCESS_MAX_HOURS', 24)
    
    async def log_phi_access(
        self,
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
        **kwargs
    ) -> PHIAccessLog:
        """
        Log PHI access with comprehensive audit trail.
        
        Args:
            db: Database session
            user_id: ID of user accessing PHI
            phi_category: Category of PHI being accessed
            resource_type: Type of resource (e.g., 'patient', 'medical_record')
            resource_id: Unique identifier of the resource
            access_purpose: Purpose of access under HIPAA
            access_method: Method of access ('web', 'api', 'mobile', etc.)
            action_performed: Action performed ('read', 'create', 'update', 'delete')
            access_justification: Required justification for access
            Other parameters: Additional context and metadata
        
        Returns:
            PHIAccessLog: Created PHI access log entry
        """
        try:
            # Validate minimum necessary principle
            if not access_justification.strip():
                raise ValueError("Access justification is required for PHI access")
            
            if access_purpose == AccessPurpose.MINIMUM_NECESSARY and not minimum_necessary_applied:
                self.logger.warning(
                    "Minimum necessary principle not applied",
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id
                )
            
            # Create PHI access log
            phi_log = await PHIAccessLog.create_phi_access_log(
                db=db,
                user_id=user_id,
                phi_category=phi_category,
                resource_type=resource_type,
                resource_id=resource_id,
                access_purpose=access_purpose,
                access_method=access_method,
                action_performed=action_performed,
                access_justification=access_justification,
                session_id=session_id,
                patient_id=patient_id,
                patient_mrn=patient_mrn,
                phi_fields_accessed=phi_fields_accessed,
                data_volume=data_volume,
                ip_address=ip_address,
                user_agent=user_agent,
                authorization_id=authorization_id,
                minimum_necessary_applied=minimum_necessary_applied,
                **kwargs
            )
            
            # Create corresponding audit log
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.HIPAA_ACCESS,
                action=f"phi_{action_performed}",
                description=f"PHI {action_performed} access for {resource_type}:{resource_id}",
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                resource_type=resource_type,
                resource_id=resource_id,
                success=True,
                severity=AuditSeverity.MEDIUM,
                pii_accessed=True,
                hipaa_relevant=True,
                event_data={
                    "phi_category": phi_category.value,
                    "access_purpose": access_purpose.value,
                    "access_justification": access_justification,
                    "patient_id": patient_id,
                    "phi_fields_accessed": phi_fields_accessed,
                    "data_volume": data_volume,
                    "minimum_necessary_applied": minimum_necessary_applied
                }
            )
            
            # Update HIPAA session context if exists
            if session_id:
                await self._update_hipaa_session_phi_access(db, session_id, patient_id)
            
            self.logger.info(
                "PHI access logged",
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                phi_category=phi_category.value,
                access_purpose=access_purpose.value,
                patient_id=patient_id
            )
            
            return phi_log
            
        except Exception as e:
            self.logger.error(
                "Failed to log PHI access",
                error=str(e),
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id
            )
            raise
    
    async def create_emergency_access(
        self,
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
        requires_approval: bool = True
    ) -> EmergencyAccess:
        """
        Create emergency access session with break-glass functionality.
        
        Args:
            db: Database session
            user_id: ID of user requesting emergency access
            emergency_type: Type of emergency access
            emergency_justification: Detailed justification for emergency access
            Other parameters: Additional context
            requires_approval: Whether approval is required (default: True)
        
        Returns:
            EmergencyAccess: Created emergency access record
        """
        try:
            # Validate emergency justification
            if not emergency_justification.strip():
                raise ValueError("Emergency justification is required")
            
            # Check for existing active emergency access
            existing_access = await EmergencyAccess.get_active_emergency_sessions(db, user_id)
            if existing_access:
                self.logger.warning(
                    "User already has active emergency access",
                    user_id=user_id,
                    existing_emergency_ids=[ea.emergency_id for ea in existing_access]
                )
            
            # Create emergency access record
            emergency_access = await EmergencyAccess.create_emergency_access(
                db=db,
                user_id=user_id,
                emergency_type=emergency_type,
                emergency_justification=emergency_justification,
                patient_id=patient_id,
                patient_mrn=patient_mrn,
                location=location,
                department=department,
                clinical_context=clinical_context,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                approval_required=requires_approval
            )
            
            # Create audit log for emergency access creation
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.SECURITY_ALERT,
                action="emergency_access_created",
                description=f"Emergency access created: {emergency_type.value}",
                user_id=user_id,
                session_id=session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                success=True,
                severity=AuditSeverity.HIGH,
                event_data={
                    "emergency_type": emergency_type.value,
                    "emergency_justification": emergency_justification,
                    "patient_id": patient_id,
                    "location": location,
                    "department": department,
                    "requires_approval": requires_approval
                }
            )
            
            # Update HIPAA session context if exists
            if session_id:
                await self._activate_emergency_session_context(db, session_id, emergency_access.emergency_id)
            
            # Auto-approve for life-threatening emergencies
            if emergency_type == EmergencyAccessType.LIFE_THREATENING and not requires_approval:
                await emergency_access.approve_emergency_access(db, user_id)
                self.logger.info(
                    "Life-threatening emergency access auto-approved",
                    emergency_id=emergency_access.emergency_id,
                    user_id=user_id
                )
            
            self.logger.info(
                "Emergency access created",
                emergency_id=emergency_access.emergency_id,
                user_id=user_id,
                emergency_type=emergency_type.value,
                patient_id=patient_id
            )
            
            return emergency_access
            
        except Exception as e:
            self.logger.error(
                "Failed to create emergency access",
                error=str(e),
                user_id=user_id,
                emergency_type=emergency_type.value
            )
            raise
    
    async def terminate_emergency_access(
        self,
        db: AsyncSession,
        emergency_id: str,
        terminated_by_user_id: int,
        termination_reason: Optional[str] = None
    ) -> bool:
        """
        Terminate emergency access session.
        
        Args:
            db: Database session
            emergency_id: ID of emergency access to terminate
            terminated_by_user_id: ID of user terminating access
            termination_reason: Reason for termination
        
        Returns:
            bool: True if successfully terminated
        """
        try:
            # Get emergency access record
            query = select(EmergencyAccess).where(
                EmergencyAccess.emergency_id == emergency_id,
                EmergencyAccess.is_active == True
            )
            result = await db.execute(query)
            emergency_access = result.scalar_one_or_none()
            
            if not emergency_access:
                self.logger.warning(
                    "Emergency access not found or already terminated",
                    emergency_id=emergency_id
                )
                return False
            
            # Terminate emergency access
            await emergency_access.terminate_emergency_access(
                db=db,
                terminated_by_user_id=terminated_by_user_id,
                termination_reason=termination_reason
            )
            
            # Create audit log for termination
            await AuditLog.create_audit_log(
                db=db,
                event_type=AuditEventType.SECURITY_ALERT,
                action="emergency_access_terminated",
                description=f"Emergency access terminated: {emergency_access.emergency_type.value}",
                user_id=terminated_by_user_id,
                success=True,
                severity=AuditSeverity.MEDIUM,
                event_data={
                    "emergency_id": emergency_id,
                    "original_user_id": emergency_access.user_id,
                    "emergency_type": emergency_access.emergency_type.value,
                    "duration_minutes": emergency_access.get_duration_minutes(),
                    "termination_reason": termination_reason
                }
            )
            
            # Deactivate emergency session context if exists
            if emergency_access.session_id:
                await self._deactivate_emergency_session_context(db, emergency_access.session_id)
            
            self.logger.info(
                "Emergency access terminated",
                emergency_id=emergency_id,
                original_user_id=emergency_access.user_id,
                terminated_by_user_id=terminated_by_user_id,
                duration_minutes=emergency_access.get_duration_minutes()
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to terminate emergency access",
                error=str(e),
                emergency_id=emergency_id,
                terminated_by_user_id=terminated_by_user_id
            )
            raise
    
    async def create_hipaa_session_context(
        self,
        db: AsyncSession,
        session_id: str,
        user_id: int,
        phi_access_level: str = "none",
        department_context: Optional[str] = None,
        role_context: Optional[str] = None,
        phi_session_timeout_minutes: Optional[int] = None
    ) -> HIPAASessionContext:
        """
        Create HIPAA-compliant session context with automatic PHI timeout.
        
        Args:
            db: Database session
            session_id: Session ID
            user_id: User ID
            phi_access_level: Level of PHI access ('none', 'limited', 'full')
            department_context: Department context
            role_context: Role context
            phi_session_timeout_minutes: PHI session timeout (default from settings)
        
        Returns:
            HIPAASessionContext: Created HIPAA session context
        """
        try:
            timeout_minutes = phi_session_timeout_minutes or self.phi_session_timeout_minutes
            
            hipaa_session = await HIPAASessionContext.create_hipaa_session(
                db=db,
                session_id=session_id,
                user_id=user_id,
                phi_access_level=phi_access_level,
                department_context=department_context,
                role_context=role_context,
                phi_session_timeout_minutes=timeout_minutes
            )
            
            self.logger.info(
                "HIPAA session context created",
                session_id=session_id,
                user_id=user_id,
                phi_access_level=phi_access_level,
                timeout_minutes=timeout_minutes
            )
            
            return hipaa_session
            
        except Exception as e:
            self.logger.error(
                "Failed to create HIPAA session context",
                error=str(e),
                session_id=session_id,
                user_id=user_id
            )
            raise
    
    async def check_phi_session_timeout(
        self,
        db: AsyncSession,
        session_id: str
    ) -> Tuple[bool, bool]:
        """
        Check if PHI session has timed out and if warning should be issued.
        
        Args:
            db: Database session
            session_id: Session ID to check
        
        Returns:
            Tuple[bool, bool]: (is_expired, should_warn)
        """
        try:
            # Get HIPAA session context
            query = select(HIPAASessionContext).where(
                HIPAASessionContext.session_id == session_id
            )
            result = await db.execute(query)
            hipaa_session = result.scalar_one_or_none()
            
            if not hipaa_session:
                return False, False
            
            is_expired = hipaa_session.is_phi_session_expired()
            should_warn = hipaa_session.should_issue_timeout_warning()
            
            if should_warn and not hipaa_session.warning_issued_at:
                await hipaa_session.issue_timeout_warning(db)
                self.logger.info(
                    "PHI session timeout warning issued",
                    session_id=session_id,
                    user_id=hipaa_session.user_id
                )
            
            if is_expired:
                self.logger.info(
                    "PHI session expired due to inactivity",
                    session_id=session_id,
                    user_id=hipaa_session.user_id,
                    last_access=hipaa_session.last_phi_access
                )
            
            return is_expired, should_warn
            
        except Exception as e:
            self.logger.error(
                "Failed to check PHI session timeout",
                error=str(e),
                session_id=session_id
            )
            return False, False
    
    async def manage_baa_agreements(
        self,
        db: AsyncSession
    ) -> Dict[str, List[BusinessAssociateAgreement]]:
        """
        Get BAA agreement management information.
        
        Args:
            db: Database session
        
        Returns:
            Dict with lists of active, expiring, and expired agreements
        """
        try:
            active_agreements = await BusinessAssociateAgreement.get_active_agreements(db)
            expiring_agreements = await BusinessAssociateAgreement.get_expiring_agreements(db, days_ahead=30)
            
            # Get expired agreements
            now = datetime.utcnow()
            query = select(BusinessAssociateAgreement).where(
                BusinessAssociateAgreement.expiration_date <= now,
                BusinessAssociateAgreement.status != BAAAgreementStatus.TERMINATED
            ).order_by(BusinessAssociateAgreement.expiration_date.desc()).limit(50)
            
            result = await db.execute(query)
            expired_agreements = result.scalars().all()
            
            return {
                "active": active_agreements,
                "expiring": expiring_agreements,
                "expired": expired_agreements
            }
            
        except Exception as e:
            self.logger.error(
                "Failed to manage BAA agreements",
                error=str(e)
            )
            raise
    
    async def get_phi_access_audit_trail(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        patient_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[PHIAccessLog]:
        """
        Get comprehensive PHI access audit trail.
        
        Args:
            db: Database session
            user_id: Filter by user ID
            patient_id: Filter by patient ID
            resource_type: Filter by resource type
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of records
        
        Returns:
            List[PHIAccessLog]: PHI access log entries
        """
        try:
            return await PHIAccessLog.get_phi_access_history(
                db=db,
                user_id=user_id,
                patient_id=patient_id,
                resource_type=resource_type,
                start_date=start_date,
                end_date=end_date,
                limit=limit
            )
        except Exception as e:
            self.logger.error(
                "Failed to get PHI access audit trail",
                error=str(e),
                user_id=user_id,
                patient_id=patient_id
            )
            raise
    
    async def cleanup_expired_emergency_access(
        self,
        db: AsyncSession,
        max_hours: Optional[int] = None
    ) -> int:
        """
        Clean up expired emergency access sessions.
        
        Args:
            db: Database session
            max_hours: Maximum hours for emergency access (default from settings)
        
        Returns:
            int: Number of expired sessions cleaned up
        """
        try:
            max_hours = max_hours or self.emergency_access_max_hours
            cutoff_time = datetime.utcnow() - timedelta(hours=max_hours)
            
            # Get active emergency access sessions that have exceeded max duration
            query = select(EmergencyAccess).where(
                EmergencyAccess.is_active == True,
                EmergencyAccess.emergency_start_time <= cutoff_time
            )
            
            result = await db.execute(query)
            expired_sessions = result.scalars().all()
            
            cleanup_count = 0
            for session in expired_sessions:
                await session.terminate_emergency_access(
                    db=db,
                    terminated_by_user_id=1,  # System user
                    termination_reason=f"Automatic termination after {max_hours} hours"
                )
                cleanup_count += 1
                
                self.logger.info(
                    "Emergency access auto-terminated",
                    emergency_id=session.emergency_id,
                    user_id=session.user_id,
                    duration_hours=max_hours
                )
            
            return cleanup_count
            
        except Exception as e:
            self.logger.error(
                "Failed to cleanup expired emergency access",
                error=str(e)
            )
            raise
    
    async def _update_hipaa_session_phi_access(
        self,
        db: AsyncSession,
        session_id: str,
        patient_context: Optional[str] = None
    ) -> None:
        """Update HIPAA session context with PHI access information."""
        try:
            query = select(HIPAASessionContext).where(
                HIPAASessionContext.session_id == session_id
            )
            result = await db.execute(query)
            hipaa_session = result.scalar_one_or_none()
            
            if hipaa_session:
                await hipaa_session.update_phi_access(
                    db=db,
                    phi_access_level="full",
                    patient_context=patient_context
                )
        except Exception as e:
            self.logger.error(
                "Failed to update HIPAA session PHI access",
                error=str(e),
                session_id=session_id
            )
    
    async def _activate_emergency_session_context(
        self,
        db: AsyncSession,
        session_id: str,
        emergency_access_id: str
    ) -> None:
        """Activate emergency access in HIPAA session context."""
        try:
            query = select(HIPAASessionContext).where(
                HIPAASessionContext.session_id == session_id
            )
            result = await db.execute(query)
            hipaa_session = result.scalar_one_or_none()
            
            if hipaa_session:
                hipaa_session.emergency_access_active = True
                hipaa_session.emergency_access_id = emergency_access_id
                await hipaa_session.save(db)
        except Exception as e:
            self.logger.error(
                "Failed to activate emergency session context",
                error=str(e),
                session_id=session_id
            )
    
    async def _deactivate_emergency_session_context(
        self,
        db: AsyncSession,
        session_id: str
    ) -> None:
        """Deactivate emergency access in HIPAA session context."""
        try:
            query = select(HIPAASessionContext).where(
                HIPAASessionContext.session_id == session_id
            )
            result = await db.execute(query)
            hipaa_session = result.scalar_one_or_none()
            
            if hipaa_session:
                hipaa_session.emergency_access_active = False
                hipaa_session.emergency_access_id = None
                await hipaa_session.save(db)
        except Exception as e:
            self.logger.error(
                "Failed to deactivate emergency session context",
                error=str(e),
                session_id=session_id
            )
    
    @asynccontextmanager
    async def hipaa_phi_access_context(
        self,
        db: AsyncSession,
        user_id: int,
        phi_category: PHICategory,
        resource_type: str,
        resource_id: str,
        access_purpose: AccessPurpose,
        access_justification: str,
        **kwargs
    ):
        """
        Context manager for PHI access with automatic logging.
        
        Usage:
            async with hipaa_service.hipaa_phi_access_context(
                db, user_id, PHICategory.MEDICAL_DATA, "patient", "123",
                AccessPurpose.TREATMENT, "Reviewing patient chart for treatment"
            ) as phi_context:
                # Access PHI data here
                patient_data = await get_patient_data(123)
                phi_context.log_fields_accessed(["name", "dob", "diagnosis"])
        """
        class PHIAccessContext:
            def __init__(self, service, db, log_data):
                self.service = service
                self.db = db
                self.log_data = log_data
                self.fields_accessed = []
                self.data_volume = None
                self.success = True
                self.error_message = None
            
            def log_fields_accessed(self, fields: List[str]):
                self.fields_accessed.extend(fields)
            
            def set_data_volume(self, volume: int):
                self.data_volume = volume
            
            def mark_error(self, error_message: str):
                self.success = False
                self.error_message = error_message
        
        context = PHIAccessContext(self, db, {
            'user_id': user_id,
            'phi_category': phi_category,
            'resource_type': resource_type,
            'resource_id': resource_id,
            'access_purpose': access_purpose,
            'access_justification': access_justification,
            **kwargs
        })
        
        try:
            yield context
        except Exception as e:
            context.mark_error(str(e))
            raise
        finally:
            # Log PHI access regardless of success/failure
            await self.log_phi_access(
                db=db,
                action_performed="read",
                phi_fields_accessed=context.fields_accessed,
                data_volume=context.data_volume,
                access_successful=context.success,
                error_message=context.error_message,
                **context.log_data
            )