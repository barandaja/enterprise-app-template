"""
Comprehensive tests for HIPAA compliance features.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.hipaa_compliance import (
    PHIAccessLog, BusinessAssociateAgreement, EmergencyAccess, HIPAASessionContext,
    PHICategory, AccessPurpose, EmergencyAccessType, BAAAgreementStatus
)
from src.services.hipaa_compliance_service import HIPAAComplianceService
from src.models.audit import AuditLog, AuditEventType
from tests.factories.user_factory import UserFactory


class TestPHIAccessLog:
    """Test PHI Access Log model functionality."""
    
    @pytest.mark.asyncio
    async def test_create_phi_access_log(self, db_session: AsyncSession):
        """Test creating PHI access log."""
        user = await UserFactory.create_async(db_session)
        
        phi_log = await PHIAccessLog.create_phi_access_log(
            db=db_session,
            user_id=user.id,
            phi_category=PHICategory.MEDICAL_DATA,
            resource_type="patient_record",
            resource_id="PR123",
            access_purpose=AccessPurpose.TREATMENT,
            access_method="web",
            action_performed="read",
            access_justification="Reviewing patient chart for treatment planning",
            patient_id="P123",
            phi_fields_accessed=["name", "dob", "diagnosis"],
            data_volume=1,
            ip_address="192.168.1.100"
        )
        
        assert phi_log.access_id is not None
        assert phi_log.user_id == user.id
        assert phi_log.phi_category == PHICategory.MEDICAL_DATA
        assert phi_log.resource_type == "patient_record"
        assert phi_log.resource_id == "PR123"
        assert phi_log.access_purpose == AccessPurpose.TREATMENT
        assert phi_log.access_successful is True
        assert phi_log.patient_id == "P123"
        assert phi_log.phi_fields_accessed == ["name", "dob", "diagnosis"]
        assert phi_log.minimum_necessary_applied is True
    
    @pytest.mark.asyncio
    async def test_get_phi_access_history(self, db_session: AsyncSession):
        """Test retrieving PHI access history."""
        user = await UserFactory.create_async(db_session)
        
        # Create multiple PHI access logs
        for i in range(3):
            await PHIAccessLog.create_phi_access_log(
                db=db_session,
                user_id=user.id,
                phi_category=PHICategory.MEDICAL_DATA,
                resource_type="patient_record",
                resource_id=f"PR{i}",
                access_purpose=AccessPurpose.TREATMENT,
                access_method="web",
                action_performed="read",
                access_justification=f"Treatment access {i}",
                patient_id=f"P{i}"
            )
        
        # Get history for user
        history = await PHIAccessLog.get_phi_access_history(
            db=db_session,
            user_id=user.id,
            limit=10
        )
        
        assert len(history) == 3
        assert all(log.user_id == user.id for log in history)
    
    @pytest.mark.asyncio
    async def test_get_phi_access_history_with_filters(self, db_session: AsyncSession):
        """Test retrieving PHI access history with filters."""
        user = await UserFactory.create_async(db_session)
        
        # Create access logs for different patients
        await PHIAccessLog.create_phi_access_log(
            db=db_session,
            user_id=user.id,
            phi_category=PHICategory.MEDICAL_DATA,
            resource_type="patient_record",
            resource_id="PR1",
            access_purpose=AccessPurpose.TREATMENT,
            access_method="web",
            action_performed="read",
            access_justification="Treatment access",
            patient_id="P123"
        )
        
        await PHIAccessLog.create_phi_access_log(
            db=db_session,
            user_id=user.id,
            phi_category=PHICategory.DEMOGRAPHIC,
            resource_type="patient_record",
            resource_id="PR2",
            access_purpose=AccessPurpose.PAYMENT,
            access_method="api",
            action_performed="read",
            access_justification="Billing access",
            patient_id="P456"
        )
        
        # Filter by patient
        patient_history = await PHIAccessLog.get_phi_access_history(
            db=db_session,
            patient_id="P123",
            limit=10
        )
        
        assert len(patient_history) == 1
        assert patient_history[0].patient_id == "P123"
        
        # Filter by resource type
        resource_history = await PHIAccessLog.get_phi_access_history(
            db=db_session,
            resource_type="patient_record",
            limit=10
        )
        
        assert len(resource_history) == 2


class TestBusinessAssociateAgreement:
    """Test Business Associate Agreement model functionality."""
    
    @pytest.mark.asyncio
    async def test_create_baa(self, db_session: AsyncSession):
        """Test creating BAA."""
        effective_date = datetime.utcnow()
        expiration_date = effective_date + timedelta(days=365)
        
        baa = await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Test Vendor Inc.",
            agreement_title="Cloud Storage Services BAA",
            covered_services=["data_storage", "backup_services"],
            phi_categories_covered=["medical_data", "demographic"],
            effective_date=effective_date,
            expiration_date=expiration_date,
            business_associate_type="vendor"
        )
        
        assert baa.agreement_id is not None
        assert baa.business_associate_name == "Test Vendor Inc."
        assert baa.agreement_title == "Cloud Storage Services BAA"
        assert baa.covered_services == ["data_storage", "backup_services"]
        assert baa.phi_categories_covered == ["medical_data", "demographic"]
        assert baa.status == BAAAgreementStatus.ACTIVE
        assert baa.is_active() is True
    
    @pytest.mark.asyncio
    async def test_get_active_agreements(self, db_session: AsyncSession):
        """Test getting active BAA agreements."""
        now = datetime.utcnow()
        
        # Create active agreement
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Active Vendor",
            agreement_title="Active BAA",
            covered_services=["service1"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=30),
            expiration_date=now + timedelta(days=335)
        )
        
        # Create expired agreement
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Expired Vendor",
            agreement_title="Expired BAA",
            covered_services=["service2"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=400),
            expiration_date=now - timedelta(days=35)
        )
        
        active_agreements = await BusinessAssociateAgreement.get_active_agreements(db_session)
        
        assert len(active_agreements) == 1
        assert active_agreements[0].business_associate_name == "Active Vendor"
    
    @pytest.mark.asyncio
    async def test_get_expiring_agreements(self, db_session: AsyncSession):
        """Test getting expiring BAA agreements."""
        now = datetime.utcnow()
        
        # Create agreement expiring soon
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Expiring Soon",
            agreement_title="Expiring BAA",
            covered_services=["service1"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=330),
            expiration_date=now + timedelta(days=20)
        )
        
        # Create agreement not expiring soon
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Not Expiring",
            agreement_title="Long Term BAA",
            covered_services=["service2"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=30),
            expiration_date=now + timedelta(days=300)
        )
        
        expiring_agreements = await BusinessAssociateAgreement.get_expiring_agreements(
            db_session, days_ahead=30
        )
        
        assert len(expiring_agreements) == 1
        assert expiring_agreements[0].business_associate_name == "Expiring Soon"
    
    def test_days_until_expiration(self):
        """Test calculating days until expiration."""
        now = datetime.utcnow()
        baa = BusinessAssociateAgreement(
            expiration_date=now + timedelta(days=15)
        )
        
        days = baa.days_until_expiration()
        assert days == 15


class TestEmergencyAccess:
    """Test Emergency Access model functionality."""
    
    @pytest.mark.asyncio
    async def test_create_emergency_access(self, db_session: AsyncSession):
        """Test creating emergency access."""
        user = await UserFactory.create_async(db_session)
        
        emergency_access = await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Patient in critical condition, need immediate access to medical records",
            patient_id="P123",
            location="Emergency Room",
            department="Emergency Medicine",
            clinical_context="Cardiac arrest, need medical history"
        )
        
        assert emergency_access.emergency_id is not None
        assert emergency_access.user_id == user.id
        assert emergency_access.emergency_type == EmergencyAccessType.BREAK_GLASS
        assert emergency_access.is_active is True
        assert emergency_access.patient_id == "P123"
        assert emergency_access.location == "Emergency Room"
        assert emergency_access.approval_required is True
    
    @pytest.mark.asyncio
    async def test_get_active_emergency_sessions(self, db_session: AsyncSession):
        """Test getting active emergency sessions."""
        user = await UserFactory.create_async(db_session)
        
        # Create active emergency access
        await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.LIFE_THREATENING,
            emergency_justification="Life threatening emergency",
            patient_id="P123"
        )
        
        # Create terminated emergency access
        terminated_access = await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.CLINICAL_EMERGENCY,
            emergency_justification="Clinical emergency",
            patient_id="P456"
        )
        await terminated_access.terminate_emergency_access(
            db=db_session,
            terminated_by_user_id=user.id,
            termination_reason="Emergency resolved"
        )
        
        active_sessions = await EmergencyAccess.get_active_emergency_sessions(db_session)
        
        assert len(active_sessions) == 1
        assert active_sessions[0].patient_id == "P123"
        assert active_sessions[0].is_active is True
    
    @pytest.mark.asyncio
    async def test_approve_emergency_access(self, db_session: AsyncSession):
        """Test approving emergency access."""
        user = await UserFactory.create_async(db_session)
        approver = await UserFactory.create_async(db_session)
        
        emergency_access = await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Emergency justification"
        )
        
        await emergency_access.approve_emergency_access(db_session, approver.id)
        
        assert emergency_access.approved_at is not None
        assert emergency_access.approved_by_user_id == approver.id
    
    @pytest.mark.asyncio
    async def test_terminate_emergency_access(self, db_session: AsyncSession):
        """Test terminating emergency access."""
        user = await UserFactory.create_async(db_session)
        terminator = await UserFactory.create_async(db_session)
        
        emergency_access = await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Emergency justification"
        )
        
        await emergency_access.terminate_emergency_access(
            db=db_session,
            terminated_by_user_id=terminator.id,
            termination_reason="Emergency resolved"
        )
        
        assert emergency_access.is_active is False
        assert emergency_access.terminated_at is not None
        assert emergency_access.terminated_by_user_id == terminator.id
        assert emergency_access.termination_reason == "Emergency resolved"
        assert emergency_access.emergency_end_time is not None
    
    def test_is_expired(self):
        """Test checking if emergency access is expired."""
        now = datetime.utcnow()
        
        # Not expired
        emergency_access = EmergencyAccess(
            emergency_start_time=now - timedelta(hours=12)
        )
        assert emergency_access.is_expired(max_duration_hours=24) is False
        
        # Expired
        emergency_access = EmergencyAccess(
            emergency_start_time=now - timedelta(hours=25)
        )
        assert emergency_access.is_expired(max_duration_hours=24) is True
    
    def test_get_duration_minutes(self):
        """Test getting emergency access duration."""
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=45)
        
        emergency_access = EmergencyAccess(
            emergency_start_time=start_time,
            emergency_end_time=end_time
        )
        
        duration = emergency_access.get_duration_minutes()
        assert duration == 45


class TestHIPAASessionContext:
    """Test HIPAA Session Context model functionality."""
    
    @pytest.mark.asyncio
    async def test_create_hipaa_session(self, db_session: AsyncSession):
        """Test creating HIPAA session context."""
        user = await UserFactory.create_async(db_session)
        session_id = "test_session_123"
        
        hipaa_session = await HIPAASessionContext.create_hipaa_session(
            db=db_session,
            session_id=session_id,
            user_id=user.id,
            phi_access_level="limited",
            department_context="Cardiology",
            role_context="physician",
            phi_session_timeout_minutes=20
        )
        
        assert hipaa_session.session_id == session_id
        assert hipaa_session.user_id == user.id
        assert hipaa_session.phi_access_level == "limited"
        assert hipaa_session.department_context == "Cardiology"
        assert hipaa_session.role_context == "physician"
        assert hipaa_session.phi_session_timeout_minutes == 20
        assert hipaa_session.emergency_access_active is False
    
    @pytest.mark.asyncio
    async def test_update_phi_access(self, db_session: AsyncSession):
        """Test updating PHI access in session."""
        user = await UserFactory.create_async(db_session)
        
        hipaa_session = await HIPAASessionContext.create_hipaa_session(
            db=db_session,
            session_id="test_session",
            user_id=user.id
        )
        
        await hipaa_session.update_phi_access(
            db=db_session,
            phi_access_level="full",
            patient_context="P123"
        )
        
        assert hipaa_session.phi_access_level == "full"
        assert hipaa_session.current_patient_context == "P123"
        assert hipaa_session.last_phi_access is not None
        assert hipaa_session.warning_issued_at is None
    
    def test_is_phi_session_expired(self):
        """Test checking if PHI session is expired."""
        now = datetime.utcnow()
        
        # Not expired
        hipaa_session = HIPAASessionContext(
            last_phi_access=now - timedelta(minutes=10),
            phi_session_timeout_minutes=15
        )
        assert hipaa_session.is_phi_session_expired() is False
        
        # Expired
        hipaa_session = HIPAASessionContext(
            last_phi_access=now - timedelta(minutes=20),
            phi_session_timeout_minutes=15
        )
        assert hipaa_session.is_phi_session_expired() is True
        
        # No access yet
        hipaa_session = HIPAASessionContext(
            last_phi_access=None,
            phi_session_timeout_minutes=15
        )
        assert hipaa_session.is_phi_session_expired() is False
    
    def test_should_issue_timeout_warning(self):
        """Test checking if timeout warning should be issued."""
        now = datetime.utcnow()
        
        # Should warn (13 minutes into 15 minute session)
        hipaa_session = HIPAASessionContext(
            last_phi_access=now - timedelta(minutes=13),
            phi_session_timeout_minutes=15,
            warning_issued_at=None
        )
        assert hipaa_session.should_issue_timeout_warning(warning_minutes_before=2) is True
        
        # Should not warn (only 5 minutes into session)
        hipaa_session = HIPAASessionContext(
            last_phi_access=now - timedelta(minutes=5),
            phi_session_timeout_minutes=15,
            warning_issued_at=None
        )
        assert hipaa_session.should_issue_timeout_warning(warning_minutes_before=2) is False
        
        # Should not warn (already warned)
        hipaa_session = HIPAASessionContext(
            last_phi_access=now - timedelta(minutes=13),
            phi_session_timeout_minutes=15,
            warning_issued_at=now - timedelta(minutes=1)
        )
        assert hipaa_session.should_issue_timeout_warning(warning_minutes_before=2) is False


class TestHIPAAComplianceService:
    """Test HIPAA Compliance Service functionality."""
    
    @pytest.fixture
    def hipaa_service(self):
        """Create HIPAA compliance service instance."""
        return HIPAAComplianceService()
    
    @pytest.mark.asyncio
    async def test_log_phi_access(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test logging PHI access."""
        user = await UserFactory.create_async(db_session)
        
        phi_log = await hipaa_service.log_phi_access(
            db=db_session,
            user_id=user.id,
            phi_category=PHICategory.MEDICAL_DATA,
            resource_type="patient_record",
            resource_id="PR123",
            access_purpose=AccessPurpose.TREATMENT,
            access_method="web",
            action_performed="read",
            access_justification="Reviewing patient chart for treatment planning",
            patient_id="P123",
            session_id="session_123"
        )
        
        assert phi_log is not None
        assert phi_log.user_id == user.id
        assert phi_log.access_successful is True
        
        # Verify audit log was created
        audit_logs = await AuditLog.get_user_audit_trail(db_session, user.id)
        audit_log = next((log for log in audit_logs if log.event_type == AuditEventType.HIPAA_ACCESS), None)
        assert audit_log is not None
        assert audit_log.hipaa_relevant is True
    
    @pytest.mark.asyncio
    async def test_log_phi_access_validation(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test PHI access logging validation."""
        user = await UserFactory.create_async(db_session)
        
        # Test missing justification
        with pytest.raises(ValueError, match="Access justification is required"):
            await hipaa_service.log_phi_access(
                db=db_session,
                user_id=user.id,
                phi_category=PHICategory.MEDICAL_DATA,
                resource_type="patient_record",
                resource_id="PR123",
                access_purpose=AccessPurpose.TREATMENT,
                access_method="web",
                action_performed="read",
                access_justification=""  # Empty justification
            )
    
    @pytest.mark.asyncio
    async def test_create_emergency_access(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test creating emergency access."""
        user = await UserFactory.create_async(db_session)
        
        emergency_access = await hipaa_service.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Patient in critical condition, immediate access required",
            patient_id="P123",
            location="Emergency Room",
            session_id="session_123"
        )
        
        assert emergency_access is not None
        assert emergency_access.user_id == user.id
        assert emergency_access.emergency_type == EmergencyAccessType.BREAK_GLASS
        assert emergency_access.is_active is True
        
        # Verify audit log was created
        audit_logs = await AuditLog.get_user_audit_trail(db_session, user.id)
        security_alert = next((log for log in audit_logs if log.event_type == AuditEventType.SECURITY_ALERT), None)
        assert security_alert is not None
    
    @pytest.mark.asyncio
    async def test_create_emergency_access_validation(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test emergency access creation validation."""
        user = await UserFactory.create_async(db_session)
        
        # Test missing justification
        with pytest.raises(ValueError, match="Emergency justification is required"):
            await hipaa_service.create_emergency_access(
                db=db_session,
                user_id=user.id,
                emergency_type=EmergencyAccessType.BREAK_GLASS,
                emergency_justification=""  # Empty justification
            )
    
    @pytest.mark.asyncio
    async def test_terminate_emergency_access(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test terminating emergency access."""
        user = await UserFactory.create_async(db_session)
        terminator = await UserFactory.create_async(db_session)
        
        # Create emergency access
        emergency_access = await hipaa_service.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Emergency justification"
        )
        
        # Terminate emergency access
        result = await hipaa_service.terminate_emergency_access(
            db=db_session,
            emergency_id=emergency_access.emergency_id,
            terminated_by_user_id=terminator.id,
            termination_reason="Emergency resolved"
        )
        
        assert result is True
        
        # Refresh object from database
        await db_session.refresh(emergency_access)
        assert emergency_access.is_active is False
        assert emergency_access.terminated_by_user_id == terminator.id
    
    @pytest.mark.asyncio
    async def test_terminate_nonexistent_emergency_access(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test terminating non-existent emergency access."""
        user = await UserFactory.create_async(db_session)
        
        result = await hipaa_service.terminate_emergency_access(
            db=db_session,
            emergency_id="nonexistent_id",
            terminated_by_user_id=user.id
        )
        
        assert result is False
    
    @pytest.mark.asyncio
    async def test_create_hipaa_session_context(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test creating HIPAA session context."""
        user = await UserFactory.create_async(db_session)
        
        hipaa_session = await hipaa_service.create_hipaa_session_context(
            db=db_session,
            session_id="test_session",
            user_id=user.id,
            phi_access_level="limited",
            department_context="Cardiology"
        )
        
        assert hipaa_session is not None
        assert hipaa_session.session_id == "test_session"
        assert hipaa_session.user_id == user.id
        assert hipaa_session.phi_access_level == "limited"
        assert hipaa_session.department_context == "Cardiology"
    
    @pytest.mark.asyncio
    async def test_check_phi_session_timeout(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test checking PHI session timeout."""
        user = await UserFactory.create_async(db_session)
        
        # Create session context
        hipaa_session = await hipaa_service.create_hipaa_session_context(
            db=db_session,
            session_id="test_session",
            user_id=user.id,
            phi_session_timeout_minutes=10
        )
        
        # Simulate recent PHI access
        hipaa_session.last_phi_access = datetime.utcnow() - timedelta(minutes=5)
        await hipaa_session.save(db_session)
        
        is_expired, should_warn = await hipaa_service.check_phi_session_timeout(
            db_session, "test_session"
        )
        
        assert is_expired is False
        assert should_warn is False
    
    @pytest.mark.asyncio
    async def test_manage_baa_agreements(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test managing BAA agreements."""
        now = datetime.utcnow()
        
        # Create active agreement
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Active Vendor",
            agreement_title="Active BAA",
            covered_services=["service1"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=30),
            expiration_date=now + timedelta(days=300)
        )
        
        # Create expiring agreement
        await BusinessAssociateAgreement.create_baa(
            db=db_session,
            business_associate_name="Expiring Vendor",
            agreement_title="Expiring BAA",
            covered_services=["service2"],
            phi_categories_covered=["medical_data"],
            effective_date=now - timedelta(days=300),
            expiration_date=now + timedelta(days=20)
        )
        
        baa_info = await hipaa_service.manage_baa_agreements(db_session)
        
        assert len(baa_info["active"]) == 2
        assert len(baa_info["expiring"]) == 1
        assert baa_info["expiring"][0].business_associate_name == "Expiring Vendor"
    
    @pytest.mark.asyncio
    async def test_get_phi_access_audit_trail(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test getting PHI access audit trail."""
        user = await UserFactory.create_async(db_session)
        
        # Create PHI access logs
        for i in range(3):
            await hipaa_service.log_phi_access(
                db=db_session,
                user_id=user.id,
                phi_category=PHICategory.MEDICAL_DATA,
                resource_type="patient_record",
                resource_id=f"PR{i}",
                access_purpose=AccessPurpose.TREATMENT,
                access_method="web",
                action_performed="read",
                access_justification=f"Treatment access {i}",
                patient_id=f"P{i}"
            )
        
        audit_trail = await hipaa_service.get_phi_access_audit_trail(
            db_session, user_id=user.id
        )
        
        assert len(audit_trail) == 3
        assert all(log.user_id == user.id for log in audit_trail)
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_emergency_access(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test cleaning up expired emergency access."""
        user = await UserFactory.create_async(db_session)
        
        # Create expired emergency access
        emergency_access = await EmergencyAccess.create_emergency_access(
            db=db_session,
            user_id=user.id,
            emergency_type=EmergencyAccessType.BREAK_GLASS,
            emergency_justification="Emergency justification"
        )
        
        # Simulate old start time
        emergency_access.emergency_start_time = datetime.utcnow() - timedelta(hours=25)
        await emergency_access.save(db_session)
        
        cleanup_count = await hipaa_service.cleanup_expired_emergency_access(
            db_session, max_hours=24
        )
        
        assert cleanup_count == 1
        
        # Verify emergency access was terminated
        await db_session.refresh(emergency_access)
        assert emergency_access.is_active is False
    
    @pytest.mark.asyncio
    async def test_hipaa_phi_access_context_manager(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test HIPAA PHI access context manager."""
        user = await UserFactory.create_async(db_session)
        
        # Test successful access
        async with hipaa_service.hipaa_phi_access_context(
            db=db_session,
            user_id=user.id,
            phi_category=PHICategory.MEDICAL_DATA,
            resource_type="patient_record",
            resource_id="PR123",
            access_purpose=AccessPurpose.TREATMENT,
            access_justification="Treatment access"
        ) as phi_context:
            phi_context.log_fields_accessed(["name", "dob"])
            phi_context.set_data_volume(1)
        
        # Verify PHI access was logged
        audit_trail = await hipaa_service.get_phi_access_audit_trail(
            db_session, user_id=user.id
        )
        
        assert len(audit_trail) == 1
        assert audit_trail[0].phi_fields_accessed == ["name", "dob"]
        assert audit_trail[0].data_volume == 1
        assert audit_trail[0].access_successful is True
    
    @pytest.mark.asyncio
    async def test_hipaa_phi_access_context_manager_with_error(self, db_session: AsyncSession, hipaa_service: HIPAAComplianceService):
        """Test HIPAA PHI access context manager with error."""
        user = await UserFactory.create_async(db_session)
        
        # Test access with error
        with pytest.raises(ValueError):
            async with hipaa_service.hipaa_phi_access_context(
                db=db_session,
                user_id=user.id,
                phi_category=PHICategory.MEDICAL_DATA,
                resource_type="patient_record", 
                resource_id="PR123",
                access_purpose=AccessPurpose.TREATMENT,
                access_justification="Treatment access"
            ) as phi_context:
                raise ValueError("Test error")
        
        # Verify PHI access was logged with error
        audit_trail = await hipaa_service.get_phi_access_audit_trail(
            db_session, user_id=user.id
        )
        
        assert len(audit_trail) == 1
        assert audit_trail[0].access_successful is False
        assert audit_trail[0].error_message == "Test error"