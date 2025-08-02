"""
Tests for GDPR Data Deletion (Right to be Forgotten) functionality.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock

from src.services.gdpr_deletion_service import (
    GDPRDeletionService, DeletionReason, DeletionScope, DeletionStatus
)
from src.models.user import User
from src.models.session import UserSession
from src.models.audit import AuditLog, AuditEventType
from src.models.gdpr_consent import UserConsent, ConsentType
from tests.factories.user_factory import UserFactory
from tests.factories.session_factory import SessionFactory
from tests.factories.audit_factory import AuditFactory


class TestGDPRDeletionService:
    """Test GDPR deletion service functionality."""
    
    @pytest.fixture
    async def deletion_service(self):
        """Create deletion service instance."""
        service = GDPRDeletionService()
        # Mock audit logger
        service.audit_logger.log_data_access = AsyncMock()
        return service
    
    @pytest.fixture
    async def test_user_with_data(self, db_session):
        """Create test user with associated data."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="deleteme@test.com",
            first_name="Delete",
            last_name="Me",
            phone_number="+1234567890",
            profile_data={"age": 25, "city": "TestCity"}
        )
        
        # Create sessions
        for i in range(2):
            await SessionFactory.create_session(
                db_session=db_session,
                user_id=user.id,
                ip_address=f"192.168.1.{i + 1}"
            )
        
        # Create audit logs
        await AuditFactory.create_audit_log(
            db_session=db_session,
            user_id=user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="login",
            description="User login"
        )
        
        return user
    
    @pytest.fixture
    async def admin_user(self, db_session):
        """Create admin user for testing admin requests."""
        return await UserFactory.create_user(
            db_session=db_session,
            email="admin@test.com",
            is_superuser=True
        )
    
    async def test_request_data_deletion_user_request(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        test_user_with_data: User
    ):
        """Test user-initiated data deletion request."""
        result = await deletion_service.request_data_deletion(
            db=db_session,
            user_id=test_user_with_data.id,
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION,
            ip_address="192.168.1.100"
        )
        
        assert 'deletion_request_id' in result
        assert result['status'] == DeletionStatus.COMPLETED
        assert 'executed_at' in result
        assert 'deletion_result' in result
        
        # Verify audit logging was called
        deletion_service.audit_logger.log_data_access.assert_called()
    
    async def test_request_data_deletion_admin_request(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        test_user_with_data: User,
        admin_user: User
    ):
        """Test admin-initiated data deletion request."""
        result = await deletion_service.request_data_deletion(
            db=db_session,
            user_id=test_user_with_data.id,
            deletion_reason=DeletionReason.ADMIN_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION,
            requested_by_user_id=admin_user.id,
            justification="Admin cleanup request"
        )
        
        assert result['status'] == DeletionStatus.COMPLETED
        assert 'deletion_result' in result
    
    async def test_request_data_deletion_non_admin_fails(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        test_user_with_data: User
    ):
        """Test that non-admin users cannot delete other users' data."""
        other_user = await UserFactory.create_user(
            db_session=db_session,
            email="otheruser@test.com"
        )
        
        with pytest.raises(Exception):  # Should raise HTTPException 403
            await deletion_service.request_data_deletion(
                db=db_session,
                user_id=test_user_with_data.id,
                deletion_reason=DeletionReason.USER_REQUEST,
                deletion_scope=DeletionScope.FULL_DELETION,
                requested_by_user_id=other_user.id
            )
    
    async def test_request_data_deletion_nonexistent_user(
        self,
        db_session,
        deletion_service: GDPRDeletionService
    ):
        """Test deletion request for non-existent user."""
        with pytest.raises(Exception):  # Should raise HTTPException 404
            await deletion_service.request_data_deletion(
                db=db_session,
                user_id=99999,
                deletion_reason=DeletionReason.USER_REQUEST,
                deletion_scope=DeletionScope.FULL_DELETION
            )
    
    async def test_request_data_deletion_already_deleted(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        test_user_with_data: User
    ):
        """Test deletion request for already deleted user."""
        # Mark user as deleted
        test_user_with_data.is_deleted = True
        await test_user_with_data.save(db_session)
        
        with pytest.raises(Exception):  # Should raise HTTPException 400
            await deletion_service.request_data_deletion(
                db=db_session,
                user_id=test_user_with_data.id,
                deletion_reason=DeletionReason.USER_REQUEST,
                deletion_scope=DeletionScope.FULL_DELETION
            )
    
    async def test_scheduled_deletion(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        test_user_with_data: User
    ):
        """Test scheduled deletion request."""
        future_time = datetime.utcnow() + timedelta(hours=24)
        
        result = await deletion_service.request_data_deletion(
            db=db_session,
            user_id=test_user_with_data.id,
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION,
            scheduled_for=future_time
        )
        
        assert result['status'] == DeletionStatus.PENDING
        assert 'scheduled_for' in result
        assert result['message'] == 'Deletion request has been scheduled'


class TestDeletionExecution:
    """Test actual data deletion execution."""
    
    @pytest.fixture
    async def deletion_service(self):
        service = GDPRDeletionService()
        service.audit_logger.log_data_access = AsyncMock()
        return service
    
    @pytest.fixture
    async def comprehensive_user_data(self, db_session):
        """Create user with comprehensive data for deletion testing."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="comprehensive@test.com",
            first_name="Comprehensive",
            last_name="User",
            profile_data={"comprehensive": True}
        )
        
        # Create multiple sessions
        for i in range(3):
            await SessionFactory.create_session(
                db_session=db_session,
                user_id=user.id,
                ip_address=f"10.0.0.{i + 1}"
            )
        
        # Create audit logs
        for event_type in [AuditEventType.LOGIN_SUCCESS, AuditEventType.USER_UPDATED]:
            await AuditFactory.create_audit_log(
                db_session=db_session,
                user_id=user.id,
                event_type=event_type,
                action=event_type.value,
                description=f"Test {event_type.value}"
            )
        
        return user
    
    async def test_full_deletion_execution(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        comprehensive_user_data: User
    ):
        """Test full deletion execution."""
        user_id = comprehensive_user_data.id
        
        # Execute deletion
        result = await deletion_service._execute_deletion(
            db=db_session,
            user_id=user_id,
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION,
            requested_by_user_id=user_id,
            deletion_request_id="test-full-deletion"
        )
        
        assert result['success'] == True
        assert 'deleted_records' in result
        assert 'user_sessions' in result['deleted_records']
        assert 'audit_logs' in result['deleted_records']
        assert result['deleted_records']['user'] == 1
        
        # Verify user record is anonymized and soft deleted
        user = await User.get_by_id(db_session, user_id)
        assert user.is_deleted == True
        assert user.email.startswith('deleted_')
        assert user.first_name is None
        assert user.last_name is None
        assert user.profile_data is None
    
    async def test_anonymization_execution(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        comprehensive_user_data: User
    ):
        """Test anonymization execution."""
        user_id = comprehensive_user_data.id
        
        # Execute anonymization
        result = await deletion_service._execute_deletion(
            db=db_session,
            user_id=user_id,
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.ANONYMIZATION,
            requested_by_user_id=user_id,
            deletion_request_id="test-anonymization"
        )
        
        assert result['success'] == True
        assert 'anonymized_records' in result
        assert result['anonymized_records']['user'] == 1
        
        # Verify user record is anonymized but not fully deleted
        user = await User.get_by_id(db_session, user_id)
        assert user.is_deleted == True
        assert user.email.endswith('@anonymized.local')
        assert user.first_name == "Anonymized"
        assert user.last_name == "User"
        assert user.profile_data.get('anonymized') == True
    
    async def test_minimal_retention_execution(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        comprehensive_user_data: User
    ):
        """Test minimal retention deletion execution."""
        user_id = comprehensive_user_data.id
        
        # Execute minimal retention deletion
        result = await deletion_service._execute_deletion(
            db=db_session,
            user_id=user_id,
            deletion_reason=DeletionReason.RETENTION_EXPIRY,
            deletion_scope=DeletionScope.MINIMAL_RETENTION,
            requested_by_user_id=user_id,
            deletion_request_id="test-minimal-retention"
        )
        
        assert result['success'] == True
        assert 'retained_records' in result
        assert result['retained_records']['user'] == 1
        
        # Verify user record is kept with minimal data
        user = await User.get_by_id(db_session, user_id)
        assert user.is_deleted == True
        assert user.is_active == False
        assert user.email.startswith('deleted_user_')
        assert user.first_name is None
        assert user.last_name is None
    
    async def test_deletion_error_handling(
        self,
        db_session,
        deletion_service: GDPRDeletionService
    ):
        """Test error handling in deletion execution."""
        # Try to delete non-existent user
        result = await deletion_service._execute_deletion(
            db=db_session,
            user_id=99999,  # Non-existent
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION,
            requested_by_user_id=99999,
            deletion_request_id="test-error"
        )
        
        assert result['success'] == False
        assert len(result['errors']) > 0


class TestSpecificDeletionOperations:
    """Test specific deletion operations."""
    
    @pytest.fixture
    async def deletion_service(self):
        service = GDPRDeletionService()
        service.audit_logger.log_data_access = AsyncMock()
        return service
    
    @pytest.fixture
    async def user_with_sessions(self, db_session):
        """Create user with multiple sessions."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="sessions@test.com"
        )
        
        # Create active and inactive sessions
        for i in range(5):
            session = await SessionFactory.create_session(
                db_session=db_session,
                user_id=user.id,
                ip_address=f"172.16.0.{i + 1}",
                is_active=(i % 2 == 0)  # Alternate active/inactive
            )
            
            # Soft delete one session
            if i == 4:
                session.is_deleted = True
                session.deleted_at = datetime.utcnow()
                await session.save(db_session)
        
        return user
    
    async def test_delete_user_sessions(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        user_with_sessions: User
    ):
        """Test deleting user sessions."""
        # Count active sessions before deletion
        from sqlalchemy.future import select
        query = select(UserSession).where(
            UserSession.user_id == user_with_sessions.id,
            UserSession.is_deleted == False
        )
        result = await db_session.execute(query)
        sessions_before = len(result.scalars().all())
        
        # Delete sessions
        deleted_count = await deletion_service._delete_user_sessions(
            db_session, user_with_sessions.id
        )
        
        assert deleted_count == sessions_before
        
        # Verify sessions are soft deleted
        query = select(UserSession).where(
            UserSession.user_id == user_with_sessions.id,
            UserSession.is_deleted == False
        )
        result = await db_session.execute(query)
        remaining_sessions = result.scalars().all()
        
        assert len(remaining_sessions) == 0
    
    async def test_delete_user_roles(
        self,
        db_session,
        deletion_service: GDPRDeletionService
    ):
        """Test deleting user role associations."""
        # Create user with roles
        user = await UserFactory.create_user(
            db_session=db_session,
            email="roleuser@test.com",
            roles=['user', 'premium']  # Assuming factory supports roles
        )
        
        # Delete user roles
        deleted_count = await deletion_service._delete_user_roles(
            db_session, user.id
        )
        
        # Verify roles were removed
        updated_user = await User.get_by_id(db_session, user.id)
        assert len(updated_user.roles) == 0
    
    async def test_handle_audit_logs_keep_critical(
        self,
        db_session,
        deletion_service: GDPRDeletionService
    ):
        """Test audit log handling with critical event retention."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="audituser@test.com"
        )
        
        # Create mix of critical and non-critical audit logs
        critical_events = [AuditEventType.LOGIN_SUCCESS, AuditEventType.PASSWORD_CHANGE]
        non_critical_events = [AuditEventType.DATA_READ]
        
        for event_type in critical_events:
            await AuditFactory.create_audit_log(
                db_session=db_session,
                user_id=user.id,
                event_type=event_type,
                action=event_type.value,
                description=f"Critical {event_type.value}",
                timestamp=datetime.utcnow() - timedelta(days=400)  # Old enough to delete
            )
        
        for event_type in non_critical_events:
            await AuditFactory.create_audit_log(
                db_session=db_session,
                user_id=user.id,
                event_type=event_type,
                action=event_type.value,
                description=f"Non-critical {event_type.value}",
                timestamp=datetime.utcnow() - timedelta(days=400)  # Old enough to delete
            )
        
        # Handle audit logs with critical retention
        result = await deletion_service._handle_audit_logs(
            db_session, user.id, delete_old=True, keep_critical=True
        )
        
        assert result['deleted'] >= len(non_critical_events)
        assert result['anonymized'] >= len(critical_events)
    
    async def test_anonymize_user_sessions(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        user_with_sessions: User
    ):
        """Test anonymizing user sessions."""
        # Anonymize sessions
        anonymized_count = await deletion_service._anonymize_user_sessions(
            db_session, user_with_sessions.id
        )
        
        assert anonymized_count > 0
        
        # Verify sessions are anonymized
        from sqlalchemy.future import select
        query = select(UserSession).where(UserSession.user_id == user_with_sessions.id)
        result = await db_session.execute(query)
        sessions = result.scalars().all()
        
        for session in sessions:
            assert session.ip_address == "0.0.0.0"
            assert session.user_agent == "anonymized"
            assert session.device_info.get('anonymized') == True


class TestRetentionCleanup:
    """Test automated retention cleanup functionality."""
    
    @pytest.fixture
    async def deletion_service(self):
        service = GDPRDeletionService()
        service.audit_logger.log_data_access = AsyncMock()
        return service
    
    @pytest.fixture
    async def expired_users(self, db_session):
        """Create users with expired retention periods."""
        users = []
        
        for i in range(3):
            user = await UserFactory.create_user(
                db_session=db_session,
                email=f"expired{i}@test.com",
                is_active=False  # Inactive users are candidates for cleanup
            )
            
            # Set expired retention date
            user.data_retention_until = datetime.utcnow() - timedelta(days=1)
            await user.save(db_session)
            users.append(user)
        
        return users
    
    async def test_schedule_retention_cleanup(
        self,
        db_session,
        deletion_service: GDPRDeletionService,
        expired_users: list
    ):
        """Test scheduling retention cleanup."""
        # Mock the request_data_deletion method to avoid actual deletion
        async def mock_request_deletion(*args, **kwargs):
            return {'deletion_request_id': f"cleanup-{kwargs['user_id']}"}
        
        deletion_service.request_data_deletion = mock_request_deletion
        
        result = await deletion_service.schedule_retention_cleanup(db_session)
        
        assert result['total_users_processed'] == len(expired_users)
        assert len(result['cleanup_results']) == len(expired_users)
        
        # Verify all cleanup results are successful
        successful_cleanups = [
            r for r in result['cleanup_results'] 
            if r['status'] == 'scheduled'
        ]
        assert len(successful_cleanups) == len(expired_users)


@pytest.mark.integration
class TestDeletionIntegration:
    """Integration tests for deletion functionality."""
    
    async def test_complete_user_deletion_workflow(self, db_session):
        """Test complete user deletion workflow."""
        # Create user with comprehensive data
        user = await UserFactory.create_user(
            db_session=db_session,
            email="workflow@test.com",
            first_name="Workflow",
            last_name="Test"
        )
        
        # Add sessions and audit logs
        await SessionFactory.create_session(
            db_session=db_session,
            user_id=user.id,
            ip_address="203.0.113.1"
        )
        
        await AuditFactory.create_audit_log(
            db_session=db_session,
            user_id=user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="login",
            description="User login"
        )
        
        # Execute full deletion
        deletion_service = GDPRDeletionService()
        deletion_service.audit_logger.log_data_access = AsyncMock()
        
        result = await deletion_service.request_data_deletion(
            db=db_session,
            user_id=user.id,
            deletion_reason=DeletionReason.USER_REQUEST,
            deletion_scope=DeletionScope.FULL_DELETION
        )
        
        assert result['status'] == DeletionStatus.COMPLETED
        assert result['deletion_result']['success'] == True
        
        # Verify user is properly deleted/anonymized
        deleted_user = await User.get_by_id(db_session, user.id)
        assert deleted_user.is_deleted == True
        assert deleted_user.email.startswith('deleted_')
        assert deleted_user.first_name is None
        assert deleted_user.last_name is None
    
    async def test_deletion_with_concurrent_operations(self, db_session):
        """Test deletion behavior with concurrent operations."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="concurrent@test.com"
        )
        
        deletion_service = GDPRDeletionService()
        deletion_service.audit_logger.log_data_access = AsyncMock()
        
        # Simulate concurrent deletion requests
        import asyncio
        
        async def delete_user():
            return await deletion_service.request_data_deletion(
                db=db_session,
                user_id=user.id,
                deletion_reason=DeletionReason.USER_REQUEST,
                deletion_scope=DeletionScope.FULL_DELETION
            )
        
        # First deletion should succeed
        result1 = await delete_user()
        assert result1['status'] == DeletionStatus.COMPLETED
        
        # Second deletion should fail (user already deleted)
        with pytest.raises(Exception):
            await delete_user()