"""
Tests for GDPR Data Subject Access Request (DSAR) functionality.
"""
import pytest
import json
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from pathlib import Path

from src.services.gdpr_data_access_service import DSARService, DataExportFormat, DSARStatus
from src.models.user import User
from src.models.session import UserSession
from src.models.audit import AuditLog, AuditEventType
from tests.factories.user_factory import UserFactory
from tests.factories.session_factory import SessionFactory
from tests.factories.audit_factory import AuditFactory


class TestDSARService:
    """Test Data Subject Access Request service."""
    
    @pytest.fixture
    async def dsar_service(self):
        """Create DSAR service instance."""
        service = DSARService()
        # Mock cache service
        service.cache_service = AsyncMock()
        return service
    
    @pytest.fixture
    async def test_user_with_data(self, db_session):
        """Create test user with associated data."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="dsaruser@test.com",
            first_name="John",
            last_name="Doe"
        )
        
        # Create some sessions
        await SessionFactory.create_session(
            db_session=db_session,
            user_id=user.id,
            ip_address="192.168.1.1"
        )
        
        # Create some audit logs
        await AuditFactory.create_audit_log(
            db_session=db_session,
            user_id=user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="login",
            description="User logged in"
        )
        
        return user
    
    async def test_create_data_request(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test creating a DSAR request."""
        # Mock cache operations
        dsar_service.cache_service.set = AsyncMock()
        dsar_service.cache_service.get = AsyncMock(return_value=None)
        
        with patch('asyncio.create_task') as mock_create_task:
            result = await dsar_service.create_data_request(
                db=db_session,
                user_id=test_user_with_data.id,
                export_format=DataExportFormat.JSON,
                ip_address="192.168.1.100"
            )
        
        assert 'request_id' in result
        assert result['status'] == DSARStatus.PENDING
        assert 'expires_at' in result
        assert 'estimated_completion' in result
        
        # Verify cache was called to store request
        dsar_service.cache_service.set.assert_called_once()
        
        # Verify background task was created
        mock_create_task.assert_called_once()
    
    async def test_create_data_request_for_nonexistent_user(
        self,
        db_session,
        dsar_service: DSARService
    ):
        """Test DSAR request for non-existent user."""
        with pytest.raises(Exception):  # Should raise HTTPException 404
            await dsar_service.create_data_request(
                db=db_session,
                user_id=99999,  # Non-existent user
                export_format=DataExportFormat.JSON
            )
    
    async def test_get_request_status(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test getting DSAR request status."""
        request_id = "test-request-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': DSARStatus.PROCESSING,
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=72)).isoformat()
        }
        
        dsar_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        dsar_service.cache_service.set = AsyncMock()
        
        result = await dsar_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=test_user_with_data.id
        )
        
        assert result['request_id'] == request_id
        assert result['status'] == DSARStatus.PROCESSING
        assert result['download_ready'] == False
    
    async def test_get_request_status_expired(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test getting status of expired DSAR request."""
        request_id = "expired-request-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': DSARStatus.READY,
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() - timedelta(hours=1)).isoformat()  # Expired
        }
        
        dsar_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        dsar_service.cache_service.set = AsyncMock()
        
        result = await dsar_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=test_user_with_data.id
        )
        
        assert result['status'] == DSARStatus.EXPIRED
        
        # Verify cache was updated with expired status
        dsar_service.cache_service.set.assert_called_once()
    
    async def test_download_data_ready(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test downloading data when request is ready."""
        request_id = "ready-request-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': DSARStatus.READY,
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'file_size_bytes': 1024,
            'filename': 'user_data.json'
        }
        
        dsar_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        dsar_service.cache_service.set = AsyncMock()
        
        with patch('src.core.security.SecurityService.create_download_token') as mock_token:
            mock_token.return_value = "secure-download-token"
            
            result = await dsar_service.download_data(
                db=db_session,
                request_id=request_id,
                user_id=test_user_with_data.id,
                ip_address="192.168.1.100"
            )
        
        assert result['download_token'] == "secure-download-token"
        assert result['file_size_bytes'] == 1024
        assert result['filename'] == 'user_data.json'
        
        # Verify request was marked as downloaded
        updated_data = dsar_service.cache_service.set.call_args[0][1]
        assert updated_data['status'] == DSARStatus.DOWNLOADED
    
    async def test_download_data_not_ready(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test downloading data when request is not ready."""
        request_id = "pending-request-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': DSARStatus.PENDING,
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
        dsar_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        
        with pytest.raises(Exception):  # Should raise HTTPException 400
            await dsar_service.download_data(
                db=db_session,
                request_id=request_id,
                user_id=test_user_with_data.id
            )
    
    async def test_access_control(
        self,
        db_session,
        dsar_service: DSARService,
        test_user_with_data: User
    ):
        """Test access control for DSAR requests."""
        other_user = await UserFactory.create_user(
            db_session=db_session,
            email="otheruser@test.com"
        )
        
        request_id = "protected-request-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,  # Request belongs to test_user_with_data
            'status': DSARStatus.READY,
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
        dsar_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        
        # Other user should not be able to access the request
        with pytest.raises(Exception):  # Should raise HTTPException 403
            await dsar_service.get_request_status(
                db=db_session,
                request_id=request_id,
                user_id=other_user.id
            )


class TestDataExtraction:
    """Test data extraction functionality."""
    
    @pytest.fixture
    async def dsar_service(self):
        return DSARService()
    
    @pytest.fixture
    async def user_with_full_data(self, db_session):
        """Create user with comprehensive data for extraction testing."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="fulldata@test.com",
            first_name="Jane",
            last_name="Smith",
            phone_number="+1234567890",
            profile_data={"age": 30, "city": "New York"},
            preferences={"language": "en", "notifications": True}
        )
        
        # Create multiple sessions
        for i in range(3):
            await SessionFactory.create_session(
                db_session=db_session,
                user_id=user.id,
                ip_address=f"192.168.1.{i + 1}",
                device_info={"device": f"device_{i}"}
            )
        
        # Create various audit logs
        audit_types = [
            AuditEventType.LOGIN_SUCCESS,
            AuditEventType.PASSWORD_CHANGE,
            AuditEventType.USER_UPDATED
        ]
        
        for audit_type in audit_types:
            await AuditFactory.create_audit_log(
                db_session=db_session,
                user_id=user.id,
                event_type=audit_type,
                action=audit_type.value,
                description=f"Test {audit_type.value}"
            )
        
        return user
    
    async def test_extract_user_data_complete(
        self,
        db_session,
        dsar_service: DSARService,
        user_with_full_data: User
    ):
        """Test complete user data extraction."""
        data = await dsar_service._extract_user_data(
            db=db_session,
            user_id=user_with_full_data.id,
            include_deleted=False
        )
        
        # Verify user profile data
        assert 'user_profile' in data
        profile = data['user_profile']
        assert profile['email'] == "fulldata@test.com"
        assert profile['first_name'] == "Jane"
        assert profile['last_name'] == "Smith"
        assert profile['phone_number'] == "+1234567890"
        assert profile['profile_data'] == {"age": 30, "city": "New York"}
        
        # Verify sessions data
        assert 'sessions' in data
        assert len(data['sessions']) == 3
        for session in data['sessions']:
            assert 'session_id' in session
            assert 'ip_address' in session
            assert 'device_info' in session
        
        # Verify audit logs
        assert 'audit_logs' in data
        assert len(data['audit_logs']) >= 3
        
        # Verify metadata
        assert 'export_metadata' in data
        metadata = data['export_metadata']
        assert metadata['user_id'] == user_with_full_data.id
        assert 'exported_at' in metadata
        assert 'gdpr_article' in metadata
    
    async def test_extract_user_data_with_deleted(
        self,
        db_session,
        dsar_service: DSARService,
        user_with_full_data: User
    ):
        """Test data extraction including deleted records."""
        # Soft delete a session
        sessions = await db_session.execute(
            "SELECT * FROM user_session WHERE user_id = :user_id LIMIT 1",
            {"user_id": user_with_full_data.id}
        )
        session = sessions.first()
        if session:
            await db_session.execute(
                "UPDATE user_session SET is_deleted = true WHERE id = :id",
                {"id": session.id}
            )
            await db_session.commit()
        
        # Extract with deleted records
        data_with_deleted = await dsar_service._extract_user_data(
            db=db_session,
            user_id=user_with_full_data.id,
            include_deleted=True
        )
        
        # Extract without deleted records
        data_without_deleted = await dsar_service._extract_user_data(
            db=db_session,
            user_id=user_with_full_data.id,
            include_deleted=False
        )
        
        # Should have more sessions when including deleted
        assert len(data_with_deleted['sessions']) > len(data_without_deleted['sessions'])


class TestFileGeneration:
    """Test export file generation functionality."""
    
    @pytest.fixture
    async def dsar_service(self):
        return DSARService()
    
    @pytest.fixture
    def sample_data(self):
        """Sample data for file generation testing."""
        return {
            'user_profile': {
                'id': 1,
                'email': 'test@example.com',
                'first_name': 'Test',
                'last_name': 'User'
            },
            'sessions': [
                {
                    'session_id': 'session-1',
                    'created_at': '2024-01-01T00:00:00',
                    'ip_address': '192.168.1.1'
                }
            ],
            'export_metadata': {
                'exported_at': '2024-01-01T12:00:00',
                'user_id': 1,
                'total_records': 2
            }
        }
    
    async def test_generate_json_export(
        self,
        dsar_service: DSARService,
        sample_data: dict
    ):
        """Test JSON export file generation."""
        file_path, file_size = await dsar_service._generate_export_file(
            data=sample_data,
            export_format=DataExportFormat.JSON,
            request_id='test-123'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.json'
        assert file_size > 0
        
        # Verify file content
        with open(file_path, 'r', encoding='utf-8') as f:
            loaded_data = json.load(f)
        
        assert loaded_data['user_profile']['email'] == 'test@example.com'
        assert len(loaded_data['sessions']) == 1
        
        # Cleanup
        file_path.unlink()
    
    async def test_generate_csv_export(
        self,
        dsar_service: DSARService,
        sample_data: dict
    ):
        """Test CSV export file generation."""
        file_path, file_size = await dsar_service._generate_export_file(
            data=sample_data,
            export_format=DataExportFormat.CSV,
            request_id='test-456'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.zip'
        assert file_size > 0
        
        # Verify ZIP contains CSV files
        import zipfile
        with zipfile.ZipFile(file_path, 'r') as zipf:
            files = zipf.namelist()
            assert any(f.endswith('.csv') for f in files)
        
        # Cleanup
        file_path.unlink()
    
    async def test_generate_xml_export(
        self,
        dsar_service: DSARService,
        sample_data: dict
    ):
        """Test XML export file generation."""
        file_path, file_size = await dsar_service._generate_export_file(
            data=sample_data,
            export_format=DataExportFormat.XML,
            request_id='test-789'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.xml'
        assert file_size > 0
        
        # Verify XML structure
        import xml.etree.ElementTree as ET
        tree = ET.parse(file_path)
        root = tree.getroot()
        assert root.tag == 'user_data'
        
        # Cleanup
        file_path.unlink()
    
    async def test_unsupported_format(
        self,
        dsar_service: DSARService,
        sample_data: dict
    ):
        """Test handling of unsupported export format."""
        with pytest.raises(ValueError):
            await dsar_service._generate_export_file(
                data=sample_data,
                export_format='unsupported_format',
                request_id='test-error'
            )


@pytest.mark.integration
class TestDSARIntegration:
    """Integration tests for DSAR functionality."""
    
    async def test_full_dsar_workflow(self, db_session):
        """Test complete DSAR workflow from request to download."""
        # Create test user with data
        user = await UserFactory.create_user(
            db_session=db_session,
            email="workflow@test.com"
        )
        
        # Create DSAR service with real cache (or mock)
        dsar_service = DSARService()
        
        # Mock the cache service for this test
        cache_data = {}
        
        async def mock_cache_set(key, value, ttl=None):
            cache_data[key] = value
        
        async def mock_cache_get(key):
            return cache_data.get(key)
        
        dsar_service.cache_service.set = mock_cache_set
        dsar_service.cache_service.get = mock_cache_get
        
        # Step 1: Create request
        with patch('asyncio.create_task'):
            request_result = await dsar_service.create_data_request(
                db=db_session,
                user_id=user.id,
                export_format=DataExportFormat.JSON
            )
        
        request_id = request_result['request_id']
        
        # Step 2: Process request (simulate background processing)
        await dsar_service._process_data_request(db_session, request_id)
        
        # Step 3: Check status
        status_result = await dsar_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=user.id
        )
        
        assert status_result['status'] == DSARStatus.READY
        assert status_result['download_ready'] == True
        
        # Step 4: Download data
        with patch('src.core.security.SecurityService.create_download_token') as mock_token:
            mock_token.return_value = "test-download-token"
            
            download_result = await dsar_service.download_data(
                db=db_session,
                request_id=request_id,
                user_id=user.id
            )
        
        assert download_result['download_token'] == "test-download-token"
        
        # Step 5: Verify final status
        final_status = await dsar_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=user.id
        )
        
        assert final_status['status'] == DSARStatus.DOWNLOADED