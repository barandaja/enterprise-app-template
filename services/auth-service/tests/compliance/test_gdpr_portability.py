"""
Tests for GDPR Data Portability functionality.
"""
import pytest
import json
import tempfile
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from pathlib import Path

from src.services.gdpr_portability_service import (
    GDPRPortabilityService, PortabilityFormat, PortabilityStatus, DataCategory
)
from src.models.user import User
from tests.factories.user_factory import UserFactory
from tests.factories.session_factory import SessionFactory
from tests.factories.audit_factory import AuditFactory


class TestPortabilityService:
    """Test data portability service functionality."""
    
    @pytest.fixture
    async def portability_service(self):
        """Create portability service instance."""
        service = GDPRPortabilityService()
        # Mock cache service
        service.cache_service = AsyncMock()
        return service
    
    @pytest.fixture
    async def test_user_with_data(self, db_session):
        """Create test user with comprehensive data."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="portable@test.com",
            first_name="Portable",
            last_name="User",
            phone_number="+1555123456",
            profile_data={"occupation": "Tester", "interests": ["tech", "privacy"]},
            preferences={"theme": "dark", "language": "en"}
        )
        
        # Create sessions
        await SessionFactory.create_session(
            db_session=db_session,
            user_id=user.id,
            ip_address="192.168.1.100",
            device_info={"browser": "Chrome", "os": "macOS"}
        )
        
        # Create audit logs
        from src.models.audit import AuditEventType
        await AuditFactory.create_audit_log(
            db_session=db_session,
            user_id=user.id,
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="login",
            description="User logged in successfully"
        )
        
        return user
    
    async def test_create_portability_request(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test creating a portability request."""
        # Mock cache operations
        portability_service.cache_service.set = AsyncMock()
        
        with patch('asyncio.create_task') as mock_create_task:
            result = await portability_service.create_portability_request(
                db=db_session,
                user_id=test_user_with_data.id,
                export_format=PortabilityFormat.STRUCTURED_JSON,
                data_categories=[DataCategory.PROFILE, DataCategory.SESSIONS],
                ip_address="203.0.113.50"
            )
        
        assert 'request_id' in result
        assert result['status'] == PortabilityStatus.PENDING
        assert result['format'] == PortabilityFormat.STRUCTURED_JSON
        assert set(result['data_categories']) == {DataCategory.PROFILE, DataCategory.SESSIONS}
        
        # Verify cache was called
        portability_service.cache_service.set.assert_called_once()
        
        # Verify background task was created
        mock_create_task.assert_called_once()
    
    async def test_create_portability_request_default_categories(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test portability request with default data categories."""
        portability_service.cache_service.set = AsyncMock()
        
        with patch('asyncio.create_task'):
            result = await portability_service.create_portability_request(
                db=db_session,
                user_id=test_user_with_data.id
            )
        
        # Should include default categories
        expected_categories = [
            DataCategory.PROFILE,
            DataCategory.AUTHENTICATION,
            DataCategory.SESSIONS,
            DataCategory.CONSENTS,
            DataCategory.PREFERENCES
        ]
        
        assert set(result['data_categories']) == set(expected_categories)
    
    async def test_create_portability_request_nonexistent_user(
        self,
        db_session,
        portability_service: GDPRPortabilityService
    ):
        """Test portability request for non-existent user."""
        with pytest.raises(Exception):  # Should raise HTTPException 404
            await portability_service.create_portability_request(
                db=db_session,
                user_id=99999
            )
    
    async def test_get_request_status(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test getting portability request status."""
        request_id = "port-req-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': PortabilityStatus.PROCESSING,
            'format': PortabilityFormat.JSON,
            'data_categories': [DataCategory.PROFILE],
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=72)).isoformat()
        }
        
        portability_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        portability_service.cache_service.set = AsyncMock()
        
        result = await portability_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=test_user_with_data.id
        )
        
        assert result['request_id'] == request_id
        assert result['status'] == PortabilityStatus.PROCESSING
        assert result['format'] == PortabilityFormat.JSON
        assert result['download_ready'] == False
    
    async def test_get_request_status_expired(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test getting status of expired portability request."""
        request_id = "expired-port-req-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': PortabilityStatus.READY,
            'format': PortabilityFormat.JSON,
            'data_categories': [DataCategory.PROFILE],
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() - timedelta(hours=1)).isoformat()  # Expired
        }
        
        portability_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        portability_service.cache_service.set = AsyncMock()
        
        result = await portability_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=test_user_with_data.id
        )
        
        assert result['status'] == PortabilityStatus.EXPIRED
        
        # Verify cache was updated
        portability_service.cache_service.set.assert_called_once()
    
    async def test_download_portable_data(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test downloading portable data."""
        request_id = "ready-port-req-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': PortabilityStatus.READY,
            'format': PortabilityFormat.JSON,
            'data_categories': [DataCategory.PROFILE],
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
            'file_size_bytes': 2048,
            'filename': 'portable_data.json'
        }
        
        portability_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        portability_service.cache_service.set = AsyncMock()
        
        with patch('src.core.security.SecurityService.create_download_token') as mock_token:
            mock_token.return_value = "secure-port-token"
            
            result = await portability_service.download_portable_data(
                db=db_session,
                request_id=request_id,
                user_id=test_user_with_data.id,
                ip_address="203.0.113.75"
            )
        
        assert result['download_token'] == "secure-port-token"
        assert result['file_size_bytes'] == 2048
        assert result['filename'] == 'portable_data.json'
        assert result['format'] == PortabilityFormat.JSON
        
        # Verify request was marked as downloaded
        updated_data = portability_service.cache_service.set.call_args[0][1]
        assert updated_data['status'] == PortabilityStatus.DOWNLOADED
    
    async def test_download_portable_data_not_ready(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test downloading data when request is not ready."""
        request_id = "pending-port-req-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,
            'status': PortabilityStatus.PENDING,
            'format': PortabilityFormat.JSON,
            'data_categories': [DataCategory.PROFILE],
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
        portability_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        
        with pytest.raises(Exception):  # Should raise HTTPException 400
            await portability_service.download_portable_data(
                db=db_session,
                request_id=request_id,
                user_id=test_user_with_data.id
            )
    
    async def test_access_control(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        test_user_with_data: User
    ):
        """Test access control for portability requests."""
        other_user = await UserFactory.create_user(
            db_session=db_session,
            email="other@test.com"
        )
        
        request_id = "protected-port-req-123"
        mock_request_data = {
            'request_id': request_id,
            'user_id': test_user_with_data.id,  # Belongs to test_user_with_data
            'status': PortabilityStatus.READY,
            'format': PortabilityFormat.JSON,
            'data_categories': [DataCategory.PROFILE],
            'requested_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
        
        portability_service.cache_service.get = AsyncMock(return_value=mock_request_data)
        
        # Other user should not be able to access the request
        with pytest.raises(Exception):  # Should raise HTTPException 403
            await portability_service.get_request_status(
                db=db_session,
                request_id=request_id,
                user_id=other_user.id
            )


class TestDataExtraction:
    """Test portable data extraction functionality."""
    
    @pytest.fixture
    async def portability_service(self):
        return GDPRPortabilityService()
    
    @pytest.fixture
    async def comprehensive_user(self, db_session):
        """Create user with comprehensive data for extraction testing."""
        user = await UserFactory.create_user(
            db_session=db_session,
            email="comprehensive@test.com",
            first_name="Comprehensive",
            last_name="DataUser",
            phone_number="+1555987654",
            profile_data={"bio": "Test user for portability", "age": 30},
            preferences={"notifications": True, "marketing": False}
        )
        
        # Create multiple sessions
        for i in range(2):
            await SessionFactory.create_session(
                db_session=db_session,
                user_id=user.id,
                ip_address=f"10.0.{i}.100",
                device_info={"device_id": f"device_{i}", "platform": "web"}
            )
        
        # Create audit logs
        from src.models.audit import AuditEventType
        audit_events = [
            AuditEventType.LOGIN_SUCCESS,
            AuditEventType.USER_UPDATED,
            AuditEventType.DATA_EXPORT
        ]
        
        for event_type in audit_events:
            await AuditFactory.create_audit_log(
                db_session=db_session,
                user_id=user.id,
                event_type=event_type,
                action=event_type.value,
                description=f"Test {event_type.value} event"
            )
        
        return user
    
    async def test_extract_portable_data_all_categories(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        comprehensive_user: User
    ):
        """Test extracting all categories of portable data."""
        data = await portability_service._extract_portable_data(
            db=db_session,
            user_id=comprehensive_user.id,
            data_categories=[
                DataCategory.PROFILE,
                DataCategory.AUTHENTICATION,
                DataCategory.SESSIONS,
                DataCategory.AUDIT_TRAIL,
                DataCategory.PREFERENCES
            ],
            include_metadata=True,
            include_system_data=True
        )
        
        # Verify profile data
        assert 'profile' in data
        profile = data['profile']
        assert profile['personal_information']['email'] == "comprehensive@test.com"
        assert profile['personal_information']['first_name'] == "Comprehensive"
        assert profile['preferences'] == {"notifications": True, "marketing": False}
        
        # Verify authentication data
        assert 'authentication' in data
        auth = data['authentication']
        assert 'account_created' in auth
        assert 'last_login' in auth
        
        # Verify sessions data
        assert 'sessions' in data
        assert len(data['sessions']) == 2
        for session in data['sessions']:
            assert 'session_id' in session
            assert 'device_info' in session  # Should be included with system_data=True
        
        # Verify audit trail
        assert 'audit_trail' in data
        assert len(data['audit_trail']) >= 3
        
        # Verify metadata
        assert '_metadata' in data
        metadata = data['_metadata']
        assert metadata['export_info']['gdpr_article'] == 'Article 20 - Right to data portability'
        assert metadata['user_info']['user_id'] == comprehensive_user.id
    
    async def test_extract_portable_data_selective_categories(
        self,
        db_session,
        portability_service: GDPRPortabilityService,
        comprehensive_user: User
    ):
        """Test extracting only selected data categories."""
        data = await portability_service._extract_portable_data(
            db=db_session,
            user_id=comprehensive_user.id,
            data_categories=[DataCategory.PROFILE, DataCategory.PREFERENCES],
            include_metadata=False,
            include_system_data=False
        )
        
        # Should only have selected categories
        assert 'profile' in data
        assert 'authentication' not in data
        assert 'sessions' not in data
        assert 'audit_trail' not in data
        assert '_metadata' not in data
        
        # System data should be excluded
        if 'sessions' in data:
            for session in data['sessions']:
                assert session.get('device_info') is None
    
    async def test_extract_portable_data_nonexistent_user(
        self,
        db_session,
        portability_service: GDPRPortabilityService
    ):
        """Test extracting data for non-existent user."""
        with pytest.raises(ValueError, match="User not found"):
            await portability_service._extract_portable_data(
                db=db_session,
                user_id=99999,
                data_categories=[DataCategory.PROFILE],
                include_metadata=True,
                include_system_data=False
            )


class TestFileGeneration:
    """Test portable file generation functionality."""
    
    @pytest.fixture
    async def portability_service(self):
        return GDPRPortabilityService()
    
    @pytest.fixture
    def sample_portable_data(self):
        """Sample portable data for file generation testing."""
        return {
            'profile': {
                'personal_information': {
                    'user_id': 1,
                    'email': 'portable@example.com',
                    'first_name': 'Portable',
                    'last_name': 'User'
                },
                'preferences': {'theme': 'dark'}
            },
            'sessions': [
                {
                    'session_id': 'sess-001',
                    'created_at': '2024-01-01T10:00:00',
                    'ip_address': '192.168.1.1'
                }
            ],
            '_metadata': {
                'export_info': {
                    'exported_at': '2024-01-01T12:00:00',
                    'gdpr_article': 'Article 20 - Right to data portability'
                }
            }
        }
    
    async def test_generate_structured_json(
        self,
        portability_service: GDPRPortabilityService,
        sample_portable_data: dict
    ):
        """Test generating structured JSON (JSON-LD) export."""
        file_path, file_size = await portability_service._generate_portable_file(
            data=sample_portable_data,
            export_format=PortabilityFormat.STRUCTURED_JSON,
            request_id='struct-json-123'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.json'
        assert file_size > 0
        
        # Verify structured content
        with open(file_path, 'r', encoding='utf-8') as f:
            structured_data = json.load(f)
        
        assert '@context' in structured_data
        assert '@type' in structured_data
        assert structured_data['@type'] == 'Dataset'
        assert 'data' in structured_data
        assert structured_data['data']['profile']['personal_information']['email'] == 'portable@example.com'
        
        # Cleanup
        file_path.unlink()
    
    async def test_generate_json_export(
        self,
        portability_service: GDPRPortabilityService,
        sample_portable_data: dict
    ):
        """Test generating regular JSON export."""
        file_path, file_size = await portability_service._generate_portable_file(
            data=sample_portable_data,
            export_format=PortabilityFormat.JSON,
            request_id='json-456'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.json'
        assert file_size > 0
        
        # Verify content
        with open(file_path, 'r', encoding='utf-8') as f:
            loaded_data = json.load(f)
        
        assert loaded_data['profile']['personal_information']['email'] == 'portable@example.com'
        assert len(loaded_data['sessions']) == 1
        
        # Cleanup
        file_path.unlink()
    
    async def test_generate_csv_export(
        self,
        portability_service: GDPRPortabilityService,
        sample_portable_data: dict
    ):
        """Test generating CSV export (ZIP with multiple CSV files)."""
        file_path, file_size = await portability_service._generate_portable_file(
            data=sample_portable_data,
            export_format=PortabilityFormat.CSV,
            request_id='csv-789'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.zip'
        assert file_size > 0
        
        # Verify ZIP contains CSV files
        import zipfile
        with zipfile.ZipFile(file_path, 'r') as zipf:
            files = zipf.namelist()
            csv_files = [f for f in files if f.endswith('.csv')]
            assert len(csv_files) > 0
            assert 'sessions.csv' in files
        
        # Cleanup
        file_path.unlink()
    
    async def test_generate_xml_export(
        self,
        portability_service: GDPRPortabilityService,
        sample_portable_data: dict
    ):
        """Test generating XML export."""
        file_path, file_size = await portability_service._generate_portable_file(
            data=sample_portable_data,
            export_format=PortabilityFormat.XML,
            request_id='xml-abc'
        )
        
        assert file_path.exists()
        assert file_path.suffix == '.xml'
        assert file_size > 0
        
        # Verify XML structure
        import xml.etree.ElementTree as ET
        tree = ET.parse(file_path)
        root = tree.getroot()
        assert root.tag == 'portable_data'
        assert root.get('xmlns:gdpr') == 'https://gdpr.eu/'
        assert root.get('article') == '20'
        
        # Cleanup
        file_path.unlink()
    
    async def test_file_size_limit(
        self,
        portability_service: GDPRPortabilityService
    ):
        """Test file size limit handling."""
        # Create large data that would exceed limit
        large_data = {
            'large_field': 'x' * (portability_service.max_file_size_mb * 1024 * 1024 + 1000)
        }
        
        # Should still create file but log warning
        file_path, file_size = await portability_service._generate_portable_file(
            data=large_data,
            export_format=PortabilityFormat.JSON,
            request_id='large-file'
        )
        
        assert file_path.exists()
        assert file_size > portability_service.max_file_size_mb * 1024 * 1024
        
        # Cleanup
        file_path.unlink()


class TestJSONLDContext:
    """Test JSON-LD context generation."""
    
    @pytest.fixture
    async def portability_service(self):
        return GDPRPortabilityService()
    
    def test_add_jsonld_context(
        self,
        portability_service: GDPRPortabilityService
    ):
        """Test adding JSON-LD context to data."""
        sample_data = {
            'profile': {
                'email': 'jsonld@example.com',
                'first_name': 'JSON',
                'last_name': 'LD'
            }
        }
        
        structured = portability_service._add_jsonld_context(sample_data)
        
        assert '@context' in structured
        assert '@type' in structured
        assert '@id' in structured
        assert structured['@type'] == 'Dataset'
        assert structured['name'] == 'Personal Data Export - GDPR Article 20'
        assert 'data' in structured
        assert structured['data'] == sample_data
        
        # Verify context structure
        context = structured['@context']
        assert '@vocab' in context
        assert 'gdpr' in context
        assert 'profile' in context


class TestUtilityFunctions:
    """Test utility functions for data processing."""
    
    @pytest.fixture
    async def portability_service(self):
        return GDPRPortabilityService()
    
    def test_flatten_dict(
        self,
        portability_service: GDPRPortabilityService
    ):
        """Test dictionary flattening functionality."""
        nested_dict = {
            'level1': {
                'level2': {
                    'level3': 'value'
                },
                'simple': 'value2'
            },
            'array': [
                {'item1': 'val1'},
                {'item2': 'val2'}
            ]
        }
        
        flattened = portability_service._flatten_dict(nested_dict)
        
        assert 'level1.level2.level3' in flattened
        assert flattened['level1.level2.level3'] == 'value'
        assert 'level1.simple' in flattened
        assert flattened['level1.simple'] == 'value2'
        assert 'array[0].item1' in flattened
        assert flattened['array[0].item1'] == 'val1'
    
    def test_count_records(
        self,
        portability_service: GDPRPortabilityService
    ):
        """Test record counting functionality."""
        data = {
            'profile': {'user_id': 1, 'email': 'test@example.com'},  # 1 record
            'sessions': [
                {'session_id': 'a'},
                {'session_id': 'b'}
            ],  # 2 records
            'preferences': {'theme': 'dark'},  # 1 record
            '_metadata': {'exported_at': '2024-01-01'}  # Should be ignored
        }
        
        count = portability_service._count_records(data)
        assert count == 4  # profile(1) + sessions(2) + preferences(1)


@pytest.mark.integration
class TestPortabilityIntegration:
    """Integration tests for portability functionality."""
    
    async def test_full_portability_workflow(self, db_session):
        """Test complete portability workflow."""
        # Create user with data
        user = await UserFactory.create_user(
            db_session=db_session,
            email="fullworkflow@test.com",
            first_name="Full",
            last_name="Workflow"
        )
        
        # Create portability service with mock cache
        portability_service = GDPRPortabilityService()
        
        cache_data = {}
        
        async def mock_cache_set(key, value, ttl=None):
            cache_data[key] = value
        
        async def mock_cache_get(key):
            return cache_data.get(key)
        
        portability_service.cache_service.set = mock_cache_set
        portability_service.cache_service.get = mock_cache_get
        
        # Step 1: Create request
        with patch('asyncio.create_task'):
            request_result = await portability_service.create_portability_request(
                db=db_session,
                user_id=user.id,
                export_format=PortabilityFormat.JSON,
                data_categories=[DataCategory.PROFILE, DataCategory.AUTHENTICATION]
            )
        
        request_id = request_result['request_id']
        
        # Step 2: Process request
        await portability_service._process_portability_request(db_session, request_id)
        
        # Step 3: Check status
        status_result = await portability_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=user.id
        )
        
        assert status_result['status'] == PortabilityStatus.READY
        assert status_result['download_ready'] == True
        
        # Step 4: Download
        with patch('src.core.security.SecurityService.create_download_token') as mock_token:
            mock_token.return_value = "port-download-token"
            
            download_result = await portability_service.download_portable_data(
                db=db_session,
                request_id=request_id,
                user_id=user.id
            )
        
        assert download_result['download_token'] == "port-download-token"
        assert download_result['format'] == PortabilityFormat.JSON
        
        # Step 5: Verify final status
        final_status = await portability_service.get_request_status(
            db=db_session,
            request_id=request_id,
            user_id=user.id
        )
        
        assert final_status['status'] == PortabilityStatus.DOWNLOADED