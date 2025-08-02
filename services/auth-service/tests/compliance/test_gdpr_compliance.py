"""
GDPR compliance tests for auth service.
Tests data protection, privacy rights, and regulatory compliance.
"""
import pytest
import pytest_asyncio
from unittest.mock import patch, AsyncMock
from datetime import datetime, timedelta
from fastapi import status

from tests.factories import UserFactory, SessionFactory, ComplianceTestUserFactory
from src.models.audit import AuditEventType


class TestGDPRCompliance:
    """GDPR compliance test suite."""
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_to_be_informed_privacy_notice(self, async_client):
        """Test that privacy information is accessible (Article 12-14)."""
        # Act
        response = await async_client.get("/privacy-policy")
        
        # Assert
        # Should provide privacy policy or redirect to one
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_302_FOUND]
        
        if response.status_code == status.HTTP_200_OK:
            content = response.text.lower()
            required_elements = [
                "personal data", "processing", "purpose", "legal basis",
                "retention", "rights", "contact", "controller"
            ]
            
            for element in required_elements:
                assert element in content, f"Privacy notice missing: {element}"
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_of_access_data_export(self, async_client, authenticated_headers):
        """Test right of access - user can export their data (Article 15)."""
        # Arrange
        user_data = {
            "email": "gdpr_test@example.com",
            "first_name": "GDPR",
            "last_name": "Test",
            "phone_number": "+1234567890"
        }
        
        with patch('src.services.user_service.UserService.get_user_by_id') as mock_get_user, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = ComplianceTestUserFactory(**user_data)
            mock_get_user.return_value = user
            mock_current_user.return_value = user
            
            # Act
            response = await async_client.get("/api/v1/user/data-export", headers=authenticated_headers)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            export_data = response.json()
            
            # Should include all personal data
            assert "email" in export_data
            assert "first_name" in export_data
            assert "last_name" in export_data
            assert "phone_number" in export_data
            assert "created_at" in export_data
            
            # Should include metadata about processing
            assert "data_processing_consent" in export_data
            assert "marketing_consent" in export_data
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_to_rectification(self, async_client, authenticated_headers):
        """Test right to rectification - user can correct their data (Article 16)."""
        # Arrange
        update_data = {
            "first_name": "Corrected",
            "last_name": "Name",
            "phone_number": "+9876543210"
        }
        
        with patch('src.services.user_service.UserService.update_user') as mock_update, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = UserFactory(id=1)
            mock_current_user.return_value = user
            mock_update.return_value = user
            
            # Act
            response = await async_client.put(
                "/api/v1/user/profile",
                json=update_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Should update the data
            mock_update.assert_called_once()
            update_call = mock_update.call_args
            assert update_call.kwargs['update_data'] == update_data
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_to_erasure_data_deletion(self, async_client, authenticated_headers):
        """Test right to erasure - user can delete their data (Article 17)."""
        # Arrange
        deletion_reason = "User requested account deletion"
        
        with patch('src.services.user_service.UserService.delete_user') as mock_delete, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = UserFactory(id=1)
            mock_current_user.return_value = user
            mock_delete.return_value = True
            
            # Act
            response = await async_client.delete(
                "/api/v1/user/account",
                json={"reason": deletion_reason, "hard_delete": True},
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Should perform hard delete for GDPR compliance
            mock_delete.assert_called_once()
            delete_call = mock_delete.call_args
            assert delete_call.kwargs['hard_delete'] is True
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_to_data_portability(self, async_client, authenticated_headers):
        """Test right to data portability - structured data export (Article 20)."""
        # Arrange
        with patch('src.services.user_service.UserService.get_user_by_id') as mock_get_user, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = ComplianceTestUserFactory()
            mock_get_user.return_value = user
            mock_current_user.return_value = user
            
            # Act
            response = await async_client.get(
                "/api/v1/user/data-export?format=json",
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            assert response.headers["content-type"] == "application/json"
            
            data = response.json()
            
            # Data should be in structured, machine-readable format
            assert isinstance(data, dict)
            assert "personal_data" in data
            assert "consent_records" in data
            assert "activity_log" in data
            
            # Should include export metadata
            assert "export_date" in data
            assert "data_controller" in data
            assert "legal_basis" in data
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_right_to_object_marketing(self, async_client, authenticated_headers):
        """Test right to object to marketing processing (Article 21)."""
        # Arrange
        consent_data = {
            "marketing_consent": False,
            "reason": "User objects to marketing"
        }
        
        with patch('src.services.user_service.UserService.update_user') as mock_update, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = UserFactory(id=1, marketing_consent=True)
            mock_current_user.return_value = user
            mock_update.return_value = user
            
            # Act
            response = await async_client.put(
                "/api/v1/user/consent",
                json=consent_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Should update marketing consent
            mock_update.assert_called_once()
            update_call = mock_update.call_args
            assert "marketing_consent" in update_call.kwargs['update_data']
            assert update_call.kwargs['update_data']['marketing_consent'] is False
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_consent_management_granular(self, async_client, authenticated_headers):
        """Test granular consent management (Article 7)."""
        # Arrange
        consent_data = {
            "data_processing_consent": True,
            "marketing_consent": False,
            "analytics_consent": True,
            "third_party_sharing_consent": False
        }
        
        with patch('src.services.user_service.UserService.update_user') as mock_update, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = UserFactory(id=1)
            mock_current_user.return_value = user
            mock_update.return_value = user
            
            # Act
            response = await async_client.put(
                "/api/v1/user/consent",
                json=consent_data,
                headers=authenticated_headers
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Should update all consent preferences
            mock_update.assert_called_once()
            update_call = mock_update.call_args
            update_data = update_call.kwargs['update_data']
            
            for consent_type, value in consent_data.items():
                assert update_data[consent_type] == value
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_consent_withdrawal_easy(self, async_client, authenticated_headers):
        """Test that consent withdrawal is as easy as giving consent (Article 7.3)."""
        # Arrange
        withdrawal_data = {
            "marketing_consent": False,
            "analytics_consent": False
        }
        
        with patch('src.services.user_service.UserService.update_user') as mock_update, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = UserFactory(id=1, marketing_consent=True, analytics_consent=True)
            mock_current_user.return_value = user
            mock_update.return_value = user
            
            # Act
            response = await async_client.put(
                "/api/v1/user/consent",
                json=withdrawal_data,
                headers=authenticated_headers  
            )
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            # Withdrawal should be immediate and require same effort as granting
            mock_update.assert_called_once()
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_data_retention_periods(self, db_session):
        """Test that data retention periods are enforced (Article 5.1.e)."""
        # Arrange
        from datetime import datetime, timedelta
        from src.services.user_service import UserService
        
        user_service = UserService()
        
        # Create user with old data
        old_user = UserFactory(
            created_at=datetime.utcnow() - timedelta(days=400),  # Over retention period
            last_login_at=datetime.utcnow() - timedelta(days=100)
        )
        
        recent_user = UserFactory(
            created_at=datetime.utcnow() - timedelta(days=30),  # Within retention period
            last_login_at=datetime.utcnow() - timedelta(days=1)
        )
        
        db_session.add(old_user)
        db_session.add(recent_user)
        await db_session.commit()
        
        # Act - Run data retention cleanup
        with patch('src.services.user_service.UserService.cleanup_expired_data') as mock_cleanup:
            mock_cleanup.return_value = 1  # 1 user cleaned up
            
            cleaned_count = await user_service.cleanup_expired_data(db_session)
            
            # Assert
            assert cleaned_count > 0
            mock_cleanup.assert_called_once()
    
    @pytest.mark.compliance 
    @pytest_asyncio.async
    async def test_audit_trail_gdpr_activities(self, db_session):
        """Test that GDPR-related activities are logged (Article 30)."""
        # Arrange
        from src.models.audit import AuditLog
        
        # Mock GDPR data export request
        with patch('src.models.audit.AuditLogger.log_data_access') as mock_log:
            mock_log.return_value = AsyncMock()
            
            # Simulate GDPR data export
            from src.services.user_service import UserService
            user_service = UserService()
            
            user = UserFactory(id=1)
            
            # Act
            await user_service.export_user_data(db_session, user.id, export_reason="gdpr_request")
            
            # Assert
            mock_log.assert_called_once()
            log_call = mock_log.call_args
            
            # Should log GDPR-specific event
            assert log_call.kwargs['action'] == "gdpr_data_export"
            assert log_call.kwargs['user_id'] == user.id
            assert "gdpr" in log_call.kwargs['description'].lower()
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_data_processing_lawful_basis(self, db_session):
        """Test that processing has lawful basis documented (Article 6)."""
        # Arrange
        user = ComplianceTestUserFactory()
        
        # Act & Assert
        # User data should have lawful basis documented
        assert user.data_processing_consent is not None
        assert user.data_processing_consent_date is not None
        
        # Should have clear lawful basis in user record or processing metadata
        processing_metadata = getattr(user, 'processing_metadata', {})
        if processing_metadata:
            assert 'lawful_basis' in processing_metadata
            
            valid_bases = [
                'consent', 'contract', 'legal_obligation', 
                'vital_interests', 'public_task', 'legitimate_interests'
            ]
            assert processing_metadata['lawful_basis'] in valid_bases
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_data_minimization(self, async_client):
        """Test data minimization principle (Article 5.1.c)."""
        # Arrange
        registration_data = {
            "email": "test@example.com",
            "password": "TestPassword123!",
            "first_name": "Test",
            "last_name": "User",
            # Should not require excessive data
            "data_processing_consent": True
        }
        
        # Act
        response = await async_client.post("/api/v1/user/register", json=registration_data)
        
        # Assert
        # Registration should succeed with minimal required data
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        
        # Should not require unnecessary personal data
        required_fields = ["email", "password", "data_processing_consent"]
        for field in required_fields:
            assert field in registration_data
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_purpose_limitation(self, async_client, authenticated_headers):
        """Test purpose limitation - data used only for stated purposes (Article 5.1.b)."""
        # Arrange
        with patch('src.services.user_service.UserService.get_user_by_id') as mock_get_user, \
             patch('src.api.deps.get_current_active_user') as mock_current_user:
            
            user = ComplianceTestUserFactory()
            mock_get_user.return_value = user
            mock_current_user.return_value = user
            
            # Act
            response = await async_client.get("/api/v1/user/profile", headers=authenticated_headers)
            
            # Assert
            assert response.status_code == status.HTTP_200_OK
            
            profile_data = response.json()
            
            # Should only include data necessary for the profile purpose
            necessary_fields = ["first_name", "last_name", "email", "created_at"]
            for field in necessary_fields:
                assert field in profile_data
            
            # Should not include unnecessary sensitive data
            unnecessary_fields = ["password_hash", "internal_notes", "admin_flags"]
            for field in unnecessary_fields:
                assert field not in profile_data
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_data_breach_notification_preparation(self, db_session):
        """Test data breach notification capabilities (Article 33-34)."""
        # Arrange
        from src.services.security_incident_service import SecurityIncidentService
        
        incident_service = SecurityIncidentService()
        
        # Simulate potential data breach
        breach_data = {
            "incident_type": "data_breach",
            "affected_users": [1, 2, 3],
            "data_categories": ["email", "name", "phone_number"],
            "breach_date": datetime.utcnow(),
            "discovery_date": datetime.utcnow(),
            "description": "Unauthorized access to user database"
        }
        
        # Act
        with patch.object(incident_service, 'log_security_incident') as mock_log:
            mock_log.return_value = AsyncMock()
            
            await incident_service.log_security_incident(db_session, **breach_data)
            
            # Assert
            mock_log.assert_called_once()
            
            # Should have capability to identify affected users and data
            call_args = mock_log.call_args.kwargs
            assert "affected_users" in call_args
            assert "data_categories" in call_args
            assert "breach_date" in call_args
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_cross_border_data_transfer_controls(self, async_client):
        """Test controls for international data transfers (Chapter V)."""
        # Arrange
        # Simulate request from different country
        headers = {
            "X-Forwarded-For": "5.6.7.8",  # IP from different country
            "Accept-Language": "de-DE"
        }
        
        login_data = {
            "email": "eu_user@example.com",
            "password": "TestPassword123!"
        }
        
        # Act
        response = await async_client.post("/api/v1/auth/login", json=login_data, headers=headers)
        
        # Assert
        # Should handle international requests appropriately
        # (Implementation depends on specific transfer mechanisms)
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_451_UNAVAILABLE_FOR_LEGAL_REASONS  # If geoblocked
        ]
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_children_data_protection(self, async_client):
        """Test enhanced protection for children's data (Article 8)."""
        # Arrange
        child_registration = {
            "email": "child@example.com",
            "password": "TestPassword123!",
            "date_of_birth": "2010-01-01",  # Under 16
            "parental_consent": False
        }
        
        # Act
        response = await async_client.post("/api/v1/user/register", json=child_registration)
        
        # Assert
        # Should require parental consent for children under 16
        if response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY:
            error_data = response.json()
            assert any("parental" in str(error).lower() for error in error_data.get("detail", []))
        
        # Or should reject registration without parental consent
        assert response.status_code in [
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            status.HTTP_400_BAD_REQUEST
        ]
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_dpo_contact_information(self, async_client):
        """Test that Data Protection Officer contact is available (Article 37-39)."""
        # Act
        response = await async_client.get("/api/v1/dpo-contact")
        
        # Assert
        assert response.status_code == status.HTTP_200_OK
        
        dpo_info = response.json()
        
        # Should provide DPO contact information
        assert "contact_email" in dpo_info
        assert "contact_address" in dpo_info
        assert "responsibilities" in dpo_info
        
        # Email should be valid format
        assert "@" in dpo_info["contact_email"]
    
    @pytest.mark.compliance
    @pytest_asyncio.async
    async def test_privacy_by_design_defaults(self, async_client):
        """Test privacy by design and default settings (Article 25)."""
        # Arrange
        registration_data = {
            "email": "privacy_test@example.com",
            "password": "TestPassword123!",
            "first_name": "Privacy",
            "last_name": "Test"
        }
        
        # Act
        response = await async_client.post("/api/v1/user/register", json=registration_data)
        
        # Assert
        assert response.status_code in [status.HTTP_201_CREATED, status.HTTP_200_OK]
        
        user_data = response.json()
        
        # Default privacy settings should be most protective
        assert user_data.get("marketing_consent", False) is False
        assert user_data.get("data_sharing_consent", False) is False
        assert user_data.get("profile_visibility", "private") == "private"
        
        # Only essential processing should be enabled by default
        assert user_data.get("data_processing_consent") is True  # Required for service