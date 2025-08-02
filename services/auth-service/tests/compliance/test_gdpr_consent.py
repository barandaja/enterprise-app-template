"""
Tests for GDPR Consent Management functionality.
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.models.gdpr_consent import (
    ConsentType, ConsentStatus, ConsentLegalBasis,
    ConsentVersion, UserConsent
)
from src.services.gdpr_consent_service import ConsentService
from tests.factories.user_factory import UserFactory


class TestConsentVersionManagement:
    """Test consent version management functionality."""
    
    @pytest.fixture
    async def consent_service(self):
        """Create consent service instance."""
        return ConsentService()
    
    @pytest.fixture
    async def admin_user(self, db_session: AsyncSession):
        """Create admin user for testing."""
        return await UserFactory.create_user(
            db_session=db_session,
            email="admin@test.com",
            is_superuser=True
        )
    
    @pytest.fixture
    async def regular_user(self, db_session: AsyncSession):
        """Create regular user for testing."""
        return await UserFactory.create_user(
            db_session=db_session,
            email="user@test.com"
        )
    
    async def test_initialize_consent_versions(self, db_session: AsyncSession, consent_service: ConsentService):
        """Test initialization of default consent versions."""
        await consent_service.initialize_consent_versions(db_session)
        
        # Verify that all default consent types have active versions
        for consent_type in ConsentType:
            version = await ConsentVersion.get_active_version(db_session, consent_type)
            assert version is not None
            assert version.is_active
            assert version.consent_type == consent_type
    
    async def test_create_consent_version_as_admin(
        self, 
        db_session: AsyncSession, 
        consent_service: ConsentService,
        admin_user: User
    ):
        """Test creating consent version as admin."""
        version_data = await consent_service.create_consent_version(
            db=db_session,
            consent_type=ConsentType.MARKETING_EMAIL,
            version_number="2.0",
            title="Updated Email Marketing Consent",
            description="Updated consent for email marketing",
            consent_text="I consent to receive updated marketing emails",
            legal_basis=ConsentLegalBasis.CONSENT,
            created_by_user_id=admin_user.id
        )
        
        assert version_data['consent_type'] == ConsentType.MARKETING_EMAIL.value
        assert version_data['version_number'] == "2.0"
        assert version_data['is_active'] == True
        
        # Verify old version is deactivated
        old_version = await ConsentVersion.get_active_version(db_session, ConsentType.MARKETING_EMAIL)
        assert old_version.version_number == "2.0"  # New version is active
    
    async def test_create_consent_version_as_regular_user_fails(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        regular_user: User
    ):
        """Test that regular users cannot create consent versions."""
        with pytest.raises(Exception):  # Should raise HTTPException with 403
            await consent_service.create_consent_version(
                db=db_session,
                consent_type=ConsentType.MARKETING_EMAIL,
                version_number="2.0",
                title="Unauthorized Version",
                description="This should fail",
                consent_text="Unauthorized consent text",
                legal_basis=ConsentLegalBasis.CONSENT,
                created_by_user_id=regular_user.id
            )


class TestUserConsentManagement:
    """Test user consent granting and withdrawal."""
    
    @pytest.fixture
    async def consent_service(self):
        """Create consent service instance."""
        return ConsentService()
    
    @pytest.fixture
    async def test_user(self, db_session: AsyncSession):
        """Create test user."""
        return await UserFactory.create_user(
            db_session=db_session,
            email="consentuser@test.com"
        )
    
    @pytest.fixture
    async def setup_consent_versions(self, db_session: AsyncSession, consent_service: ConsentService):
        """Set up default consent versions."""
        await consent_service.initialize_consent_versions(db_session)
    
    async def test_grant_consent(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test granting consent."""
        consent_data = await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL,
            ip_address="192.168.1.1",
            user_agent="Test Agent",
            consent_method="web_form"
        )
        
        assert consent_data['status'] == ConsentStatus.GRANTED.value
        assert consent_data['is_valid'] == True
        assert consent_data['consent_type'] == ConsentType.MARKETING_EMAIL.value
        
        # Verify consent exists in database
        consent = await UserConsent.get_user_consent(
            db_session, test_user.id, ConsentType.MARKETING_EMAIL
        )
        assert consent is not None
        assert consent.status == ConsentStatus.GRANTED
    
    async def test_withdraw_consent(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test withdrawing consent."""
        # First grant consent
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Then withdraw it
        withdrawal_data = await consent_service.withdraw_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL,
            withdrawal_reason="No longer interested"
        )
        
        assert withdrawal_data['status'] == ConsentStatus.WITHDRAWN.value
        assert withdrawal_data['is_valid'] == False
        assert withdrawal_data['withdrawal_reason'] == "No longer interested"
    
    async def test_bulk_grant_consents(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test bulk consent granting."""
        consents_to_grant = {
            ConsentType.MARKETING_EMAIL: {"expires_at": (datetime.utcnow() + timedelta(days=365)).isoformat()},
            ConsentType.ANALYTICS: {"metadata": {"source": "registration"}},
            ConsentType.COOKIES_FUNCTIONAL: {}
        }
        
        result = await consent_service.bulk_grant_consents(
            db=db_session,
            user_id=test_user.id,
            consents=consents_to_grant,
            consent_method="registration_form"
        )
        
        assert result['successful_count'] == 3
        assert result['failed_count'] == 0
        assert len(result['granted_consents']) == 3
    
    async def test_get_user_consents(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test retrieving user consents."""
        # Grant some consents
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.ANALYTICS
        )
        
        # Retrieve consents
        result = await consent_service.get_user_consents(
            db=db_session,
            user_id=test_user.id
        )
        
        assert result['user_id'] == test_user.id
        assert len(result['current_consents']) >= 2
        assert ConsentType.MARKETING_EMAIL.value in result['current_consents']
        assert ConsentType.ANALYTICS.value in result['current_consents']
    
    async def test_consent_validity_check(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test consent validity checking."""
        # Test without consent
        validity = await consent_service.check_consent_validity(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        assert validity['has_valid_consent'] == False
        assert validity['consent_required'] == True
        
        # Grant consent
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Test with valid consent
        validity = await consent_service.check_consent_validity(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        assert validity['has_valid_consent'] == True
        assert validity['consent_required'] == False
    
    async def test_consent_expiry(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test consent expiry handling."""
        # Grant consent with short expiry
        expires_at = datetime.utcnow() - timedelta(days=1)  # Already expired
        
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL,
            expires_at=expires_at
        )
        
        # Check validity
        validity = await consent_service.check_consent_validity(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        assert validity['has_valid_consent'] == False
        assert validity['is_expired'] == True
    
    async def test_consent_history(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User,
        setup_consent_versions
    ):
        """Test consent history tracking."""
        # Grant consent
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Withdraw consent
        await consent_service.withdraw_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Grant again
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Get history
        history = await consent_service.get_user_consents(
            db=db_session,
            user_id=test_user.id,
            consent_types=[ConsentType.MARKETING_EMAIL],
            include_history=True
        )
        
        # Should have multiple entries for the same consent type
        email_consents = [c for c in history['consents'] if c.get('consent_type') == ConsentType.MARKETING_EMAIL.value]
        assert len(email_consents) >= 1  # At least the current valid consent


class TestConsentCompliance:
    """Test GDPR compliance aspects of consent management."""
    
    @pytest.fixture
    async def consent_service(self):
        return ConsentService()
    
    @pytest.fixture
    async def test_user(self, db_session: AsyncSession):
        return await UserFactory.create_user(
            db_session=db_session,
            email="compliance@test.com"
        )
    
    async def test_consent_audit_logging(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User
    ):
        """Test that consent operations are properly audited."""
        # Initialize versions first
        await consent_service.initialize_consent_versions(db_session)
        
        # Mock audit logger to verify calls
        consent_service.audit_logger.log_data_access = AsyncMock()
        
        # Grant consent
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL,
            ip_address="192.168.1.1"
        )
        
        # Verify audit log was called
        consent_service.audit_logger.log_data_access.assert_called()
        call_args = consent_service.audit_logger.log_data_access.call_args
        assert call_args[1]['action'] == 'grant_consent'
        assert call_args[1]['user_id'] == test_user.id
        assert call_args[1]['ip_address'] == '192.168.1.1'
    
    async def test_consent_versioning_compliance(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User
    ):
        """Test that consent versioning works for compliance."""
        await consent_service.initialize_consent_versions(db_session)
        
        # Grant consent on version 1.0
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        # Create new version (would be done by admin)
        admin_user = await UserFactory.create_user(
            db_session=db_session,
            email="admin@test.com",
            is_superuser=True
        )
        
        await consent_service.create_consent_version(
            db=db_session,
            consent_type=ConsentType.MARKETING_EMAIL,
            version_number="2.0",
            title="Updated Marketing Consent",
            description="Updated terms",
            consent_text="Updated text",
            legal_basis=ConsentLegalBasis.CONSENT,
            created_by_user_id=admin_user.id
        )
        
        # User's old consent should still be valid but linked to old version
        consent = await UserConsent.get_user_consent(
            db_session, test_user.id, ConsentType.MARKETING_EMAIL
        )
        assert consent is not None
        assert consent.is_valid()
        
        # But new consents should use new version
        new_user = await UserFactory.create_user(
            db_session=db_session,
            email="newuser@test.com"
        )
        
        await consent_service.grant_consent(
            db=db_session,
            user_id=new_user.id,
            consent_type=ConsentType.MARKETING_EMAIL
        )
        
        new_consent = await UserConsent.get_user_consent(
            db_session, new_user.id, ConsentType.MARKETING_EMAIL
        )
        assert new_consent.consent_version.version_number == "2.0"
    
    async def test_cleanup_expired_consents(
        self,
        db_session: AsyncSession,
        consent_service: ConsentService,
        test_user: User
    ):
        """Test cleanup of expired consents."""
        await consent_service.initialize_consent_versions(db_session)
        
        # Grant consent that's already expired
        expired_time = datetime.utcnow() - timedelta(days=1)
        await consent_service.grant_consent(
            db=db_session,
            user_id=test_user.id,
            consent_type=ConsentType.MARKETING_EMAIL,
            expires_at=expired_time
        )
        
        # Run cleanup
        result = await consent_service.cleanup_expired_consents(db_session)
        
        assert result['updated_count'] >= 1
        
        # Verify consent status was updated
        consent = await UserConsent.get_user_consent(
            db_session, test_user.id, ConsentType.MARKETING_EMAIL
        )
        assert consent.status == ConsentStatus.EXPIRED


@pytest.mark.integration
class TestConsentIntegration:
    """Integration tests for consent management with other systems."""
    
    async def test_consent_with_user_registration(
        self,
        db_session: AsyncSession
    ):
        """Test consent granting during user registration flow."""
        consent_service = ConsentService()
        await consent_service.initialize_consent_versions(db_session)
        
        # Simulate user registration with consents
        user = await UserFactory.create_user(
            db_session=db_session,
            email="newregistration@test.com"
        )
        
        # Grant essential consents during registration
        essential_consents = {
            ConsentType.DATA_PROCESSING: {},
            ConsentType.COOKIES_FUNCTIONAL: {},
            ConsentType.ANALYTICS: {"metadata": {"registration_source": "web"}}
        }
        
        result = await consent_service.bulk_grant_consents(
            db=db_session,
            user_id=user.id,
            consents=essential_consents,
            consent_method="registration"
        )
        
        assert result['successful_count'] == 3
        
        # Verify all consents are valid
        for consent_type in essential_consents.keys():
            validity = await consent_service.check_consent_validity(
                db=db_session,
                user_id=user.id,
                consent_type=consent_type
            )
            assert validity['has_valid_consent'] == True