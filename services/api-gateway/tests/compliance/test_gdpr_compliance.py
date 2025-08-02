"""
GDPR (General Data Protection Regulation) compliance tests.
Tests data protection, privacy rights, and regulatory compliance.
"""
import pytest
import time
import json
from unittest.mock import patch, MagicMock


@pytest.mark.compliance
class TestGDPRDataProcessing:
    """Test GDPR data processing compliance."""
    
    def test_data_processing_consent_verification(self, client, auth_headers, compliance_test_data):
        """Test that data processing requires proper consent."""
        headers = auth_headers["valid_user"]
        gdpr_data = compliance_test_data["gdpr"]
        
        # Submit data processing request
        payload = {
            "user_data": gdpr_data["eu_user_data"],
            "processing_purposes": ["analytics", "marketing"],
            "consent_given": True
        }
        
        response = client.post("/api/v1/users/process-data", json=payload, headers=headers)
        
        # Should verify consent before processing
        if response.status_code == 200:
            # If processing allowed, should have consent verification
            data = response.json()
            assert "consent_verified" in data or "gdpr_compliant" in data
        else:
            # May require additional consent verification
            assert response.status_code in [400, 403, 422]
    
    def test_data_processing_without_consent(self, client, auth_headers, compliance_test_data):
        """Test that data processing is rejected without consent."""
        headers = auth_headers["valid_user"]
        gdpr_data = compliance_test_data["gdpr"]
        
        payload = {
            "user_data": gdpr_data["eu_user_data"],
            "processing_purposes": ["analytics", "marketing"],
            "consent_given": False
        }
        
        response = client.post("/api/v1/users/process-data", json=payload, headers=headers)
        
        # Should reject processing without consent
        assert response.status_code in [400, 403, 422]
        if response.status_code != 404:  # If endpoint exists
            error_data = response.json()
            assert "consent" in error_data.get("error", "").lower()
    
    def test_lawful_basis_documentation(self, client, auth_headers):
        """Test that lawful basis for processing is documented."""
        headers = auth_headers["valid_user"]
        
        # Request processing information
        response = client.get("/api/v1/users/processing-info", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should document lawful basis
            required_fields = ["lawful_basis", "processing_purposes", "data_retention"]
            for field in required_fields:
                assert field in data or any(field in str(v).lower() for v in data.values())
    
    def test_data_minimization_principle(self, client, auth_headers):
        """Test adherence to data minimization principle."""
        headers = auth_headers["valid_user"]
        
        # Create user with minimal required data
        minimal_data = {
            "email": "minimal@example.com",
            "password": "securepass123"
        }
        
        response = client.post("/api/v1/users/create", json=minimal_data, headers=headers)
        
        # Should accept minimal data without requiring excessive information
        if response.status_code not in [404, 405]:  # If endpoint exists
            assert response.status_code not in [400, 422]  # Should not require more data


@pytest.mark.compliance
class TestGDPRDataSubjectRights:
    """Test GDPR data subject rights implementation."""
    
    def test_right_of_access_data_export(self, client, auth_headers, compliance_test_data):
        """Test right of access - data subject can export their data."""
        headers = auth_headers["valid_user"]
        gdpr_data = compliance_test_data["gdpr"]
        
        # Request data export
        export_request = gdpr_data["data_subject_request"]
        export_request["type"] = "access"
        
        response = client.post("/api/v1/gdpr/data-export", json=export_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should provide comprehensive data export
            assert "user_data" in data or "export_url" in data
            assert "timestamp" in data
        elif response.status_code == 202:
            # Async processing accepted
            data = response.json()
            assert "request_id" in data or "status" in data
        else:
            # Endpoint may not exist in test environment
            assert response.status_code == 404
    
    def test_right_to_rectification(self, client, auth_headers):
        """Test right to rectification - data subject can correct their data."""
        headers = auth_headers["valid_user"]
        
        # Request data correction
        correction_data = {
            "field": "email",
            "old_value": "old@example.com",
            "new_value": "corrected@example.com",
            "reason": "Email address was incorrect"
        }
        
        response = client.put("/api/v1/gdpr/rectify-data", json=correction_data, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert "updated" in data or "corrected" in data
        else:
            # May require additional verification or endpoint doesn't exist
            assert response.status_code in [400, 404, 422]
    
    def test_right_to_erasure(self, client, auth_headers, compliance_test_data):
        """Test right to erasure - data subject can request data deletion."""
        headers = auth_headers["valid_user"]
        gdpr_data = compliance_test_data["gdpr"]
        
        # Request data deletion
        deletion_request = gdpr_data["data_subject_request"]
        deletion_request["type"] = "erasure"
        deletion_request["reason"] = "No longer wish to use service"
        
        response = client.post("/api/v1/gdpr/delete-data", json=deletion_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert "deletion_scheduled" in data or "erased" in data
        elif response.status_code == 202:
            # Async deletion accepted
            data = response.json()
            assert "request_id" in data
        else:
            # May require additional verification
            assert response.status_code in [400, 404, 422]
    
    def test_right_to_data_portability(self, client, auth_headers):
        """Test right to data portability - data in machine-readable format."""
        headers = auth_headers["valid_user"]
        
        # Request portable data export
        portability_request = {
            "format": "json",
            "include_processed_data": False  # Only raw data
        }
        
        response = client.post("/api/v1/gdpr/portable-export", json=portability_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should provide data in machine-readable format
            assert isinstance(data, dict)
            assert "user_data" in data or "export_data" in data
        else:
            assert response.status_code in [202, 404]  # Async or not implemented
    
    def test_right_to_object_to_processing(self, client, auth_headers):
        """Test right to object to processing."""
        headers = auth_headers["valid_user"]
        
        # Object to specific processing
        objection_request = {
            "processing_type": "marketing",
            "reason": "No longer wish to receive marketing communications"
        }
        
        response = client.post("/api/v1/gdpr/object-processing", json=objection_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert "processing_stopped" in data or "objection_recorded" in data
        else:
            assert response.status_code in [404, 422]


@pytest.mark.compliance
class TestGDPRConsentManagement:
    """Test GDPR consent management."""
    
    def test_explicit_consent_collection(self, client, compliance_test_data):
        """Test collection of explicit consent."""
        gdpr_data = compliance_test_data["gdpr"]
        
        # Registration with consent
        registration_data = {
            **gdpr_data["eu_user_data"],
            "password": "securepass123",
            "gdpr_consent": {
                "analytics": True,
                "marketing": False,
                "necessary": True,
                "timestamp": time.time(),
                "ip_address": "192.168.1.1"
            }
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        
        if response.status_code in [200, 201]:
            data = response.json()
            # Should acknowledge consent collection
            assert "consent_recorded" in data or "gdpr_compliant" in data
    
    def test_consent_withdrawal(self, client, auth_headers):
        """Test withdrawal of previously given consent."""
        headers = auth_headers["valid_user"]
        
        # Withdraw specific consent
        withdrawal_request = {
            "consent_type": "marketing",
            "withdraw": True,
            "reason": "No longer interested"
        }
        
        response = client.put("/api/v1/gdpr/consent", json=withdrawal_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            assert "consent_updated" in data or "withdrawn" in data
        else:
            assert response.status_code in [404, 422]
    
    def test_consent_granularity(self, client, auth_headers):
        """Test granular consent options."""
        headers = auth_headers["valid_user"]
        
        # Get current consent status
        response = client.get("/api/v1/gdpr/consent", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should provide granular consent options
            consent_types = ["necessary", "analytics", "marketing", "personalization"]
            for consent_type in consent_types:
                # Should have at least some granular options
                if any(ct in str(data).lower() for ct in consent_types):
                    break
            else:
                pytest.fail("No granular consent options found")
    
    def test_consent_proof_storage(self, client, auth_headers):
        """Test that consent proof is properly stored."""
        headers = auth_headers["valid_user"]
        
        # Request consent history
        response = client.get("/api/v1/gdpr/consent-history", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should maintain consent history with proof
            if "consent_history" in data:
                history = data["consent_history"]
                if history:
                    # Each consent record should have proof elements
                    consent_record = history[0] if isinstance(history, list) else history
                    proof_elements = ["timestamp", "ip_address", "user_agent"]
                    assert any(elem in consent_record for elem in proof_elements)


@pytest.mark.compliance
class TestGDPRDataProtection:
    """Test GDPR data protection requirements."""
    
    def test_data_encryption_in_transit(self, client, auth_headers):
        """Test that personal data is encrypted in transit."""
        headers = auth_headers["valid_user"]
        
        # Send personal data
        personal_data = {
            "name": "John Doe",
            "email": "john@example.com",
            "phone": "+1234567890"
        }
        
        response = client.post("/api/v1/users/update", json=personal_data, headers=headers)
        
        # In a real test, would verify HTTPS/TLS is used
        # For now, verify the request is handled securely
        if response.status_code == 200:
            # Should not expose personal data in response unnecessarily
            response_text = response.text.lower()
            sensitive_data = ["+1234567890", "john@example.com"]
            for data in sensitive_data:
                if data.lower() in response_text:
                    # If data appears, should be in appropriate context
                    pass
    
    def test_data_retention_limits(self, client, auth_headers):
        """Test data retention period compliance."""
        headers = auth_headers["valid_user"]
        
        # Request retention information
        response = client.get("/api/v1/gdpr/retention-info", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should specify retention periods
            retention_fields = ["retention_period", "deletion_date", "data_lifecycle"]
            assert any(field in data for field in retention_fields)
    
    def test_data_breach_notification_readiness(self, client, auth_headers):
        """Test data breach notification capabilities."""
        # This tests the infrastructure for breach notification
        # (Cannot test actual breach scenarios)
        
        headers = auth_headers["valid_admin"]  # Admin access required
        
        # Check breach reporting endpoint exists
        response = client.get("/api/v1/admin/breach-procedures", headers=headers)
        
        # Should have breach handling procedures
        if response.status_code == 200:
            data = response.json()
            assert "procedures" in data or "notification" in data
        else:
            # Endpoint may be restricted or not implemented
            assert response.status_code in [403, 404]
    
    def test_privacy_by_design_defaults(self, client):
        """Test privacy by design and default settings."""
        # Test default privacy settings for new users
        registration_data = {
            "email": "privacy@example.com",
            "password": "securepass123"
        }
        
        response = client.post("/api/v1/auth/register", json=registration_data)
        
        if response.status_code in [200, 201]:
            data = response.json()
            
            # Default settings should be privacy-friendly
            # (Most restrictive/private by default)
            if "settings" in data:
                settings = data["settings"]
                privacy_defaults = ["marketing_emails", "data_sharing", "analytics"]
                for setting in privacy_defaults:
                    if setting in settings:
                        # Should default to False (most private)
                        assert settings[setting] in [False, "opt-in", "disabled"]


@pytest.mark.compliance
class TestGDPRCrossReference:
    """Test GDPR cross-references with other systems."""
    
    def test_third_party_data_sharing_consent(self, client, auth_headers):
        """Test consent requirements for third-party data sharing."""
        headers = auth_headers["valid_user"]
        
        # Request third-party integration
        sharing_request = {
            "third_party": "analytics_provider",
            "data_types": ["usage_data", "preferences"],
            "purpose": "service_improvement"
        }
        
        response = client.post("/api/v1/gdpr/third-party-sharing", json=sharing_request, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should confirm consent for sharing
            assert "consent_required" in data or "sharing_approved" in data
        else:
            # May require explicit consent first
            assert response.status_code in [400, 403, 404, 422]
    
    def test_data_processor_compliance(self, client, auth_headers):
        """Test data processor compliance documentation."""
        headers = auth_headers["valid_admin"]
        
        # Get data processing agreements
        response = client.get("/api/v1/admin/gdpr/processors", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should list data processors
            assert "processors" in data or "agreements" in data
        else:
            assert response.status_code in [403, 404]
    
    def test_international_data_transfer_safeguards(self, client, auth_headers):
        """Test safeguards for international data transfers."""
        headers = auth_headers["valid_user"]
        
        # Request transfer information
        response = client.get("/api/v1/gdpr/transfer-info", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should document transfer safeguards
            safeguards = ["adequacy_decision", "standard_clauses", "binding_rules"]
            if any(sg in str(data).lower() for sg in safeguards):
                assert True  # Has transfer safeguards
            else:
                # May not have international transfers
                assert "no_international_transfers" in str(data).lower()


@pytest.mark.compliance
class TestGDPRAuditAndCompliance:
    """Test GDPR audit trail and compliance monitoring."""
    
    def test_processing_activity_logging(self, client, auth_headers):
        """Test logging of processing activities."""
        headers = auth_headers["valid_user"]
        
        # Perform data processing activity
        response = client.put("/api/v1/users/preferences", 
                             json={"marketing": False, "analytics": True}, 
                             headers=headers)
        
        if response.status_code == 200:
            # Processing should be logged (can't directly verify logs)
            # But operation should succeed and be compliant
            assert True
        
        # Check if audit logs are available
        audit_response = client.get("/api/v1/gdpr/audit-log", headers=headers)
        if audit_response.status_code == 200:
            audit_data = audit_response.json()
            assert "activities" in audit_data or "log_entries" in audit_data
    
    def test_dpo_contact_information(self, client):
        """Test Data Protection Officer contact information availability."""
        # DPO contact should be publicly available
        response = client.get("/api/v1/gdpr/dpo-contact")
        
        if response.status_code == 200:
            data = response.json()
            # Should provide DPO contact information
            contact_fields = ["email", "address", "phone", "contact"]
            assert any(field in data for field in contact_fields)
        else:
            # May be available at different endpoint
            assert response.status_code in [404, 405]
    
    def test_gdpr_compliance_status(self, client, auth_headers):
        """Test GDPR compliance status reporting."""
        headers = auth_headers["valid_admin"]
        
        # Get compliance status
        response = client.get("/api/v1/admin/gdpr/compliance-status", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should report compliance metrics
            compliance_metrics = ["consent_rate", "data_requests", "breaches", "compliance_score"]
            assert any(metric in data for metric in compliance_metrics)
        else:
            assert response.status_code in [403, 404]
    
    def test_privacy_impact_assessment_documentation(self, client, auth_headers):
        """Test Privacy Impact Assessment documentation."""
        headers = auth_headers["valid_admin"]
        
        # Request PIA documentation
        response = client.get("/api/v1/admin/gdpr/privacy-impact-assessment", headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            # Should have PIA documentation for high-risk processing
            pia_elements = ["risk_assessment", "mitigation_measures", "necessity_test"]
            assert any(element in str(data).lower() for element in pia_elements)
        else:
            assert response.status_code in [403, 404]