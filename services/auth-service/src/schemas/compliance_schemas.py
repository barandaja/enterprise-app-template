"""
Pydantic schemas for HIPAA and SOC2 compliance API endpoints.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, validator
from enum import Enum

from ..models.hipaa_compliance import (
    PHICategory, AccessPurpose, EmergencyAccessType, BAAAgreementStatus
)
from ..models.soc2_compliance import (
    IncidentSeverity, IncidentStatus, IncidentCategory, AnomalyType,
    VendorAccessLevel, ChangeType, ChangeStatus, TrustServiceCriteria
)


# HIPAA Compliance Schemas

class PHIAccessLogCreate(BaseModel):
    """Schema for creating PHI access log."""
    phi_category: PHICategory
    resource_type: str = Field(..., min_length=1, max_length=100)
    resource_id: str = Field(..., min_length=1, max_length=100)
    access_purpose: AccessPurpose
    access_method: str = Field(..., min_length=1, max_length=50)
    action_performed: str = Field(..., min_length=1, max_length=50)
    access_justification: str = Field(..., min_length=10)
    patient_id: Optional[str] = Field(None, max_length=100)
    patient_mrn: Optional[str] = Field(None, max_length=100)
    phi_fields_accessed: Optional[List[str]] = Field(default_factory=list)
    data_volume: Optional[int] = Field(None, ge=0)
    authorization_id: Optional[str] = Field(None, max_length=128)
    minimum_necessary_applied: bool = True
    
    class Config:
        use_enum_values = True


class PHIAccessLogResponse(BaseModel):
    """Schema for PHI access log response."""
    access_id: str
    user_id: int
    phi_category: str
    resource_type: str
    resource_id: str
    access_purpose: str
    access_method: str
    action_performed: str
    access_justification: str
    access_timestamp: datetime
    access_successful: bool
    patient_id: Optional[str] = None
    patient_mrn: Optional[str] = None
    phi_fields_accessed: Optional[List[str]] = None
    data_volume: Optional[int] = None
    minimum_necessary_applied: bool
    
    class Config:
        from_attributes = True


class EmergencyAccessCreate(BaseModel):
    """Schema for creating emergency access."""
    emergency_type: EmergencyAccessType
    emergency_justification: str = Field(..., min_length=20)
    patient_id: Optional[str] = Field(None, max_length=100)
    patient_mrn: Optional[str] = Field(None, max_length=100)
    location: Optional[str] = Field(None, max_length=255)
    department: Optional[str] = Field(None, max_length=100)
    clinical_context: Optional[str] = None
    requires_approval: bool = True
    
    class Config:
        use_enum_values = True


class EmergencyAccessResponse(BaseModel):
    """Schema for emergency access response."""
    emergency_id: str
    user_id: int
    emergency_type: str
    emergency_justification: str
    emergency_start_time: datetime
    emergency_end_time: Optional[datetime] = None
    is_active: bool
    approved_at: Optional[datetime] = None
    approved_by_user_id: Optional[int] = None
    patient_id: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    duration_minutes: Optional[int] = None
    
    class Config:
        from_attributes = True


class EmergencyAccessTerminate(BaseModel):
    """Schema for terminating emergency access."""
    termination_reason: Optional[str] = None


class BusinessAssociateAgreementCreate(BaseModel):
    """Schema for creating BAA."""
    business_associate_name: str = Field(..., min_length=1, max_length=255)
    business_associate_type: str = Field(..., min_length=1, max_length=100)
    agreement_title: str = Field(..., min_length=1, max_length=255)
    agreement_description: Optional[str] = None
    covered_services: List[str] = Field(..., min_items=1)
    phi_categories_covered: List[str] = Field(..., min_items=1)
    effective_date: datetime
    expiration_date: datetime
    security_requirements: Optional[Dict[str, Any]] = None
    audit_requirements: Optional[Dict[str, Any]] = None
    
    @validator('expiration_date')
    def expiration_after_effective(cls, v, values):
        if 'effective_date' in values and v <= values['effective_date']:
            raise ValueError('Expiration date must be after effective date')
        return v


class BusinessAssociateAgreementResponse(BaseModel):
    """Schema for BAA response."""
    agreement_id: str
    agreement_number: Optional[str] = None
    business_associate_name: str
    business_associate_type: str
    agreement_title: str
    covered_services: List[str]
    phi_categories_covered: List[str]
    effective_date: datetime
    expiration_date: datetime
    status: str
    is_active: bool
    days_until_expiration: int
    
    class Config:
        from_attributes = True


class HIPAASessionCreate(BaseModel):
    """Schema for creating HIPAA session context."""
    phi_access_level: str = Field(default="none", regex="^(none|limited|full)$")
    department_context: Optional[str] = Field(None, max_length=100)
    role_context: Optional[str] = Field(None, max_length=100)
    phi_session_timeout_minutes: int = Field(default=15, ge=5, le=60)


class HIPAASessionResponse(BaseModel):
    """Schema for HIPAA session response."""
    session_id: str
    user_id: int
    phi_access_level: str
    current_patient_context: Optional[str] = None
    department_context: Optional[str] = None
    role_context: Optional[str] = None
    last_phi_access: Optional[datetime] = None
    phi_session_timeout_minutes: int
    emergency_access_active: bool
    is_phi_session_expired: bool
    should_warn: bool
    
    class Config:
        from_attributes = True


# SOC2 Compliance Schemas

class SecurityIncidentCreate(BaseModel):
    """Schema for creating security incident."""
    category: IncidentCategory
    severity: IncidentSeverity
    title: str = Field(..., min_length=5, max_length=255)
    description: str = Field(..., min_length=20)
    trust_criteria_affected: List[TrustServiceCriteria] = Field(..., min_items=1)
    detected_at: Optional[datetime] = None
    systems_affected: Optional[List[str]] = Field(default_factory=list)
    users_affected_count: Optional[int] = Field(None, ge=0)
    data_affected: bool = False
    customer_impact: bool = False
    
    class Config:
        use_enum_values = True


class SecurityIncidentResponse(BaseModel):
    """Schema for security incident response."""
    incident_id: str
    incident_number: str
    category: str
    severity: str
    title: str
    description: str
    trust_criteria_affected: List[str]
    detected_at: datetime
    reported_at: datetime
    status: str
    systems_affected: Optional[List[str]] = None
    users_affected_count: Optional[int] = None
    data_affected: bool
    customer_impact: bool
    reported_by_user_id: Optional[int] = None
    assigned_to_user_id: Optional[int] = None
    response_time_minutes: Optional[int] = None
    resolution_time_hours: Optional[float] = None
    
    class Config:
        from_attributes = True


class SecurityIncidentUpdate(BaseModel):
    """Schema for updating security incident."""
    status: Optional[IncidentStatus] = None
    assigned_to_user_id: Optional[int] = None
    root_cause: Optional[str] = None
    resolution_summary: Optional[str] = None
    corrective_actions: Optional[List[str]] = None
    
    class Config:
        use_enum_values = True


class SecurityAnomalyResponse(BaseModel):
    """Schema for security anomaly response."""
    anomaly_id: str
    anomaly_type: str
    detected_at: datetime
    detection_source: str
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    risk_score: float = Field(..., ge=0.0, le=10.0)
    description: str
    anomalous_behavior: Dict[str, Any]
    baseline_behavior: Optional[Dict[str, Any]] = None
    potential_impact: str
    user_id: Optional[int] = None
    ip_address: Optional[str] = None
    investigated: bool
    false_positive: bool
    
    class Config:
        from_attributes = True


class SecurityAnomalyInvestigate(BaseModel):
    """Schema for investigating security anomaly."""
    investigation_notes: Optional[str] = None
    false_positive: bool = False


class VendorAccessCreate(BaseModel):
    """Schema for creating vendor access request."""
    vendor_name: str = Field(..., min_length=1, max_length=255)
    vendor_contact_email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    access_level: VendorAccessLevel
    systems_accessed: List[str] = Field(..., min_items=1)
    access_purpose: str = Field(..., min_length=20)
    business_justification: str = Field(..., min_length=20)
    access_start_date: datetime
    access_end_date: datetime
    mfa_required: bool = True
    vpn_required: bool = True
    ip_restrictions: Optional[List[str]] = None
    
    @validator('access_end_date')
    def end_after_start(cls, v, values):
        if 'access_start_date' in values and v <= values['access_start_date']:
            raise ValueError('End date must be after start date')
        return v
    
    @validator('access_end_date')
    def max_duration_check(cls, v, values):
        if 'access_start_date' in values:
            duration = v - values['access_start_date']
            if duration.days > 90:
                raise ValueError('Access duration cannot exceed 90 days')
        return v
    
    class Config:
        use_enum_values = True


class VendorAccessResponse(BaseModel):
    """Schema for vendor access response."""
    access_id: str
    vendor_name: str
    vendor_contact_email: str
    access_level: str
    systems_accessed: List[str]
    access_purpose: str
    business_justification: str
    access_start_date: datetime
    access_end_date: datetime
    is_active: bool
    is_revoked: bool
    approved_at: Optional[datetime] = None
    approved_by_user_id: Optional[int] = None
    revoked_at: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    is_expired: bool
    
    class Config:
        from_attributes = True


class VendorAccessApprove(BaseModel):
    """Schema for approving vendor access."""
    pass  # No additional fields needed


class VendorAccessRevoke(BaseModel):
    """Schema for revoking vendor access."""
    revocation_reason: Optional[str] = None


class ChangeRequestCreate(BaseModel):
    """Schema for creating change request."""
    change_type: ChangeType
    title: str = Field(..., min_length=5, max_length=255)
    description: str = Field(..., min_length=20)
    business_justification: str = Field(..., min_length=20)
    systems_affected: List[str] = Field(..., min_items=1)
    trust_criteria_impact: List[TrustServiceCriteria] = Field(..., min_items=1)
    requested_implementation_date: datetime
    implementation_steps: List[str] = Field(..., min_items=1)
    rollback_plan: str = Field(..., min_length=20)
    risk_level: str = Field(default="medium", regex="^(low|medium|high|critical)$")
    estimated_downtime_minutes: Optional[int] = Field(None, ge=0)
    testing_plan: Optional[str] = None
    
    @validator('requested_implementation_date')
    def future_date(cls, v):
        if v <= datetime.utcnow():
            raise ValueError('Implementation date must be in the future')
        return v
    
    class Config:
        use_enum_values = True


class ChangeRequestResponse(BaseModel):
    """Schema for change request response."""
    change_id: str
    change_number: str
    change_type: str
    title: str
    description: str
    business_justification: str
    systems_affected: List[str]
    trust_criteria_impact: List[str]
    requested_implementation_date: datetime
    actual_implementation_date: Optional[datetime] = None
    completion_date: Optional[datetime] = None
    status: str
    risk_level: str
    approval_required: bool
    approved_at: Optional[datetime] = None
    approved_by_user_id: Optional[int] = None
    implementation_successful: Optional[bool] = None
    verification_completed: bool
    requested_by_user_id: int
    
    class Config:
        from_attributes = True


class ChangeRequestUpdate(BaseModel):
    """Schema for updating change request."""
    status: Optional[ChangeStatus] = None
    rejection_reason: Optional[str] = None
    implementation_successful: Optional[bool] = None
    verification_notes: Optional[str] = None
    
    class Config:
        use_enum_values = True


class ComplianceControlResponse(BaseModel):
    """Schema for compliance control response."""
    control_id: str
    control_number: str
    trust_criteria: str
    control_category: str
    control_title: str
    control_description: str
    control_objective: str
    is_implemented: bool
    implementation_status: str
    testing_frequency: str
    last_tested_date: Optional[datetime] = None
    next_test_due_date: Optional[datetime] = None
    is_effective: Optional[bool] = None
    effectiveness_rating: Optional[str] = None
    deficiency_identified: bool
    
    class Config:
        from_attributes = True


class ComplianceControlTest(BaseModel):
    """Schema for testing compliance control."""
    is_effective: bool
    effectiveness_rating: str = Field(..., regex="^(effective|needs_improvement|ineffective)$")
    next_test_date: Optional[datetime] = None


# Reporting and Dashboard Schemas

class ComplianceReportRequest(BaseModel):
    """Schema for compliance report request."""
    start_date: datetime
    end_date: datetime
    report_type: str = Field(..., regex="^(hipaa|soc2|combined)$")
    trust_criteria: Optional[List[TrustServiceCriteria]] = None
    include_details: bool = True
    
    @validator('end_date')
    def end_after_start(cls, v, values):
        if 'start_date' in values and v <= values['start_date']:
            raise ValueError('End date must be after start date')
        return v
    
    class Config:
        use_enum_values = True


class ComplianceDashboardResponse(BaseModel):
    """Schema for compliance dashboard response."""
    hipaa_metrics: Dict[str, Any]
    soc2_metrics: Dict[str, Any]
    incidents_summary: Dict[str, Any]
    anomalies_summary: Dict[str, Any]
    vendor_access_summary: Dict[str, Any]
    change_management_summary: Dict[str, Any]
    control_effectiveness_summary: Dict[str, Any]
    compliance_score: float = Field(..., ge=0.0, le=100.0)
    alerts: List[Dict[str, Any]]
    generated_at: datetime


class HIPAAComplianceReport(BaseModel):
    """Schema for HIPAA compliance report."""
    report_period: Dict[str, str]
    phi_access_summary: Dict[str, Any]
    emergency_access_summary: Dict[str, Any]
    baa_management_summary: Dict[str, Any]
    audit_trail_summary: Dict[str, Any]
    compliance_score: float
    recommendations: List[str]
    generated_at: datetime


class SOC2ComplianceReport(BaseModel):
    """Schema for SOC2 compliance report."""
    report_period: Dict[str, str]
    incident_management: Dict[str, Any]
    anomaly_detection: Dict[str, Any]
    vendor_access_management: Dict[str, Any]
    change_management: Dict[str, Any]
    control_effectiveness: Dict[str, Any]
    audit_trail: Dict[str, Any]
    compliance_score: float
    trust_criteria_scores: Dict[str, float]
    generated_at: datetime


class ComplianceAlert(BaseModel):
    """Schema for compliance alerts."""
    alert_id: str
    alert_type: str  # 'hipaa', 'soc2', 'general'
    severity: str    # 'low', 'medium', 'high', 'critical'
    title: str
    description: str
    created_at: datetime
    resolved: bool = False
    action_required: bool = True
    related_resource_type: Optional[str] = None
    related_resource_id: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)


# Query and Filter Schemas

class PHIAccessLogFilter(BaseModel):
    """Schema for filtering PHI access logs."""
    user_id: Optional[int] = None
    patient_id: Optional[str] = None
    resource_type: Optional[str] = None
    phi_category: Optional[PHICategory] = None
    access_purpose: Optional[AccessPurpose] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    
    class Config:
        use_enum_values = True


class SecurityIncidentFilter(BaseModel):
    """Schema for filtering security incidents."""
    category: Optional[IncidentCategory] = None
    severity: Optional[IncidentSeverity] = None
    status: Optional[IncidentStatus] = None
    assigned_to_user_id: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    data_affected: Optional[bool] = None
    customer_impact: Optional[bool] = None
    limit: int = Field(default=100, ge=1, le=1000)
    
    class Config:
        use_enum_values = True


class SecurityAnomalyFilter(BaseModel):
    """Schema for filtering security anomalies."""
    anomaly_type: Optional[AnomalyType] = None
    user_id: Optional[int] = None
    min_risk_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    min_confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    investigated: Optional[bool] = None
    false_positive: Optional[bool] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    
    class Config:
        use_enum_values = True


class VendorAccessFilter(BaseModel):
    """Schema for filtering vendor access."""
    vendor_name: Optional[str] = None
    access_level: Optional[VendorAccessLevel] = None
    is_active: Optional[bool] = None
    is_revoked: Optional[bool] = None
    expiring_within_days: Optional[int] = Field(None, ge=0, le=365)
    limit: int = Field(default=100, ge=1, le=1000)
    
    class Config:
        use_enum_values = True


class ChangeRequestFilter(BaseModel):
    """Schema for filtering change requests."""
    change_type: Optional[ChangeType] = None
    status: Optional[ChangeStatus] = None
    risk_level: Optional[str] = Field(None, regex="^(low|medium|high|critical)$")
    requested_by_user_id: Optional[int] = None
    approved_by_user_id: Optional[int] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    
    class Config:
        use_enum_values = True