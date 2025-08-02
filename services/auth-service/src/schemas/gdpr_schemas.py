"""
GDPR API schemas for request/response validation.
Includes schemas for consent management, data access, deletion, and portability.
"""
from datetime import datetime
from typing import Dict, Any, Optional, List, Union
from enum import Enum
from pydantic import BaseModel, Field, validator, EmailStr

from ..models.gdpr_consent import ConsentType, ConsentStatus, ConsentLegalBasis
from ..services.gdpr_deletion_service import DeletionReason, DeletionScope
from ..services.gdpr_portability_service import PortabilityFormat, DataCategory


# Base schemas
class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class PaginationRequest(BaseModel):
    """Request schema for pagination."""
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Number of items per page")


class PaginationResponse(BaseModel):
    """Response schema for paginated results."""
    page: int
    page_size: int
    total_count: int
    total_pages: int
    has_next: bool
    has_prev: bool


# Consent schemas
class ConsentVersionRequest(BaseModel):
    """Request schema for creating consent version."""
    consent_type: ConsentType
    version_number: str = Field(..., min_length=1, max_length=20)
    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    consent_text: str = Field(..., min_length=1)
    legal_basis: ConsentLegalBasis
    effective_from: Optional[datetime] = None


class ConsentVersionResponse(BaseModel, TimestampMixin):
    """Response schema for consent version."""
    id: int
    consent_type: str
    version_number: str
    title: str
    description: str
    consent_text: str
    legal_basis: str
    effective_from: Optional[datetime]
    effective_until: Optional[datetime]
    is_active: bool
    created_by_user_id: Optional[int]


class ConsentGrantRequest(BaseModel):
    """Request schema for granting consent."""
    consent_type: ConsentType
    consent_method: str = Field(default="web_form", max_length=50)
    expires_at: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


class ConsentWithdrawRequest(BaseModel):
    """Request schema for withdrawing consent."""
    consent_type: ConsentType
    withdrawal_reason: Optional[str] = Field(None, max_length=1000)


class ConsentBulkRequest(BaseModel):
    """Request schema for bulk consent operations."""
    consents: Dict[ConsentType, Dict[str, Any]]
    consent_method: str = Field(default="web_form", max_length=50)
    
    @validator('consents')
    def validate_consents(cls, v):
        if not v:
            raise ValueError("At least one consent must be specified")
        return v


class UserConsentResponse(BaseModel, TimestampMixin):
    """Response schema for user consent."""
    id: int
    user_id: int
    consent_type: str
    consent_title: Optional[str]
    consent_description: Optional[str]
    status: str
    granted_at: Optional[datetime]
    withdrawn_at: Optional[datetime]
    expires_at: Optional[datetime]
    consent_method: Optional[str]
    legal_basis: Optional[str]
    version_number: Optional[str]
    is_valid: bool
    is_expired: bool


class ConsentHistoryResponse(BaseModel):
    """Response schema for consent history."""
    user_id: int
    consents: List[UserConsentResponse]
    current_consents: Dict[str, UserConsentResponse]
    total_count: int
    retrieved_at: datetime


class ConsentValidityResponse(BaseModel):
    """Response schema for consent validity check."""
    user_id: int
    consent_type: str
    has_valid_consent: bool
    consent_required: bool
    is_expired: bool = False
    granted_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    status: str
    legal_basis: Optional[str] = None
    reason: Optional[str] = None


# Data Access Request (DSAR) schemas
class DSARRequest(BaseModel):
    """Request schema for Data Subject Access Request."""
    export_format: str = Field(default="json", description="Export format: json, csv, xml")
    include_deleted: bool = Field(default=False, description="Include soft-deleted records")
    justification: Optional[str] = Field(None, max_length=1000, description="Justification for request")


class DSARStatusResponse(BaseModel):
    """Response schema for DSAR status."""
    request_id: str
    status: str
    requested_at: datetime
    expires_at: datetime
    download_ready: bool
    file_size_bytes: Optional[int] = None
    record_count: Optional[int] = None
    estimated_completion: Optional[datetime] = None


class DSARCreateResponse(BaseModel):
    """Response schema for DSAR creation."""
    request_id: str
    status: str
    estimated_completion: datetime
    expires_at: datetime
    message: str = "Data request has been created and is being processed"


class DSARDownloadResponse(BaseModel):
    """Response schema for DSAR download."""
    download_token: str
    expires_at: datetime
    file_size_bytes: Optional[int]
    filename: Optional[str]
    download_instructions: str = "Use the download_token to securely download your data"


# Data Deletion schemas
class DataDeletionRequest(BaseModel):
    """Request schema for data deletion."""
    deletion_reason: DeletionReason
    deletion_scope: DeletionScope = DeletionScope.FULL_DELETION
    justification: Optional[str] = Field(None, max_length=1000)
    scheduled_for: Optional[datetime] = None
    
    @validator('scheduled_for')
    def validate_scheduled_for(cls, v):
        if v and v < datetime.utcnow():
            raise ValueError("Scheduled deletion time must be in the future")
        return v


class DataDeletionResponse(BaseModel):
    """Response schema for data deletion."""
    deletion_request_id: str
    status: str
    executed_at: Optional[datetime] = None
    scheduled_for: Optional[datetime] = None
    deletion_result: Optional[Dict[str, Any]] = None
    message: str


class DeletionResultDetail(BaseModel):
    """Detailed deletion result."""
    user_id: int
    deletion_request_id: str
    deletion_scope: str
    deletion_reason: str
    started_at: datetime
    completed_at: Optional[datetime]
    success: bool
    deleted_records: Dict[str, int]
    anonymized_records: Dict[str, int]
    retained_records: Dict[str, int]
    errors: List[str]


# Data Portability schemas
class PortabilityRequest(BaseModel):
    """Request schema for data portability."""
    export_format: PortabilityFormat = PortabilityFormat.STRUCTURED_JSON
    data_categories: Optional[List[DataCategory]] = None
    include_metadata: bool = Field(default=True, description="Include technical metadata")
    include_system_data: bool = Field(default=False, description="Include system-generated data")
    
    @validator('data_categories')
    def validate_data_categories(cls, v):
        if v is not None and not v:
            raise ValueError("If specified, data_categories cannot be empty")
        return v


class PortabilityStatusResponse(BaseModel):
    """Response schema for portability status."""
    request_id: str
    status: str
    requested_at: datetime
    expires_at: datetime
    format: str
    data_categories: List[str]
    download_ready: bool
    file_size_bytes: Optional[int] = None
    record_count: Optional[int] = None


class PortabilityCreateResponse(BaseModel):
    """Response schema for portability creation."""
    request_id: str
    status: str
    estimated_completion: datetime
    expires_at: datetime
    data_categories: List[str]
    format: str
    message: str = "Data portability request has been created and is being processed"


class PortabilityDownloadResponse(BaseModel):
    """Response schema for portability download."""
    download_token: str
    expires_at: datetime
    file_size_bytes: Optional[int]
    filename: Optional[str]
    format: str
    download_instructions: str = "Use the download_token to securely download your portable data"


# Admin schemas
class GDPRDashboardResponse(BaseModel):
    """Response schema for GDPR compliance dashboard."""
    total_users: int
    active_consents: int
    pending_dsar_requests: int
    pending_deletion_requests: int
    recent_portability_requests: int
    compliance_score: float = Field(ge=0.0, le=100.0)
    last_updated: datetime


class ConsentStatistics(BaseModel):
    """Consent statistics for reporting."""
    consent_type: str
    total_grants: int
    total_withdrawals: int
    active_consents: int
    expired_consents: int
    conversion_rate: float = Field(ge=0.0, le=100.0)


class GDPRComplianceReport(BaseModel):
    """GDPR compliance report."""
    report_id: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    consent_statistics: List[ConsentStatistics]
    dsar_requests: int
    deletion_requests: int
    portability_requests: int
    average_response_time_hours: float
    compliance_incidents: int
    recommendations: List[str]


# Error schemas
class GDPRError(BaseModel):
    """GDPR-specific error response."""
    error_code: str
    error_type: str
    message: str
    details: Optional[Dict[str, Any]] = None
    user_guidance: Optional[str] = None
    legal_reference: Optional[str] = None


class ValidationError(BaseModel):
    """Validation error details."""
    field: str
    message: str
    rejected_value: Any


class GDPRValidationError(GDPRError):
    """GDPR validation error with field details."""
    validation_errors: List[ValidationError]


# Request context schemas
class RequestContext(BaseModel):
    """Context information for GDPR requests."""
    user_id: int
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# Audit schemas
class GDPRAuditLog(BaseModel, TimestampMixin):
    """GDPR audit log entry."""
    id: int
    event_type: str
    user_id: Optional[int]
    action: str
    description: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    ip_address: Optional[str]
    success: bool
    pii_accessed: bool
    gdpr_relevant: bool
    event_data: Optional[Dict[str, Any]]


class GDPRAuditQuery(BaseModel):
    """Query parameters for GDPR audit logs."""
    user_id: Optional[int] = None
    event_type: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    pii_accessed: Optional[bool] = None
    success: Optional[bool] = None


class GDPRAuditResponse(BaseModel):
    """Response schema for GDPR audit query."""
    audit_logs: List[GDPRAuditLog]
    pagination: PaginationResponse
    query_parameters: GDPRAuditQuery
    generated_at: datetime


# Utility schemas
class HealthCheckResponse(BaseModel):
    """Health check response for GDPR services."""
    service: str
    status: str
    timestamp: datetime
    version: str
    dependencies: Dict[str, str]
    gdpr_compliance_status: str


class ConfigurationResponse(BaseModel):
    """GDPR configuration response."""
    data_retention_days: int
    consent_expiry_days: int
    dsar_response_days: int
    deletion_grace_period_days: int
    portability_expiry_hours: int
    supported_export_formats: List[str]
    supported_consent_types: List[str]
    legal_basis_options: List[str]


# Response wrappers
class GDPRResponse(BaseModel):
    """Generic GDPR API response wrapper."""
    success: bool
    data: Optional[Any] = None
    error: Optional[GDPRError] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: Optional[str] = None


class PaginatedGDPRResponse(GDPRResponse):
    """Paginated GDPR API response."""
    pagination: Optional[PaginationResponse] = None


# Export these for use in API routes
__all__ = [
    # Base schemas
    'TimestampMixin',
    'PaginationRequest', 
    'PaginationResponse',
    
    # Consent schemas
    'ConsentVersionRequest',
    'ConsentVersionResponse',
    'ConsentGrantRequest',
    'ConsentWithdrawRequest',
    'ConsentBulkRequest',
    'UserConsentResponse',
    'ConsentHistoryResponse',
    'ConsentValidityResponse',
    
    # DSAR schemas
    'DSARRequest',
    'DSARStatusResponse',
    'DSARCreateResponse',
    'DSARDownloadResponse',
    
    # Deletion schemas
    'DataDeletionRequest',
    'DataDeletionResponse',
    'DeletionResultDetail',
    
    # Portability schemas
    'PortabilityRequest',
    'PortabilityStatusResponse',
    'PortabilityCreateResponse',
    'PortabilityDownloadResponse',
    
    # Admin schemas
    'GDPRDashboardResponse',
    'ConsentStatistics',
    'GDPRComplianceReport',
    
    # Error schemas
    'GDPRError',
    'ValidationError',
    'GDPRValidationError',
    
    # Context schemas
    'RequestContext',
    
    # Audit schemas
    'GDPRAuditLog',
    'GDPRAuditQuery',
    'GDPRAuditResponse',
    
    # Utility schemas
    'HealthCheckResponse',
    'ConfigurationResponse',
    
    # Response wrappers
    'GDPRResponse',
    'PaginatedGDPRResponse'
]