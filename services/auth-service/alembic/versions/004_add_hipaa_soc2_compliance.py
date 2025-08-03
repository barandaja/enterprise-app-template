"""Add HIPAA and SOC2 compliance tables

Revision ID: 004_add_hipaa_soc2_compliance
Revises: 003
Create Date: 2025-08-01 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision = '004_add_hipaa_soc2_compliance'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add HIPAA and SOC2 compliance tables."""
    
    # Create enum types for PostgreSQL (with checkfirst=True for idempotency)
    phicategory_enum = sa.Enum(
        'demographic', 'financial', 'medical_record_number', 'health_plan_number',
        'biometric', 'photo', 'contact', 'device_identifier', 'web_url',
        'ip_address', 'medical_data', 'insurance', 'other',
        name='phicategory'
    )
    phicategory_enum.create(op.get_bind(), checkfirst=True)
    
    accesspurpose_enum = sa.Enum(
        'treatment', 'payment', 'operations', 'research', 'public_health',
        'emergency', 'legal', 'audit', 'administrative', 'minimum_necessary',
        name='accesspurpose'
    )
    accesspurpose_enum.create(op.get_bind(), checkfirst=True)
    
    baaagreementstatus_enum = sa.Enum(
        'active', 'pending', 'expired', 'terminated', 'suspended', 'under_review',
        name='baaagreementstatus'
    )
    baaagreementstatus_enum.create(op.get_bind(), checkfirst=True)
    
    emergencyaccesstype_enum = sa.Enum(
        'break_glass', 'life_threatening', 'clinical_emergency', 'system_outage',
        'disaster_recovery', 'security_incident',
        name='emergencyaccesstype'
    )
    emergencyaccesstype_enum.create(op.get_bind(), checkfirst=True)
    
    incidentcategory_enum = sa.Enum(
        'security_breach', 'unauthorized_access', 'system_outage', 'data_loss',
        'malware', 'phishing', 'policy_violation', 'vulnerability',
        'performance', 'compliance', 'other',
        name='incidentcategory'
    )
    incidentcategory_enum.create(op.get_bind(), checkfirst=True)
    
    incidentseverity_enum = sa.Enum(
        'low', 'medium', 'high', 'critical',
        name='incidentseverity'
    )
    incidentseverity_enum.create(op.get_bind(), checkfirst=True)
    
    incidentstatus_enum = sa.Enum(
        'open', 'in_progress', 'escalated', 'resolved', 'closed', 'reopened',
        name='incidentstatus'
    )
    incidentstatus_enum.create(op.get_bind(), checkfirst=True)
    
    anomalytype_enum = sa.Enum(
        'login_anomaly', 'access_pattern', 'data_volume', 'time_pattern',
        'location_anomaly', 'permission_escalation', 'failed_attempts',
        'resource_usage', 'network_traffic', 'system_behavior',
        name='anomalytype'
    )
    anomalytype_enum.create(op.get_bind(), checkfirst=True)
    
    vendoraccesslevel_enum = sa.Enum(
        'no_access', 'limited', 'standard', 'elevated', 'full_admin',
        name='vendoraccesslevel'
    )
    vendoraccesslevel_enum.create(op.get_bind(), checkfirst=True)
    
    changetype_enum = sa.Enum(
        'standard', 'normal', 'emergency', 'configuration', 'access_control',
        'security_policy', 'system_update', 'user_management', 'role_permission',
        'data_schema',
        name='changetype'
    )
    changetype_enum.create(op.get_bind(), checkfirst=True)
    
    changestatus_enum = sa.Enum(
        'requested', 'approved', 'rejected', 'in_progress', 'completed',
        'failed', 'rolled_back', 'under_review',
        name='changestatus'
    )
    changestatus_enum.create(op.get_bind(), checkfirst=True)
    
    trustservicecriteria_enum = sa.Enum(
        'security', 'availability', 'processing_integrity', 'confidentiality', 'privacy',
        name='trustservicecriteria'
    )
    trustservicecriteria_enum.create(op.get_bind(), checkfirst=True)
    
    # Create HIPAA compliance tables
    
    # PHI Access Log table
    op.create_table(
        'phi_access_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Access identification
        sa.Column('access_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
        sa.Column('session_id', sa.String(128), nullable=True, index=True),
        
        # PHI details
        sa.Column('phi_category', phicategory_enum, nullable=False, index=True),
        sa.Column('resource_type', sa.String(100), nullable=False, index=True),
        sa.Column('resource_id', sa.String(100), nullable=False, index=True),
        sa.Column('resource_description', sa.Text(), nullable=True),
        
        # Access details
        sa.Column('access_timestamp', sa.DateTime(timezone=True), 
                 server_default=sa.text('now()'), nullable=False, index=True),
        sa.Column('access_purpose', accesspurpose_enum, nullable=False, index=True),
        sa.Column('access_method', sa.String(50), nullable=False),
        sa.Column('action_performed', sa.String(50), nullable=False, index=True),
        
        # Justification and authorization
        sa.Column('access_justification', sa.Text(), nullable=False),
        sa.Column('minimum_necessary_applied', sa.Boolean(), nullable=False, default=True),
        sa.Column('authorization_id', sa.String(128), nullable=True),
        
        # Request context
        sa.Column('ip_address', sa.String(45), nullable=True, index=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_headers', sa.Text(), nullable=True),  # Encrypted JSON
        
        # Data accessed
        sa.Column('phi_fields_accessed', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('data_volume', sa.Integer(), nullable=True),
        
        # Patient information
        sa.Column('patient_id', sa.String(100), nullable=True, index=True),
        sa.Column('patient_mrn', sa.Text(), nullable=True),  # Encrypted
        
        # System information
        sa.Column('application_name', sa.String(100), nullable=True),
        sa.Column('module_name', sa.String(100), nullable=True),
        
        # Result and errors
        sa.Column('access_successful', sa.Boolean(), nullable=False, index=True),
        sa.Column('error_code', sa.String(50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        
        # Audit trail
        sa.Column('created_by_system', sa.String(100), nullable=False, default='auth-service'),
        sa.Column('correlation_id', sa.String(128), nullable=True, index=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for PHI access log
    op.create_index('idx_phi_access_user_timestamp', 'phi_access_log', 
                   ['user_id', 'access_timestamp'])
    op.create_index('idx_phi_access_resource', 'phi_access_log', 
                   ['resource_type', 'resource_id'])
    op.create_index('idx_phi_access_patient', 'phi_access_log', 
                   ['patient_id', 'access_timestamp'])
    op.create_index('idx_phi_access_purpose', 'phi_access_log', 
                   ['access_purpose', 'access_timestamp'])
    op.create_index('idx_phi_access_category', 'phi_access_log', 
                   ['phi_category', 'access_timestamp'])
    
    # Business Associate Agreement table
    op.create_table(
        'business_associate_agreement',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Agreement identification
        sa.Column('agreement_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('agreement_number', sa.String(100), nullable=True, index=True),
        
        # Business Associate information
        sa.Column('business_associate_name', sa.String(255), nullable=False, index=True),
        sa.Column('business_associate_contact', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('business_associate_type', sa.String(100), nullable=False),
        
        # Agreement details
        sa.Column('agreement_title', sa.String(255), nullable=False),
        sa.Column('agreement_description', sa.Text(), nullable=True),
        sa.Column('covered_services', postgresql.JSON(), nullable=False),
        sa.Column('phi_categories_covered', postgresql.JSON(), nullable=False),
        
        # Dates and status
        sa.Column('effective_date', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('expiration_date', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('termination_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', baaagreementstatus_enum, nullable=False, default='active', index=True),
        
        # Compliance requirements
        sa.Column('security_requirements', postgresql.JSON(), nullable=True),
        sa.Column('audit_requirements', postgresql.JSON(), nullable=True),
        sa.Column('data_return_requirements', sa.Text(), nullable=True),
        
        # Incident response
        sa.Column('incident_notification_timeframe', sa.Integer(), nullable=True),
        sa.Column('breach_notification_procedure', sa.Text(), nullable=True),
        
        # Management information
        sa.Column('signed_by_covered_entity', sa.String(255), nullable=True),
        sa.Column('signed_by_business_associate', sa.String(255), nullable=True),
        sa.Column('signed_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approved_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        
        # Document management
        sa.Column('agreement_document_path', sa.Text(), nullable=True),  # Encrypted
        sa.Column('additional_documents', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for BAA
    op.create_index('idx_baa_status_expiration', 'business_associate_agreement', 
                   ['status', 'expiration_date'])
    op.create_index('idx_baa_business_associate', 'business_associate_agreement', 
                   ['business_associate_name'])
    op.create_index('idx_baa_effective_dates', 'business_associate_agreement', 
                   ['effective_date', 'expiration_date'])
    
    # Emergency Access table
    op.create_table(
        'emergency_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Emergency access identification
        sa.Column('emergency_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
        sa.Column('session_id', sa.String(128), nullable=True, index=True),
        
        # Emergency details
        sa.Column('emergency_type', emergencyaccesstype_enum, nullable=False, index=True),
        sa.Column('emergency_justification', sa.Text(), nullable=False),
        sa.Column('emergency_start_time', sa.DateTime(timezone=True), 
                 server_default=sa.text('now()'), nullable=False, index=True),
        sa.Column('emergency_end_time', sa.DateTime(timezone=True), nullable=True),
        
        # Authorization and approval
        sa.Column('authorized_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('authorization_code', sa.String(128), nullable=True),
        sa.Column('approval_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approved_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        
        # Patient and resource information
        sa.Column('patient_id', sa.String(100), nullable=True, index=True),
        sa.Column('patient_mrn', sa.Text(), nullable=True),  # Encrypted
        sa.Column('affected_resources', postgresql.JSON(), nullable=True),
        
        # Context information
        sa.Column('location', sa.String(255), nullable=True),
        sa.Column('department', sa.String(100), nullable=True),
        sa.Column('clinical_context', sa.Text(), nullable=True),
        
        # System information
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('access_method', sa.String(50), nullable=False, default='web'),
        
        # Status tracking
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True, index=True),
        sa.Column('terminated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('terminated_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('termination_reason', sa.Text(), nullable=True),
        
        # Audit and review
        sa.Column('review_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reviewed_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        
        # Additional metadata
        sa.Column('emergency_metadata', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for emergency access
    op.create_index('idx_emergency_access_user_time', 'emergency_access', 
                   ['user_id', 'emergency_start_time'])
    op.create_index('idx_emergency_access_type', 'emergency_access', 
                   ['emergency_type', 'emergency_start_time'])
    op.create_index('idx_emergency_access_patient', 'emergency_access', 
                   ['patient_id', 'emergency_start_time'])
    op.create_index('idx_emergency_access_active', 'emergency_access', 
                   ['is_active', 'emergency_start_time'])
    
    # HIPAA Session Context table
    op.create_table(
        'hipaa_session_context',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Session identification
        sa.Column('session_id', sa.String(128), sa.ForeignKey('user_session.session_id'), 
                 nullable=False, unique=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False, index=True),
        
        # HIPAA-specific context
        sa.Column('phi_access_level', sa.String(50), nullable=False, default='none'),
        sa.Column('current_patient_context', sa.String(100), nullable=True, index=True),
        sa.Column('department_context', sa.String(100), nullable=True),
        sa.Column('role_context', sa.String(100), nullable=True),
        
        # Timeout management
        sa.Column('last_phi_access', sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column('phi_session_timeout_minutes', sa.Integer(), nullable=False, default=15),
        sa.Column('warning_issued_at', sa.DateTime(timezone=True), nullable=True),
        
        # Emergency access
        sa.Column('emergency_access_active', sa.Boolean(), nullable=False, default=False),
        sa.Column('emergency_access_id', sa.String(128), 
                 sa.ForeignKey('emergency_access.emergency_id'), nullable=True),
        
        # Audit context
        sa.Column('access_justification_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('minimum_necessary_enforced', sa.Boolean(), nullable=False, default=True),
        
        # Session metadata
        sa.Column('session_metadata', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for HIPAA session context
    op.create_index('idx_hipaa_session_user', 'hipaa_session_context', ['user_id'])
    op.create_index('idx_hipaa_session_patient', 'hipaa_session_context', 
                   ['current_patient_context'])
    op.create_index('idx_hipaa_session_phi_access', 'hipaa_session_context', 
                   ['last_phi_access'])
    
    # Create SOC2 compliance tables
    
    # Security Incident table
    op.create_table(
        'security_incident',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Incident identification
        sa.Column('incident_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('incident_number', sa.String(50), nullable=False, unique=True, index=True),
        
        # Incident classification
        sa.Column('category', incidentcategory_enum, nullable=False, index=True),
        sa.Column('severity', incidentseverity_enum, nullable=False, index=True),
        sa.Column('trust_criteria_affected', postgresql.JSON(), nullable=False),
        
        # Incident details
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        
        # Timeline
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('reported_at', sa.DateTime(timezone=True), 
                 server_default=sa.text('now()'), nullable=False),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        
        # Status tracking
        sa.Column('status', incidentstatus_enum, nullable=False, default='open', index=True),
        
        # Impact assessment
        sa.Column('systems_affected', postgresql.JSON(), nullable=True),
        sa.Column('users_affected_count', sa.Integer(), nullable=True),
        sa.Column('data_affected', sa.Boolean(), nullable=False, default=False),
        sa.Column('customer_impact', sa.Boolean(), nullable=False, default=False),
        
        # Response team
        sa.Column('reported_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('assigned_to_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('incident_commander_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        
        # Root cause and resolution
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('resolution_summary', sa.Text(), nullable=True),
        sa.Column('corrective_actions', postgresql.JSON(), nullable=True),
        
        # External reporting
        sa.Column('external_reporting_required', sa.Boolean(), nullable=False, default=False),
        sa.Column('regulatory_notification_sent', sa.Boolean(), nullable=False, default=False),
        sa.Column('customer_notification_sent', sa.Boolean(), nullable=False, default=False),
        
        # Evidence and documentation
        sa.Column('evidence_collected', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('incident_notes', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for security incidents
    op.create_index('idx_incident_category_severity', 'security_incident', 
                   ['category', 'severity'])
    op.create_index('idx_incident_status_detected', 'security_incident', 
                   ['status', 'detected_at'])
    op.create_index('idx_incident_assigned', 'security_incident', 
                   ['assigned_to_user_id', 'status'])
    
    # Security Anomaly table
    op.create_table(
        'security_anomaly',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Anomaly identification
        sa.Column('anomaly_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('anomaly_type', anomalytype_enum, nullable=False, index=True),
        
        # Detection details
        sa.Column('detected_at', sa.DateTime(timezone=True), 
                 server_default=sa.text('now()'), nullable=False, index=True),
        sa.Column('detection_source', sa.String(100), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        
        # Subject information
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True, index=True),
        sa.Column('session_id', sa.String(128), nullable=True, index=True),
        sa.Column('ip_address', sa.String(45), nullable=True, index=True),
        
        # Anomaly details
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('baseline_behavior', postgresql.JSON(), nullable=True),
        sa.Column('anomalous_behavior', postgresql.JSON(), nullable=False),
        
        # Risk assessment
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('potential_impact', sa.String(100), nullable=False),
        
        # Response status
        sa.Column('investigated', sa.Boolean(), nullable=False, default=False),
        sa.Column('false_positive', sa.Boolean(), nullable=False, default=False),
        sa.Column('incident_created', sa.Boolean(), nullable=False, default=False),
        sa.Column('security_incident_id', sa.String(128), 
                 sa.ForeignKey('security_incident.incident_id'), nullable=True),
        
        # Investigation details
        sa.Column('investigated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('investigated_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('investigation_notes', sa.Text(), nullable=True),
        
        # Raw data
        sa.Column('raw_event_data', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for security anomalies
    op.create_index('idx_anomaly_type_detected', 'security_anomaly', 
                   ['anomaly_type', 'detected_at'])
    op.create_index('idx_anomaly_user_detected', 'security_anomaly', 
                   ['user_id', 'detected_at'])
    op.create_index('idx_anomaly_risk_score', 'security_anomaly', ['risk_score'])
    op.create_index('idx_anomaly_investigation', 'security_anomaly', 
                   ['investigated', 'detected_at'])
    
    # Vendor Access table
    op.create_table(
        'vendor_access',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Access identification
        sa.Column('access_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('vendor_name', sa.String(255), nullable=False, index=True),
        sa.Column('vendor_contact_email', sa.Text(), nullable=False),  # Encrypted
        
        # Access details
        sa.Column('access_level', vendoraccesslevel_enum, nullable=False, index=True),
        sa.Column('systems_accessed', postgresql.JSON(), nullable=False),
        sa.Column('access_purpose', sa.Text(), nullable=False),
        sa.Column('business_justification', sa.Text(), nullable=False),
        
        # Time constraints
        sa.Column('access_start_date', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('access_end_date', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('last_accessed', sa.DateTime(timezone=True), nullable=True),
        
        # Approval workflow
        sa.Column('requested_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
        sa.Column('approved_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        
        # Status tracking
        sa.Column('is_active', sa.Boolean(), nullable=False, default=False, index=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False, default=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('revocation_reason', sa.Text(), nullable=True),
        
        # Security requirements
        sa.Column('mfa_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('vpn_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('ip_restrictions', postgresql.JSON(), nullable=True),
        
        # Monitoring and compliance
        sa.Column('activity_monitored', sa.Boolean(), nullable=False, default=True),
        sa.Column('data_access_logged', sa.Boolean(), nullable=False, default=True),
        sa.Column('compliance_reviewed', sa.Boolean(), nullable=False, default=False),
        
        # Additional metadata
        sa.Column('vendor_metadata', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('access_credentials', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for vendor access
    op.create_index('idx_vendor_access_dates', 'vendor_access', 
                   ['access_start_date', 'access_end_date'])
    op.create_index('idx_vendor_access_status', 'vendor_access', 
                   ['is_active', 'is_revoked'])
    op.create_index('idx_vendor_access_level', 'vendor_access', 
                   ['access_level', 'is_active'])
    
    # Change Management table
    op.create_table(
        'change_management',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Change identification
        sa.Column('change_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('change_number', sa.String(50), nullable=False, unique=True, index=True),
        
        # Change classification
        sa.Column('change_type', changetype_enum, nullable=False, index=True),
        sa.Column('risk_level', sa.String(20), nullable=False, default='medium'),
        
        # Change details
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('business_justification', sa.Text(), nullable=False),
        
        # Systems and impact
        sa.Column('systems_affected', postgresql.JSON(), nullable=False),
        sa.Column('trust_criteria_impact', postgresql.JSON(), nullable=False),
        sa.Column('estimated_downtime_minutes', sa.Integer(), nullable=True),
        
        # Timing
        sa.Column('requested_implementation_date', sa.DateTime(timezone=True), nullable=False),
        sa.Column('actual_implementation_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completion_date', sa.DateTime(timezone=True), nullable=True),
        
        # Status tracking
        sa.Column('status', changestatus_enum, nullable=False, default='requested', index=True),
        
        # Personnel
        sa.Column('requested_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=False),
        sa.Column('approved_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('implemented_by_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        
        # Review and approval
        sa.Column('approval_required', sa.Boolean(), nullable=False, default=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        
        # Implementation details
        sa.Column('implementation_steps', postgresql.JSON(), nullable=False),
        sa.Column('rollback_plan', sa.Text(), nullable=False),
        sa.Column('testing_plan', sa.Text(), nullable=True),
        
        # Results and verification
        sa.Column('implementation_successful', sa.Boolean(), nullable=True),
        sa.Column('verification_completed', sa.Boolean(), nullable=False, default=False),
        sa.Column('verification_notes', sa.Text(), nullable=True),
        
        # Documentation
        sa.Column('change_documentation', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('implementation_log', sa.Text(), nullable=True),  # Encrypted JSON
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for change management
    op.create_index('idx_change_type_status', 'change_management', 
                   ['change_type', 'status'])
    op.create_index('idx_change_implementation_date', 'change_management', 
                   ['requested_implementation_date'])
    op.create_index('idx_change_risk_level', 'change_management', 
                   ['risk_level', 'status'])
    
    # Compliance Control table
    op.create_table(
        'compliance_control',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        
        # Control identification
        sa.Column('control_id', sa.String(128), nullable=False, unique=True, index=True),
        sa.Column('control_number', sa.String(50), nullable=False, unique=True, index=True),
        
        # Control classification
        sa.Column('trust_criteria', trustservicecriteria_enum, nullable=False, index=True),
        sa.Column('control_category', sa.String(100), nullable=False, index=True),
        
        # Control details
        sa.Column('control_title', sa.String(255), nullable=False),
        sa.Column('control_description', sa.Text(), nullable=False),
        sa.Column('control_objective', sa.Text(), nullable=False),
        
        # Implementation
        sa.Column('is_implemented', sa.Boolean(), nullable=False, default=False),
        sa.Column('implementation_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('implementation_status', sa.String(50), nullable=False, default='not_started'),
        
        # Testing and monitoring
        sa.Column('testing_frequency', sa.String(50), nullable=False),
        sa.Column('last_tested_date', sa.DateTime(timezone=True), nullable=True, index=True),
        sa.Column('next_test_due_date', sa.DateTime(timezone=True), nullable=True, index=True),
        
        # Effectiveness
        sa.Column('is_effective', sa.Boolean(), nullable=True),
        sa.Column('effectiveness_rating', sa.String(20), nullable=True),
        sa.Column('deficiency_identified', sa.Boolean(), nullable=False, default=False),
        
        # Ownership and responsibility
        sa.Column('control_owner_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        sa.Column('reviewer_user_id', sa.Integer(), sa.ForeignKey('user.id'), nullable=True),
        
        # Documentation
        sa.Column('control_procedures', sa.Text(), nullable=True),  # Encrypted JSON
        sa.Column('evidence_requirements', postgresql.JSON(), nullable=True),
        sa.Column('testing_procedures', postgresql.JSON(), nullable=True),
        
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for compliance controls
    op.create_index('idx_control_criteria', 'compliance_control', 
                   ['trust_criteria', 'is_implemented'])
    op.create_index('idx_control_testing', 'compliance_control', 
                   ['next_test_due_date', 'is_implemented'])
    op.create_index('idx_control_effectiveness', 'compliance_control', 
                   ['is_effective', 'deficiency_identified'])
    
    # Update existing audit_log table to include new compliance flags
    op.add_column('audit_log', sa.Column('soc2_relevant', sa.Boolean(), nullable=False, default=False))
    op.create_index('idx_audit_soc2_relevant', 'audit_log', ['soc2_relevant'])
    op.create_index('idx_audit_compliance_all', 'audit_log', 
                   ['gdpr_relevant', 'hipaa_relevant', 'soc2_relevant'])


def downgrade() -> None:
    """Remove HIPAA and SOC2 compliance tables."""
    
    # Drop indexes first
    op.drop_index('idx_audit_compliance_all', table_name='audit_log')
    op.drop_index('idx_audit_soc2_relevant', table_name='audit_log')
    
    # Drop added column
    op.drop_column('audit_log', 'soc2_relevant')
    
    # Drop compliance control table and indexes
    op.drop_index('idx_control_effectiveness', table_name='compliance_control')
    op.drop_index('idx_control_testing', table_name='compliance_control')
    op.drop_index('idx_control_criteria', table_name='compliance_control')
    op.drop_table('compliance_control')
    
    # Drop change management table and indexes
    op.drop_index('idx_change_risk_level', table_name='change_management')
    op.drop_index('idx_change_implementation_date', table_name='change_management')
    op.drop_index('idx_change_type_status', table_name='change_management')
    op.drop_table('change_management')
    
    # Drop vendor access table and indexes
    op.drop_index('idx_vendor_access_level', table_name='vendor_access')
    op.drop_index('idx_vendor_access_status', table_name='vendor_access')
    op.drop_index('idx_vendor_access_dates', table_name='vendor_access')
    op.drop_table('vendor_access')
    
    # Drop security anomaly table and indexes
    op.drop_index('idx_anomaly_investigation', table_name='security_anomaly')
    op.drop_index('idx_anomaly_risk_score', table_name='security_anomaly')
    op.drop_index('idx_anomaly_user_detected', table_name='security_anomaly')
    op.drop_index('idx_anomaly_type_detected', table_name='security_anomaly')
    op.drop_table('security_anomaly')
    
    # Drop security incident table and indexes
    op.drop_index('idx_incident_assigned', table_name='security_incident')
    op.drop_index('idx_incident_status_detected', table_name='security_incident')
    op.drop_index('idx_incident_category_severity', table_name='security_incident')
    op.drop_table('security_incident')
    
    # Drop HIPAA session context table and indexes
    op.drop_index('idx_hipaa_session_phi_access', table_name='hipaa_session_context')
    op.drop_index('idx_hipaa_session_patient', table_name='hipaa_session_context')
    op.drop_index('idx_hipaa_session_user', table_name='hipaa_session_context')
    op.drop_table('hipaa_session_context')
    
    # Drop emergency access table and indexes
    op.drop_index('idx_emergency_access_active', table_name='emergency_access')
    op.drop_index('idx_emergency_access_patient', table_name='emergency_access')
    op.drop_index('idx_emergency_access_type', table_name='emergency_access')
    op.drop_index('idx_emergency_access_user_time', table_name='emergency_access')
    op.drop_table('emergency_access')
    
    # Drop BAA table and indexes
    op.drop_index('idx_baa_effective_dates', table_name='business_associate_agreement')
    op.drop_index('idx_baa_business_associate', table_name='business_associate_agreement')
    op.drop_index('idx_baa_status_expiration', table_name='business_associate_agreement')
    op.drop_table('business_associate_agreement')
    
    # Drop PHI access log table and indexes
    op.drop_index('idx_phi_access_category', table_name='phi_access_log')
    op.drop_index('idx_phi_access_purpose', table_name='phi_access_log')
    op.drop_index('idx_phi_access_patient', table_name='phi_access_log')
    op.drop_index('idx_phi_access_resource', table_name='phi_access_log')
    op.drop_index('idx_phi_access_user_timestamp', table_name='phi_access_log')
    op.drop_table('phi_access_log')
    
    # Drop enum types (with checkfirst=True for idempotency)
    sa.Enum(name='trustservicecriteria').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='changestatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='changetype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='vendoraccesslevel').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='anomalytype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='incidentstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='incidentseverity').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='incidentcategory').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='emergencyaccesstype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='baaagreementstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='accesspurpose').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='phicategory').drop(op.get_bind(), checkfirst=True)