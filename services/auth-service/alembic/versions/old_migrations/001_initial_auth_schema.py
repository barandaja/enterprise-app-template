"""Initial auth service schema

Revision ID: 001
Revises: 
Create Date: 2024-01-01 00:00:00.000000

This migration creates the initial database schema for the enterprise
authentication service with full RBAC, session management, and audit logging.

Migration Details:
- Revision: 001
- Previous: None (initial migration)
- Created: 2024-01-01 00:00:00.000000

IMPORTANT NOTES:
1. This creates tables with encrypted PII fields using BYTEA columns
2. Audit logging table includes all compliance-required fields
3. Session management supports device tracking and security features
4. All tables include soft delete and timestamp functionality
5. Proper indexes are created for performance optimization
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Apply the initial database schema for the auth service.
    
    This creates all necessary tables for:
    - User management with RBAC
    - Session management
    - Audit logging for compliance
    - Field-level encryption for PII data
    
    All tables include:
    - Primary keys with auto-increment
    - Created/updated timestamps
    - Soft delete functionality
    - Appropriate indexes for performance
    """
    
    # Note: Using CHECK constraints instead of ENUM types to avoid SQLAlchemy conflicts
    # The constraints are added after table creation to ensure proper validation
    
    
    # Create permission table
    op.create_table(
        'permission',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('resource', 'action', name='uq_permission_resource_action')
    )
    
    # Create indexes for permission table
    op.create_index('idx_permission_name', 'permission', ['name'])
    op.create_index('idx_permission_resource', 'permission', ['resource'])
    op.create_index('idx_permission_action', 'permission', ['action'])
    op.create_index('idx_permission_resource_action', 'permission', ['resource', 'action'])
    
    # Create role table
    op.create_table(
        'role',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system_role', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # Create indexes for role table
    op.create_index('idx_role_name', 'role', ['name'])
    
    # Create user table with encrypted PII fields
    op.create_table(
        'user',
        sa.Column('id', sa.Integer(), nullable=False),
        # Encrypted PII fields using BYTEA
        sa.Column('email', postgresql.BYTEA(), nullable=False),
        sa.Column('first_name', postgresql.BYTEA(), nullable=True),
        sa.Column('last_name', postgresql.BYTEA(), nullable=True),
        sa.Column('phone_number', postgresql.BYTEA(), nullable=True),
        # Authentication fields
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, default=False),
        # Security tracking
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(length=45), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        # Account management
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('privacy_policy_accepted_at', sa.DateTime(timezone=True), nullable=True),
        # GDPR compliance
        sa.Column('data_processing_consent', sa.Boolean(), nullable=False, default=False),
        sa.Column('marketing_consent', sa.Boolean(), nullable=False, default=False),
        sa.Column('data_retention_until', sa.DateTime(timezone=True), nullable=True),
        # Additional encrypted metadata
        sa.Column('profile_data', postgresql.BYTEA(), nullable=True),
        sa.Column('preferences', postgresql.BYTEA(), nullable=True),
        # Standard fields
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for user table
    op.create_index('idx_user_email', 'user', ['email'])
    op.create_index('idx_user_active_verified', 'user', ['is_active', 'is_verified'])
    op.create_index('idx_user_last_login', 'user', ['last_login_at'])
    op.create_index('idx_user_created_at', 'user', ['created_at'])
    
    # Create role_permissions association table
    op.create_table(
        'role_permissions',
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('assigned_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['user.id']),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    
    # Create indexes for role_permissions table
    op.create_index('idx_role_permissions_role_id', 'role_permissions', ['role_id'])
    op.create_index('idx_role_permissions_permission_id', 'role_permissions', ['permission_id'])
    
    # Create user_roles association table
    op.create_table(
        'user_roles',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('assigned_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['user.id']),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # Create indexes for user_roles table
    op.create_index('idx_user_roles_user_id', 'user_roles', ['user_id'])
    op.create_index('idx_user_roles_role_id', 'user_roles', ['role_id'])
    
    # Create user session table
    op.create_table(
        'user_session',
        sa.Column('id', sa.Integer(), nullable=False),
        # Session identification
        sa.Column('session_id', sa.String(length=128), nullable=False),
        sa.Column('refresh_token_id', sa.String(length=128), nullable=True),
        # User association
        sa.Column('user_id', sa.Integer(), nullable=False),
        # Session metadata (encrypted)
        sa.Column('device_info', postgresql.BYTEA(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('location_data', postgresql.BYTEA(), nullable=True),
        # Session lifecycle
        sa.Column('started_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        # Session state
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_mobile', sa.Boolean(), nullable=False, default=False),
        sa.Column('is_trusted_device', sa.Boolean(), nullable=False, default=False),
        # Security flags
        sa.Column('requires_mfa', sa.Boolean(), nullable=False, default=False),
        sa.Column('mfa_completed', sa.Boolean(), nullable=False, default=False),
        sa.Column('suspicious_activity', sa.Boolean(), nullable=False, default=False),
        # Additional session data (encrypted)
        sa.Column('session_data', postgresql.BYTEA(), nullable=True),
        # Standard fields
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('session_id'),
        sa.UniqueConstraint('refresh_token_id')
    )
    
    # Create indexes for user_session table
    op.create_index('idx_session_session_id', 'user_session', ['session_id'])
    op.create_index('idx_session_refresh_token_id', 'user_session', ['refresh_token_id'])
    op.create_index('idx_session_user_id', 'user_session', ['user_id'])
    op.create_index('idx_session_active', 'user_session', ['is_active'])
    op.create_index('idx_session_expires', 'user_session', ['expires_at'])
    op.create_index('idx_session_last_activity', 'user_session', ['last_activity_at'])
    
    # Create audit log table
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        # Event identification
        sa.Column('event_type', sa.Text(), nullable=False),
        sa.Column('event_id', sa.String(length=128), nullable=False),
        sa.Column('correlation_id', sa.String(length=128), nullable=True),
        # Event metadata
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('severity', sa.Text(), nullable=False, default='LOW'),
        # User and session context
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('session_id', sa.String(length=128), nullable=True),
        sa.Column('impersonator_user_id', sa.Integer(), nullable=True),
        # Request context
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('request_method', sa.String(length=10), nullable=True),
        sa.Column('request_path', sa.String(length=500), nullable=True),
        sa.Column('request_id', sa.String(length=128), nullable=True),
        # Resource information
        sa.Column('resource_type', sa.String(length=100), nullable=True),
        sa.Column('resource_id', sa.String(length=100), nullable=True),
        sa.Column('resource_name', sa.String(length=255), nullable=True),
        # Event details
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('event_data', postgresql.BYTEA(), nullable=True),  # Encrypted
        # Result information
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('error_code', sa.String(length=50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        # Compliance flags
        sa.Column('pii_accessed', sa.Boolean(), nullable=False, default=False),
        sa.Column('gdpr_relevant', sa.Boolean(), nullable=False, default=False),
        sa.Column('hipaa_relevant', sa.Boolean(), nullable=False, default=False),
        # Technical details
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        # Standard fields
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.ForeignKeyConstraint(['impersonator_user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('event_id')
    )
    
    # Create indexes for audit_log table
    op.create_index('idx_audit_event_type', 'audit_log', ['event_type'])
    op.create_index('idx_audit_timestamp', 'audit_log', ['timestamp'])
    op.create_index('idx_audit_user_id', 'audit_log', ['user_id'])
    op.create_index('idx_audit_session_id', 'audit_log', ['session_id'])
    op.create_index('idx_audit_ip_address', 'audit_log', ['ip_address'])
    op.create_index('idx_audit_resource_type', 'audit_log', ['resource_type'])
    op.create_index('idx_audit_resource_id', 'audit_log', ['resource_id'])
    op.create_index('idx_audit_user_timestamp', 'audit_log', ['user_id', 'timestamp'])
    op.create_index('idx_audit_event_timestamp', 'audit_log', ['event_type', 'timestamp'])
    op.create_index('idx_audit_resource', 'audit_log', ['resource_type', 'resource_id'])
    op.create_index('idx_audit_compliance', 'audit_log', ['gdpr_relevant', 'hipaa_relevant'])
    op.create_index('idx_audit_security', 'audit_log', ['severity', 'success'])
    
    # Create additional tables for role/permission metadata (if needed)
    op.create_table(
        'user_role',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('assigned_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['user.id']),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Add constraints to enforce enum values
    op.execute("""
        ALTER TABLE audit_log 
        ADD CONSTRAINT audit_log_event_type_check 
        CHECK (event_type IN (
            'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT', 'PASSWORD_CHANGE', 'PASSWORD_RESET',
            'ACCOUNT_LOCKED', 'ACCOUNT_UNLOCKED', 'PERMISSION_GRANTED', 'PERMISSION_DENIED',
            'ROLE_ASSIGNED', 'ROLE_REMOVED', 'DATA_READ', 'DATA_CREATE', 'DATA_UPDATE',
            'DATA_DELETE', 'DATA_EXPORT', 'USER_CREATED', 'USER_UPDATED', 'USER_DELETED',
            'USER_ACTIVATED', 'USER_DEACTIVATED', 'SYSTEM_START', 'SYSTEM_STOP',
            'CONFIG_CHANGE', 'BACKUP_CREATED', 'SECURITY_ALERT', 'SUSPICIOUS_ACTIVITY',
            'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED_ACCESS', 'GDPR_DATA_REQUEST',
            'GDPR_DATA_DELETE', 'HIPAA_ACCESS', 'SOC2_CONTROL_CHECK'
        ))
    """)
    
    op.execute("""
        ALTER TABLE audit_log 
        ADD CONSTRAINT audit_log_severity_check 
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
    """)

    op.create_table(
        'role_permission',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('permission_id', sa.Integer(), nullable=False),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('granted_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, default=False),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['permission_id'], ['permission.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['granted_by'], ['user.id']),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """
    Revert the initial database schema.
    
    WARNING: This will drop all tables and data!
    This should only be used in development environments.
    
    The downgrade removes all tables in reverse dependency order:
    1. Association tables and dependent tables
    2. Main entity tables
    3. Enum types
    """
    # Drop tables in reverse dependency order
    op.drop_table('role_permission')
    op.drop_table('user_role')
    op.drop_table('audit_log')
    op.drop_table('user_session')
    op.drop_table('user_roles')
    op.drop_table('role_permissions')
    op.drop_table('user')
    op.drop_table('role')
    op.drop_table('permission')
    
    # Note: Check constraints are automatically dropped with the tables