"""Create ENUM types for audit_log table

Revision ID: 005_create_enum_types
Revises: 004_add_hipaa_soc2_compliance
Create Date: 2025-08-04 12:00:00.000000

This migration fixes the ENUM type mismatch issue by:
1. Creating PostgreSQL ENUM types for auditeventtype and auditseverity
2. Dropping existing CHECK constraints on audit_log table
3. Converting event_type and severity columns to use the ENUM types

This is critical for authentication to work properly as the application
models expect PostgreSQL ENUM types, not CHECK constraints.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic
revision = '005_create_enum_types'
down_revision = '004_add_hipaa_soc2_compliance'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create PostgreSQL ENUM types and convert audit_log columns."""
    
    # Create the auditeventtype ENUM type
    auditeventtype_enum = postgresql.ENUM(
        'login_success', 'login_failure', 'logout', 'password_change', 'password_reset',
        'account_locked', 'account_unlocked', 'permission_granted', 'permission_denied',
        'role_assigned', 'role_removed', 'data_read', 'data_create', 'data_update',
        'data_delete', 'data_export', 'user_created', 'user_updated', 'user_deleted',
        'user_activated', 'user_deactivated', 'system_start', 'system_stop',
        'config_change', 'backup_created', 'security_alert', 'suspicious_activity',
        'rate_limit_exceeded', 'unauthorized_access', 'token_created', 'token_refreshed',
        'session_created', 'session_ended', 'gdpr_data_request',
        'gdpr_data_delete', 'hipaa_access', 'soc2_control_check',
        name='auditeventtype'
    )
    auditeventtype_enum.create(op.get_bind(), checkfirst=True)
    
    # Create the auditseverity ENUM type
    auditseverity_enum = postgresql.ENUM(
        'low', 'medium', 'high', 'critical',
        name='auditseverity'
    )
    auditseverity_enum.create(op.get_bind(), checkfirst=True)
    
    # Drop existing CHECK constraints
    op.drop_constraint('audit_log_event_type_check', 'audit_log', type_='check')
    op.drop_constraint('audit_log_severity_check', 'audit_log', type_='check')
    
    # Convert existing values to lowercase to match ENUM values
    # First, update the data to use lowercase values
    op.execute("""
        UPDATE audit_log SET event_type = LOWER(event_type);
    """)
    
    op.execute("""
        UPDATE audit_log SET severity = LOWER(severity);
    """)
    
    # Convert the event_type column to use the ENUM type
    # We need to do this in steps: alter column type
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN event_type TYPE auditeventtype 
        USING event_type::auditeventtype;
    """)
    
    # Convert the severity column to use the ENUM type
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN severity TYPE auditseverity 
        USING severity::auditseverity;
    """)
    
    # Set default value for severity column
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN severity SET DEFAULT 'low'::auditseverity;
    """)


def downgrade() -> None:
    """Revert audit_log columns back to TEXT with CHECK constraints."""
    
    # Convert columns back to TEXT
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN event_type TYPE TEXT;
    """)
    
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN severity TYPE TEXT;
    """)
    
    # Set default value for severity column
    op.execute("""
        ALTER TABLE audit_log 
        ALTER COLUMN severity SET DEFAULT 'LOW';
    """)
    
    # Convert data back to uppercase
    op.execute("""
        UPDATE audit_log SET event_type = UPPER(event_type);
    """)
    
    op.execute("""
        UPDATE audit_log SET severity = UPPER(severity);
    """)
    
    # Recreate the CHECK constraints
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
            'RATE_LIMIT_EXCEEDED', 'UNAUTHORIZED_ACCESS', 'TOKEN_CREATED', 'TOKEN_REFRESHED',
            'SESSION_CREATED', 'SESSION_ENDED', 'GDPR_DATA_REQUEST',
            'GDPR_DATA_DELETE', 'HIPAA_ACCESS', 'SOC2_CONTROL_CHECK'
        ))
    """)
    
    op.execute("""
        ALTER TABLE audit_log 
        ADD CONSTRAINT audit_log_severity_check 
        CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'))
    """)
    
    # Drop the ENUM types
    postgresql.ENUM(name='auditseverity').drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name='auditeventtype').drop(op.get_bind(), checkfirst=True)