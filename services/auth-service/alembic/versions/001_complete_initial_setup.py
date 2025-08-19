"""Complete initial setup for auth service database

Revision ID: 001_initial
Revises: 
Create Date: 2025-08-18 20:00:00.000000

This migration consolidates all initial setup:
1. Creates all required ENUM types first
2. Creates all tables with proper constraints
3. Adds indexes for performance
4. Seeds initial admin user
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import text
from datetime import datetime
from passlib.context import CryptContext
import hashlib

# revision identifiers
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create complete schema with proper ordering."""
    
    # First, ensure alembic_version can handle longer names
    op.execute("ALTER TABLE IF EXISTS alembic_version ALTER COLUMN version_num TYPE VARCHAR(100)")
    
    # 1. CREATE ALL ENUM TYPES FIRST
    # Create audit enum types
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auditeventtype AS ENUM (
                'login_success', 'login_failure', 'logout', 'password_change', 'password_reset',
                'account_locked', 'account_unlocked', 'permission_granted', 'permission_denied',
                'role_assigned', 'role_removed', 'data_read', 'data_create', 'data_update',
                'data_delete', 'data_export', 'user_created', 'user_updated', 'user_deleted',
                'user_activated', 'user_deactivated', 'system_start', 'system_stop',
                'config_change', 'backup_created', 'security_alert', 'suspicious_activity',
                'rate_limit_exceeded', 'unauthorized_access', 'token_created', 'token_refreshed',
                'session_created', 'session_ended', 'gdpr_data_request',
                'gdpr_data_delete', 'hipaa_access', 'soc2_control_check'
            );
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    op.execute("""
        DO $$ BEGIN
            CREATE TYPE auditseverity AS ENUM ('low', 'medium', 'high', 'critical');
        EXCEPTION
            WHEN duplicate_object THEN null;
        END $$;
    """)
    
    # 2. CREATE TABLES
    # User table
    op.create_table('user',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('email_hash', sa.String(length=64), nullable=True),
        sa.Column('first_name', sa.String(), nullable=True),
        sa.Column('last_name', sa.String(), nullable=True),
        sa.Column('phone_number', sa.String(), nullable=True),
        sa.Column('hashed_password', sa.String(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_superuser', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_login_ip', sa.String(), nullable=True),
        sa.Column('password_changed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('email_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('privacy_policy_accepted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data_processing_consent', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('marketing_consent', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('data_retention_until', sa.DateTime(timezone=True), nullable=True),
        sa.Column('profile_data', sa.JSON(), nullable=True),
        sa.Column('preferences', sa.JSON(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_email', 'user', ['email'], unique=True)
    op.create_index('ix_user_email_hash', 'user', ['email_hash'], unique=True)
    op.create_index('ix_user_is_active', 'user', ['is_active'])
    op.create_index('ix_user_is_verified', 'user', ['is_verified'])
    
    # User Session table (includes BaseModel fields)
    op.create_table('user_session',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(128), unique=True, nullable=False),
        sa.Column('refresh_token_id', sa.String(128), unique=True, nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('device_info', sa.JSON(), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('location_data', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_mobile', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_trusted_device', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('requires_mfa', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('mfa_completed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('suspicious_activity', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('session_data', sa.JSON(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_session_session_id', 'user_session', ['session_id'])
    op.create_index('ix_user_session_refresh_token_id', 'user_session', ['refresh_token_id'])
    op.create_index('ix_user_session_user_id', 'user_session', ['user_id'])
    op.create_index('ix_user_session_is_active', 'user_session', ['is_active'])
    op.create_index('ix_user_session_expires_at', 'user_session', ['expires_at'])
    
    # Audit log table
    op.create_table('audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_type', postgresql.ENUM('login_success', 'login_failure', 'logout', 'password_change', 'password_reset',
                'account_locked', 'account_unlocked', 'permission_granted', 'permission_denied',
                'role_assigned', 'role_removed', 'data_read', 'data_create', 'data_update',
                'data_delete', 'data_export', 'user_created', 'user_updated', 'user_deleted',
                'user_activated', 'user_deactivated', 'system_start', 'system_stop',
                'config_change', 'backup_created', 'security_alert', 'suspicious_activity',
                'rate_limit_exceeded', 'unauthorized_access', 'token_created', 'token_refreshed',
                'session_created', 'session_ended', 'gdpr_data_request',
                'gdpr_data_delete', 'hipaa_access', 'soc2_control_check',
                name='auditeventtype', create_type=False), nullable=False),
        sa.Column('event_id', sa.String(), nullable=False),
        sa.Column('correlation_id', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('severity', postgresql.ENUM('low', 'medium', 'high', 'critical', 
                name='auditseverity', create_type=False), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('session_id', sa.String(), nullable=True),
        sa.Column('impersonator_user_id', sa.Integer(), nullable=True),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('request_method', sa.String(), nullable=True),
        sa.Column('request_path', sa.String(), nullable=True),
        sa.Column('request_id', sa.String(), nullable=True),
        sa.Column('resource_type', sa.String(), nullable=True),
        sa.Column('resource_id', sa.String(), nullable=True),
        sa.Column('resource_name', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('event_data', sa.JSON(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('error_code', sa.String(), nullable=True),
        sa.Column('error_message', sa.String(), nullable=True),
        sa.Column('pii_accessed', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('gdpr_relevant', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('hipaa_relevant', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('execution_time_ms', sa.Integer(), nullable=True),
        sa.Column('response_status', sa.Integer(), nullable=True),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_log_event_type', 'audit_log', ['event_type'])
    op.create_index('ix_audit_log_user_id', 'audit_log', ['user_id'])
    op.create_index('ix_audit_log_timestamp', 'audit_log', ['timestamp'])
    op.create_index('ix_audit_log_severity', 'audit_log', ['severity'])
    
    # Role table
    op.create_table('role',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('permissions', sa.JSON(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_system_role', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_role_name', 'role', ['name'], unique=True)
    
    # User-Role association table
    op.create_table('user_roles',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('assigned_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['role_id'], ['role.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['assigned_by'], ['user.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # 3. SEED INITIAL DATA
    # Create admin user
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    admin_email = 'admin@example.com'
    admin_password = 'Admin123!'
    email_hash = hashlib.sha256(admin_email.lower().encode()).hexdigest()
    hashed_password = pwd_context.hash(admin_password)
    
    # Use connection.execute instead of op.execute for parameterized queries
    connection = op.get_bind()
    connection.execute(
        text("""
            INSERT INTO "user" (
                email, email_hash, first_name, last_name, 
                hashed_password, is_active, is_verified, is_superuser,
                email_verified_at, password_changed_at
            ) VALUES (
                :email, :email_hash, :first_name, :last_name,
                :hashed_password, true, true, true,
                NOW(), NOW()
            )
        """),
        {
            'email': admin_email,
            'email_hash': email_hash,
            'first_name': 'Admin',
            'last_name': 'User',
            'hashed_password': hashed_password
        }
    )
    
    print(f"✅ Database initialized successfully")
    print(f"✅ Admin user created: {admin_email} / {admin_password}")


def downgrade() -> None:
    """Drop all tables and types."""
    op.drop_table('user_roles')
    op.drop_table('role')
    op.drop_table('audit_log')
    op.drop_table('user_session')
    op.drop_table('user')
    
    op.execute("DROP TYPE IF EXISTS auditeventtype")
    op.execute("DROP TYPE IF EXISTS auditseverity")