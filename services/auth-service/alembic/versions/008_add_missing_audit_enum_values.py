"""Add missing audit enum values

Revision ID: 008_add_missing_audit_enum_values
Revises: 007_add_missing_enum_values
Create Date: 2025-08-04 20:00:00.000000

This migration adds missing enum values to the auditeventtype PostgreSQL enum:
- gdpr_data_access
- gdpr_consent_update  
- system_error
- permission_revoked

These values are needed for proper audit logging throughout the application.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = '008_add_missing_audit_enum_values'
down_revision = '007_add_missing_enum_values'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing ENUM values to auditeventtype."""
    
    # Add new values to the auditeventtype ENUM
    # We need to add them one by one to avoid conflicts
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'gdpr_data_access'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'gdpr_consent_update'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'system_error'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'permission_revoked'")


def downgrade() -> None:
    """Remove the added ENUM values.
    
    Note: PostgreSQL does not support removing ENUM values directly.
    This would require recreating the ENUM type, which is complex and risky.
    For now, we'll leave the values in place as they don't cause harm.
    """
    pass