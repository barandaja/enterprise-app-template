"""Add missing ENUM values for token and session events

Revision ID: 007_add_missing_enum_values
Revises: 006_fix_superuser
Create Date: 2025-08-04 16:00:00.000000

This migration adds the missing ENUM values for audit events:
- token_created
- token_refreshed  
- session_created
- session_ended

These values are needed for proper audit logging of authentication events.
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic
revision = '007_add_missing_enum_values'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add missing ENUM values to auditeventtype."""
    
    # Add new values to the auditeventtype ENUM
    # We need to add them one by one to avoid conflicts
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'token_created'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'token_refreshed'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'session_created'")
    op.execute("ALTER TYPE auditeventtype ADD VALUE IF NOT EXISTS 'session_ended'")


def downgrade() -> None:
    """Remove the added ENUM values.
    
    Note: PostgreSQL does not support removing ENUM values directly.
    This would require recreating the ENUM type, which is complex and risky.
    For now, we'll leave the values in place as they don't cause harm.
    """
    pass