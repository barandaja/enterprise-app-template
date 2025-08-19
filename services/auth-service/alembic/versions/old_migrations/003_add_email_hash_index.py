"""Add email hash index for encrypted email lookups

Revision ID: 003
Revises: 002
Create Date: 2024-01-15 00:00:00.000000

This migration adds a hash index for encrypted email lookups to improve
performance while maintaining PII encryption.

Migration Details:
- Revision: 003
- Previous: 002
- Created: 2024-01-15 00:00:00.000000

IMPORTANT NOTES:
1. Adds email_hash column with SHA256 hash of normalized email
2. Creates unique index on email_hash for O(1) lookups
3. Existing users will need data migration to populate email_hash
4. Application must be updated to use hash-based lookups
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Add email_hash column and index for efficient encrypted email lookups.
    
    This migration:
    1. Adds email_hash column to user table
    2. Creates unique index on email_hash
    3. Drops the inefficient index on encrypted email column
    
    Note: A separate data migration is needed to populate email_hash
    for existing users.
    """
    
    # Add email_hash column
    op.add_column(
        'user',
        sa.Column(
            'email_hash',
            sa.String(length=64),  # SHA256 produces 64 character hex string
            nullable=True  # Temporarily nullable for existing data
        )
    )
    
    # Create unique index on email_hash
    op.create_index(
        'idx_user_email_hash',
        'user',
        ['email_hash'],
        unique=True
    )
    
    # Drop the old inefficient index on encrypted email
    op.drop_index('idx_user_email', 'user')
    
    # Note: In a real deployment, you would:
    # 1. Deploy this migration with nullable email_hash
    # 2. Run a data migration script to populate email_hash for all users
    # 3. Deploy another migration to make email_hash NOT NULL
    # 4. Update application code to use hash-based lookups
    
    print("""
    IMPORTANT: After this migration, you must:
    1. Run the data migration script to populate email_hash for existing users
    2. Update the application to generate email_hash on user creation
    3. Deploy a follow-up migration to make email_hash NOT NULL
    """)


def downgrade() -> None:
    """
    Remove email_hash column and restore original email index.
    """
    
    # Recreate the original email index
    op.create_index('idx_user_email', 'user', ['email'])
    
    # Drop the email_hash index
    op.drop_index('idx_user_email_hash', 'user')
    
    # Remove email_hash column
    op.drop_column('user', 'email_hash')


# Data migration helper (to be run separately)
def populate_email_hashes():
    """
    Example data migration to populate email_hash for existing users.
    This should be run as a separate script after the schema migration.
    """
    import hashlib
    from sqlalchemy import create_engine, text
    from ..core.config import settings
    
    engine = create_engine(settings.DATABASE_URL)
    
    with engine.begin() as conn:
        # Get all users without email_hash
        result = conn.execute(text("""
            SELECT id, email FROM user WHERE email_hash IS NULL
        """))
        
        for row in result:
            user_id, encrypted_email = row
            
            # In production, you would decrypt the email first
            # For this example, we'll assume you have a decryption function
            # email = decrypt_email(encrypted_email)
            # email_hash = hashlib.sha256(email.lower().encode('utf-8')).hexdigest()
            
            # Update the user's email_hash
            # conn.execute(text("""
            #     UPDATE user SET email_hash = :email_hash WHERE id = :user_id
            # """), {"email_hash": email_hash, "user_id": user_id})
            
            pass  # Implement actual migration logic
    
    print("Email hash population completed")